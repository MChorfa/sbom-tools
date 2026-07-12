//! Safetensors header parsing — metadata only, tensors are never read.
//!
//! Format: 8 bytes little-endian `u64` header length, then a JSON object
//! mapping tensor names to `{ dtype, shape, data_offsets }`, plus an optional
//! `__metadata__` string map. Parameter counts computed here are *measured*
//! facts (shape products), unlike the model card's declared values.
//!
//! The parser is bounded for untrusted input: the header length is capped
//! before any allocation, and only the header bytes are ever read.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

/// Upper bound on the accepted header size. The format specification caps
/// headers at 100 MB; real headers are a few MB at most for huge models.
const MAX_HEADER_BYTES: u64 = 100 * 1024 * 1024;

/// Parsed safetensors metadata (header only).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SafetensorsMeta {
    /// Total parameter count: sum of shape products over all tensors.
    pub param_count: u64,
    /// Tensor count per dtype (e.g. `F32` → 197). `BTreeMap` for
    /// deterministic iteration in emitted properties.
    pub dtype_params: BTreeMap<String, u64>,
    /// Number of tensors.
    pub tensor_count: usize,
    /// The optional `__metadata__` string map (e.g. `format: pt`).
    pub metadata: BTreeMap<String, String>,
}

impl SafetensorsMeta {
    /// Parse the header of the safetensors file at `path`.
    ///
    /// Returns `None` on any structural problem (short file, oversized or
    /// non-JSON header) — the file is then inventoried without tensor
    /// metadata rather than failing generation.
    #[must_use]
    pub fn read_from_file(path: &Path) -> Option<Self> {
        let mut file = std::fs::File::open(path).ok()?;
        let mut len_bytes = [0u8; 8];
        file.read_exact(&mut len_bytes).ok()?;
        let header_len = u64::from_le_bytes(len_bytes);
        if header_len == 0 || header_len > MAX_HEADER_BYTES {
            return None;
        }
        // Bounded by MAX_HEADER_BYTES, so the cast and allocation are safe.
        #[allow(clippy::cast_possible_truncation)]
        let mut header = vec![0u8; header_len as usize];
        file.read_exact(&mut header).ok()?;
        Self::parse_header(&header)
    }

    /// Parse a raw header JSON blob (exposed for fuzzing).
    #[must_use]
    pub fn parse_header(header: &[u8]) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_slice(header).ok()?;
        let obj = v.as_object()?;

        let mut meta = Self::default();
        for (name, entry) in obj {
            if name == "__metadata__" {
                if let Some(map) = entry.as_object() {
                    for (k, val) in map {
                        if let Some(s) = val.as_str() {
                            meta.metadata.insert(k.clone(), s.to_string());
                        }
                    }
                }
                continue;
            }
            let Some(tensor) = entry.as_object() else {
                continue;
            };
            let dtype = tensor
                .get("dtype")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            // Empty shape = scalar tensor = 1 parameter (the empty product);
            // a 0-length dimension genuinely contributes 0 parameters.
            let params: u64 = tensor
                .get("shape")
                .and_then(serde_json::Value::as_array)
                .map_or(0, |shape| {
                    shape
                        .iter()
                        .filter_map(serde_json::Value::as_u64)
                        .fold(1u64, u64::saturating_mul)
                });
            meta.param_count = meta.param_count.saturating_add(params);
            *meta.dtype_params.entry(dtype).or_insert(0) += params;
            meta.tensor_count += 1;
        }
        Some(meta)
    }

    /// Merge another shard's metadata into this one (sharded models).
    pub fn merge(&mut self, other: &Self) {
        self.param_count = self.param_count.saturating_add(other.param_count);
        self.tensor_count += other.tensor_count;
        for (dtype, params) in &other.dtype_params {
            *self.dtype_params.entry(dtype.clone()).or_insert(0) += params;
        }
        for (k, v) in &other.metadata {
            self.metadata.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    /// The dtype holding the most parameters (the model's dominant precision).
    #[must_use]
    pub fn dominant_dtype(&self) -> Option<&str> {
        self.dtype_params
            .iter()
            .max_by_key(|(_, params)| **params)
            .map(|(dtype, _)| dtype.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid safetensors file: header + zeroed tensor data.
    pub(crate) fn build_safetensors(tensors: &[(&str, &str, &[u64])]) -> Vec<u8> {
        let mut header = serde_json::Map::new();
        let mut offset = 0u64;
        for (name, dtype, shape) in tensors {
            let elem_size = match *dtype {
                "F64" | "I64" | "U64" => 8,
                "F32" | "I32" | "U32" => 4,
                "F16" | "BF16" | "I16" | "U16" => 2,
                _ => 1,
            };
            let n: u64 = shape.iter().product();
            let bytes = n * elem_size;
            header.insert(
                (*name).to_string(),
                serde_json::json!({
                    "dtype": dtype,
                    "shape": shape,
                    "data_offsets": [offset, offset + bytes],
                }),
            );
            offset += bytes;
        }
        let header_json = serde_json::to_vec(&serde_json::Value::Object(header)).unwrap();
        let mut out = Vec::new();
        out.extend((header_json.len() as u64).to_le_bytes());
        out.extend(&header_json);
        out.extend(std::iter::repeat_n(0u8, usize::try_from(offset).unwrap()));
        out
    }

    #[test]
    fn parses_param_counts() {
        let bytes = build_safetensors(&[
            ("embed.weight", "F32", &[100, 8]),
            ("head.weight", "F32", &[8, 2]),
        ]);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &bytes).unwrap();
        let meta = SafetensorsMeta::read_from_file(tmp.path()).unwrap();
        assert_eq!(meta.param_count, 816);
        assert_eq!(meta.tensor_count, 2);
        assert_eq!(meta.dominant_dtype(), Some("F32"));
    }

    #[test]
    fn metadata_map_extracted() {
        let header = br#"{"__metadata__": {"format": "pt"}, "w": {"dtype": "F16", "shape": [4]}}"#;
        let meta = SafetensorsMeta::parse_header(header).unwrap();
        assert_eq!(meta.metadata.get("format").map(String::as_str), Some("pt"));
        assert_eq!(meta.param_count, 4);
    }

    #[test]
    fn oversized_header_rejected() {
        let mut bytes = Vec::new();
        bytes.extend((MAX_HEADER_BYTES + 1).to_le_bytes());
        bytes.extend(b"{}");
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &bytes).unwrap();
        assert!(SafetensorsMeta::read_from_file(tmp.path()).is_none());
    }

    #[test]
    fn truncated_file_rejected() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), [1u8, 0, 0]).unwrap();
        assert!(SafetensorsMeta::read_from_file(tmp.path()).is_none());
    }

    #[test]
    fn merge_accumulates() {
        let a = SafetensorsMeta::parse_header(br#"{"w": {"dtype": "F32", "shape": [10]}}"#).unwrap();
        let mut b =
            SafetensorsMeta::parse_header(br#"{"v": {"dtype": "BF16", "shape": [30]}}"#).unwrap();
        b.merge(&a);
        assert_eq!(b.param_count, 40);
        assert_eq!(b.dominant_dtype(), Some("BF16"));
    }

    #[test]
    fn non_json_header_rejected() {
        assert!(SafetensorsMeta::parse_header(b"not json").is_none());
    }
}
