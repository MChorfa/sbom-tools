//! JSON serialization for pipeline receipts.
use super::pipeline_receipt::{PipelineShardReceipt, ReceiptError, validate_receipt};
use serde::de::{DeserializeOwned, IgnoredAny};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

/// Upper bound for a receipt, aggregate policy, or generator descriptor.
/// These are small metadata documents; the cap keeps a hostile or corrupted
/// input (e.g. a downloaded artifact) from exhausting memory.
pub const MAX_CONTRACT_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

pub fn write_receipt(path: &Path, receipt: &PipelineShardReceipt) -> Result<(), ReceiptError> {
    validate_receipt(receipt)?;
    let bytes = serde_json::to_vec_pretty(receipt).map_err(|source| ReceiptError::Json {
        path: path.into(),
        source,
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| ReceiptError::Io {
            path: path.into(),
            source,
        })?;
    file.write_all(&bytes).map_err(|source| ReceiptError::Io {
        path: path.into(),
        source,
    })
}

/// Read a contract document (receipt, policy, or descriptor) with the
/// documented exit split: unreadable files and bytes that are not JSON are
/// operational errors (`Io`/`Json` -> exit 3), while well-formed JSON that
/// violates the document shape is a gate verdict (`Contract` -> exit 1).
///
/// The shape phase deserializes straight from the bytes rather than via
/// `serde_json::Value`: a `Value` map silently keeps the last of two duplicate
/// keys, whereas the derived structs reject duplicate fields outright.
pub fn read_contract_json<T: DeserializeOwned>(path: &Path) -> Result<T, ReceiptError> {
    let io_error = |source| ReceiptError::Io {
        path: path.into(),
        source,
    };
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(io_error)?
        .take(MAX_CONTRACT_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > MAX_CONTRACT_DOCUMENT_BYTES {
        return Err(ReceiptError::Contract(format!(
            "document exceeds {MAX_CONTRACT_DOCUMENT_BYTES} bytes"
        )));
    }
    // Syntax phase: validates the whole document without building a tree.
    serde_json::from_slice::<IgnoredAny>(&bytes).map_err(|source| ReceiptError::Json {
        path: path.into(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| ReceiptError::Contract(source.to_string()))
}

pub fn read_receipt(path: &Path) -> Result<PipelineShardReceipt, ReceiptError> {
    let receipt: PipelineShardReceipt = read_contract_json(path)?;
    validate_receipt(&receipt)?;
    Ok(receipt)
}

pub fn check_receipt(path: &Path) -> Result<(), ReceiptError> {
    read_receipt(path).map(|_| ())
}
