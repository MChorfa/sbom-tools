//! C-compatible ABI for Go and Swift wrappers.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::diff::DiffEngine;
use crate::model::{CanonicalId, Component, DependencyEdge, DocumentMetadata, FormatExtensions, NormalizedSbom};
use crate::parsers::{ParseError, detect_format, parse_sbom, parse_sbom_str};
use crate::quality::{QualityScorer, ScoringProfile};
use indexmap::IndexMap;
use serde::Serialize;
use std::ffi::{CStr, CString, c_char};
use std::path::Path;

const ABI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stable error codes for the C ABI.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomToolsErrorCode {
    /// Successful operation.
    Ok = 0,
    /// Parsing of raw SBOM input failed.
    Parse = 1,
    /// Semantic diffing failed.
    Diff = 2,
    /// Validation of normalized JSON input failed.
    Validation = 3,
    /// IO failed while reading from disk.
    Io = 4,
    /// Requested functionality is unsupported.
    Unsupported = 5,
    /// Unexpected internal failure.
    Internal = 6,
}

/// Stable scoring profile identifiers for the C ABI.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomToolsScoringProfile {
    Minimal = 0,
    Standard = 1,
    Security = 2,
    LicenseCompliance = 3,
    Cra = 4,
    Comprehensive = 5,
}

impl SbomToolsScoringProfile {
    const fn into_rust(self) -> ScoringProfile {
        match self {
            Self::Minimal => ScoringProfile::Minimal,
            Self::Standard => ScoringProfile::Standard,
            Self::Security => ScoringProfile::Security,
            Self::LicenseCompliance => ScoringProfile::LicenseCompliance,
            Self::Cra => ScoringProfile::Cra,
            Self::Comprehensive => ScoringProfile::Comprehensive,
        }
    }
}

/// Generic string payload result for the C ABI.
#[repr(C)]
#[derive(Debug)]
pub struct SbomToolsStringResult {
    /// JSON payload on success.
    pub data: *mut c_char,
    /// Stable ABI error code.
    pub error_code: SbomToolsErrorCode,
    /// UTF-8 error message on failure.
    pub error_message: *mut c_char,
}

impl SbomToolsStringResult {
    fn success(payload: String) -> Self {
        Self {
            data: into_c_string(payload),
            error_code: SbomToolsErrorCode::Ok,
            error_message: std::ptr::null_mut(),
        }
    }

    fn error(code: SbomToolsErrorCode, message: impl Into<String>) -> Self {
        Self {
            data: std::ptr::null_mut(),
            error_code: code,
            error_message: into_c_string(message.into()),
        }
    }
}

struct FfiError {
    code: SbomToolsErrorCode,
    message: String,
}

#[derive(Debug, Serialize, serde::Deserialize)]
struct AbiComponentEntry {
    canonical_id: CanonicalId,
    component: Component,
}

#[derive(Debug, Serialize, serde::Deserialize)]
struct AbiNormalizedSbom {
    document: DocumentMetadata,
    components: Vec<AbiComponentEntry>,
    edges: Vec<DependencyEdge>,
    extensions: FormatExtensions,
    content_hash: u64,
    primary_component_id: Option<CanonicalId>,
    collision_count: usize,
}

impl AbiNormalizedSbom {
    fn from_sbom(sbom: NormalizedSbom) -> Self {
        Self {
            document: sbom.document,
            components: sbom
                .components
                .into_iter()
                .map(|(canonical_id, component)| AbiComponentEntry {
                    canonical_id,
                    component,
                })
                .collect(),
            edges: sbom.edges,
            extensions: sbom.extensions,
            content_hash: sbom.content_hash,
            primary_component_id: sbom.primary_component_id,
            collision_count: sbom.collision_count,
        }
    }

    fn into_sbom(self) -> NormalizedSbom {
        let components = self
            .components
            .into_iter()
            .map(|entry| (entry.canonical_id, entry.component))
            .collect::<IndexMap<_, _>>();

        NormalizedSbom {
            document: self.document,
            components,
            edges: self.edges,
            extensions: self.extensions,
            content_hash: self.content_hash,
            primary_component_id: self.primary_component_id,
            collision_count: self.collision_count,
        }
    }
}

#[derive(Serialize)]
struct AbiVersionPayload<'a> {
    abi_version: &'a str,
    crate_version: &'a str,
}

fn into_c_string(value: String) -> *mut c_char {
    let sanitized = value.replace('\0', " ");
    match CString::new(sanitized) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn read_input(value: *const c_char, field: &str) -> Result<String, FfiError> {
    if value.is_null() {
        return Err(FfiError {
            code: SbomToolsErrorCode::Validation,
            message: format!("{field} pointer must not be null"),
        });
    }

    // SAFETY: The caller guarantees a valid NUL-terminated string pointer.
    let c_string = unsafe { CStr::from_ptr(value) };
    c_string.to_str().map(str::to_owned).map_err(|err| FfiError {
        code: SbomToolsErrorCode::Validation,
        message: format!("{field} must be valid UTF-8: {err}"),
    })
}

fn parse_normalized_sbom(json: &str, field: &str) -> Result<NormalizedSbom, FfiError> {
    serde_json::from_str::<AbiNormalizedSbom>(json)
        .map(AbiNormalizedSbom::into_sbom)
        .map_err(|err| FfiError {
        code: SbomToolsErrorCode::Validation,
        message: format!("invalid normalized SBOM JSON in {field}: {err}"),
    })
}

fn map_parse_error(err: ParseError) -> FfiError {
    let code = match err {
        ParseError::IoError(_) => SbomToolsErrorCode::Io,
        ParseError::UnsupportedVersion(_) | ParseError::UnknownFormat(_) => {
            SbomToolsErrorCode::Unsupported
        }
        ParseError::ValidationError(_) | ParseError::MissingField(_) => {
            SbomToolsErrorCode::Validation
        }
        ParseError::JsonError(_) | ParseError::XmlError(_) | ParseError::YamlError(_) => {
            SbomToolsErrorCode::Parse
        }
        ParseError::InvalidStructure(_) => SbomToolsErrorCode::Parse,
    };

    FfiError {
        code,
        message: err.to_string(),
    }
}

fn run_json<T, F>(operation: F) -> SbomToolsStringResult
where
    T: Serialize,
    F: FnOnce() -> Result<T, FfiError>,
{
    match operation() {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(payload) => SbomToolsStringResult::success(payload),
            Err(err) => SbomToolsStringResult::error(
                SbomToolsErrorCode::Internal,
                format!("failed to serialize ABI response: {err}"),
            ),
        },
        Err(err) => SbomToolsStringResult::error(err.code, err.message),
    }
}

/// Return the ABI and crate versions as JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_abi_version_json() -> SbomToolsStringResult {
    run_json(|| {
        Ok(AbiVersionPayload {
            abi_version: "1",
            crate_version: ABI_VERSION,
        })
    })
}

/// Detect the SBOM format from raw content and return JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_detect_format_json(content: *const c_char) -> SbomToolsStringResult {
    run_json(|| {
        let content = read_input(content, "content")?;
        Ok(detect_format(&content))
    })
}

/// Parse an SBOM file from disk and return normalized JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_parse_sbom_path_json(
    path: *const c_char,
) -> SbomToolsStringResult {
    run_json(|| {
        let path = read_input(path, "path")?;
        parse_sbom(Path::new(&path))
            .map(AbiNormalizedSbom::from_sbom)
            .map_err(map_parse_error)
    })
}

/// Parse raw SBOM content and return normalized JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_parse_sbom_str_json(
    content: *const c_char,
) -> SbomToolsStringResult {
    run_json(|| {
        let content = read_input(content, "content")?;
        parse_sbom_str(&content)
            .map(AbiNormalizedSbom::from_sbom)
            .map_err(map_parse_error)
    })
}

/// Diff two normalized SBOM JSON documents and return a diff result as JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_diff_sboms_json(
    old_sbom_json: *const c_char,
    new_sbom_json: *const c_char,
) -> SbomToolsStringResult {
    run_json(|| {
        let old_json = read_input(old_sbom_json, "old_sbom_json")?;
        let new_json = read_input(new_sbom_json, "new_sbom_json")?;
        let old = parse_normalized_sbom(&old_json, "old_sbom_json")?;
        let new = parse_normalized_sbom(&new_json, "new_sbom_json")?;

        DiffEngine::new().diff(&old, &new).map_err(|err| FfiError {
            code: SbomToolsErrorCode::Diff,
            message: err.to_string(),
        })
    })
}

/// Score a normalized SBOM JSON document and return a quality report as JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_score_sbom_json(
    sbom_json: *const c_char,
    profile: SbomToolsScoringProfile,
) -> SbomToolsStringResult {
    run_json(|| {
        let sbom_json = read_input(sbom_json, "sbom_json")?;
        let sbom = parse_normalized_sbom(&sbom_json, "sbom_json")?;
        Ok(QualityScorer::new(profile.into_rust()).score(&sbom))
    })
}

/// Free memory allocated by the ABI result.
///
/// # Safety
/// The caller must pass a result obtained from this ABI and must not reuse any
/// pointers inside it after this function returns.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_string_result_free(result: SbomToolsStringResult) {
    if !result.data.is_null() {
        // SAFETY: The pointer was allocated by CString::into_raw in this module.
        unsafe {
            drop(CString::from_raw(result.data));
        }
    }

    if !result.error_message.is_null() {
        // SAFETY: The pointer was allocated by CString::into_raw in this module.
        unsafe {
            drop(CString::from_raw(result.error_message));
        }
    }
}