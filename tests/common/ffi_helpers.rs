//! Shared test helpers for FFI bindings tests

#![allow(dead_code)] // Some helpers are used only in some test files

use sbom_tools::ffi::{SbomToolsErrorCode, SbomToolsStringResult, sbom_tools_string_result_free};
use std::ffi::{CStr, c_char};

/// Consume an FFI result and return its payload or error.
///
/// Handles pointer safety and calls the appropriate free function.
///
/// # Safety
/// The result must be a valid SbomToolsStringResult returned from an FFI function.
pub fn consume_result(
    result: SbomToolsStringResult,
) -> Result<String, (SbomToolsErrorCode, String)> {
    let code = result.error_code;
    let payload = if result.data.is_null() {
        None
    } else {
        // SAFETY: The FFI result is allocated by the Rust ABI and remains valid
        // until sbom_tools_string_result_free is called below.
        Some(
            unsafe { CStr::from_ptr(result.data) }
                .to_string_lossy()
                .into_owned(),
        )
    };
    let error_message = if result.error_message.is_null() {
        None
    } else {
        // SAFETY: The FFI result is allocated by the Rust ABI and remains valid
        // until sbom_tools_string_result_free is called below.
        Some(
            unsafe { CStr::from_ptr(result.error_message) }
                .to_string_lossy()
                .into_owned(),
        )
    };
    sbom_tools_string_result_free(result);

    if code == SbomToolsErrorCode::Ok {
        Ok(payload.expect("successful results should contain a payload"))
    } else {
        Err((
            code,
            error_message.expect("failing results should contain an error message"),
        ))
    }
}

/// Convert a Rust string to a C string for FFI calls.
///
/// # Panics
/// Panics if the input string contains NUL bytes.
pub fn into_c_string(value: &str) -> std::ffi::CString {
    std::ffi::CString::new(value).expect("fixture input should be free of NUL bytes")
}

/// Parse a C string from a pointer, returning None if null.
///
/// # Safety
/// The pointer must be a valid C string (NUL-terminated).
pub fn c_str_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: The pointer is guaranteed valid by the FFI boundary.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_owned)
}
