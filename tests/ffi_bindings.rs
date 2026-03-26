use sbom_tools::ffi::{
    SbomToolsErrorCode, SbomToolsScoringProfile, SbomToolsStringResult,
    sbom_tools_abi_version_json, sbom_tools_detect_format_json, sbom_tools_diff_sboms_json,
    sbom_tools_parse_sbom_path_json, sbom_tools_parse_sbom_str_json,
    sbom_tools_score_sbom_json, sbom_tools_string_result_free,
};
use std::ffi::{CStr, CString};
use std::path::Path;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn into_c_string(value: &str) -> CString {
    CString::new(value).expect("fixture input should be free of NUL bytes")
}

fn consume_result(result: SbomToolsStringResult) -> Result<String, (SbomToolsErrorCode, String)> {
    let code = result.error_code;
    let payload = if result.data.is_null() {
        None
    } else {
        // SAFETY: The FFI result is allocated by the Rust ABI and remains valid
        // until sbom_tools_string_result_free is called below.
        Some(unsafe { CStr::from_ptr(result.data) }.to_string_lossy().into_owned())
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

#[test]
fn ffi_reports_abi_version() {
    let payload = consume_result(sbom_tools_abi_version_json()).expect("ABI version should load");
    let value: serde_json::Value = serde_json::from_str(&payload).expect("valid JSON response");
    assert_eq!(value["abi_version"], "1");
    assert!(value["crate_version"].as_str().is_some());
}

#[test]
fn ffi_detects_format_and_parses_path() {
    let fixture = fixture_path("cyclonedx/minimal.cdx.json");
    let content = std::fs::read_to_string(&fixture).expect("fixture should load");
    let content = into_c_string(&content);
    let detection = consume_result(sbom_tools_detect_format_json(content.as_ptr()))
        .expect("format detection should succeed");
    assert!(detection.contains("CycloneDX"));

    let path = into_c_string(fixture.to_string_lossy().as_ref());
    let parsed = consume_result(sbom_tools_parse_sbom_path_json(path.as_ptr()))
        .expect("path parsing should succeed");
    let value: serde_json::Value = serde_json::from_str(&parsed).expect("parsed JSON should load");
    assert_eq!(value["document"]["format"], "CycloneDx");
}

#[test]
fn ffi_can_diff_and_score_normalized_sboms() {
    let old_path = fixture_path("demo-old.cdx.json");
    let new_path = fixture_path("demo-new.cdx.json");
    let old_input = into_c_string(&std::fs::read_to_string(&old_path).expect("old fixture"));
    let new_input = into_c_string(&std::fs::read_to_string(&new_path).expect("new fixture"));

    let old_json = consume_result(sbom_tools_parse_sbom_str_json(old_input.as_ptr()))
        .expect("old parse should succeed");
    let new_json = consume_result(sbom_tools_parse_sbom_str_json(new_input.as_ptr()))
        .expect("new parse should succeed");

    let old_json_c = into_c_string(&old_json);
    let new_json_c = into_c_string(&new_json);
    let diff_json = consume_result(sbom_tools_diff_sboms_json(
        old_json_c.as_ptr(),
        new_json_c.as_ptr(),
    ))
    .expect("diff should succeed");
    let diff_value: serde_json::Value = serde_json::from_str(&diff_json).expect("diff JSON");
    assert!(diff_value["summary"]["total_changes"].as_u64().unwrap_or(0) > 0);

    let score_json = consume_result(sbom_tools_score_sbom_json(
        new_json_c.as_ptr(),
        SbomToolsScoringProfile::Standard,
    ))
    .expect("score should succeed");
    let score_value: serde_json::Value = serde_json::from_str(&score_json).expect("score JSON");
    assert!(score_value["overall_score"].as_f64().unwrap_or(0.0) > 0.0);
}

#[test]
fn ffi_reports_validation_errors() {
    let invalid_json = into_c_string("{not-json}");
    let err = consume_result(sbom_tools_diff_sboms_json(
        invalid_json.as_ptr(),
        invalid_json.as_ptr(),
    ))
    .expect_err("invalid normalized JSON should fail");

    assert_eq!(err.0, SbomToolsErrorCode::Validation);
    assert!(err.1.contains("invalid normalized SBOM JSON"));
}