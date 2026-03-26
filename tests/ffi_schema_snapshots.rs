use sbom_tools::ffi::{
    SbomToolsErrorCode, SbomToolsScoringProfile, SbomToolsStringResult,
    sbom_tools_abi_version_json, sbom_tools_detect_format_json, sbom_tools_diff_sboms_json,
    sbom_tools_parse_sbom_path_json, sbom_tools_score_sbom_json, sbom_tools_string_result_free,
};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn into_c_string(value: &str) -> CString {
    CString::new(value).expect("input should be free of NUL bytes")
}

fn consume_result(result: SbomToolsStringResult) -> Result<String, (SbomToolsErrorCode, String)> {
    let code = result.error_code;
    let payload = if result.data.is_null() {
        None
    } else {
        // SAFETY: pointer ownership belongs to the ABI result and stays valid
        // until sbom_tools_string_result_free is invoked.
        Some(unsafe { CStr::from_ptr(result.data) }.to_string_lossy().into_owned())
    };
    let error_message = if result.error_message.is_null() {
        None
    } else {
        // SAFETY: pointer ownership belongs to the ABI result and stays valid
        // until sbom_tools_string_result_free is invoked.
        Some(
            unsafe { CStr::from_ptr(result.error_message) }
                .to_string_lossy()
                .into_owned(),
        )
    };

    sbom_tools_string_result_free(result);

    if code == SbomToolsErrorCode::Ok {
        Ok(payload.expect("successful result should include payload"))
    } else {
        Err((
            code,
            error_message.expect("failing result should include error message"),
        ))
    }
}

fn assert_required_keys(payload: &str, required: &[String]) {
    let value: serde_json::Value = serde_json::from_str(payload).expect("ABI JSON should be valid");
    let object = value.as_object().expect("ABI response should be a JSON object");
    for key in required {
        assert!(
            object.contains_key(key),
            "ABI payload is missing required key '{key}': {payload}"
        );
    }
}

#[test]
fn abi_contract_snapshots_are_enforced() {
    let contract_path = fixture_path("abi/contract_required_keys.json");
    let contract_raw = std::fs::read_to_string(contract_path).expect("snapshot fixture should exist");
    let contract: HashMap<String, HashMap<String, Vec<String>>> =
        serde_json::from_str(&contract_raw).expect("snapshot fixture should parse");

    let abi_version = consume_result(sbom_tools_abi_version_json()).expect("ABI version payload");
    assert_required_keys(
        &abi_version,
        &contract["abi_version_json"]["required_keys"],
    );

    let detect_input = into_c_string(r#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#);
    let detection = consume_result(sbom_tools_detect_format_json(detect_input.as_ptr()))
        .expect("detected format payload");
    assert_required_keys(
        &detection,
        &contract["detected_format_json"]["required_keys"],
    );

    let old_path = into_c_string(fixture_path("demo-old.cdx.json").to_string_lossy().as_ref());
    let new_path = into_c_string(fixture_path("demo-new.cdx.json").to_string_lossy().as_ref());
    let old_payload = consume_result(sbom_tools_parse_sbom_path_json(old_path.as_ptr()))
        .expect("old normalized SBOM payload");
    let new_payload = consume_result(sbom_tools_parse_sbom_path_json(new_path.as_ptr()))
        .expect("new normalized SBOM payload");

    assert_required_keys(
        &old_payload,
        &contract["normalized_sbom_json"]["required_keys"],
    );

    let old_payload_c = into_c_string(&old_payload);
    let new_payload_c = into_c_string(&new_payload);
    let diff_payload = consume_result(sbom_tools_diff_sboms_json(
        old_payload_c.as_ptr(),
        new_payload_c.as_ptr(),
    ))
    .expect("diff payload");
    assert_required_keys(
        &diff_payload,
        &contract["diff_result_json"]["required_keys"],
    );

    let quality_payload = consume_result(sbom_tools_score_sbom_json(
        new_payload_c.as_ptr(),
        SbomToolsScoringProfile::Standard,
    ))
    .expect("quality payload");
    assert_required_keys(
        &quality_payload,
        &contract["quality_report_json"]["required_keys"],
    );
}

#[test]
fn c_header_signatures_snapshot_is_enforced() {
    let header = std::fs::read_to_string(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/bindings/swift/Sources/CSbomTools/include/sbom_tools.h"
        ),
    )
    .expect("header should exist");

    let expected = std::fs::read_to_string(fixture_path("abi/header_signatures.txt"))
        .expect("header signatures snapshot should exist");

    for signature in expected.lines().filter(|line| !line.trim().is_empty()) {
        assert!(
            header.contains(signature),
            "Header is missing expected signature: {signature}"
        );
    }
}