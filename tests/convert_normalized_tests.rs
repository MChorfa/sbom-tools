//! `convert --to normalized`: the canonical model as JSON, shared with the ABI.
//!
//! Issue #366 asked for the normalized payload from the CLI so downstream
//! tools can consume it without linking the C ABI. These tests pin what that
//! surface promises: the contract's top-level keys, lossless round-trip, the
//! presence of domain detail that `view -o json` deliberately omits (crypto
//! properties), and that the fidelity report is empty.

use sbom_tools::serialization::{EmitTarget, NormalizedSbomPayload, emit, normalized_sbom_json};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn normalized_target_parses_from_cli_spelling() {
    assert_eq!(
        EmitTarget::parse("normalized"),
        Some(EmitTarget::Normalized)
    );
    assert_eq!(
        EmitTarget::parse("NORMALIZED"),
        Some(EmitTarget::Normalized)
    );
    assert_eq!(
        EmitTarget::parse("json"),
        None,
        "`json` alone stays rejected"
    );
}

#[test]
fn normalized_output_has_contract_keys_and_is_lossless() {
    let sbom = sbom_tools::parse_sbom(&fixture("demo-new.cdx.json")).expect("parse fixture");
    let (json, report) = emit(&sbom, EmitTarget::Normalized).expect("emit normalized");

    assert!(
        !report.is_lossy(),
        "normalized emission must never be lossy"
    );
    assert_eq!(report.dropped_count(), 0);

    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    for key in [
        "document",
        "components",
        "edges",
        "extensions",
        "content_hash",
        "primary_component_id",
        "collision_count",
    ] {
        assert!(value.get(key).is_some(), "missing contract key {key}");
    }
    assert_eq!(
        value["components"].as_array().map(Vec::len),
        Some(sbom.component_count()),
        "every component must be present, in order"
    );

    let back: NormalizedSbomPayload = serde_json::from_str(&json).expect("payload deserializes");
    let rebuilt = back.into_sbom();
    assert_eq!(rebuilt.content_hash, sbom.content_hash);
    assert_eq!(
        normalized_sbom_json(&rebuilt).expect("re-serialize"),
        json,
        "round trip must be byte-stable"
    );
}

/// The reporter's use case: a PQC policy checker needs `crypto_properties`,
/// which `view -o json` does not carry. The normalized payload must.
#[test]
fn normalized_output_carries_crypto_properties_for_cbom() {
    let sbom = sbom_tools::parse_sbom(&fixture("cyclonedx/cbom-1.6.cdx.json")).expect("parse CBOM");
    let (json, _) = emit(&sbom, EmitTarget::Normalized).expect("emit normalized");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    let with_crypto = value["components"]
        .as_array()
        .expect("components array")
        .iter()
        .filter(|entry| entry["component"].get("crypto_properties").is_some())
        .count();
    assert!(
        with_crypto > 0,
        "CBOM components must expose crypto_properties"
    );

    let algo = value["components"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|entry| {
            entry["component"]["crypto_properties"]
                .get("algorithm_properties")
                .filter(|v| !v.is_null())
        })
        .expect("at least one algorithm component");
    for key in ["primitive", "parameter_set_identifier", "crypto_functions"] {
        assert!(
            algo.get(key).is_some(),
            "algorithm_properties must carry `{key}`; got {algo}"
        );
    }
}
