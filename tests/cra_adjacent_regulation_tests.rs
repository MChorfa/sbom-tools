//! Integration tests for CRA-P4.4 Adjacent regulation surfacing.
//!
//! Asserts that the cra-docs technical-documentation.md template surfaces
//! NIS2 / GDPR / AI Act / RED guidance only when the corresponding
//! sidecar flag is set, and that none of the sections fire when the
//! sidecar omits all five flags.

use sbom_tools::cli::run_cra_docs;
use sbom_tools::model::CraSidecarMetadata;
use std::fs;
use tempfile::tempdir;

const MINIMAL_CDX: &str = r#"{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"type": "application", "name": "app", "version": "1.0.0"}},
    "components": []
}"#;

fn write_temp(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    fs::write(&p, body).unwrap();
    p
}

fn run_with_sidecar(sidecar: CraSidecarMetadata) -> String {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let sidecar_path = dir.path().join("app.cra.json");
    fs::write(&sidecar_path, serde_json::to_string(&sidecar).unwrap()).unwrap();
    let out = dir.path().join("dossier");
    run_cra_docs(sbom, out.clone(), Some(sidecar_path), None).expect("cra-docs runs");
    fs::read_to_string(out.join("technical-documentation.md")).unwrap()
}

#[test]
fn empty_sidecar_omits_adjacent_regulation_section() {
    let tech = run_with_sidecar(CraSidecarMetadata::default());
    assert!(
        !tech.contains("Adjacent regulation"),
        "Adjacent regulation must NOT render when no flags set"
    );
}

#[test]
fn nis2_essential_entity_renders_art_23_guidance() {
    let tech = run_with_sidecar(CraSidecarMetadata {
        is_nis2_essential_entity: true,
        ..Default::default()
    });
    assert!(tech.contains("Adjacent regulation"));
    assert!(tech.contains("NIS2"));
    assert!(tech.contains("essential entity"));
    assert!(tech.contains("Art. 23"));
}

#[test]
fn nis2_important_entity_renders_distinct_label() {
    let tech = run_with_sidecar(CraSidecarMetadata {
        is_nis2_important_entity: true,
        ..Default::default()
    });
    assert!(tech.contains("important entity"));
    assert!(tech.contains("Annex II"));
}

#[test]
fn personal_data_renders_gdpr_art_32_guidance() {
    let tech = run_with_sidecar(CraSidecarMetadata {
        processes_personal_data: true,
        ..Default::default()
    });
    assert!(tech.contains("GDPR"));
    assert!(tech.contains("Art. 32"));
    assert!(tech.contains("DPIA") || tech.contains("Art. 35"));
}

#[test]
fn high_risk_ai_renders_ai_act_guidance() {
    let tech = run_with_sidecar(CraSidecarMetadata {
        is_high_risk_ai: true,
        ..Default::default()
    });
    assert!(tech.contains("AI Act"));
    assert!(tech.contains("high-risk"));
    assert!(tech.contains("Art. 72") || tech.contains("Art. 73"));
}

#[test]
fn red_repealed_until_renders_red_guidance() {
    let until = chrono::DateTime::parse_from_rfc3339("2025-08-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let tech = run_with_sidecar(CraSidecarMetadata {
        red_repealed_until: Some(until),
        ..Default::default()
    });
    assert!(tech.contains("Radio Equipment Directive"));
    assert!(tech.contains("2014/53/EU"));
    assert!(tech.contains("2025-08-01"));
}

#[test]
fn all_flags_set_renders_all_four_sections() {
    let until = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let tech = run_with_sidecar(CraSidecarMetadata {
        is_nis2_essential_entity: true,
        processes_personal_data: true,
        is_high_risk_ai: true,
        red_repealed_until: Some(until),
        ..Default::default()
    });
    assert!(tech.contains("NIS2"));
    assert!(tech.contains("GDPR"));
    assert!(tech.contains("AI Act"));
    assert!(tech.contains("Radio Equipment Directive"));
}

#[test]
fn sidecar_flag_serde_roundtrip() {
    let original = CraSidecarMetadata {
        is_nis2_essential_entity: true,
        is_nis2_important_entity: false,
        processes_personal_data: true,
        is_high_risk_ai: true,
        red_repealed_until: Some(
            chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        ..Default::default()
    };
    let json = serde_json::to_string(&original).unwrap();
    let parsed: CraSidecarMetadata = serde_json::from_str(&json).unwrap();
    assert!(parsed.is_nis2_essential_entity);
    assert!(!parsed.is_nis2_important_entity);
    assert!(parsed.processes_personal_data);
    assert!(parsed.is_high_risk_ai);
    assert!(parsed.red_repealed_until.is_some());

    // Default values should not serialize (skip_serializing_if).
    let default_json = serde_json::to_string(&CraSidecarMetadata::default()).unwrap();
    assert!(!default_json.contains("is_nis2_essential_entity"));
    assert!(!default_json.contains("is_nis2_important_entity"));
    assert!(!default_json.contains("processes_personal_data"));
    assert!(!default_json.contains("is_high_risk_ai"));
    assert!(!default_json.contains("red_repealed_until"));
}
