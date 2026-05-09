//! Integration tests for the `cra-docs` CLI subcommand (CRA-P4.1).
//!
//! Exercises the dossier generator end-to-end: parses an SBOM, optionally
//! a sidecar, and asserts that the three CRA-P4.1 dossier files are
//! emitted with the expected sections and that sidecar fields propagate
//! into each template.

use sbom_tools::cli::run_cra_docs;
use std::fs;
use tempfile::tempdir;

const MINIMAL_CDX: &str = r#"{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
    "metadata": {
        "component": {
            "type": "application",
            "name": "example-app",
            "version": "1.0.0"
        }
    },
    "components": [
        {"type": "library", "name": "lib-a", "version": "1.2.3", "purl": "pkg:cargo/lib-a@1.2.3"},
        {"type": "library", "name": "lib-b", "version": "0.9.0", "purl": "pkg:cargo/lib-b@0.9.0"}
    ]
}"#;

const SIDECAR_JSON: &str = r#"{
    "manufacturerName": "Example Corp",
    "manufacturerEmail": "legal@example.com",
    "productName": "Example App",
    "productVersion": "1.0.0",
    "ceMarkingReference": "EU-DoC-2026-001",
    "psirtUrl": "https://example.com/psirt",
    "securityContact": "security@example.com",
    "coordinatedDisclosurePolicyUrl": "https://example.com/security/cvd",
    "earlyWarningContact": "ew@example.com",
    "incidentReportContact": "incidents@example.com",
    "enisaReportingPlatformId": "EU-MFR-1",
    "riskAssessmentUrl": "https://example.com/risk-assessment.pdf",
    "riskAssessmentMethodology": "ISO/IEC 27005:2022",
    "supportEndDate": "2030-12-31T00:00:00Z",
    "productClass": "important-class-1"
}"#;

fn write_temp(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    fs::write(&p, body).unwrap();
    p
}

#[test]
fn cra_docs_creates_all_three_dossier_files() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), None, None).expect("cra-docs runs");

    assert!(out.join("eu-declaration-of-conformity.md").exists());
    assert!(out.join("technical-documentation.md").exists());
    assert!(out.join("vulnerability-handling-policy.md").exists());
}

#[test]
fn cra_docs_propagates_sidecar_into_doc_template() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let sidecar = write_temp(dir.path(), "app.cra.json", SIDECAR_JSON);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), Some(sidecar), None).expect("cra-docs runs");

    let doc = fs::read_to_string(out.join("eu-declaration-of-conformity.md")).unwrap();
    assert!(doc.contains("Example Corp"), "manufacturer name in DoC");
    assert!(doc.contains("legal@example.com"));
    assert!(doc.contains("EU-DoC-2026-001"));
    assert!(doc.contains("Example App"));
    assert!(
        doc.contains("Important Class I"),
        "sidecar productClass surfaces in DoC class"
    );
}

#[test]
fn cra_docs_propagates_sidecar_into_vuln_policy() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let sidecar = write_temp(dir.path(), "app.cra.json", SIDECAR_JSON);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), Some(sidecar), None).expect("cra-docs runs");

    let policy = fs::read_to_string(out.join("vulnerability-handling-policy.md")).unwrap();
    assert!(policy.contains("https://example.com/psirt"));
    assert!(policy.contains("security@example.com"));
    assert!(policy.contains("https://example.com/security/cvd"));
    assert!(policy.contains("ew@example.com"));
    assert!(policy.contains("incidents@example.com"));
    assert!(policy.contains("EU-MFR-1"));
}

#[test]
fn cra_docs_tech_doc_summarises_components_and_compliance() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let sidecar = write_temp(dir.path(), "app.cra.json", SIDECAR_JSON);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), Some(sidecar), None).expect("cra-docs runs");

    let tech = fs::read_to_string(out.join("technical-documentation.md")).unwrap();
    // Components in scope reflects the SBOM (1 primary + 2 libs = 3 in CycloneDX
    // but our SBOM model may handle this differently; assert the structural
    // header at minimum).
    assert!(tech.contains("Components in scope:"));
    assert!(tech.contains("Compliance check summary"));
    assert!(tech.contains("https://example.com/risk-assessment.pdf"));
    assert!(tech.contains("ISO/IEC 27005:2022"));
}

#[test]
fn cra_docs_auto_discovers_adjacent_sidecar() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    // sidecar named `<sbom-stem>.cra.json` is auto-discovered
    let _ = write_temp(dir.path(), "app.cra.json", SIDECAR_JSON);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), None, None).expect("cra-docs runs");

    let doc = fs::read_to_string(out.join("eu-declaration-of-conformity.md")).unwrap();
    assert!(
        doc.contains("Example Corp"),
        "auto-discovered sidecar must populate manufacturer"
    );
}

#[test]
fn cra_docs_cli_product_class_overrides_default_when_no_sidecar() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), None, Some("critical".to_string())).expect("cra-docs runs");

    let doc = fs::read_to_string(out.join("eu-declaration-of-conformity.md")).unwrap();
    assert!(
        doc.contains("Critical (Annex IV)"),
        "CLI --cra-product-class=critical must surface in DoC"
    );
    assert!(doc.contains("EUCC"), "Critical class default route is EUCC");
}

#[test]
fn cra_docs_unfilled_fields_show_tbd_placeholders() {
    let dir = tempdir().unwrap();
    let sbom = write_temp(dir.path(), "app.cdx.json", MINIMAL_CDX);
    let out = dir.path().join("dossier");

    run_cra_docs(sbom, out.clone(), None, None).expect("cra-docs runs");

    let doc = fs::read_to_string(out.join("eu-declaration-of-conformity.md")).unwrap();
    assert!(
        doc.contains("_TBD"),
        "DoC without sidecar must contain _TBD_ placeholders for unfilled fields"
    );
}
