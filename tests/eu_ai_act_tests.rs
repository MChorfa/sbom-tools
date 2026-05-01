//! Integration tests for EU AI Act validation.

use sbom_tools::parsers::parse_sbom;
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel};
use std::path::Path;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

#[test]
fn test_cyclonedx_eu_ai_act_compliance_passes_for_documented_ml_bom() {
    let path = fixture_path("cyclonedx/mlbom-eu-ai-act.cdx.json");
    let sbom = parse_sbom(&path).expect("Failed to parse documented EU AI Act ML BOM");

    let checker = ComplianceChecker::new(ComplianceLevel::EuAiAct);
    let report = checker.check(&sbom);

    assert!(report.is_compliant, "{report:?}");
    assert_eq!(report.error_count, 0, "{report:?}");
    assert_eq!(report.warning_count, 0, "{report:?}");
}

#[test]
fn test_cyclonedx_eu_ai_act_compliance_fails_for_undocumented_ml_bom() {
    let path = fixture_path("cyclonedx/mlbom-no-modelcard.cdx.json");
    let sbom = parse_sbom(&path).expect("Failed to parse undocumented EU AI Act ML BOM");

    let checker = ComplianceChecker::new(ComplianceLevel::EuAiAct);
    let report = checker.check(&sbom);

    assert!(!report.is_compliant, "{report:?}");
    assert!(
        report
            .violations
            .iter()
            .any(|violation| violation.requirement.contains("Intended purpose")),
        "{report:?}"
    );
    assert!(
        report
            .violations
            .iter()
            .any(|violation| violation.requirement.contains("Training data")),
        "{report:?}"
    );
}
