//! Golden-fixture regression tests (CRA-P5.2).
//!
//! Each fixture pins an expected violation profile against
//! `ComplianceChecker` so future changes that flip a check into / out of
//! the active set fail loudly. The expectations are deliberately broad
//! (presence/absence of a CRA Article, severity classes) rather than
//! exact violation count, so that adding more fine-grained checks does
//! not require updating every fixture in lockstep.

use sbom_tools::model::CraSidecarMetadata;
use sbom_tools::parsers::parse_sbom;
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel, ViolationSeverity};
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cra")
}

#[test]
fn cra_compliant_cdx_with_sidecar_has_no_errors_at_phase2() {
    let sbom_path = fixtures_dir().join("cra-compliant.cdx.json");
    let sidecar_path = fixtures_dir().join("cra-compliant.cra.json");
    assert!(sbom_path.exists(), "fixture missing: {}", sbom_path.display());
    assert!(sidecar_path.exists(), "sidecar missing: {}", sidecar_path.display());

    let parsed = parse_sbom(&sbom_path).expect("parse compliant fixture");
    let sidecar = CraSidecarMetadata::from_file(&sidecar_path).expect("load sidecar");

    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&parsed);

    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "Compliant fixture should produce no Errors at CraPhase2; got: {errors:?}"
    );
}

#[test]
fn cra_compliant_cdx_passes_bsi_with_no_errors() {
    let sbom_path = fixtures_dir().join("cra-compliant.cdx.json");
    let parsed = parse_sbom(&sbom_path).expect("parse compliant fixture");
    let result = ComplianceChecker::new(ComplianceLevel::BsiTr03183_2).check(&parsed);
    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "Compliant fixture should pass BSI TR-03183-2 §5 with no Errors; got: {errors:?}"
    );
}

#[test]
fn cra_compliant_passes_oss_steward_floor() {
    let sbom_path = fixtures_dir().join("cra-compliant.cdx.json");
    let sidecar_path = fixtures_dir().join("cra-compliant.cra.json");
    let parsed = parse_sbom(&sbom_path).unwrap();
    let sidecar = CraSidecarMetadata::from_file(&sidecar_path).unwrap();
    let result = ComplianceChecker::new(ComplianceLevel::CraOssSteward)
        .with_sidecar(sidecar)
        .check(&parsed);
    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "Compliant fixture should pass OSS-steward floor with no Errors; got: {errors:?}"
    );
}

#[test]
fn noncompliant_no_manufacturer_fires_art_13_15_or_supplier_check() {
    let sbom_path = fixtures_dir().join("cra-noncompliant-no-manufacturer.cdx.json");
    assert!(sbom_path.exists());
    let parsed = parse_sbom(&sbom_path).expect("parse fixture");
    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&parsed);

    let manufacturer_finding = result.violations.iter().any(|v| {
        v.requirement.contains("Art. 13(15)")
            || v.requirement.contains("Manufacturer")
            || v.requirement.contains("manufacturer")
            || v.requirement.contains("Supplier")
            || v.requirement.contains("supplier")
    });
    assert!(
        manufacturer_finding,
        "no-manufacturer fixture should fire either Art. 13(15) or supplier-tracking violation"
    );
}

#[test]
fn noncompliant_weak_hashes_fires_at_bsi_or_phase2() {
    // BSI TR-03183-2 §5.4 requires SHA-256+ on every component.
    let sbom_path = fixtures_dir().join("cra-noncompliant-weak-hashes.cdx.json");
    let parsed = parse_sbom(&sbom_path).expect("parse fixture");

    let bsi = ComplianceChecker::new(ComplianceLevel::BsiTr03183_2).check(&parsed);
    let bsi_hash_finding = bsi
        .violations
        .iter()
        .any(|v| v.requirement.contains("BSI TR-03183-2") || v.requirement.contains("hash"));
    assert!(
        bsi_hash_finding,
        "weak-hashes fixture must fire a BSI TR-03183-2 hash-related violation; \
         got requirements: {:?}",
        bsi.violations.iter().map(|v| &v.requirement).collect::<Vec<_>>()
    );
}

#[test]
fn vendor_hash_carry_through_satisfied_by_compliant_fixture() {
    // The compliant fixture has SHA-256 on every vendor component. Under
    // CraPhase2 + ImportantClass2 (80% threshold, Error), no vendor-hash
    // violation should fire.
    let sbom_path = fixtures_dir().join("cra-compliant.cdx.json");
    let sidecar_path = fixtures_dir().join("cra-compliant.cra.json");
    let parsed = parse_sbom(&sbom_path).unwrap();
    let mut sc = CraSidecarMetadata::from_file(&sidecar_path).unwrap();
    sc.product_class = Some(sbom_tools::model::CraProductClass::ImportantClass2);
    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_sidecar(sc)
        .check(&parsed);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("PRE-7-RQ-07-RE")),
        "Compliant fixture must clear vendor-hash carry-through at Important-2"
    );
}

#[test]
fn conformity_summary_present_when_class_pinned_via_sidecar() {
    let sbom_path = fixtures_dir().join("cra-compliant.cdx.json");
    let sidecar_path = fixtures_dir().join("cra-compliant.cra.json");
    let parsed = parse_sbom(&sbom_path).unwrap();
    let sc = CraSidecarMetadata::from_file(&sidecar_path).unwrap();
    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_sidecar(sc)
        .check(&parsed);
    assert!(
        result.conformity_summary.is_some(),
        "Sidecar pins productClass=important-class-1 → summary expected"
    );
    let summary = result.conformity_summary.unwrap();
    assert_eq!(
        summary.product_class,
        sbom_tools::model::CraProductClass::ImportantClass1
    );
}
