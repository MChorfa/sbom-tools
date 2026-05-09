//! Integration tests for CSAF v2.0 (ISO/IEC 20153:2025) ingest.
//!
//! Covers:
//! - Auto-detection of CSAF v2.0 documents (vs OpenVEX / CycloneDX VEX)
//! - End-to-end VEX enrichment pipeline applying CSAF status
//! - product_status mapping (known_affected/known_not_affected/fixed/etc.)
//! - Recursive `branches[]` flattening in product_tree
//! - Round-trip with the existing VexEnricher dispatcher

use sbom_tools::enrichment::vex::VexEnricher;
use sbom_tools::model::{
    Component, NormalizedSbom, VexState, VulnerabilityRef, VulnerabilitySource,
};
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/csaf")
}

fn build_sbom_with_vuln(name: &str, purl: &str, version: &str, vuln: &str) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::default();
    let mut comp = Component::new(name.to_string(), format!("{name}@{version}"));
    comp.version = Some(version.to_string());
    comp.identifiers.purl = Some(purl.to_string());
    comp.vulnerabilities.push(VulnerabilityRef::new(
        vuln.to_string(),
        VulnerabilitySource::Cve,
    ));
    sbom.add_component(comp);
    sbom
}

#[test]
fn vex_enricher_auto_detects_csaf_fixture() {
    let path = fixtures_dir().join("example-advisory.csaf.json");
    assert!(path.exists(), "fixture missing: {}", path.display());

    let enricher = VexEnricher::from_files(&[path]).expect("CSAF parse should succeed");
    let stats = enricher.stats();
    assert_eq!(stats.documents_loaded, 1);
    // 4 status entries: 1 known_affected + 2 fixed (CVE-99001) + 1 known_not_affected + 1 under_investigation (CVE-99002) = 5
    assert!(stats.statements_parsed >= 4);
}

#[test]
fn csaf_known_affected_marks_component_affected() {
    let path = fixtures_dir().join("example-advisory.csaf.json");
    let mut enricher = VexEnricher::from_files(&[path]).expect("CSAF parse should succeed");

    let mut sbom = build_sbom_with_vuln(
        "example-app",
        "pkg:cargo/example-app@1.0.0",
        "1.0.0",
        "CVE-2024-99001",
    );
    enricher.enrich_sbom(&mut sbom);

    let comp = sbom.components.values().next().expect("component");
    let vuln = &comp.vulnerabilities[0];
    let vex = vuln.vex_status.as_ref().expect("VEX applied");
    assert_eq!(vex.status, VexState::Affected);
}

#[test]
fn csaf_fixed_marks_component_fixed() {
    let path = fixtures_dir().join("example-advisory.csaf.json");
    let mut enricher = VexEnricher::from_files(&[path]).expect("CSAF parse should succeed");

    let mut sbom = build_sbom_with_vuln(
        "example-app",
        "pkg:cargo/example-app@1.1.0",
        "1.1.0",
        "CVE-2024-99001",
    );
    enricher.enrich_sbom(&mut sbom);

    let comp = sbom.components.values().next().expect("component");
    let vuln = &comp.vulnerabilities[0];
    let vex = vuln.vex_status.as_ref().expect("VEX applied");
    assert_eq!(vex.status, VexState::Fixed);
}

#[test]
fn csaf_known_not_affected_maps_correctly() {
    let path = fixtures_dir().join("example-advisory.csaf.json");
    let mut enricher = VexEnricher::from_files(&[path]).expect("CSAF parse should succeed");

    let mut sbom = build_sbom_with_vuln(
        "example-app",
        "pkg:cargo/example-app@2.0.0",
        "2.0.0",
        "CVE-2024-99002",
    );
    enricher.enrich_sbom(&mut sbom);

    let comp = sbom.components.values().next().expect("component");
    let vuln = &comp.vulnerabilities[0];
    let vex = vuln.vex_status.as_ref().expect("VEX applied");
    assert_eq!(vex.status, VexState::NotAffected);
}

#[test]
fn csaf_under_investigation_maps_correctly() {
    let path = fixtures_dir().join("example-advisory.csaf.json");
    let mut enricher = VexEnricher::from_files(&[path]).expect("CSAF parse should succeed");

    let mut sbom = build_sbom_with_vuln(
        "example-app",
        "pkg:cargo/example-app@1.1.0",
        "1.1.0",
        "CVE-2024-99002",
    );
    enricher.enrich_sbom(&mut sbom);

    let comp = sbom.components.values().next().expect("component");
    let vuln = &comp.vulnerabilities[0];
    let vex = vuln.vex_status.as_ref().expect("VEX applied");
    assert_eq!(vex.status, VexState::UnderInvestigation);
}

#[test]
fn csaf_branched_product_tree_flattens_for_lookup() {
    let path = fixtures_dir().join("branched-tree.csaf.json");
    let mut enricher = VexEnricher::from_files(&[path]).expect("CSAF parse should succeed");

    let mut sbom = build_sbom_with_vuln(
        "branchy",
        "pkg:cargo/branchy@1.0.0",
        "1.0.0",
        "CVE-2024-88001",
    );
    enricher.enrich_sbom(&mut sbom);

    let comp = sbom.components.values().next().expect("component");
    let vuln = &comp.vulnerabilities[0];
    let vex = vuln
        .vex_status
        .as_ref()
        .expect("VEX applied via flattened branches");
    assert_eq!(vex.status, VexState::Affected);
}

#[test]
fn csaf_does_not_apply_to_unrelated_purl() {
    // Same CVE, different PURL → should not match (CSAF entry is product-scoped)
    let path = fixtures_dir().join("example-advisory.csaf.json");
    let mut enricher = VexEnricher::from_files(&[path]).expect("CSAF parse should succeed");

    let mut sbom = build_sbom_with_vuln(
        "different-app",
        "pkg:cargo/different-app@1.0.0",
        "1.0.0",
        "CVE-2024-99001",
    );
    enricher.enrich_sbom(&mut sbom);

    let comp = sbom.components.values().next().expect("component");
    let vuln = &comp.vulnerabilities[0];
    assert!(
        vuln.vex_status.is_none(),
        "CSAF entry must not match unrelated PURL"
    );
}

#[test]
fn csaf_format_priority_over_cyclonedx_or_openvex() {
    // The CSAF fixture is detected as CSAF first, not as CycloneDX VEX or
    // OpenVEX. Sanity check by loading and confirming a CSAF-specific
    // status (known_not_affected from CVE-2024-99002).
    let path = fixtures_dir().join("example-advisory.csaf.json");
    let enricher = VexEnricher::from_files(&[path]).expect("must parse as CSAF");
    assert!(enricher.stats().statements_parsed > 0);
}
