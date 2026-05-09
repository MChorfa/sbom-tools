//! Integration tests for CRA-P4.2 CSAF v2.0 emitter.
//!
//! Covers:
//! - Schema-level structural assertions on emitted CSAF documents.
//! - Round-trip: ingest a CSAF advisory → enrich an SBOM → emit CSAF →
//!   re-ingest the emitted document → identical VEX states are produced.
//! - Sidecar/options propagation (publisher, title, document ID).

use sbom_tools::enrichment::vex::VexEnricher;
use sbom_tools::model::{
    Component, NormalizedSbom, VexState, VexStatus, VulnerabilityRef, VulnerabilitySource,
};
use sbom_tools::reports::{CsafEmitOptions, emit_csaf};
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/csaf")
}

fn sbom_with_vex_states(entries: &[(&str, &str, &str, VexState)]) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::default();
    for (name, version, vuln, state) in entries {
        let mut c = Component::new((*name).to_string(), format!("{name}@{version}"));
        c.version = Some((*version).to_string());
        c.identifiers.purl = Some(format!("pkg:cargo/{name}@{version}"));
        let mut v = VulnerabilityRef::new((*vuln).to_string(), VulnerabilitySource::Cve);
        v.vex_status = Some(VexStatus::new(state.clone()));
        c.vulnerabilities.push(v);
        sbom.add_component(c);
    }
    sbom
}

#[test]
fn emit_produces_valid_csaf_v2_0_document_skeleton() {
    let sbom = sbom_with_vex_states(&[
        ("foo", "1.0.0", "CVE-2024-12345", VexState::Affected),
        ("bar", "2.0.0", "CVE-2024-12345", VexState::Fixed),
    ]);
    let csaf = emit_csaf(&sbom, &CsafEmitOptions::default()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&csaf).unwrap();
    assert_eq!(json["document"]["csaf_version"], "2.0");
    assert!(json["document"]["title"].as_str().unwrap().contains("VEX"));
    assert!(
        json["document"]["tracking"]["id"]
            .as_str()
            .is_some_and(|s| s.starts_with("sbom-tools-vex-"))
    );
    assert_eq!(json["document"]["tracking"]["version"], "1");
    assert_eq!(json["document"]["tracking"]["status"], "final");

    // Generator metadata identifies sbom-tools as the engine.
    let engine = &json["document"]["tracking"]["generator"]["engine"];
    assert_eq!(engine["name"], "sbom-tools");
    assert!(engine["version"].is_string());
}

#[test]
fn emit_options_override_defaults() {
    let sbom = sbom_with_vex_states(&[("foo", "1.0", "CVE-2024-1", VexState::Affected)]);
    let opts = CsafEmitOptions {
        document_id: Some("EX-2026-001".to_string()),
        publisher_name: Some("Example Corp".to_string()),
        publisher_namespace: Some("https://example.com".to_string()),
        publisher_category: Some("vendor".to_string()),
        title: Some("Test Advisory".to_string()),
        category: Some("csaf_security_advisory".to_string()),
    };
    let csaf = emit_csaf(&sbom, &opts).unwrap();
    let json: serde_json::Value = serde_json::from_str(&csaf).unwrap();
    assert_eq!(json["document"]["category"], "csaf_security_advisory");
    assert_eq!(json["document"]["title"], "Test Advisory");
    assert_eq!(json["document"]["tracking"]["id"], "EX-2026-001");
    assert_eq!(json["document"]["publisher"]["name"], "Example Corp");
    assert_eq!(
        json["document"]["publisher"]["namespace"],
        "https://example.com"
    );
}

#[test]
fn emitted_csaf_passes_internal_format_detector() {
    // The emitter output should re-parse via the same VexEnricher path
    // that ingests CSAF advisories — the auto-detector must classify it
    // as CSAF (not as OpenVEX or CycloneDX VEX).
    let sbom = sbom_with_vex_states(&[("foo", "1.0", "CVE-2024-1", VexState::Affected)]);
    let csaf = emit_csaf(&sbom, &CsafEmitOptions::default()).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("emitted.csaf.json");
    std::fs::write(&path, &csaf).unwrap();

    let enricher = VexEnricher::from_files(&[path]).expect("re-ingest");
    assert_eq!(enricher.stats().documents_loaded, 1);
    assert!(enricher.stats().statements_parsed >= 1);
}

#[test]
fn round_trip_preserves_vex_states_across_ingest_emit_ingest() {
    // 1. Ingest the canonical CSAF fixture and apply it to a matching SBOM.
    let csaf_in = fixtures_dir().join("example-advisory.csaf.json");
    let mut enricher_in = VexEnricher::from_files(&[csaf_in]).unwrap();

    let mut sbom = NormalizedSbom::default();
    for (name, version, purl) in [
        ("example-app-1.0", "1.0.0", "pkg:cargo/example-app@1.0.0"),
        ("example-app-1.1", "1.1.0", "pkg:cargo/example-app@1.1.0"),
        ("example-app-2.0", "2.0.0", "pkg:cargo/example-app@2.0.0"),
    ] {
        let mut c = Component::new(name.to_string(), format!("{name}@{version}"));
        c.version = Some(version.to_string());
        c.identifiers.purl = Some(purl.to_string());
        for vuln in ["CVE-2024-99001", "CVE-2024-99002"] {
            c.vulnerabilities.push(VulnerabilityRef::new(
                vuln.to_string(),
                VulnerabilitySource::Cve,
            ));
        }
        sbom.add_component(c);
    }
    enricher_in.enrich_sbom(&mut sbom);

    // Snapshot the VEX states after the first ingest.
    let mut before: Vec<(String, String, String)> = Vec::new();
    for c in sbom.components.values() {
        let purl = c.identifiers.purl.clone().unwrap();
        for v in &c.vulnerabilities {
            if let Some(state) = v.vex_status.as_ref().map(|s| s.status.clone()) {
                before.push((purl.clone(), v.id.clone(), format!("{state:?}")));
            }
        }
    }
    before.sort();
    assert!(
        !before.is_empty(),
        "first ingest should have applied at least one VEX status"
    );

    // 2. Emit the SBOM's VEX state as a new CSAF advisory.
    let csaf_out = emit_csaf(&sbom, &CsafEmitOptions::default()).unwrap();

    // 3. Re-ingest the emitted CSAF into a fresh SBOM with identical
    //    components and check the same VEX states are reapplied.
    let dir = tempfile::tempdir().unwrap();
    let csaf_path = dir.path().join("round-trip.csaf.json");
    std::fs::write(&csaf_path, &csaf_out).unwrap();

    let mut enricher_out = VexEnricher::from_files(&[csaf_path]).unwrap();
    let mut sbom2 = NormalizedSbom::default();
    for c in sbom.components.values() {
        let mut nc = Component::new(c.name.clone(), c.name.clone());
        nc.version = c.version.clone();
        nc.identifiers.purl = c.identifiers.purl.clone();
        for v in &c.vulnerabilities {
            nc.vulnerabilities.push(VulnerabilityRef::new(
                v.id.clone(),
                VulnerabilitySource::Cve,
            ));
        }
        sbom2.add_component(nc);
    }
    enricher_out.enrich_sbom(&mut sbom2);

    let mut after: Vec<(String, String, String)> = Vec::new();
    for c in sbom2.components.values() {
        let purl = c.identifiers.purl.clone().unwrap();
        for v in &c.vulnerabilities {
            if let Some(state) = v.vex_status.as_ref().map(|s| s.status.clone()) {
                after.push((purl.clone(), v.id.clone(), format!("{state:?}")));
            }
        }
    }
    after.sort();

    assert_eq!(
        before, after,
        "Round-trip CSAF emit→ingest must preserve every VEX state"
    );
}

#[test]
fn emit_skips_components_without_purl_or_vex_status() {
    let mut sbom = NormalizedSbom::default();
    // No PURL: should be skipped
    let mut c1 = Component::new("nopurl".to_string(), "nopurl".to_string());
    let mut v1 = VulnerabilityRef::new("CVE-2024-1".to_string(), VulnerabilitySource::Cve);
    v1.vex_status = Some(VexStatus::new(VexState::Affected));
    c1.vulnerabilities.push(v1);
    sbom.add_component(c1);

    // PURL but no vex_status on its vuln: product surfaces, no status entry
    let mut c2 = Component::new("withpurl".to_string(), "withpurl".to_string());
    c2.identifiers.purl = Some("pkg:cargo/withpurl@1".to_string());
    c2.vulnerabilities.push(VulnerabilityRef::new(
        "CVE-2024-2".to_string(),
        VulnerabilitySource::Cve,
    ));
    sbom.add_component(c2);

    let csaf = emit_csaf(&sbom, &CsafEmitOptions::default()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&csaf).unwrap();

    let products = json["product_tree"]["full_product_names"]
        .as_array()
        .unwrap();
    assert_eq!(products.len(), 1);
    assert_eq!(products[0]["name"], "withpurl");

    // No vex_status anywhere → no vulnerabilities[]
    assert!(
        json["vulnerabilities"]
            .as_array()
            .map_or(true, std::vec::Vec::is_empty)
    );
}
