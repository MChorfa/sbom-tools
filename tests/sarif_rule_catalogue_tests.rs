//! SARIF rule-catalogue integrity: every result ruleId must have a
//! reportingDescriptor in driver.rules, and descriptor ids must be unique
//! (SARIF 2.1.0 requirement; GitHub code scanning drops rule metadata for
//! undeclared ids and rejects duplicate descriptors).

use sbom_tools::model::{Component, DocumentMetadata, NormalizedSbom};
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel};
use sbom_tools::reports::{generate_compliance_sarif, generate_multi_compliance_sarif};
use std::collections::HashSet;

/// SBOM engineered to fire many rules: no timestamp, no creators, missing
/// versions/suppliers/identifiers, no edges.
fn violating_sbom() -> NormalizedSbom {
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    sbom.document.created = chrono::DateTime::UNIX_EPOCH;
    sbom.document.creators.clear();
    for i in 0..3 {
        sbom.add_component(Component::new(format!("lib{i}"), format!("lib{i}@1")));
    }
    sbom
}

fn assert_catalogue_complete(sarif_json: &str, label: &str) {
    let sarif: serde_json::Value = serde_json::from_str(sarif_json).expect("valid JSON");
    let run = &sarif["runs"][0];
    let declared: Vec<&str> = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array")
        .iter()
        .map(|r| r["id"].as_str().expect("rule id"))
        .collect();
    let mut seen = HashSet::new();
    for id in &declared {
        assert!(
            seen.insert(*id),
            "[{label}] duplicate reportingDescriptor id {id}"
        );
    }
    for result in run["results"].as_array().expect("results array") {
        let rule_id = result["ruleId"].as_str().expect("result ruleId");
        assert!(
            seen.contains(rule_id),
            "[{label}] result references undeclared rule {rule_id}"
        );
    }
}

#[test]
fn single_standard_sarif_declares_every_emitted_rule() {
    let sbom = violating_sbom();
    for level in [
        ComplianceLevel::NtiaMinimum,
        ComplianceLevel::FdaMedicalDevice,
        ComplianceLevel::Eo14028,
        ComplianceLevel::NistSsdf,
        ComplianceLevel::Cnsa2,
        ComplianceLevel::NistPqc,
        ComplianceLevel::CraPhase2,
        ComplianceLevel::CraOssSteward,
        ComplianceLevel::BsiTr03183_2,
    ] {
        let result = ComplianceChecker::new(level).check(&sbom);
        let sarif = generate_compliance_sarif(&result).expect("sarif generation");
        assert_catalogue_complete(&sarif, level.name());
    }
}

#[test]
fn multi_standard_sarif_has_unique_descriptors() {
    let sbom = violating_sbom();
    let results: Vec<_> = [
        ComplianceLevel::CraPhase2,
        ComplianceLevel::BsiTr03183_2,
        ComplianceLevel::NtiaMinimum,
    ]
    .into_iter()
    .map(|l| ComplianceChecker::new(l).check(&sbom))
    .collect();
    let sarif = generate_multi_compliance_sarif(&results).expect("sarif generation");
    assert_catalogue_complete(&sarif, "multi cra,bsi,ntia");
}
