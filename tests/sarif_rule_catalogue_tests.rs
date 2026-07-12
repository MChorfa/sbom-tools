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
        ComplianceLevel::EuccSubstantial,
    ] {
        let result = ComplianceChecker::new(level).check(&sbom);
        let sarif = generate_compliance_sarif(&result).expect("sarif generation");
        assert_catalogue_complete(&sarif, level.name());
    }
}

/// The EUCC checks carry their own per-check rule identity: a sidecar-less
/// run must emit — and declare — the five SBOM-EUCC-* ids (not the collapsed
/// SBOM-CRA-GENERAL bucket), each with the Reg. (EU) 2024/482 helpUri.
#[test]
fn eucc_sarif_declares_per_check_rule_ids() {
    let sbom = NormalizedSbom::default();
    let result = ComplianceChecker::new(ComplianceLevel::EuccSubstantial).check(&sbom);
    let sarif = generate_compliance_sarif(&result).expect("sarif generation");
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");
    let run = &json["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
    let declared: HashSet<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();
    let emitted: HashSet<&str> = run["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|r| r["ruleId"].as_str())
        .collect();
    for id in [
        "SBOM-EUCC-PP",
        "SBOM-EUCC-TOE",
        "SBOM-EUCC-ITSEF",
        "SBOM-EUCC-VALIDITY",
        "SBOM-EUCC-CERTREF",
    ] {
        assert!(declared.contains(id), "rule {id} must be declared");
        assert!(emitted.contains(id), "rule {id} must be emitted");
    }
    assert!(
        !emitted.contains("SBOM-CRA-GENERAL"),
        "EUCC findings must no longer collapse into SBOM-CRA-GENERAL"
    );
    for rule in rules.iter().filter(|r| {
        r["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("SBOM-EUCC"))
    }) {
        assert_eq!(
            rule["helpUri"].as_str(),
            Some("https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng"),
            "EUCC rule {} must cite Implementing Regulation (EU) 2024/482",
            rule["id"]
        );
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
