//! Registry-driven rule identity across every output surface (P2-B).
//!
//! Pins the machine contracts this refactor establishes:
//! 1. serialized `Violation`s carry the stable internal `rule_id` AND the
//!    externally-visible `sarif_rule_id` (both registry-derived);
//! 2. SARIF reportingDescriptors are generated from the rule registry —
//!    name / shortDescription / default level cannot drift;
//! 3. `quality -o sarif` and `validate -o sarif` emit the SAME external rule
//!    id for the same violation (no more invented `QUALITY-*` ids), and
//!    quality recommendations are never `error`;
//! 4. OSCAL emits one `results[]` entry per standard with a machine-readable
//!    verdict (standard id, is_compliant, applicability, counts, score);
//! 5. structured violation identity (P2-H): component-scoped violations carry
//!    a `component_id` join key (the component's canonical id) and aggregate
//!    findings carry `counts` mirroring the message's affected/total numbers —
//!    on JSON and SARIF alike — while old payloads still deserialize.

use sbom_tools::model::{Component, DocumentMetadata, NormalizedSbom};
use sbom_tools::quality::{
    ComplianceChecker, ComplianceLevel, QualityScorer, ScoringProfile, rule_meta,
};
use sbom_tools::reports::{generate_compliance_sarif, generate_quality_sarif};
use std::collections::BTreeSet;

/// SBOM engineered to fire many rules: epoch timestamp, no creators, missing
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

// ---------------------------------------------------------------------------
// 1. Violation JSON carries registry rule identity
// ---------------------------------------------------------------------------

#[test]
fn serialized_violations_carry_rule_id_and_sarif_rule_id() {
    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&violating_sbom());
    assert!(
        !result.violations.is_empty(),
        "fixture must fire violations"
    );
    let json = serde_json::to_value(&result).expect("serialize ComplianceResult");
    let violations = json["violations"].as_array().expect("violations array");
    for v in violations {
        let rule_id = v["rule_id"].as_str().expect("violation carries rule_id");
        let sarif_rule_id = v["sarif_rule_id"]
            .as_str()
            .expect("violation carries sarif_rule_id");
        assert!(rule_id.starts_with("SBOM-"), "rule_id {rule_id:?}");
        // The serialized SARIF id must be exactly the registry mapping.
        let expected = rule_meta(rule_id).map_or("SBOM-CRA-GENERAL", |m| m.sarif_id);
        assert_eq!(
            sarif_rule_id, expected,
            "sarif_rule_id drifted for {rule_id}"
        );
    }
}

#[test]
fn old_payloads_without_rule_id_still_deserialize() {
    let payload = serde_json::json!({
        "is_compliant": false,
        "level": "NtiaMinimum",
        "violations": [{
            "severity": "Error",
            "category": "DocumentMetadata",
            "message": "SBOM must have creator information",
            "element": null,
            "requirement": "NTIA: author"
        }],
        "error_count": 1,
        "warning_count": 0,
        "info_count": 0
    });
    let result: sbom_tools::quality::ComplianceResult =
        serde_json::from_value(payload).expect("old payload deserializes");
    assert_eq!(result.violations[0].rule_id, "SBOM-CRA-GENERAL");
}

#[test]
fn known_rule_ids_survive_a_serde_round_trip() {
    let result = ComplianceChecker::new(ComplianceLevel::NtiaMinimum).check(&violating_sbom());
    let json = serde_json::to_string(&result).expect("serialize");
    let back: sbom_tools::quality::ComplianceResult =
        serde_json::from_str(&json).expect("deserialize");
    let original: Vec<&str> = result.violations.iter().map(|v| v.rule_id).collect();
    let round_tripped: Vec<&str> = back.violations.iter().map(|v| v.rule_id).collect();
    assert_eq!(
        original, round_tripped,
        "registered rule ids must survive round-trips"
    );
}

// ---------------------------------------------------------------------------
// 2. SARIF descriptors come from the registry
// ---------------------------------------------------------------------------

#[test]
fn sarif_descriptors_match_registry_name_description_and_severity() {
    use sbom_tools::quality::ViolationSeverity;
    let sbom = violating_sbom();
    for level in [
        ComplianceLevel::NtiaMinimum,
        ComplianceLevel::FdaMedicalDevice,
        ComplianceLevel::NistSsdf,
        ComplianceLevel::Eo14028,
        ComplianceLevel::CraPhase2,
        ComplianceLevel::Cnsa2,
        ComplianceLevel::NistPqc,
    ] {
        let result = ComplianceChecker::new(level).check(&sbom);
        let sarif = generate_compliance_sarif(&result).expect("sarif generation");
        let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid JSON");
        let rules = json["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array");
        assert!(!rules.is_empty());
        for rule in rules {
            let id = rule["id"].as_str().expect("rule id");
            let Some(meta) = rule_meta(id) else {
                continue; // non-registry rules (e.g. SBOM-TOOLS-*) are exempt
            };
            if meta.sarif_id != id {
                continue; // aliased identities never appear as descriptors
            }
            assert_eq!(
                rule["name"].as_str(),
                Some(meta.name),
                "[{level:?}] descriptor name for {id} drifted from the registry"
            );
            assert_eq!(
                rule["shortDescription"]["text"].as_str(),
                Some(meta.short_description),
                "[{level:?}] descriptor text for {id} drifted from the registry"
            );
            let expected_level = match meta.default_severity {
                ViolationSeverity::Error => "error",
                ViolationSeverity::Warning => "warning",
                ViolationSeverity::Info => "note",
            };
            assert_eq!(
                rule["defaultConfiguration"]["level"].as_str(),
                Some(expected_level),
                "[{level:?}] descriptor level for {id} drifted from the registry"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 3. quality -o sarif parity with validate -o sarif
// ---------------------------------------------------------------------------

fn sarif_rule_ids(sarif: &str) -> BTreeSet<String> {
    let json: serde_json::Value = serde_json::from_str(sarif).expect("valid SARIF");
    json["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .iter()
        .filter_map(|r| r["ruleId"].as_str().map(String::from))
        .collect()
}

#[test]
fn quality_and_validate_sarif_agree_on_rule_ids() {
    let sbom = violating_sbom();

    // `quality --profile cra -o sarif`
    let report = QualityScorer::new(ScoringProfile::Cra).score(&sbom);
    assert_eq!(report.compliance.level, ComplianceLevel::CraPhase2);
    let quality_sarif = generate_quality_sarif(&report, "test.cdx.json", "cra").expect("sarif");

    // `validate --standard cra-phase-2 -o sarif`
    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
    let validate_sarif = generate_compliance_sarif(&result).expect("sarif");

    let quality_ids: BTreeSet<String> = sarif_rule_ids(&quality_sarif)
        .into_iter()
        .filter(|id| !id.starts_with("SBOM-QUALITY-REC-"))
        .collect();
    let validate_ids = sarif_rule_ids(&validate_sarif);
    assert!(!validate_ids.is_empty());
    assert_eq!(
        quality_ids, validate_ids,
        "the same violation must carry the same SARIF rule id on both surfaces"
    );
}

#[test]
fn quality_sarif_has_no_invented_quality_ids_and_no_error_level_recommendations() {
    let sbom = violating_sbom();
    let report = QualityScorer::new(ScoringProfile::Cra).score(&sbom);
    assert!(
        !report.recommendations.is_empty(),
        "fixture must produce recommendations"
    );
    let sarif = generate_quality_sarif(&report, "test.cdx.json", "cra").expect("sarif");
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid SARIF");
    let run = &json["runs"][0];

    let declared: BTreeSet<&str> = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    for result in run["results"].as_array().expect("results") {
        let rule_id = result["ruleId"].as_str().expect("ruleId");
        assert!(
            rule_id.starts_with("SBOM-"),
            "invented rule id {rule_id:?} leaked into quality SARIF"
        );
        assert!(
            declared.contains(rule_id),
            "result rule {rule_id} lacks a reportingDescriptor"
        );
        if rule_id.starts_with("SBOM-QUALITY-REC-") {
            assert_ne!(
                result["level"].as_str(),
                Some("error"),
                "recommendations are advisory and must never be `error`"
            );
        }
    }

    // Score / grade / verdict ride on run-level properties.
    let props = &run["properties"];
    assert!(props["overallScore"].is_number());
    assert!(props["grade"].is_string());
    assert!(props["compliant"].is_boolean());
    assert_eq!(props["profile"].as_str(), Some("cra"));
}

// ---------------------------------------------------------------------------
// 4. OSCAL per-standard identity
// ---------------------------------------------------------------------------

#[test]
fn oscal_emits_one_result_per_standard_with_verdict_and_applicability() {
    let sbom = violating_sbom();
    let results: Vec<_> = [ComplianceLevel::NtiaMinimum, ComplianceLevel::CraPhase2]
        .into_iter()
        .map(|l| ComplianceChecker::new(l).check(&sbom))
        .collect();
    let oscal = sbom_tools::reports::oscal::generate_assessment_results(&results).expect("oscal");
    let json: serde_json::Value = serde_json::from_str(&oscal).expect("valid JSON");
    let entries = json["assessment-results"]["results"]
        .as_array()
        .expect("results");
    assert_eq!(entries.len(), 2, "one results[] entry per standard");
    for (entry, expected_id) in entries.iter().zip(["NtiaMinimum", "CraPhase2"]) {
        let props = entry["props"].as_array().expect("props");
        let get = |name: &str| {
            props
                .iter()
                .find(|p| p["name"] == name)
                .and_then(|p| p["value"].as_str())
                .unwrap_or_else(|| panic!("missing prop {name}"))
        };
        assert_eq!(get("standard"), expected_id);
        assert!(matches!(get("is-compliant"), "true" | "false"));
        assert_eq!(get("applicability"), "applicable");
        get("error-count");
        get("warning-count");
        get("info-count");
        get("score");
        // Roll-up finding present for applicable standards.
        let findings = entry["findings"].as_array().expect("findings");
        assert!(
            findings[0]["title"]
                .as_str()
                .expect("title")
                .contains("compliance roll-up")
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Structured violation identity (P2-H)
// ---------------------------------------------------------------------------

#[test]
fn component_scoped_violations_carry_canonical_component_id() {
    let sbom = violating_sbom();
    // NTIA emits one per-component finding per missing version, so every
    // fixture component fires SBOM-NTIA-VERSION.
    let result = ComplianceChecker::new(ComplianceLevel::NtiaMinimum).check(&sbom);
    let per_component: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.rule_id == "SBOM-NTIA-VERSION")
        .collect();
    assert_eq!(
        per_component.len(),
        3,
        "one finding per versionless component"
    );

    let canonical_ids: BTreeSet<String> = sbom
        .components
        .keys()
        .map(|id| id.value().to_string())
        .collect();
    for v in &per_component {
        let cid = v
            .component_id
            .as_deref()
            .expect("component-scoped violation carries component_id");
        assert!(
            canonical_ids.contains(cid),
            "component_id {cid:?} must join back to an SBOM component (element {:?} is only a label)",
            v.element
        );
    }

    // The join key survives a JSON round-trip.
    let json = serde_json::to_string(&result).expect("serialize");
    let back: sbom_tools::quality::ComplianceResult =
        serde_json::from_str(&json).expect("deserialize");
    let original: Vec<Option<String>> = result
        .violations
        .iter()
        .map(|v| v.component_id.clone())
        .collect();
    let round_tripped: Vec<Option<String>> = back
        .violations
        .iter()
        .map(|v| v.component_id.clone())
        .collect();
    assert_eq!(original, round_tripped, "component_id must round-trip");
}

#[test]
fn aggregate_violations_carry_counts_matching_the_message() {
    let sbom = violating_sbom();
    // EO 14028 aggregates missing versions into a single "N/M components"
    // finding; all 3 fixture components lack a version.
    let result = ComplianceChecker::new(ComplianceLevel::Eo14028).check(&sbom);
    let v = result
        .violations
        .iter()
        .find(|v| v.rule_id == "SBOM-EO14028-VERSION")
        .expect("aggregate version finding fires");
    let counts = v.counts.expect("aggregate finding carries counts");
    assert_eq!(
        (counts.affected, counts.total),
        (3, 3),
        "counts must match the fixture cohort"
    );
    assert!(
        v.message
            .contains(&format!("{}/{}", counts.affected, counts.total)),
        "counts must mirror the numbers printed in the message: {}",
        v.message
    );

    // Structured shape in JSON, and it round-trips.
    let json = serde_json::to_value(v).expect("serialize violation");
    assert_eq!(json["counts"]["affected"], 3);
    assert_eq!(json["counts"]["total"], 3);
    let back: sbom_tools::quality::Violation =
        serde_json::from_value(json).expect("deserialize violation");
    assert_eq!(back.counts, v.counts, "counts must round-trip");
}

#[test]
fn old_payloads_without_identity_fields_deserialize_to_none() {
    // Violation JSON predating component_id/counts (and the fields are also
    // omitted from serialization when None, so old consumers see no change).
    let payload = serde_json::json!({
        "severity": "Error",
        "category": "ComponentIdentification",
        "message": "Component 'lib0' missing version",
        "element": "lib0",
        "requirement": "NTIA: Component version",
        "rule_id": "SBOM-NTIA-VERSION"
    });
    let v: sbom_tools::quality::Violation =
        serde_json::from_value(payload).expect("old payload deserializes");
    assert_eq!(v.component_id, None);
    assert_eq!(v.counts, None);

    // And a document-level violation serializes WITHOUT the new keys.
    let json = serde_json::to_value(&v).expect("serialize");
    let obj = json.as_object().expect("object");
    assert!(!obj.contains_key("component_id"));
    assert!(!obj.contains_key("counts"));
}

#[test]
fn sarif_results_carry_component_id_and_counts_properties() {
    let sbom = violating_sbom();

    // Per-component surface: componentId property joins back to the SBOM.
    let canonical_ids: BTreeSet<String> = sbom
        .components
        .keys()
        .map(|id| id.value().to_string())
        .collect();
    let result = ComplianceChecker::new(ComplianceLevel::NtiaMinimum).check(&sbom);
    let sarif = generate_compliance_sarif(&result).expect("sarif");
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid SARIF");
    let component_ids: Vec<&str> = json["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|r| r["properties"]["componentId"].as_str())
        .collect();
    assert!(
        !component_ids.is_empty(),
        "component-scoped SARIF results must carry properties.componentId"
    );
    for cid in component_ids {
        assert!(
            canonical_ids.contains(cid),
            "SARIF componentId {cid:?} must join back to an SBOM component"
        );
    }

    // Aggregate surface: affected/total properties mirror Violation::counts.
    let result = ComplianceChecker::new(ComplianceLevel::Eo14028).check(&sbom);
    let sarif = generate_compliance_sarif(&result).expect("sarif");
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("valid SARIF");
    assert!(
        json["runs"][0]["results"]
            .as_array()
            .expect("results")
            .iter()
            .any(|r| r["properties"]["affected"] == 3 && r["properties"]["total"] == 3),
        "aggregate SARIF results must carry properties.affected/total"
    );
}
