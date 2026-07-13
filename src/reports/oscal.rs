//! OSCAL assessment-results export for compliance validation findings.
//!
//! One `results[]` entry is emitted per checked standard
//! ([`ComplianceResult`]), so a multi-standard validation no longer flattens
//! into a single anonymous assessment: each entry carries the standard's
//! identity in its title/description and a per-result `props` block with the
//! machine-readable verdict (standard id, `is_compliant`, applicability,
//! severity counts, score). A fully compliant standard still gets its result
//! entry, with a satisfied roll-up finding.

use crate::quality::{Applicability, ComplianceResult, Violation, ViolationSeverity};
use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

const OSCAL_VERSION: &str = "1.1.2";
const ASSESSMENT_PLAN_URN: &str = "urn:sbom-tools:assessment-plan:validation";
const PROP_NS: &str = "https://sbom.tools/ns/oscal";

/// Generate an OSCAL 1.1.2 assessment-results JSON document.
pub fn generate_assessment_results(results: &[ComplianceResult]) -> Result<String> {
    build_assessment_results(results, Utc::now(), &mut Uuid::new_v4)
}

fn build_assessment_results(
    results: &[ComplianceResult],
    timestamp: DateTime<Utc>,
    uuid: &mut impl FnMut() -> Uuid,
) -> Result<String> {
    let collected = timestamp.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut result_entries: Vec<Value> = results
        .iter()
        .map(|result| standard_result(result, &collected, uuid))
        .collect();
    // OSCAL requires at least one result entry; keep the historical empty
    // assessment shape when no standard was checked at all.
    if result_entries.is_empty() {
        result_entries.push(json!({
            "uuid": uuid(),
            "title": "sbom-tools validation assessment",
            "description": "Validation results derived only from the supplied SBOM.",
            "start": collected,
            "reviewed-controls": reviewed_controls(),
        }));
    }

    Ok(serde_json::to_string_pretty(&json!({
        "assessment-results": {
            "uuid": uuid(),
            "metadata": {
                "title": "sbom-tools validation assessment results",
                "last-modified": collected,
                "version": env!("CARGO_PKG_VERSION"),
                "oscal-version": OSCAL_VERSION
            },
            "import-ap": { "href": ASSESSMENT_PLAN_URN },
            "results": result_entries
        }
    }))?)
}

fn reviewed_controls() -> Value {
    json!({
        "control-selections": [{
            "description": "Controls represented by the selected sbom-tools validation standards.",
            "include-all": {}
        }]
    })
}

/// Stable machine identifier for a standard (the serde variant name, e.g.
/// `NtiaMinimum`, `CraPhase2`).
fn standard_id(result: &ComplianceResult) -> String {
    format!("{:?}", result.level)
}

/// Build the `results[]` entry for one checked standard.
fn standard_result(
    result: &ComplianceResult,
    collected: &str,
    uuid: &mut impl FnMut() -> Uuid,
) -> Value {
    let standard_name = result.level.name();
    let mut props = vec![
        prop("standard", &standard_id(result)),
        prop("standard-name", standard_name),
        prop("is-compliant", &result.is_compliant.to_string()),
        prop(
            "applicability",
            if result.is_applicable() {
                "applicable"
            } else {
                "not-applicable"
            },
        ),
        prop("error-count", &result.error_count.to_string()),
        prop("warning-count", &result.warning_count.to_string()),
        prop("info-count", &result.info_count.to_string()),
    ];
    if let Applicability::NotApplicable(reason) = &result.applicability {
        props.push(prop("not-applicable-reason", reason));
    }
    if let Some(score) = result.score() {
        props.push(prop("score", &score.to_string()));
    }

    let mut observations = Vec::new();
    let mut findings = Vec::new();
    // Roll-up finding: the standard-level verdict. Not-applicable standards
    // keep `is_compliant = true` by contract but were never evaluated, so
    // they get no roll-up — the props above carry the N/A verdict instead.
    if result.is_applicable() {
        findings.push(rollup_finding(result, standard_name, uuid()));
    }
    for violation in &result.violations {
        // A real N/A result carries exactly one Info marker violation
        // (SBOM-AIACT-NA / SBOM-BSIAI-NA) — that is how the checker encodes
        // "this standard never evaluated the SBOM". The applicability props
        // above already carry that verdict; rendering the marker through
        // `finding()` would emit a `not-satisfied` objective (OSCAL's
        // finding-target state is a closed satisfied/not-satisfied enum with
        // no N/A) for a standard that was never evaluated. Skip it, like the
        // CSV export does; any other violation keeps current behavior.
        if !result.is_applicable() && is_not_applicable_marker(violation) {
            continue;
        }
        let observation_uuid = uuid();
        observations.push(observation(violation, observation_uuid, collected));
        findings.push(finding(violation, observation_uuid, uuid()));
    }

    let mut entry = json!({
        "uuid": uuid(),
        "title": format!("sbom-tools validation assessment — {standard_name}"),
        "description": format!(
            "Validation results for {standard_name}, derived only from the supplied SBOM."
        ),
        "start": collected,
        "reviewed-controls": reviewed_controls(),
        "props": props,
    });
    if !observations.is_empty() {
        entry["observations"] = Value::Array(observations);
    }
    if !findings.is_empty() {
        entry["findings"] = Value::Array(findings);
    }
    entry
}

/// Whether a violation is a readiness profile's not-applicable placeholder
/// (mirrors `NOT_APPLICABLE_RULES` in `quality::compliance`, the marker set
/// `ComplianceResult::new` derives `Applicability::NotApplicable` from).
fn is_not_applicable_marker(violation: &Violation) -> bool {
    matches!(violation.rule_id, "SBOM-AIACT-NA" | "SBOM-BSIAI-NA")
}

fn prop(name: &str, value: &str) -> Value {
    json!({
        "name": name,
        "ns": PROP_NS,
        "value": value
    })
}

/// Standard-level roll-up finding: `satisfied` when the standard evaluated
/// the SBOM and found no blocking violation, `not-satisfied` otherwise.
fn rollup_finding(result: &ComplianceResult, standard_name: &str, uuid: Uuid) -> Value {
    let state = if result.is_compliant {
        "satisfied"
    } else {
        "not-satisfied"
    };
    json!({
        "uuid": uuid,
        "title": format!("{standard_name} compliance roll-up"),
        "description": format!(
            "Overall verdict for {standard_name}: {} error(s), {} warning(s), {} informational finding(s).",
            result.error_count, result.warning_count, result.info_count
        ),
        "target": {
            "type": "objective-id",
            "target-id": format!("{}-compliance", standard_id(result).to_ascii_lowercase()),
            "status": { "state": state }
        }
    })
}

fn observation(violation: &Violation, uuid: Uuid, collected: &str) -> Value {
    let mut props = vec![
        prop("severity", severity(violation.severity)),
        prop("standard-reference", &violation.requirement),
        prop("rule-id", violation.rule_id),
        prop("sarif-rule-id", violation.sarif_rule_id()),
    ];
    if let Some(element) = &violation.element {
        props.push(prop("sbom-element", element));
    }
    json!({
        "uuid": uuid,
        "title": violation.rule_id,
        "description": violation.message,
        "methods": ["EXAMINE"],
        "types": ["finding"],
        "collected": collected,
        "props": props
    })
}

fn finding(violation: &Violation, observation_uuid: Uuid, uuid: Uuid) -> Value {
    json!({
        "uuid": uuid,
        "title": violation.rule_id,
        "description": violation.message,
        "target": {
            "type": "objective-id",
            "target-id": violation.rule_id.to_ascii_lowercase(),
            "status": {
                // OSCAL 1.1.2 finding-target status `state` is a closed enum
                // (satisfied | not-satisfied, no allow-other). Any violation —
                // regardless of severity — is a non-satisfied objective; the
                // severity detail is carried separately in the observation's
                // custom `severity` property.
                "state": "not-satisfied"
            }
        },
        "related-observations": [{ "observation-uuid": observation_uuid }]
    })
}

const fn severity(value: ViolationSeverity) -> &'static str {
    match value {
        ViolationSeverity::Error => "error",
        ViolationSeverity::Warning => "warning",
        ViolationSeverity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::build_assessment_results;
    use crate::quality::{
        ComplianceLevel, ComplianceResult, Violation, ViolationCategory, ViolationSeverity,
    };
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn violation(message: &str) -> Violation {
        Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::DocumentMetadata,
            message: message.to_string(),
            element: Some("metadata".to_string()),
            requirement: "NTIA minimum elements".to_string(),
            rule_id: "SBOM-NTIA-TIMESTAMP",
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
        }
    }

    fn result(violations: Vec<Violation>) -> ComplianceResult {
        ComplianceResult {
            is_compliant: violations.is_empty(),
            level: ComplianceLevel::NtiaMinimum,
            error_count: violations.len(),
            warning_count: 0,
            info_count: 0,
            violations,
            conformity_summary: None,
            applicability: crate::quality::Applicability::Applicable,
        }
    }

    fn build(results: &[ComplianceResult]) -> serde_json::Value {
        let timestamp = Utc
            .with_ymd_and_hms(2026, 7, 1, 12, 0, 0)
            .single()
            .expect("valid timestamp");
        let mut next = 0u128;
        let json = build_assessment_results(results, timestamp, &mut || {
            next += 1;
            Uuid::from_u128(next)
        })
        .expect("OSCAL serialization");
        serde_json::from_str(&json).expect("valid JSON")
    }

    fn prop_value<'a>(entry: &'a serde_json::Value, name: &str) -> Option<&'a str> {
        entry["props"]
            .as_array()?
            .iter()
            .find(|p| p["name"] == name)?["value"]
            .as_str()
    }

    #[test]
    fn compliant_result_still_gets_an_entry_with_satisfied_rollup() {
        let document = build(&[result(Vec::new())]);
        let assessment = &document["assessment-results"]["results"][0];
        assert!(
            assessment["title"]
                .as_str()
                .expect("title")
                .contains("NTIA Minimum Elements"),
            "per-standard entry must carry the standard name in its title"
        );
        assert_eq!(prop_value(assessment, "standard"), Some("NtiaMinimum"));
        assert_eq!(prop_value(assessment, "is-compliant"), Some("true"));
        assert_eq!(prop_value(assessment, "applicability"), Some("applicable"));
        assert_eq!(prop_value(assessment, "error-count"), Some("0"));
        assert_eq!(prop_value(assessment, "score"), Some("100"));
        assert!(assessment.get("observations").is_none());
        let findings = assessment["findings"].as_array().expect("findings");
        assert_eq!(findings.len(), 1, "clean run keeps only the roll-up");
        assert_eq!(findings[0]["target"]["status"]["state"], "satisfied");
    }

    #[test]
    fn single_finding_links_to_its_observation() {
        let document = build(&[result(vec![violation("missing metadata")])]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(assessment["observations"].as_array().map(Vec::len), Some(1));
        // Roll-up (not-satisfied) + one violation finding.
        let findings = assessment["findings"].as_array().expect("findings");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0]["target"]["status"]["state"], "not-satisfied");
        assert_eq!(
            findings[1]["related-observations"][0]["observation-uuid"],
            assessment["observations"][0]["uuid"]
        );
        assert_eq!(prop_value(assessment, "is-compliant"), Some("false"));
    }

    #[test]
    fn multiple_findings_are_emitted_in_input_order() {
        let document = build(&[result(vec![violation("first"), violation("second")])]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(assessment["observations"].as_array().map(Vec::len), Some(2));
        // findings[0] is the roll-up; violations follow in input order.
        assert_eq!(assessment["findings"][1]["description"], "first");
        assert_eq!(assessment["findings"][2]["description"], "second");
        assert_eq!(
            document["assessment-results"]["metadata"]["last-modified"],
            "2026-07-01T12:00:00Z"
        );
    }

    #[test]
    fn each_standard_gets_its_own_result_entry() {
        let ntia = result(vec![violation("missing metadata")]);
        let mut cra = result(Vec::new());
        cra.level = ComplianceLevel::CraPhase2;
        let document = build(&[ntia, cra]);
        let entries = document["assessment-results"]["results"]
            .as_array()
            .expect("results");
        assert_eq!(entries.len(), 2, "one results[] entry per standard");
        assert_eq!(prop_value(&entries[0], "standard"), Some("NtiaMinimum"));
        assert_eq!(prop_value(&entries[0], "is-compliant"), Some("false"));
        assert_eq!(prop_value(&entries[1], "standard"), Some("CraPhase2"));
        assert_eq!(prop_value(&entries[1], "is-compliant"), Some("true"));
        assert!(
            entries[1]["title"]
                .as_str()
                .expect("title")
                .contains("EU CRA Phase 2"),
        );
    }

    /// The single Info marker violation the readiness checkers actually emit
    /// for out-of-scope SBOMs (`ComplianceResult::new` derives
    /// `Applicability::NotApplicable` from its presence).
    fn na_marker() -> Violation {
        Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::DocumentMetadata,
            message: "[AI-Act] Not applicable: no ML components".to_string(),
            element: None,
            requirement: "EU AI Act Annex IV".to_string(),
            rule_id: "SBOM-AIACT-NA",
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
        }
    }

    #[test]
    fn not_applicable_standard_carries_na_verdict_and_no_rollup() {
        // Build through the production constructor: a real N/A result always
        // contains the marker violation — the shape that used to leak a
        // `not-satisfied` finding for a standard that never evaluated the SBOM.
        let na = ComplianceResult::new(ComplianceLevel::EuAiAct, vec![na_marker()]);
        assert!(!na.is_applicable(), "marker must derive not-applicable");
        let document = build(&[na]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(
            prop_value(assessment, "applicability"),
            Some("not-applicable")
        );
        assert_eq!(
            prop_value(assessment, "not-applicable-reason"),
            Some("[AI-Act] Not applicable: no ML components")
        );
        assert!(
            prop_value(assessment, "score").is_none(),
            "an unevaluated standard has no score"
        );
        assert!(
            assessment.get("findings").is_none(),
            "an unevaluated standard gets no roll-up and no marker finding"
        );
        assert!(
            assessment.get("observations").is_none(),
            "the N/A marker is not an actionable observation"
        );
    }

    #[test]
    fn not_applicable_standard_still_renders_non_marker_violations() {
        // Should a checker ever attach a real violation to an N/A result,
        // only the marker is suppressed — everything else keeps the current
        // observation + not-satisfied finding behavior.
        let na = ComplianceResult::new(
            ComplianceLevel::EuAiAct,
            vec![na_marker(), violation("genuine finding")],
        );
        let document = build(&[na]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(
            prop_value(assessment, "applicability"),
            Some("not-applicable")
        );
        let findings = assessment["findings"].as_array().expect("findings");
        assert_eq!(findings.len(), 1, "marker skipped, real violation kept");
        assert_eq!(findings[0]["description"], "genuine finding");
        assert_eq!(findings[0]["target"]["status"]["state"], "not-satisfied");
        assert_eq!(assessment["observations"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn observations_carry_rule_identity() {
        let document = build(&[result(vec![violation("missing timestamp")])]);
        let assessment = &document["assessment-results"]["results"][0];
        let obs = &assessment["observations"][0];
        assert_eq!(prop_value(obs, "rule-id"), Some("SBOM-NTIA-TIMESTAMP"));
        assert_eq!(
            prop_value(obs, "sarif-rule-id"),
            Some("SBOM-NTIA-TIMESTAMP")
        );
    }

    #[test]
    fn finding_status_state_is_valid_oscal_token_for_every_severity() {
        // OSCAL 1.1.2 finding-target status `state` is a CLOSED enum:
        // only "satisfied" / "not-satisfied" (no allow-other). Every violation
        // is a non-satisfied objective regardless of severity. This guards the
        // Info/Warning branches that the other tests (Error-only) never reach.
        let with_severity = |message: &str, severity: ViolationSeverity| Violation {
            severity,
            category: ViolationCategory::DocumentMetadata,
            message: message.to_string(),
            element: Some("metadata".to_string()),
            requirement: "NTIA minimum elements".to_string(),
            rule_id: "SBOM-NTIA-TIMESTAMP",
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
        };
        let document = build(&[result(vec![
            with_severity("info finding", ViolationSeverity::Info),
            with_severity("warning finding", ViolationSeverity::Warning),
            with_severity("error finding", ViolationSeverity::Error),
        ])]);
        let findings = document["assessment-results"]["results"][0]["findings"]
            .as_array()
            .expect("findings array");
        // Roll-up + three violation findings.
        assert_eq!(findings.len(), 4);
        for finding in findings.iter().skip(1) {
            assert_eq!(finding["target"]["status"]["state"], "not-satisfied");
        }
    }
}
