//! Combined integration tests for CRA-P5.4 (EuccSubstantial),
//! P5.5 (controls-assertion sidecar block), and P5.7 (TUI presets).

use sbom_tools::model::{ControlAssertion, CraSidecarMetadata};
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel, ViolationSeverity};
use std::collections::BTreeMap;

// ============================================================================
// P5.4 — EuccSubstantial
// ============================================================================

#[test]
fn eucc_substantial_in_compliance_level_all() {
    assert!(ComplianceLevel::all().contains(&ComplianceLevel::EuccSubstantial));
}

#[test]
fn eucc_substantial_short_name_fits_compact_label() {
    assert!(ComplianceLevel::EuccSubstantial.short_name().len() <= 8);
}

#[test]
fn eucc_substantial_without_sidecar_fires_all_four_must_haves() {
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = ComplianceChecker::new(ComplianceLevel::EuccSubstantial).check(&sbom);
    let requirements: Vec<&String> = result.violations.iter().map(|v| &v.requirement).collect();
    assert!(
        requirements
            .iter()
            .any(|r| r.contains("Protection Profile reference"))
    );
    assert!(
        requirements
            .iter()
            .any(|r| r.contains("Target of Evaluation reference"))
    );
    assert!(requirements.iter().any(|r| r.contains("ITSEF")));
    assert!(
        requirements
            .iter()
            .any(|r| r.contains("valid-until date"))
    );
}

#[test]
fn eucc_substantial_with_complete_sidecar_only_warns() {
    let sidecar = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP-CC-MFR-2024-01".to_string()),
        eucc_target_of_evaluation: Some("https://example.com/toe".to_string()),
        eucc_itsef_identifier: Some("ITSEF-DE-001".to_string()),
        eucc_valid_until: Some(
            chrono::DateTime::parse_from_rfc3339("2030-12-31T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = ComplianceChecker::new(ComplianceLevel::EuccSubstantial)
        .with_sidecar(sidecar)
        .check(&sbom);
    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "Complete EUCC sidecar should produce no Errors; got {errors:?}"
    );
}

#[test]
fn eucc_substantial_expired_certificate_is_error() {
    let sidecar = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP".to_string()),
        eucc_target_of_evaluation: Some("toe".to_string()),
        eucc_itsef_identifier: Some("itsef".to_string()),
        eucc_valid_until: Some(
            chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = ComplianceChecker::new(ComplianceLevel::EuccSubstantial)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        result.violations.iter().any(|v| v.severity == ViolationSeverity::Error
            && v.message.contains("expired"))
    );
}

#[test]
fn eucc_substantial_near_expiry_is_warning() {
    let near = chrono::Utc::now() + chrono::Duration::days(60);
    let sidecar = CraSidecarMetadata {
        eucc_protection_profile_id: Some("PP".to_string()),
        eucc_target_of_evaluation: Some("toe".to_string()),
        eucc_itsef_identifier: Some("itsef".to_string()),
        eucc_valid_until: Some(near),
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = ComplianceChecker::new(ComplianceLevel::EuccSubstantial)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        result.violations.iter().any(|v| v.severity == ViolationSeverity::Warning
            && v.message.contains("expires within"))
    );
}

// ============================================================================
// P5.5 — controls-assertion sidecar block
// ============================================================================

#[test]
fn controls_assertion_satisfied_with_evidence_clears_check() {
    let mut controls: BTreeMap<String, ControlAssertion> = BTreeMap::new();
    controls.insert(
        "1.a".to_string(),
        ControlAssertion {
            satisfied: true,
            evidence_url: Some("https://example.com/evidence/1.a.pdf".to_string()),
            methodology: Some("prEN 40000-1-2 §5.3".to_string()),
            note: None,
        },
    );
    let sidecar = CraSidecarMetadata {
        annex_i_part_i_controls: controls,
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Annex I Part I 1.a")),
        "satisfied + evidence_url present must not fire"
    );
}

#[test]
fn controls_assertion_satisfied_without_evidence_fires_warning() {
    let mut controls: BTreeMap<String, ControlAssertion> = BTreeMap::new();
    controls.insert(
        "1.a".to_string(),
        ControlAssertion {
            satisfied: true,
            evidence_url: None,
            methodology: Some("informal".to_string()),
            note: None,
        },
    );
    let sidecar = CraSidecarMetadata {
        annex_i_part_i_controls: controls,
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    let v = result
        .violations
        .iter()
        .find(|v| v.requirement.contains("Annex I Part I 1.a"))
        .expect("warning expected");
    assert_eq!(v.severity, ViolationSeverity::Warning);
}

#[test]
fn controls_assertion_unsatisfied_does_not_fire() {
    let mut controls: BTreeMap<String, ControlAssertion> = BTreeMap::new();
    controls.insert(
        "1.b".to_string(),
        ControlAssertion {
            satisfied: false,
            evidence_url: None,
            methodology: None,
            note: Some("Not yet implemented".to_string()),
        },
    );
    let sidecar = CraSidecarMetadata {
        annex_i_part_i_controls: controls,
        ..Default::default()
    };
    let sbom = sbom_tools::model::NormalizedSbom::default();
    let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
        .with_sidecar(sidecar)
        .check(&sbom);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Annex I Part I 1.b"))
    );
}

#[test]
fn controls_assertion_serde_roundtrip_preserves_btreemap() {
    let mut controls: BTreeMap<String, ControlAssertion> = BTreeMap::new();
    controls.insert(
        "1.a".to_string(),
        ControlAssertion {
            satisfied: true,
            evidence_url: Some("u".to_string()),
            methodology: Some("m".to_string()),
            note: None,
        },
    );
    controls.insert(
        "2.m".to_string(),
        ControlAssertion {
            satisfied: false,
            ..Default::default()
        },
    );
    let original = CraSidecarMetadata {
        annex_i_part_i_controls: controls,
        ..Default::default()
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("annex_i_part_i_controls") || json.contains("annexIPartIControls"));
    let parsed: CraSidecarMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.annex_i_part_i_controls.len(), 2);
    assert!(parsed.annex_i_part_i_controls["1.a"].satisfied);
    assert!(!parsed.annex_i_part_i_controls["2.m"].satisfied);

    // Default (empty) must skip serialization.
    let default_json = serde_json::to_string(&CraSidecarMetadata::default()).unwrap();
    assert!(!default_json.contains("annex_i_part_i_controls"));
    assert!(!default_json.contains("annexIPartIControls"));
}

// ============================================================================
// P5.7 — TUI presets
// ============================================================================

#[test]
fn tui_policy_preset_includes_eucc_and_oss_steward() {
    use sbom_tools::tui::PolicyPreset;
    let p = PolicyPreset::EuccSubstantial;
    assert_eq!(
        p.compliance_level(),
        Some(ComplianceLevel::EuccSubstantial)
    );
    assert!(p.is_standards_based());

    let oss = PolicyPreset::CraOssSteward;
    assert_eq!(
        oss.compliance_level(),
        Some(ComplianceLevel::CraOssSteward)
    );
    assert!(oss.is_standards_based());
}

#[test]
fn tui_policy_preset_cycle_visits_eucc_and_oss_steward() {
    use sbom_tools::tui::PolicyPreset;
    let mut seen = Vec::new();
    let mut p = PolicyPreset::Enterprise;
    for _ in 0..14 {
        seen.push(p);
        p = p.next();
    }
    assert!(seen.contains(&PolicyPreset::EuccSubstantial));
    assert!(seen.contains(&PolicyPreset::CraOssSteward));
}
