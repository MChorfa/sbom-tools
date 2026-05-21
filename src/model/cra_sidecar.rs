//! CRA Sidecar Metadata Support
//!
//! Allows loading additional CRA-required metadata from a sidecar file
//! when the SBOM doesn't contain this information.
//!
//! The sidecar file can be JSON or YAML and supplements the SBOM with:
//! - Security contact information
//! - Vulnerability disclosure URLs
//! - Support end dates
//! - Manufacturer details

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// CRA sidecar metadata that supplements SBOM information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CraSidecarMetadata {
    /// Security contact email or URL for vulnerability disclosure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_contact: Option<String>,

    /// URL for vulnerability disclosure policy/portal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerability_disclosure_url: Option<String>,

    /// End of support/security updates date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_end_date: Option<DateTime<Utc>>,

    /// Manufacturer/vendor name (supplements SBOM creator info)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer_name: Option<String>,

    /// Manufacturer contact email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer_email: Option<String>,

    /// Product name (supplements SBOM document name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,

    /// Product version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,

    /// CE marking declaration reference (URL or document ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ce_marking_reference: Option<String>,

    /// Security update delivery mechanism description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_mechanism: Option<String>,

    // -------- CRA Article 14 reporting-readiness fields (apply 2026-09-11) --------
    /// PSIRT (Product Security Incident Response Team) public URL.
    /// Required to handle external vulnerability reports under Annex I Part II
    /// and Art. 14 incident reporting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psirt_url: Option<String>,

    /// Channel (email, URL, phone) for the 24-hour early-warning notification
    /// to ENISA / CSIRT under CRA Art. 14(1) when an actively-exploited
    /// vulnerability is identified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub early_warning_contact: Option<String>,

    /// Channel for the 72-hour incident report under CRA Art. 14(2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incident_report_contact: Option<String>,

    /// Manufacturer-side identifier for the ENISA single reporting platform
    /// (Art. 14(7)). Until ENISA publishes the technical interface this is a
    /// placeholder string — typically a manufacturer registration ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enisa_reporting_platform_id: Option<String>,

    /// Coordinated vulnerability disclosure policy URL.
    /// Distinct from `vulnerability_disclosure_url` (which may point at a
    /// portal) — this is the published *policy* that meets CRA Art. 13(7)
    /// and ISO/IEC 29147 expectations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinated_disclosure_policy_url: Option<String>,

    // -------- CRA Article 13(2) risk-assessment fields --------
    /// URL or document reference for the documented risk assessment
    /// required by CRA Art. 13(2). Annex V technical documentation must
    /// include or reference this assessment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_assessment_url: Option<String>,

    /// Methodology used for the risk assessment (e.g.,
    /// "ISO/IEC 27005:2022", "NIST SP 800-30 r1", "ETSI TS 102 165-1 TVRA").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_assessment_methodology: Option<String>,

    // -------- CRA Annex III/IV product class & conformity-assessment route --------
    /// CRA product class drives the conformity-assessment route and the
    /// severity calibration of compliance checks (vendor-hash coverage,
    /// PSIRT, EUCC reference, attestation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_class: Option<CraProductClass>,

    /// Conformity-assessment route per CRA Annex VIII (Module A self-assessment,
    /// B+C EU-type examination, H full QA, or EUCC). Sidecar value wins over
    /// any CLI-provided default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conformity_assessment_route: Option<ConformityRoute>,

    // -------- CRA Article 24 — open-source steward profile --------
    /// Whether this product is supplied by an open-source software steward
    /// (CRA Art. 24). When `true`, manufacturer-only obligations (DoC,
    /// notified-body attestation, manufacturer email) are not enforced;
    /// SBOM, vulnerability-handling, and CVD policy are still required.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub is_oss_steward: bool,

    // -------- Adjacent regulation overlap (CRA-P4.4) --------
    /// True if the manufacturer is a NIS2 essential entity (Annex I of
    /// Directive (EU) 2022/2555). Triggers Art. 23 incident-reporting
    /// guidance in the cra-docs dossier.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub is_nis2_essential_entity: bool,

    /// True if the manufacturer is a NIS2 important entity (Annex II of
    /// Directive (EU) 2022/2555).
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub is_nis2_important_entity: bool,

    /// True when the product processes personal data (GDPR Art. 32
    /// security-of-processing applies in parallel to CRA Annex I).
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub processes_personal_data: bool,

    /// True when the product is a high-risk AI system per the AI Act
    /// (Regulation (EU) 2024/1689). AI-Act conformity coordination must
    /// be handled alongside CRA Module assessment.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub is_high_risk_ai: bool,

    /// Date until which the Radio Equipment Directive (RED, Directive
    /// 2014/53/EU) cybersecurity provisions still apply for this product.
    /// CRA repeals RED Art. 3(3)(d/e/f) on 2025-08-01; older device
    /// inventories may carry RED references through their support
    /// horizon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub red_repealed_until: Option<DateTime<Utc>>,

    // -------- EUCC Substantial (CRA-P5.4 reference profile) --------
    /// Common Criteria Protection Profile identifier (e.g., "PP-CC-MFR-2024-01").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eucc_protection_profile_id: Option<String>,

    /// Common Criteria Target of Evaluation reference (URL or document ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eucc_target_of_evaluation: Option<String>,

    /// IT Security Evaluation Facility (ITSEF) identifier — the accredited
    /// laboratory that performed the EUCC evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eucc_itsef_identifier: Option<String>,

    /// EUCC certificate valid-until date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eucc_valid_until: Option<DateTime<Utc>>,

    // -------- prEN 40000-1-2/1-4 controls-assertion (CRA-P5.5) --------
    /// Per-control assertions for CRA Annex I Part I, keyed by control ID
    /// (e.g., `"1.a"` through `"1.l"` for §1, `"2.a"` through `"2.m"` for
    /// §2 vulnerability-handling). Each entry records whether the
    /// manufacturer claims the control is satisfied, the evidence URL,
    /// and the methodology used.
    ///
    /// `BTreeMap` for deterministic ordering in dossier output.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annex_i_part_i_controls: BTreeMap<String, ControlAssertion>,
}

/// A manufacturer-supplied assertion that a specific Annex I Part I control
/// is satisfied. Surfaced verbatim in the cra-docs technical-documentation
/// dossier and cross-checked by `ComplianceChecker` (a control claimed
/// `satisfied = true` without an `evidence_url` is flagged as a Warning).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlAssertion {
    /// Whether the manufacturer claims this control is satisfied.
    #[serde(default)]
    pub satisfied: bool,
    /// URL pointing at the evidence document (test report, design review,
    /// SAST/DAST output, etc.). Required when `satisfied = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_url: Option<String>,
    /// Methodology / standard the assertion was made against
    /// (e.g., `"prEN 40000-1-2 §5.3"`, `"OWASP ASVS L2"`,
    /// `"NIST SP 800-53 SI-10"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methodology: Option<String>,
    /// Free-form notes from the manufacturer (rationale, caveats).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// CRA product class per Regulation (EU) 2024/2847 Annex III/IV.
///
/// The class drives the conformity-assessment route and the severity
/// calibration of compliance checks (per CRA-P3.2 calibration table):
/// stricter classes upgrade Warning→Error and add EUCC / attestation
/// expectations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CraProductClass {
    /// Default — neither Annex III nor Annex IV. Module A self-assessment.
    #[serde(rename = "default")]
    Default,
    /// Annex III items 1–11 (Important Class I). Module A or B+C.
    #[serde(
        rename = "important-class-1",
        alias = "important1",
        alias = "ImportantClass1"
    )]
    ImportantClass1,
    /// Annex III items 12–17 (Important Class II). Module B+C, H, or EUCC.
    #[serde(
        rename = "important-class-2",
        alias = "important2",
        alias = "ImportantClass2"
    )]
    ImportantClass2,
    /// Annex IV (Critical). EUCC mandatory.
    #[serde(rename = "critical")]
    Critical,
}

impl CraProductClass {
    /// Short label for compact display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::ImportantClass1 => "Important-1",
            Self::ImportantClass2 => "Important-2",
            Self::Critical => "Critical",
        }
    }

    /// Long human-readable name including Annex reference.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Default => "Default (no Annex)",
            Self::ImportantClass1 => "Important Class I (Annex III items 1–11)",
            Self::ImportantClass2 => "Important Class II (Annex III items 12–17)",
            Self::Critical => "Critical (Annex IV)",
        }
    }

    /// Parse from the CLI-friendly kebab-case form. Accepts a few aliases.
    #[must_use]
    pub fn parse_cli(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "default" | "none" => Some(Self::Default),
            "important-class-1" | "important-1" | "important1" | "annex-iii-1" => {
                Some(Self::ImportantClass1)
            }
            "important-class-2" | "important-2" | "important2" | "annex-iii-2" => {
                Some(Self::ImportantClass2)
            }
            "critical" | "annex-iv" => Some(Self::Critical),
            _ => None,
        }
    }

    /// The conformity-assessment route the regulation expects (or strictly
    /// requires) for this class. Manufacturers may choose a stricter route.
    #[must_use]
    pub const fn default_route(self) -> ConformityRoute {
        match self {
            Self::Default | Self::ImportantClass1 => ConformityRoute::ModuleA,
            Self::ImportantClass2 => ConformityRoute::ModuleBC,
            Self::Critical => ConformityRoute::Eucc,
        }
    }
}

/// Conformity-assessment module per CRA Annex VIII.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ConformityRoute {
    /// Module A — internal control / self-assessment.
    ModuleA,
    /// Module B+C — EU-type examination plus production conformity.
    ModuleBC,
    /// Module H — full quality assurance.
    ModuleH,
    /// EUCC — Common Criteria via European Cybersecurity Certification scheme.
    Eucc,
}

impl ConformityRoute {
    /// Short label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ModuleA => "Module A",
            Self::ModuleBC => "Module B+C",
            Self::ModuleH => "Module H",
            Self::Eucc => "EUCC",
        }
    }

    /// Long descriptive name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ModuleA => "Module A — internal control (self-assessment)",
            Self::ModuleBC => "Module B+C — EU-type examination + production conformity",
            Self::ModuleH => "Module H — full quality assurance",
            Self::Eucc => "EUCC — Common Criteria via EU certification scheme",
        }
    }

    /// Parse from the CLI-friendly kebab-case form.
    #[must_use]
    pub fn parse_cli(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "module-a" | "a" | "self-assessment" => Some(Self::ModuleA),
            "module-bc" | "module-b+c" | "module-b-c" | "bc" | "b+c" => Some(Self::ModuleBC),
            "module-h" | "h" => Some(Self::ModuleH),
            "eucc" | "common-criteria" => Some(Self::Eucc),
            _ => None,
        }
    }
}

impl CraSidecarMetadata {
    /// Load sidecar metadata from a JSON file
    pub fn from_json_file(path: &Path) -> Result<Self, CraSidecarError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| CraSidecarError::IoError(e.to_string()))?;
        serde_json::from_str(&content).map_err(|e| CraSidecarError::ParseError(e.to_string()))
    }

    /// Load sidecar metadata from a YAML file
    pub fn from_yaml_file(path: &Path) -> Result<Self, CraSidecarError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| CraSidecarError::IoError(e.to_string()))?;
        serde_yaml_ng::from_str(&content).map_err(|e| CraSidecarError::ParseError(e.to_string()))
    }

    /// Load sidecar metadata, auto-detecting format from extension
    pub fn from_file(path: &Path) -> Result<Self, CraSidecarError> {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match extension.as_str() {
            "json" => Self::from_json_file(path),
            "yaml" | "yml" => Self::from_yaml_file(path),
            _ => Err(CraSidecarError::UnsupportedFormat(extension)),
        }
    }

    /// Try to find a sidecar file for the given SBOM path.
    ///
    /// Looks for `<stem>.cra.{json,yaml,yml}` and `<stem>-cra.{json,yaml}`
    /// alongside the SBOM. Multi-extension stems (`app.cdx.json`,
    /// `app.spdx.json`, `app.spdx3.json`) also try the inner stem
    /// (`app.cra.json`) so the common SBOM naming conventions work
    /// without forcing operators to repeat the format suffix.
    #[must_use]
    pub fn find_for_sbom(sbom_path: &Path) -> Option<Self> {
        let parent = sbom_path.parent()?;
        let stem = sbom_path.file_stem()?.to_str()?;

        // Build the list of stems to try. Strip well-known SBOM format
        // suffixes (`.cdx`, `.spdx`, `.spdx3`, `.cyclonedx`) so e.g.
        // `app.cdx.json` looks for `app.cra.json` as well as
        // `app.cdx.cra.json`.
        let mut stems: Vec<&str> = vec![stem];
        for suffix in [".cdx", ".cyclonedx", ".spdx", ".spdx3"] {
            if let Some(inner) = stem.strip_suffix(suffix)
                && !inner.is_empty()
            {
                stems.push(inner);
            }
        }

        for s in &stems {
            for pattern in [
                format!("{s}.cra.json"),
                format!("{s}.cra.yaml"),
                format!("{s}.cra.yml"),
                format!("{s}-cra.json"),
                format!("{s}-cra.yaml"),
            ] {
                let sidecar_path = parent.join(&pattern);
                if sidecar_path.exists()
                    && let Ok(metadata) = Self::from_file(&sidecar_path)
                {
                    return Some(metadata);
                }
            }
        }

        None
    }

    /// Check if any CRA-relevant fields are populated
    #[must_use]
    pub fn has_cra_data(&self) -> bool {
        self.security_contact.is_some()
            || self.vulnerability_disclosure_url.is_some()
            || self.support_end_date.is_some()
            || self.manufacturer_name.is_some()
            || self.ce_marking_reference.is_some()
            || self.psirt_url.is_some()
            || self.early_warning_contact.is_some()
            || self.incident_report_contact.is_some()
            || self.enisa_reporting_platform_id.is_some()
            || self.coordinated_disclosure_policy_url.is_some()
            || self.risk_assessment_url.is_some()
            || self.risk_assessment_methodology.is_some()
            || self.product_class.is_some()
            || self.conformity_assessment_route.is_some()
            || self.is_oss_steward
            || self.is_nis2_essential_entity
            || self.is_nis2_important_entity
            || self.processes_personal_data
            || self.is_high_risk_ai
            || self.red_repealed_until.is_some()
            || self.eucc_protection_profile_id.is_some()
            || self.eucc_target_of_evaluation.is_some()
            || self.eucc_itsef_identifier.is_some()
            || self.eucc_valid_until.is_some()
            || !self.annex_i_part_i_controls.is_empty()
    }

    /// Generate an example sidecar file content
    #[must_use]
    pub fn example_json() -> String {
        let example = Self {
            security_contact: Some("security@example.com".to_string()),
            vulnerability_disclosure_url: Some("https://example.com/security".to_string()),
            support_end_date: Some(Utc::now() + chrono::Duration::days(365 * 2)),
            manufacturer_name: Some("Example Corp".to_string()),
            manufacturer_email: Some("contact@example.com".to_string()),
            product_name: Some("Example Product".to_string()),
            product_version: Some("1.0.0".to_string()),
            ce_marking_reference: Some("EU-DoC-2024-001".to_string()),
            update_mechanism: Some("Automatic OTA updates via secure channel".to_string()),
            psirt_url: Some("https://example.com/psirt".to_string()),
            early_warning_contact: Some("psirt@example.com".to_string()),
            incident_report_contact: Some("incidents@example.com".to_string()),
            enisa_reporting_platform_id: Some("EU-MFR-12345".to_string()),
            coordinated_disclosure_policy_url: Some(
                "https://example.com/security/cvd-policy".to_string(),
            ),
            risk_assessment_url: Some(
                "https://example.com/docs/risk-assessment-2026.pdf".to_string(),
            ),
            risk_assessment_methodology: Some("ISO/IEC 27005:2022".to_string()),
            product_class: Some(CraProductClass::ImportantClass1),
            conformity_assessment_route: Some(ConformityRoute::ModuleA),
            is_oss_steward: false,
            is_nis2_essential_entity: false,
            is_nis2_important_entity: false,
            processes_personal_data: false,
            is_high_risk_ai: false,
            red_repealed_until: None,
            eucc_protection_profile_id: None,
            eucc_target_of_evaluation: None,
            eucc_itsef_identifier: None,
            eucc_valid_until: None,
            annex_i_part_i_controls: BTreeMap::new(),
        };
        serde_json::to_string_pretty(&example).unwrap_or_default()
    }
}

/// Errors that can occur when loading sidecar metadata
#[derive(Debug)]
pub enum CraSidecarError {
    IoError(String),
    ParseError(String),
    UnsupportedFormat(String),
}

impl std::fmt::Display for CraSidecarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error reading sidecar file: {e}"),
            Self::ParseError(e) => write!(f, "Parse error in sidecar file: {e}"),
            Self::UnsupportedFormat(ext) => {
                write!(f, "Unsupported sidecar file format: .{ext}")
            }
        }
    }
}

impl std::error::Error for CraSidecarError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_has_no_data() {
        let sidecar = CraSidecarMetadata::default();
        assert!(!sidecar.has_cra_data());
    }

    #[test]
    fn test_has_cra_data_with_contact() {
        let sidecar = CraSidecarMetadata {
            security_contact: Some("security@example.com".to_string()),
            ..Default::default()
        };
        assert!(sidecar.has_cra_data());
    }

    #[test]
    fn test_example_json_is_valid() {
        let json = CraSidecarMetadata::example_json();
        let parsed: Result<CraSidecarMetadata, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_json_roundtrip() {
        let original = CraSidecarMetadata {
            security_contact: Some("test@example.com".to_string()),
            support_end_date: Some(Utc::now()),
            ..Default::default()
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: CraSidecarMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(original.security_contact, parsed.security_contact);
    }

    #[test]
    fn product_class_parse_cli_accepts_aliases() {
        assert_eq!(
            CraProductClass::parse_cli("default"),
            Some(CraProductClass::Default)
        );
        assert_eq!(
            CraProductClass::parse_cli("important-class-1"),
            Some(CraProductClass::ImportantClass1)
        );
        assert_eq!(
            CraProductClass::parse_cli("important-2"),
            Some(CraProductClass::ImportantClass2)
        );
        assert_eq!(
            CraProductClass::parse_cli("CRITICAL"),
            Some(CraProductClass::Critical)
        );
        assert_eq!(CraProductClass::parse_cli("nonsense"), None);
    }

    #[test]
    fn product_class_default_route_matches_regulation() {
        assert_eq!(
            CraProductClass::Default.default_route(),
            ConformityRoute::ModuleA
        );
        assert_eq!(
            CraProductClass::ImportantClass1.default_route(),
            ConformityRoute::ModuleA
        );
        assert_eq!(
            CraProductClass::ImportantClass2.default_route(),
            ConformityRoute::ModuleBC
        );
        assert_eq!(
            CraProductClass::Critical.default_route(),
            ConformityRoute::Eucc
        );
    }

    #[test]
    fn product_class_serde_kebab_case() {
        let json = serde_json::to_string(&CraProductClass::ImportantClass1).unwrap();
        assert_eq!(json, "\"important-class-1\"");
        let parsed: CraProductClass = serde_json::from_str("\"critical\"").unwrap();
        assert_eq!(parsed, CraProductClass::Critical);
    }

    #[test]
    fn conformity_route_parse_cli_accepts_aliases() {
        assert_eq!(
            ConformityRoute::parse_cli("module-a"),
            Some(ConformityRoute::ModuleA)
        );
        assert_eq!(
            ConformityRoute::parse_cli("B+C"),
            Some(ConformityRoute::ModuleBC)
        );
        assert_eq!(
            ConformityRoute::parse_cli("Module-H"),
            Some(ConformityRoute::ModuleH)
        );
        assert_eq!(
            ConformityRoute::parse_cli("EUCC"),
            Some(ConformityRoute::Eucc)
        );
        assert_eq!(ConformityRoute::parse_cli("module-z"), None);
    }
}
