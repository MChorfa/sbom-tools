//! SBOM Compliance checking module.
//!
//! Validates SBOMs against format requirements and industry standards.

use crate::model::{NormalizedSbom, SbomFormat};
use serde::{Deserialize, Serialize};

/// CRA enforcement phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CraPhase {
    /// Phase 1: Reporting obligations — deadline 11 December 2027
    /// Basic SBOM requirements: product/component identification, manufacturer, version, format
    Phase1,
    /// Phase 2: Full compliance — deadline 11 December 2029
    /// Adds: vulnerability metadata, lifecycle/end-of-support, disclosure policy, EU `DoC`
    Phase2,
}

impl CraPhase {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Phase1 => "Phase 1 (2027)",
            Self::Phase2 => "Phase 2 (2029)",
        }
    }

    pub const fn deadline(self) -> &'static str {
        match self {
            Self::Phase1 => "11 December 2027",
            Self::Phase2 => "11 December 2029",
        }
    }
}

/// Compliance level/profile
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ComplianceLevel {
    /// Minimum viable SBOM (basic identification)
    Minimum,
    /// Standard compliance (recommended fields)
    Standard,
    /// NTIA Minimum Elements compliance
    NtiaMinimum,
    /// EU CRA Phase 1 — Reporting obligations (deadline: 11 Dec 2027)
    CraPhase1,
    /// EU CRA Phase 2 — Full compliance (deadline: 11 Dec 2029)
    CraPhase2,
    /// FDA Medical Device SBOM requirements
    FdaMedicalDevice,
    /// NIST SP 800-218 Secure Software Development Framework
    NistSsdf,
    /// Executive Order 14028 Section 4 — Enhancing Software Supply Chain Security
    Eo14028,
    /// NSA CNSA 2.0 — Commercial National Security Algorithm Suite 2.0
    Cnsa2,
    /// NIST PQC Readiness — Post-Quantum Cryptography migration (IR 8547 + FIPS 203/204/205)
    NistPqc,
    /// BSI TR-03183-2 (German national CRA-aligned SBOM technical guideline).
    /// Free, ENISA-cited; stricter than NTIA on hashes and identifiers.
    BsiTr03183_2,
    /// Comprehensive compliance (all recommended fields)
    Comprehensive,
}

impl ComplianceLevel {
    /// Get human-readable name
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Minimum => "Minimum",
            Self::Standard => "Standard",
            Self::NtiaMinimum => "NTIA Minimum Elements",
            Self::CraPhase1 => "EU CRA Phase 1 (2027)",
            Self::CraPhase2 => "EU CRA Phase 2 (2029)",
            Self::FdaMedicalDevice => "FDA Medical Device",
            Self::NistSsdf => "NIST SSDF (SP 800-218)",
            Self::Eo14028 => "EO 14028 Section 4",
            Self::Cnsa2 => "CNSA 2.0",
            Self::NistPqc => "NIST PQC Readiness",
            Self::BsiTr03183_2 => "BSI TR-03183-2",
            Self::Comprehensive => "Comprehensive",
        }
    }

    /// Get compact tab label (max ~8 chars) for terminal display.
    #[must_use]
    pub const fn short_name(&self) -> &'static str {
        match self {
            Self::Minimum => "Min",
            Self::Standard => "Std",
            Self::NtiaMinimum => "NTIA",
            Self::CraPhase1 => "CRA-1",
            Self::CraPhase2 => "CRA-2",
            Self::FdaMedicalDevice => "FDA",
            Self::NistSsdf => "SSDF",
            Self::Eo14028 => "EO14028",
            Self::Cnsa2 => "CNSA2",
            Self::NistPqc => "PQC",
            Self::BsiTr03183_2 => "BSI",
            Self::Comprehensive => "Full",
        }
    }

    /// Get description of what this level checks
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Minimum => "Basic component identification only",
            Self::Standard => "Recommended fields for general use",
            Self::NtiaMinimum => "NTIA minimum elements for software transparency",
            Self::CraPhase1 => {
                "CRA reporting obligations — product ID, SBOM format, manufacturer (deadline: 11 Dec 2027)"
            }
            Self::CraPhase2 => {
                "Full CRA compliance — adds vulnerability metadata, lifecycle, disclosure (deadline: 11 Dec 2029)"
            }
            Self::FdaMedicalDevice => "FDA premarket submission requirements for medical devices",
            Self::NistSsdf => {
                "Secure Software Development Framework — provenance, build integrity, VCS references"
            }
            Self::Eo14028 => {
                "Executive Order 14028 — machine-readable SBOM, auto-generation, supply chain security"
            }
            Self::Cnsa2 => {
                "CNSA 2.0 — AES-256, SHA-384+, ML-KEM-1024, ML-DSA-87, quantum security level 5"
            }
            Self::NistPqc => {
                "NIST PQC — quantum-vulnerable algorithm detection, FIPS 203/204/205, SP 800-131A"
            }
            Self::BsiTr03183_2 => {
                "BSI TR-03183-2 — German national SBOM guideline (free, ENISA-cited): mandatory hashes, identifiers, ISO-8601 timestamps"
            }
            Self::Comprehensive => "All recommended fields and best practices",
        }
    }

    /// Get all compliance levels
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Minimum,
            Self::Standard,
            Self::NtiaMinimum,
            Self::CraPhase1,
            Self::CraPhase2,
            Self::FdaMedicalDevice,
            Self::NistSsdf,
            Self::Eo14028,
            Self::Cnsa2,
            Self::NistPqc,
            Self::BsiTr03183_2,
            Self::Comprehensive,
        ]
    }

    /// Whether this level is a CRA check (either phase)
    #[must_use]
    pub const fn is_cra(&self) -> bool {
        matches!(self, Self::CraPhase1 | Self::CraPhase2)
    }

    /// Get CRA phase, if applicable
    #[must_use]
    pub const fn cra_phase(&self) -> Option<CraPhase> {
        match self {
            Self::CraPhase1 => Some(CraPhase::Phase1),
            Self::CraPhase2 => Some(CraPhase::Phase2),
            _ => None,
        }
    }
}

/// Identifies the source standard a `StandardRef` points at.
///
/// The CRA harmonised-standard ecosystem references multiple parallel
/// hierarchies (the regulation itself, the prEN 40000-1-3 horizontal
/// standard, BSI TR-03183 national guidance) and a violation typically
/// maps to several at once. Notified bodies will read prEN IDs; auditors
/// quote regulation articles; engineers prefer BSI sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StandardKind {
    /// EU CRA regulation article (e.g., "Art. 13(4)")
    CraArticle,
    /// EU CRA regulation annex (e.g., "Annex I Part II 1")
    CraAnnex,
    /// prEN 40000-1-3 normative requirement ID (e.g., "PRE-7-RQ-07")
    Pren40000_1_3,
    /// BSI TR-03183-2 section reference
    BsiTr03183_2,
    /// NIST SP 800-218 SSDF practice
    NistSsdf,
    /// US Executive Order 14028 Section 4
    Eo14028,
    /// FDA premarket cybersecurity guidance
    FdaPremarket,
    /// NTIA Minimum Elements for an SBOM
    NtiaMinimum,
    /// CSAF v2.0 / ISO/IEC 20153:2025 advisory format
    Csaf2,
    /// CNSA 2.0 (NSA Commercial National Security Algorithm Suite)
    Cnsa2,
    /// NIST Post-Quantum Cryptography (FIPS 203/204/205, SP 800-131A)
    NistPqc,
    /// Other / unrecognised standard
    Other,
}

impl StandardKind {
    /// Short label for compact display (≤16 chars).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CraArticle => "CRA Article",
            Self::CraAnnex => "CRA Annex",
            Self::Pren40000_1_3 => "prEN 40000-1-3",
            Self::BsiTr03183_2 => "BSI TR-03183-2",
            Self::NistSsdf => "NIST SSDF",
            Self::Eo14028 => "EO 14028",
            Self::FdaPremarket => "FDA",
            Self::NtiaMinimum => "NTIA",
            Self::Csaf2 => "CSAF v2.0",
            Self::Cnsa2 => "CNSA 2.0",
            Self::NistPqc => "NIST PQC",
            Self::Other => "Other",
        }
    }
}

/// A reference to a specific clause/requirement in a published standard.
///
/// Surfaced in JSON, SARIF, Markdown, and HTML output so that downstream
/// tooling (notified-body checklists, GRC platforms, internal dashboards)
/// can map a violation directly to the standards landscape without parsing
/// the human-readable `requirement` string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StandardRef {
    /// Which standard this reference points at
    pub standard: StandardKind,
    /// The clause/requirement ID within that standard (e.g., "PRE-7-RQ-07")
    pub id: String,
    /// Optional canonical URL anchor for the clause
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
}

impl StandardRef {
    #[must_use]
    pub fn new(standard: StandardKind, id: impl Into<String>) -> Self {
        Self {
            standard,
            id: id.into(),
            help_uri: None,
        }
    }

    #[must_use]
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.help_uri = Some(uri.into());
        self
    }
}

/// A compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Severity: error, warning, info
    pub severity: ViolationSeverity,
    /// Category of the violation
    pub category: ViolationCategory,
    /// Human-readable message
    pub message: String,
    /// Component or element that violated (if applicable)
    pub element: Option<String>,
    /// Standard/requirement being violated
    pub requirement: String,
    /// Structured references to harmonised-standard / regulation clauses.
    ///
    /// Populated by `ComplianceChecker::check()` from `requirement` via
    /// `Violation::derive_standard_refs()`. Empty when a violation cannot be
    /// mapped (e.g., custom rules from external configuration).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standard_refs: Vec<StandardRef>,
}

impl Violation {
    /// Derive structured standard references from the violation's
    /// `requirement` string.
    ///
    /// Maps each violation to the canonical IDs in the parallel CRA standards
    /// hierarchies — CRA regulation articles/annexes, prEN 40000-1-3 normative
    /// requirements, BSI TR-03183, and adjacent profiles (NIST SSDF, EO 14028,
    /// FDA, NTIA). The output is deterministic and regenerated on each call,
    /// so the canonical source of truth remains the `requirement` string.
    ///
    /// References are emitted in registration order — typically the most
    /// specific harmonised-standard ID first, then the regulation reference.
    ///
    /// `ComplianceChecker::check()` invokes this once and stores the result
    /// in `Violation::standard_refs`, so most consumers should read the field
    /// directly rather than re-deriving.
    #[must_use]
    pub fn derive_standard_refs(&self) -> Vec<StandardRef> {
        let req = self.requirement.to_lowercase();
        let mut refs: Vec<StandardRef> = Vec::new();

        // ---- CRA Articles -------------------------------------------------
        let cra_articles: &[(&str, &str)] = &[
            ("art. 13(2)", "Art. 13(2)"),
            ("art. 13(3)", "Art. 13(3)"),
            ("art. 13(4)", "Art. 13(4)"),
            ("art. 13(5)", "Art. 13(5)"),
            ("art. 13(6)", "Art. 13(6)"),
            ("art. 13(7)", "Art. 13(7)"),
            ("art. 13(8)", "Art. 13(8)"),
            ("art. 13(9)", "Art. 13(9)"),
            ("art. 13(11)", "Art. 13(11)"),
            ("art. 13(12)", "Art. 13(12)"),
            ("art. 13(15)", "Art. 13(15)"),
            ("art. 14", "Art. 14"),
        ];
        for (needle, id) in cra_articles {
            if req.contains(needle) {
                refs.push(StandardRef::new(StandardKind::CraArticle, *id));
            }
        }

        // ---- CRA Annexes --------------------------------------------------
        if req.contains("annex i, part iii") || req.contains("annex i part iii") {
            refs.push(StandardRef::new(StandardKind::CraAnnex, "Annex I Part III"));
        }
        if req.contains("annex i, part ii") || req.contains("annex i part ii") {
            refs.push(StandardRef::new(StandardKind::CraAnnex, "Annex I Part II"));
        }
        if req.contains("annex i,") || req.contains("annex i:") || req.contains("annex i ") {
            // Avoid double-pushing when more specific Part II/III already matched
            let already = refs
                .iter()
                .any(|r| r.standard == StandardKind::CraAnnex && r.id.starts_with("Annex I"));
            if !already {
                refs.push(StandardRef::new(StandardKind::CraAnnex, "Annex I"));
            }
        }
        if req.contains("annex iii") {
            refs.push(StandardRef::new(StandardKind::CraAnnex, "Annex III"));
        }
        if req.contains("annex iv") {
            refs.push(StandardRef::new(StandardKind::CraAnnex, "Annex IV"));
        }
        if req.contains("annex v") && !req.contains("annex vii") {
            refs.push(StandardRef::new(StandardKind::CraAnnex, "Annex V"));
        }
        if req.contains("annex vii") {
            refs.push(StandardRef::new(StandardKind::CraAnnex, "Annex VII"));
        }
        if req.contains("annex viii") {
            refs.push(StandardRef::new(StandardKind::CraAnnex, "Annex VIII"));
        }

        // ---- prEN 40000-1-3 normative requirement IDs ---------------------
        // First, harvest any IDs already mentioned literally in `requirement`.
        for token in [
            "PRE-7-RQ-01",
            "PRE-7-RQ-03",
            "PRE-7-RQ-04",
            "PRE-7-RQ-06",
            "PRE-7-RQ-07",
            "PRE-7-RQ-07-RE",
            "PRE-8-RQ-02",
            "RLS-2-RQ-03-RE",
        ] {
            if self.requirement.contains(token) {
                refs.push(StandardRef::new(StandardKind::Pren40000_1_3, token));
            }
        }

        // Inferred mappings — only add if the literal ID was not already present.
        // (Inline `iter().any()` checks rather than a closure to avoid borrow conflicts.)

        // Art. 13(4) machine-readable format → [PRE-7-RQ-04]
        if req.contains("art. 13(4)")
            && req.contains("machine-readable")
            && !refs.iter().any(|r| r.id == "PRE-7-RQ-04")
        {
            refs.push(StandardRef::new(StandardKind::Pren40000_1_3, "PRE-7-RQ-04"));
        }
        // Art. 13(7) coordinated disclosure → [RLS-2-RQ-03-RE]
        if req.contains("art. 13(7)") && !refs.iter().any(|r| r.id == "RLS-2-RQ-03-RE") {
            refs.push(StandardRef::new(
                StandardKind::Pren40000_1_3,
                "RLS-2-RQ-03-RE",
            ));
        }
        // Annex I Part III supply chain → [PRE-7-RQ-01] + [PRE-7-RQ-03]
        if req.contains("annex i, part iii") || req.contains("annex i part iii") {
            if !refs.iter().any(|r| r.id == "PRE-7-RQ-01") {
                refs.push(StandardRef::new(StandardKind::Pren40000_1_3, "PRE-7-RQ-01"));
            }
            if !refs.iter().any(|r| r.id == "PRE-7-RQ-03") {
                refs.push(StandardRef::new(StandardKind::Pren40000_1_3, "PRE-7-RQ-03"));
            }
        }
        // Annex I identifier traceability → [PRE-7-RQ-07]
        if (req.contains("annex i") && req.contains("identifier"))
            && !refs.iter().any(|r| r.id == "PRE-7-RQ-07")
        {
            refs.push(StandardRef::new(StandardKind::Pren40000_1_3, "PRE-7-RQ-07"));
        }
        // Component version (Art. 13(12)) → [PRE-7-RQ-06]
        if req.contains("art. 13(12)")
            && req.contains("version")
            && !refs.iter().any(|r| r.id == "PRE-7-RQ-06")
        {
            refs.push(StandardRef::new(StandardKind::Pren40000_1_3, "PRE-7-RQ-06"));
        }
        // CSAF advisory format (Art. 13(7)/Annex I Part II 5)
        if (req.contains("csaf") || req.contains("iso/iec 20153"))
            && !refs.iter().any(|r| r.standard == StandardKind::Csaf2)
        {
            refs.push(StandardRef::new(StandardKind::Csaf2, "CSAF v2.0"));
        }

        // ---- Adjacent profiles --------------------------------------------
        if req.contains("nist ssdf") || req.contains("sp 800-218") {
            // Try to extract the practice ID (e.g., "PS.1", "PW.4", "RV.1")
            for needle in [
                "ps.1", "ps.2", "ps.3", "po.1", "po.3", "pw.4", "pw.6", "rv.1",
            ] {
                if req.contains(needle) {
                    refs.push(StandardRef::new(
                        StandardKind::NistSsdf,
                        needle.to_uppercase(),
                    ));
                }
            }
            if !refs.iter().any(|r| r.standard == StandardKind::NistSsdf) {
                refs.push(StandardRef::new(StandardKind::NistSsdf, "SP 800-218"));
            }
        }
        if req.contains("eo 14028") || req.contains("executive order 14028") {
            refs.push(StandardRef::new(StandardKind::Eo14028, "EO 14028 §4"));
        }
        if req.contains("fda") {
            refs.push(StandardRef::new(
                StandardKind::FdaPremarket,
                "FDA Premarket",
            ));
        }
        if req.contains("ntia") {
            refs.push(StandardRef::new(
                StandardKind::NtiaMinimum,
                "NTIA Minimum Elements",
            ));
        }
        if req.contains("cnsa") {
            refs.push(StandardRef::new(StandardKind::Cnsa2, "CNSA 2.0"));
        }
        if req.contains("nist pqc")
            || req.contains("fips 203")
            || req.contains("fips 204")
            || req.contains("fips 205")
        {
            refs.push(StandardRef::new(StandardKind::NistPqc, "NIST PQC"));
        }

        refs
    }

    /// Return remediation guidance for this violation based on the requirement.
    #[must_use]
    pub fn remediation_guidance(&self) -> &'static str {
        let req = self.requirement.to_lowercase();
        if req.contains("art. 13(4)") {
            "Ensure the SBOM is produced in CycloneDX 1.4+ (JSON or XML), SPDX 2.3+ (JSON or tag-value), or SPDX 3.0+ (JSON-LD). Older format versions may not be recognized as machine-readable under the CRA."
        } else if req.contains("art. 13(6)") && req.contains("vulnerability metadata") {
            "Add severity (e.g., CVSS score) and remediation details to each vulnerability entry. CycloneDX: use vulnerability.ratings[].score and vulnerability.analysis. SPDX: use annotation or externalRef."
        } else if req.contains("art. 13(6)") {
            "Add a security contact or vulnerability disclosure URL. CycloneDX: add a component externalReference with type 'security-contact' or set metadata.manufacturer.contact. SPDX: add an SECURITY external reference."
        } else if req.contains("art. 13(7)") {
            "Reference a coordinated vulnerability disclosure policy. CycloneDX: add an externalReference of type 'advisories' linking to your disclosure policy. SPDX: add an external document reference."
        } else if req.contains("art. 13(8)") {
            "Specify when security updates will no longer be provided. CycloneDX 1.5+: use component.releaseNotes or metadata properties. SPDX: use an annotation with end-of-support date."
        } else if req.contains("art. 13(11)") {
            "Include lifecycle or end-of-support metadata for components. CycloneDX: use component properties (e.g., cdx:lifecycle:status). SPDX: use annotations."
        } else if req.contains("art. 13(12)") && req.contains("version") {
            "Every component must have a version string. Use the actual release version (e.g., '1.2.3'), not a range or placeholder."
        } else if req.contains("art. 13(12)") {
            "The SBOM must identify the product by name. CycloneDX: set metadata.component.name. SPDX: set documentDescribes with the primary package name."
        } else if req.contains("art. 13(15)") && req.contains("email") {
            "Provide a valid contact email for the manufacturer. The email must contain an @ sign with valid local and domain parts."
        } else if req.contains("art. 13(15)") {
            "Identify the manufacturer/supplier. CycloneDX: set metadata.manufacturer or component.supplier. SPDX: set PackageSupplier."
        } else if req.contains("annex vii") {
            "Reference the EU Declaration of Conformity. CycloneDX: add an externalReference of type 'attestation' or 'certification'. SPDX: add an external document reference."
        } else if req.contains("annex i") && req.contains("identifier") {
            "Add a PURL, CPE, or SWID tag to each component for unique identification. PURLs are preferred (e.g., pkg:npm/lodash@4.17.21)."
        } else if req.contains("annex i") && req.contains("dependency") {
            "Add dependency relationships between components. CycloneDX: use the dependencies array. SPDX: use DEPENDS_ON relationships."
        } else if req.contains("annex i") && req.contains("primary") {
            "Identify the top-level product component. CycloneDX: set metadata.component. SPDX: use documentDescribes to point to the primary package."
        } else if req.contains("annex i") && req.contains("hash") {
            "Add cryptographic hashes (SHA-256 or stronger) to components for integrity verification."
        } else if req.contains("annex i") && req.contains("traceability") {
            "The primary product component needs a stable unique identifier (PURL or CPE) that persists across software updates for traceability."
        } else if req.contains("art. 13(3)") {
            "Regenerate the SBOM when components are added, removed, or updated. CRA Art. 13(3) requires timely updates reflecting the current state of the software."
        } else if req.contains("art. 13(5)") {
            "Ensure every component has license information. CycloneDX: use component.licenses[]. SPDX 2.x: use PackageLicenseDeclared / PackageLicenseConcluded. SPDX 3.0: use HAS_DECLARED_LICENSE / HAS_CONCLUDED_LICENSE relationships."
        } else if req.contains("art. 13(9)") {
            "Include vulnerability data or add a vulnerability-assertion external reference stating no known vulnerabilities. CycloneDX: use the vulnerabilities array. SPDX: use annotations or external references."
        } else if req.contains("annex i") && req.contains("supply chain") {
            "Populate the supplier field for all components, especially transitive dependencies. CycloneDX: use component.supplier. SPDX: use PackageSupplier."
        } else if req.contains("annex iii") {
            "Add document-level integrity metadata: a serial number (CycloneDX: serialNumber, SPDX: documentNamespace), or a digital signature/attestation with a cryptographic hash."
        } else if req.contains("nist ssdf") || req.contains("sp 800-218") {
            "Follow NIST SP 800-218 SSDF practices: include tool provenance, source VCS references, build metadata, and cryptographic hashes for all components."
        } else if req.contains("eo 14028") {
            "Follow EO 14028 Section 4(e) requirements: use a machine-readable format (CycloneDX 1.4+, SPDX 2.3+, or SPDX 3.0+), auto-generate the SBOM, include unique identifiers, versions, hashes, dependencies, and supplier information."
        } else {
            "Review the requirement and update the SBOM accordingly. Consult the EU CRA regulation (EU 2024/2847) for detailed guidance."
        }
    }
}

/// Severity of a compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Must be fixed for compliance
    Error,
    /// Should be fixed, but not strictly required
    Warning,
    /// Informational recommendation
    Info,
}

/// Category of compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ViolationCategory {
    /// Document metadata issue
    DocumentMetadata,
    /// Component identification issue
    ComponentIdentification,
    /// Dependency information issue
    DependencyInfo,
    /// License information issue
    LicenseInfo,
    /// Supplier information issue
    SupplierInfo,
    /// Hash/integrity issue
    IntegrityInfo,
    /// Security/vulnerability disclosure info
    SecurityInfo,
    /// Format-specific requirement
    FormatSpecific,
    /// Cryptographic algorithm/key/protocol issue
    CryptographyInfo,
}

impl ViolationCategory {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::DocumentMetadata => "Document Metadata",
            Self::ComponentIdentification => "Component Identification",
            Self::DependencyInfo => "Dependency Information",
            Self::LicenseInfo => "License Information",
            Self::SupplierInfo => "Supplier Information",
            Self::IntegrityInfo => "Integrity Information",
            Self::SecurityInfo => "Security Information",
            Self::FormatSpecific => "Format-Specific",
            Self::CryptographyInfo => "Cryptography",
        }
    }

    /// Short name suitable for compact table display (max 10 chars).
    #[must_use]
    pub const fn short_name(&self) -> &'static str {
        match self {
            Self::DocumentMetadata => "Doc Meta",
            Self::ComponentIdentification => "Comp IDs",
            Self::DependencyInfo => "Deps",
            Self::LicenseInfo => "License",
            Self::SupplierInfo => "Supplier",
            Self::IntegrityInfo => "Integrity",
            Self::SecurityInfo => "Security",
            Self::FormatSpecific => "Format",
            Self::CryptographyInfo => "Crypto",
        }
    }

    /// All category variants in display order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::SupplierInfo,
            Self::ComponentIdentification,
            Self::DocumentMetadata,
            Self::IntegrityInfo,
            Self::LicenseInfo,
            Self::DependencyInfo,
            Self::SecurityInfo,
            Self::FormatSpecific,
            Self::CryptographyInfo,
        ]
    }
}

/// Result of compliance checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    /// Overall compliance status
    pub is_compliant: bool,
    /// Compliance level checked against
    pub level: ComplianceLevel,
    /// All violations found
    pub violations: Vec<Violation>,
    /// Error count
    pub error_count: usize,
    /// Warning count
    pub warning_count: usize,
    /// Info count
    pub info_count: usize,
}

impl ComplianceResult {
    /// Create a new compliance result
    #[must_use]
    pub fn new(level: ComplianceLevel, violations: Vec<Violation>) -> Self {
        let error_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .count();
        let warning_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Warning)
            .count();
        let info_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Info)
            .count();

        Self {
            is_compliant: error_count == 0,
            level,
            violations,
            error_count,
            warning_count,
            info_count,
        }
    }

    /// Get violations filtered by severity
    #[must_use]
    pub fn violations_by_severity(&self, severity: ViolationSeverity) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.severity == severity)
            .collect()
    }

    /// Get violations filtered by category
    #[must_use]
    pub fn violations_by_category(&self, category: ViolationCategory) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.category == category)
            .collect()
    }
}

/// Calibration check identifiers for `ComplianceChecker::class_severity()`.
///
/// Each variant corresponds to a row in the CRA-P3.2 calibration table —
/// the severity that a given finding should produce *given* the product
/// class (Default → Critical) and conformity-assessment route. `None`
/// from `class_severity()` means "this check is not applicable for the
/// given class" (typically Default doesn't carry EUCC/attestation
/// expectations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClassCheck {
    /// Vendor-supplied hash coverage below threshold ([PRE-7-RQ-07-RE]).
    VendorHashCoverage,
    /// EOL component present in SBOM.
    EolComponents,
    /// Dependency cycles detected.
    Cycles,
    /// Annex VII Declaration-of-Conformity reference missing.
    DocReference,
    /// EUCC (Common Criteria) reference missing.
    EuccReference,
    /// PSIRT URL / 24h / 72h / ENISA channel missing (Art. 14).
    Psirt,
    /// Conformity-assessment-module attestation reference missing
    /// (only meaningful on Module B+C / H / EUCC routes).
    ModuleAttestation,
}

/// Compliance checker for SBOMs
#[derive(Debug, Clone)]
pub struct ComplianceChecker {
    /// Compliance level to check
    level: ComplianceLevel,
    /// Optional CRA sidecar metadata that supplements the SBOM with
    /// manufacturer / disclosure / lifecycle fields the SBOM itself doesn't
    /// carry. When set, document-metadata checks consult the sidecar before
    /// emitting "missing" violations.
    sidecar: Option<crate::model::CraSidecarMetadata>,
    /// Optional CRA Annex III/IV product class. Drives severity calibration
    /// for `class_severity()` (vendor-hash, EOL, cycles, DoC, EUCC, PSIRT,
    /// attestation). When `None`, behaves as `CraProductClass::Default`.
    product_class: Option<crate::model::CraProductClass>,
}

impl ComplianceChecker {
    /// Create a new compliance checker
    #[must_use]
    pub const fn new(level: ComplianceLevel) -> Self {
        Self {
            level,
            sidecar: None,
            product_class: None,
        }
    }

    /// Attach CRA sidecar metadata to supplement SBOM-level fields.
    ///
    /// Sidecar values are only consulted as fallbacks — fields present in the
    /// SBOM always take precedence. Used by `validate`, `quality`, and `view`
    /// CLIs via the `--cra-sidecar` flag (with auto-discovery for adjacent
    /// `<sbom>.cra.{json,yaml}` files).
    #[must_use]
    pub fn with_sidecar(mut self, sidecar: crate::model::CraSidecarMetadata) -> Self {
        self.sidecar = Some(sidecar);
        self
    }

    /// Set the CRA Annex III/IV product class explicitly.
    ///
    /// Sidecar `productClass` (when set on the attached sidecar) wins over
    /// this; resolve via [`Self::effective_product_class`].
    #[must_use]
    pub const fn with_product_class(mut self, class: crate::model::CraProductClass) -> Self {
        self.product_class = Some(class);
        self
    }

    /// Resolve the effective product class:
    /// 1. sidecar `productClass` if present,
    /// 2. otherwise `with_product_class` value,
    /// 3. otherwise `CraProductClass::Default`.
    #[must_use]
    pub fn effective_product_class(&self) -> crate::model::CraProductClass {
        self.sidecar
            .as_ref()
            .and_then(|s| s.product_class)
            .or(self.product_class)
            .unwrap_or(crate::model::CraProductClass::Default)
    }

    /// Resolve the effective conformity-assessment route. Falls back to
    /// `CraProductClass::default_route()` when the sidecar doesn't pin one.
    #[must_use]
    pub fn effective_route(&self) -> crate::model::ConformityRoute {
        self.sidecar
            .as_ref()
            .and_then(|s| s.conformity_assessment_route)
            .unwrap_or_else(|| self.effective_product_class().default_route())
    }

    /// CRA-P3.2 calibration table — severity for a given check at the
    /// effective product class. Returns `None` when the check does not
    /// apply for that class (e.g., EUCC reference at `Default`).
    #[must_use]
    pub fn class_severity(&self, check: ClassCheck) -> Option<ViolationSeverity> {
        use crate::model::CraProductClass as C;
        let class = self.effective_product_class();
        match (check, class) {
            // Vendor-hash coverage threshold escalation handled by
            // `vendor_hash_thresholds()`; this row reflects the *severity*
            // emitted when the threshold is breached.
            (ClassCheck::VendorHashCoverage, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::VendorHashCoverage, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::EolComponents, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::EolComponents, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::Cycles, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::Cycles, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::DocReference, C::Default) => Some(ViolationSeverity::Info),
            (ClassCheck::DocReference, C::ImportantClass1) => Some(ViolationSeverity::Warning),
            (ClassCheck::DocReference, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::EuccReference, C::Default | C::ImportantClass1) => None,
            (ClassCheck::EuccReference, C::ImportantClass2) => Some(ViolationSeverity::Info),
            (ClassCheck::EuccReference, C::Critical) => Some(ViolationSeverity::Error),

            (ClassCheck::Psirt, C::Default | C::ImportantClass1) => Some(ViolationSeverity::Warning),
            (ClassCheck::Psirt, C::ImportantClass2 | C::Critical) => Some(ViolationSeverity::Error),

            (ClassCheck::ModuleAttestation, C::Default) => None,
            (ClassCheck::ModuleAttestation, C::ImportantClass1) => Some(ViolationSeverity::Warning),
            (ClassCheck::ModuleAttestation, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }
        }
    }

    /// Vendor-hash coverage threshold (single-stage) below which a violation
    /// fires. The severity is `class_severity(VendorHashCoverage)`. Values:
    /// Default 50%, Important-1 80%, Important-2 80%, Critical 100%.
    #[must_use]
    pub fn vendor_hash_threshold(&self) -> f64 {
        use crate::model::CraProductClass as C;
        match self.effective_product_class() {
            C::Default => 0.50,
            C::ImportantClass1 | C::ImportantClass2 => 0.80,
            C::Critical => 1.00,
        }
    }

    /// Whether a CRA product class has been explicitly configured (either
    /// via `with_product_class()` or the attached sidecar). Used by the
    /// per-check calibration to decide whether to override phase-based
    /// defaults — when no class is set, existing phase-driven behavior is
    /// preserved verbatim for backwards compatibility.
    #[must_use]
    pub fn has_explicit_product_class(&self) -> bool {
        self.product_class.is_some()
            || self
                .sidecar
                .as_ref()
                .and_then(|s| s.product_class)
                .is_some()
    }

    /// Check an SBOM for compliance
    #[must_use]
    pub fn check(&self, sbom: &NormalizedSbom) -> ComplianceResult {
        let mut violations = Vec::new();

        match self.level {
            ComplianceLevel::NistSsdf => {
                self.check_nist_ssdf(sbom, &mut violations);
            }
            ComplianceLevel::Eo14028 => {
                self.check_eo14028(sbom, &mut violations);
            }
            ComplianceLevel::Cnsa2 => {
                self.check_cnsa2(sbom, &mut violations);
            }
            ComplianceLevel::NistPqc => {
                self.check_nist_pqc(sbom, &mut violations);
            }
            ComplianceLevel::BsiTr03183_2 => {
                self.check_bsi_tr_03183_2(sbom, &mut violations);
            }
            _ => {
                // Check document-level requirements
                self.check_document_metadata(sbom, &mut violations);

                // Check component requirements
                self.check_components(sbom, &mut violations);

                // Check dependency requirements
                self.check_dependencies(sbom, &mut violations);

                // Check vulnerability metadata (CRA readiness)
                self.check_vulnerability_metadata(sbom, &mut violations);

                // Check format-specific requirements
                self.check_format_specific(sbom, &mut violations);

                // Check CRA-specific gap requirements (Art. 13(3), 13(5), 13(9), Annex I Part III, Annex III)
                if self.level.is_cra() {
                    self.check_cra_gaps(sbom, &mut violations);
                    self.check_hardware_components(sbom, &mut violations);
                }
            }
        }

        // Populate harmonised-standard references for every violation.
        for v in &mut violations {
            if v.standard_refs.is_empty() {
                v.standard_refs = v.derive_standard_refs();
            }
        }

        ComplianceResult::new(self.level, violations)
    }

    fn check_document_metadata(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{CreatorType, ExternalRefType};

        // All levels require creator information
        if sbom.document.creators.is_empty() {
            violations.push(Violation {
                severity: match self.level {
                    ComplianceLevel::Minimum => ViolationSeverity::Warning,
                    _ => ViolationSeverity::Error,
                },
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM must have creator/tool information".to_string(),
                element: None,
                requirement: "Document creator identification".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // CRA: Manufacturer identification and product name
        if self.level.is_cra() {
            let has_org = sbom
                .document
                .creators
                .iter()
                .any(|c| c.creator_type == CreatorType::Organization);
            let sidecar_has_manufacturer = self
                .sidecar
                .as_ref()
                .is_some_and(|s| s.manufacturer_name.is_some());
            if !has_org {
                if sidecar_has_manufacturer {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::DocumentMetadata,
                        message:
                            "[CRA Art. 13(15)] Manufacturer identified via CRA sidecar (consider adding to the SBOM directly for portability)"
                                .to_string(),
                        element: None,
                        requirement: "CRA Art. 13(15): Manufacturer identification".to_string(),
                        standard_refs: Vec::new(),
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DocumentMetadata,
                        message:
                            "[CRA Art. 13(15)] SBOM should identify the manufacturer (organization)"
                                .to_string(),
                        element: None,
                        requirement: "CRA Art. 13(15): Manufacturer identification".to_string(),
                        standard_refs: Vec::new(),
                    });
                }
            }

            // Validate manufacturer email format if present
            for creator in &sbom.document.creators {
                if creator.creator_type == CreatorType::Organization
                    && let Some(email) = &creator.email
                    && !is_valid_email_format(email)
                {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DocumentMetadata,
                        message: format!(
                            "[CRA Art. 13(15)] Manufacturer email '{email}' appears invalid"
                        ),
                        element: None,
                        requirement: "CRA Art. 13(15): Valid contact information".to_string(),
                        standard_refs: Vec::new(),
                    });
                }
            }

            if sbom.document.name.is_none() {
                let sidecar_has_product_name = self
                    .sidecar
                    .as_ref()
                    .is_some_and(|s| s.product_name.is_some());
                if sidecar_has_product_name {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::DocumentMetadata,
                        message: "[CRA Art. 13(12)] Product name provided via CRA sidecar (consider adding metadata.component.name to the SBOM)".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(12): Product identification".to_string(),
                        standard_refs: Vec::new(),
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DocumentMetadata,
                        message: "[CRA Art. 13(12)] SBOM should include the product name"
                            .to_string(),
                        element: None,
                        requirement: "CRA Art. 13(12): Product identification".to_string(),
                        standard_refs: Vec::new(),
                    });
                }
            }

            // CRA: Security contact / vulnerability disclosure point
            // First check document-level security contact (preferred)
            let has_doc_security_contact = sbom.document.security_contact.is_some()
                || sbom.document.vulnerability_disclosure_url.is_some();

            // Fallback: check component-level external refs
            let has_component_security_contact = sbom.components.values().any(|comp| {
                comp.external_refs.iter().any(|r| {
                    matches!(
                        r.ref_type,
                        ExternalRefType::SecurityContact
                            | ExternalRefType::Support
                            | ExternalRefType::Advisories
                    )
                })
            });

            if !has_doc_security_contact && !has_component_security_contact {
                let sidecar_has_security = self.sidecar.as_ref().is_some_and(|s| {
                    s.security_contact.is_some() || s.vulnerability_disclosure_url.is_some()
                });
                if sidecar_has_security {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Art. 13(6)] Security contact provided via CRA sidecar (consider adding a security-contact externalReference to the SBOM)".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(6): Vulnerability disclosure contact".to_string(),
                        standard_refs: Vec::new(),
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Art. 13(6)] SBOM should include a security contact or vulnerability disclosure reference".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(6): Vulnerability disclosure contact".to_string(),
                        standard_refs: Vec::new(),
                    });
                }
            }

            // CRA: Check for primary/root product component identification
            if sbom.primary_component_id.is_none() && sbom.components.len() > 1 {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "[CRA Annex I] SBOM should identify the primary product component (CycloneDX metadata.component or SPDX documentDescribes)".to_string(),
                    element: None,
                    requirement: "CRA Annex I: Primary product identification".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // CRA: Check for support end date (informational)
            if sbom.document.support_end_date.is_none() {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::SecurityInfo,
                    message: "[CRA Art. 13(8)] Consider specifying a support end date for security updates".to_string(),
                    element: None,
                    requirement: "CRA Art. 13(8): Support period disclosure".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // CRA Art. 13(4): Machine-readable SBOM format validation
            // The CRA requires SBOMs in a "commonly used and machine-readable" format.
            // CycloneDX 1.4+ and SPDX 2.3+ are widely accepted as machine-readable.
            let format_ok = match sbom.document.format {
                SbomFormat::CycloneDx => {
                    let v = &sbom.document.spec_version;
                    !(v.starts_with("1.0")
                        || v.starts_with("1.1")
                        || v.starts_with("1.2")
                        || v.starts_with("1.3"))
                }
                SbomFormat::Spdx => {
                    let v = &sbom.document.spec_version;
                    v.starts_with("2.3") || v.starts_with("3.")
                }
            };
            if !format_ok {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::FormatSpecific,
                    message: format!(
                        "[CRA Art. 13(4)] SBOM format version {} {} may not meet CRA machine-readable requirements; use CycloneDX 1.4+, SPDX 2.3+, or SPDX 3.0+",
                        sbom.document.format, sbom.document.spec_version
                    ),
                    element: None,
                    requirement: "CRA Art. 13(4): Machine-readable SBOM format".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // CRA Annex I, Part II, 1: Unique product identifier traceability
            // The primary/root component should have a stable unique identifier (PURL or CPE)
            // that can be traced across software updates.
            if let Some(ref primary_id) = sbom.primary_component_id
                && let Some(primary) = sbom.components.get(primary_id)
                && primary.identifiers.purl.is_none()
                && primary.identifiers.cpe.is_empty()
            {
                violations.push(Violation {
                            severity: ViolationSeverity::Warning,
                            category: ViolationCategory::ComponentIdentification,
                            message: format!(
                                "[CRA Annex I, Part II] Primary component '{}' missing unique identifier (PURL/CPE) for cross-update traceability",
                                primary.name
                            ),
                            element: Some(primary.name.clone()),
                            requirement: "CRA Annex I, Part II, 1: Product identifier traceability across updates".to_string(),
                            standard_refs: Vec::new(),
                        });
            }
        }

        // CRA Phase 2-only checks (deadline: 11 Dec 2029)
        if matches!(self.level, ComplianceLevel::CraPhase2) {
            // CRA Art. 13(7): Coordinated vulnerability disclosure policy reference
            // Check for a vulnerability disclosure policy URL or advisories reference
            let has_vuln_disclosure_policy = sbom.document.vulnerability_disclosure_url.is_some()
                || sbom.components.values().any(|comp| {
                    comp.external_refs
                        .iter()
                        .any(|r| matches!(r.ref_type, ExternalRefType::Advisories))
                });
            if !has_vuln_disclosure_policy {
                let sidecar_has_cvd = self
                    .sidecar
                    .as_ref()
                    .is_some_and(|s| s.vulnerability_disclosure_url.is_some());
                if sidecar_has_cvd {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Art. 13(7)] CVD policy URL provided via CRA sidecar (consider adding an advisories externalReference to the SBOM)".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(7): Coordinated vulnerability disclosure policy".to_string(),
                        standard_refs: Vec::new(),
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Art. 13(7)] SBOM should reference a coordinated vulnerability disclosure policy (advisories URL or disclosure URL)".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(7): Coordinated vulnerability disclosure policy".to_string(),
                        standard_refs: Vec::new(),
                    });
                }
            }

            // CRA Art. 13(11): Component lifecycle status
            // Check whether the primary component (or any top-level component) has end-of-life
            // or lifecycle information. Currently we check support_end_date at doc level.
            // Also check for lifecycle properties on components.
            let has_lifecycle_info = sbom.document.support_end_date.is_some()
                || sbom.components.values().any(|comp| {
                    comp.extensions.properties.iter().any(|p| {
                        let name_lower = p.name.to_lowercase();
                        name_lower.contains("lifecycle")
                            || name_lower.contains("end-of-life")
                            || name_lower.contains("eol")
                            || name_lower.contains("end-of-support")
                    })
                });
            if !has_lifecycle_info {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::SecurityInfo,
                    message: "[CRA Art. 13(11)] Consider including component lifecycle/end-of-support information".to_string(),
                    element: None,
                    requirement: "CRA Art. 13(11): Component lifecycle status".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // CRA Annex VII: EU Declaration of Conformity reference
            // Check for an attestation, certification, or declaration-of-conformity reference
            let has_conformity_ref = sbom.components.values().any(|comp| {
                comp.external_refs.iter().any(|r| {
                    matches!(
                        r.ref_type,
                        ExternalRefType::Attestation | ExternalRefType::Certification
                    ) || (matches!(r.ref_type, ExternalRefType::Other(ref s) if s.to_lowercase().contains("declaration-of-conformity"))
                    )
                })
            });
            let sidecar_has_doc_ref = self
                .sidecar
                .as_ref()
                .is_some_and(|s| s.ce_marking_reference.is_some());
            if !has_conformity_ref && !sidecar_has_doc_ref {
                let severity = self
                    .class_severity(ClassCheck::DocReference)
                    .unwrap_or(ViolationSeverity::Info);
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::DocumentMetadata,
                    message: format!(
                        "[CRA Annex VII] Missing reference to the EU Declaration of Conformity (attestation or certification external reference) for product class {}",
                        self.effective_product_class().label()
                    ),
                    element: None,
                    requirement: "CRA Annex VII: EU Declaration of Conformity reference".to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }

        // FDA requires manufacturer (organization) as creator
        if matches!(self.level, ComplianceLevel::FdaMedicalDevice) {
            let has_org = sbom
                .document
                .creators
                .iter()
                .any(|c| c.creator_type == CreatorType::Organization);
            if !has_org {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "FDA: SBOM should have manufacturer (organization) as creator"
                        .to_string(),
                    element: None,
                    requirement: "FDA: Manufacturer identification".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // FDA recommends contact information
            let has_contact = sbom.document.creators.iter().any(|c| c.email.is_some());
            if !has_contact {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "FDA: SBOM creators should include contact email".to_string(),
                    element: None,
                    requirement: "FDA: Contact information".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // FDA: Document name required
            if sbom.document.name.is_none() {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "FDA: SBOM should have a document name/title".to_string(),
                    element: None,
                    requirement: "FDA: Document identification".to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }

        // NTIA requires timestamp
        if matches!(
            self.level,
            ComplianceLevel::NtiaMinimum | ComplianceLevel::Comprehensive
        ) {
            // Timestamp is always set in our model, but check if it's meaningful
            // For now, we'll skip this check as we always set a timestamp
        }

        // Standard+ requires serial number/document ID
        if matches!(
            self.level,
            ComplianceLevel::Standard
                | ComplianceLevel::FdaMedicalDevice
                | ComplianceLevel::CraPhase1
                | ComplianceLevel::CraPhase2
                | ComplianceLevel::Comprehensive
        ) && sbom.document.serial_number.is_none()
        {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM should have a serial number/unique identifier".to_string(),
                element: None,
                requirement: "Document unique identification".to_string(),
                standard_refs: Vec::new(),
            });
        }
    }

    fn check_components(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::HashAlgorithm;

        for comp in sbom.components.values() {
            // All levels: component must have a name
            // (Always true in our model, but check anyway)
            if comp.name.is_empty() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: "Component must have a name".to_string(),
                    element: Some(comp.identifiers.format_id.clone()),
                    requirement: "Component name (required)".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // NTIA minimum & FDA: version required
            if matches!(
                self.level,
                ComplianceLevel::NtiaMinimum
                    | ComplianceLevel::FdaMedicalDevice
                    | ComplianceLevel::Standard
                    | ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::Comprehensive
            ) && comp.version.is_none()
            {
                let (req, msg) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        "FDA: Component version".to_string(),
                        format!("Component '{}' missing version", comp.name),
                    ),
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        "CRA Art. 13(12): Component version".to_string(),
                        format!(
                            "[CRA Art. 13(12)] Component '{}' missing version",
                            comp.name
                        ),
                    ),
                    _ => (
                        "NTIA: Component version".to_string(),
                        format!("Component '{}' missing version", comp.name),
                    ),
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: msg,
                    element: Some(comp.name.clone()),
                    requirement: req,
                    standard_refs: Vec::new(),
                });
            }

            // Standard+ & FDA: should have PURL/CPE/SWHID/SWID
            // CRA prEN 40000-1-3 [PRE-7-RQ-07] explicitly names PURL, CPE, SWHID
            if matches!(
                self.level,
                ComplianceLevel::Standard
                    | ComplianceLevel::FdaMedicalDevice
                    | ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::Comprehensive
            ) && !comp.identifiers.has_cra_identifier()
            {
                let severity = if matches!(
                    self.level,
                    ComplianceLevel::FdaMedicalDevice
                        | ComplianceLevel::CraPhase1
                        | ComplianceLevel::CraPhase2
                ) {
                    ViolationSeverity::Error
                } else {
                    ViolationSeverity::Warning
                };
                let (message, requirement) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        format!(
                            "Component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                            comp.name
                        ),
                        "FDA: Unique component identifier".to_string(),
                    ),
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        format!(
                            "[CRA Annex I, [PRE-7-RQ-07]] Component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                            comp.name
                        ),
                        "CRA Annex I / prEN 40000-1-3 [PRE-7-RQ-07]: Unique component identifier (PURL/CPE/SWHID/SWID)".to_string(),
                    ),
                    _ => (
                        format!(
                            "Component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                            comp.name
                        ),
                        "Standard identifier (PURL/CPE/SWHID)".to_string(),
                    ),
                };
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::ComponentIdentification,
                    message,
                    element: Some(comp.name.clone()),
                    requirement,
                    standard_refs: Vec::new(),
                });
            }

            // NTIA minimum & FDA: supplier required
            if matches!(
                self.level,
                ComplianceLevel::NtiaMinimum
                    | ComplianceLevel::FdaMedicalDevice
                    | ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::Comprehensive
            ) && comp.supplier.is_none()
                && comp.author.is_none()
            {
                let severity = match self.level {
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => {
                        ViolationSeverity::Warning
                    }
                    _ => ViolationSeverity::Error,
                };
                let (message, requirement) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        format!("Component '{}' missing supplier/manufacturer", comp.name),
                        "FDA: Supplier/manufacturer information".to_string(),
                    ),
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        format!(
                            "[CRA Art. 13(15)] Component '{}' missing supplier/manufacturer",
                            comp.name
                        ),
                        "CRA Art. 13(15): Supplier/manufacturer information".to_string(),
                    ),
                    _ => (
                        format!("Component '{}' missing supplier/manufacturer", comp.name),
                        "NTIA: Supplier information".to_string(),
                    ),
                };
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::SupplierInfo,
                    message,
                    element: Some(comp.name.clone()),
                    requirement,
                    standard_refs: Vec::new(),
                });
            }

            // Standard+: should have license information
            if matches!(
                self.level,
                ComplianceLevel::Standard | ComplianceLevel::Comprehensive
            ) && comp.licenses.declared.is_empty()
                && comp.licenses.concluded.is_none()
            {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::LicenseInfo,
                    message: format!("Component '{}' should have license information", comp.name),
                    element: Some(comp.name.clone()),
                    requirement: "License declaration".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // FDA & Comprehensive: must have cryptographic hashes
            if matches!(
                self.level,
                ComplianceLevel::FdaMedicalDevice | ComplianceLevel::Comprehensive
            ) {
                if comp.hashes.is_empty() {
                    violations.push(Violation {
                        severity: if self.level == ComplianceLevel::FdaMedicalDevice {
                            ViolationSeverity::Error
                        } else {
                            ViolationSeverity::Warning
                        },
                        category: ViolationCategory::IntegrityInfo,
                        message: format!("Component '{}' missing cryptographic hash", comp.name),
                        element: Some(comp.name.clone()),
                        requirement: if self.level == ComplianceLevel::FdaMedicalDevice {
                            "FDA: Cryptographic hash for integrity".to_string()
                        } else {
                            "Integrity verification (hashes)".to_string()
                        },
                        standard_refs: Vec::new(),
                    });
                } else if self.level == ComplianceLevel::FdaMedicalDevice {
                    // FDA: Check for strong hash algorithm (SHA-256 or better)
                    let has_strong_hash = comp.hashes.iter().any(|h| {
                        matches!(
                            h.algorithm,
                            HashAlgorithm::Sha256
                                | HashAlgorithm::Sha384
                                | HashAlgorithm::Sha512
                                | HashAlgorithm::Sha3_256
                                | HashAlgorithm::Sha3_384
                                | HashAlgorithm::Sha3_512
                                | HashAlgorithm::Blake2b256
                                | HashAlgorithm::Blake2b384
                                | HashAlgorithm::Blake2b512
                                | HashAlgorithm::Blake3
                                | HashAlgorithm::Streebog256
                                | HashAlgorithm::Streebog512
                        )
                    });
                    if !has_strong_hash {
                        violations.push(Violation {
                            severity: ViolationSeverity::Warning,
                            category: ViolationCategory::IntegrityInfo,
                            message: format!(
                                "Component '{}' has only weak hash algorithm (use SHA-256+)",
                                comp.name
                            ),
                            element: Some(comp.name.clone()),
                            requirement: "FDA: Strong cryptographic hash (SHA-256 or better)"
                                .to_string(),
                            standard_refs: Vec::new(),
                        });
                    }
                }
            }

            // CRA: hashes are recommended for integrity verification
            if self.level.is_cra() && comp.hashes.is_empty() {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::IntegrityInfo,
                    message: format!(
                        "[CRA Annex I] Component '{}' missing cryptographic hash (recommended for integrity)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA Annex I: Component integrity information (hash)".to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }
    }

    fn check_dependencies(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // NTIA & FDA require dependency relationships
        if matches!(
            self.level,
            ComplianceLevel::NtiaMinimum
                | ComplianceLevel::FdaMedicalDevice
                | ComplianceLevel::CraPhase1
                | ComplianceLevel::CraPhase2
                | ComplianceLevel::Comprehensive
        ) {
            let has_deps = !sbom.edges.is_empty();
            let has_multiple_components = sbom.components.len() > 1;

            if has_multiple_components && !has_deps {
                let (message, requirement) = match self.level {
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        "[CRA Annex I] SBOM with multiple components must include dependency relationships".to_string(),
                        "CRA Annex I: Dependency relationships".to_string(),
                    ),
                    _ => (
                        "SBOM with multiple components must include dependency relationships".to_string(),
                        "NTIA: Dependency relationships".to_string(),
                    ),
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::DependencyInfo,
                    message,
                    element: None,
                    requirement,
                    standard_refs: Vec::new(),
                });
            }
        }

        // CRA: warn if multiple root components (no incoming edges) and no primary component set
        if self.level.is_cra() && sbom.components.len() > 1 && sbom.primary_component_id.is_none() {
            use std::collections::HashSet;
            let mut incoming: HashSet<&crate::model::CanonicalId> = HashSet::new();
            for edge in &sbom.edges {
                incoming.insert(&edge.to);
            }
            let root_count = sbom.components.len().saturating_sub(incoming.len());
            if root_count > 1 {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DependencyInfo,
                    message: "[CRA Annex I] SBOM appears to have multiple root components; identify a primary product component for top-level dependencies".to_string(),
                    element: None,
                    requirement: "CRA Annex I: Top-level dependency clarity".to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }
    }

    fn check_vulnerability_metadata(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        if !matches!(self.level, ComplianceLevel::CraPhase2) {
            return;
        }

        for (comp, vuln) in sbom.all_vulnerabilities() {
            if vuln.severity.is_none() && vuln.cvss.is_empty() {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::SecurityInfo,
                    message: format!(
                        "[CRA Art. 13(6)] Vulnerability '{}' in '{}' lacks severity or CVSS score",
                        vuln.id, comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA Art. 13(6): Vulnerability metadata completeness".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            if let Some(remediation) = &vuln.remediation
                && remediation.fixed_version.is_none()
                && remediation.description.is_none()
            {
                violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::SecurityInfo,
                        message: format!(
                            "[CRA Art. 13(6)] Vulnerability '{}' in '{}' has remediation without details",
                            vuln.id, comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "CRA Art. 13(6): Remediation detail".to_string(),
                        standard_refs: Vec::new(),
                    });
            }
        }
    }

    /// CRA gap checks: Art. 13(3), 13(5), 13(9), Annex I Part III, Annex III
    fn check_cra_gaps(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // B1: Art. 13(3) — Update frequency / SBOM freshness
        let age_days = (chrono::Utc::now() - sbom.document.created).num_days();
        if age_days > 90 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[CRA Art. 13(3)] SBOM is {age_days} days old; CRA requires timely updates when components change"
                ),
                element: None,
                requirement: "CRA Art. 13(3): SBOM update frequency".to_string(),
                standard_refs: Vec::new(),
            });
        } else if age_days > 30 {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[CRA Art. 13(3)] SBOM is {age_days} days old; consider regenerating after component changes"
                ),
                element: None,
                requirement: "CRA Art. 13(3): SBOM update frequency".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // B2: Art. 13(5) — Licensed component tracking (all components should have license info)
        let total = sbom.components.len();
        let without_license = sbom
            .components
            .values()
            .filter(|c| c.licenses.declared.is_empty() && c.licenses.concluded.is_none())
            .count();
        if without_license > 0 {
            let pct = (without_license * 100) / total.max(1);
            let severity = if pct > 50 {
                ViolationSeverity::Warning
            } else {
                ViolationSeverity::Info
            };
            violations.push(Violation {
                severity,
                category: ViolationCategory::LicenseInfo,
                message: format!(
                    "[CRA Art. 13(5)] {without_license}/{total} components ({pct}%) missing license information"
                ),
                element: None,
                requirement: "CRA Art. 13(5): Licensed component tracking".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // B3: Art. 13(9) — Known vulnerabilities statement
        // SBOM should either contain vulnerability data or explicitly indicate "none known"
        let has_vuln_data = sbom
            .components
            .values()
            .any(|c| !c.vulnerabilities.is_empty());
        let has_vuln_assertion = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                matches!(
                    r.ref_type,
                    crate::model::ExternalRefType::VulnerabilityAssertion
                        | crate::model::ExternalRefType::ExploitabilityStatement
                )
            })
        });
        if !has_vuln_data && !has_vuln_assertion {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::SecurityInfo,
                message:
                    "[CRA Art. 13(9)] No vulnerability data or vulnerability assertion found; \
                    include vulnerability information or a statement of no known vulnerabilities"
                        .to_string(),
                element: None,
                requirement: "CRA Art. 13(9): Known vulnerabilities statement".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // B4: Annex I Part III — Supply-chain transparency.
        //
        // prEN 40000-1-3 [PRE-7-RQ-03] makes direct dependencies *mandatory*
        // and transitive dependencies *recommended*. We split the cohort
        // accordingly:
        // - direct (1 hop from the primary component) missing supplier:
        //   Error under CraPhase2, Warning otherwise.
        // - transitive missing supplier: Warning under CraPhase2 if >30%,
        //   Info otherwise.
        if !sbom.edges.is_empty() {
            let direct_ids = sbom.direct_dependency_ids();
            let mut direct_missing: Vec<String> = Vec::new();
            let mut transitive_missing: Vec<String> = Vec::new();
            for comp in sbom.components.values() {
                if comp.supplier.is_some() || comp.author.is_some() {
                    continue;
                }
                if direct_ids.contains(&comp.canonical_id) {
                    direct_missing.push(comp.name.clone());
                } else {
                    transitive_missing.push(comp.name.clone());
                }
            }

            if !direct_missing.is_empty() {
                let severity = if matches!(self.level, ComplianceLevel::CraPhase2) {
                    ViolationSeverity::Error
                } else {
                    ViolationSeverity::Warning
                };
                let n = direct_missing.len();
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::SupplierInfo,
                    message: format!(
                        "[CRA Annex I, Part III / [PRE-7-RQ-03]] {n} direct dependencies missing supplier (mandatory): {}",
                        truncate_list(&direct_missing, 5)
                    ),
                    element: None,
                    requirement: "CRA Annex I, Part III / prEN 40000-1-3 [PRE-7-RQ-03]: Direct dependency supplier (mandatory)"
                        .to_string(),
                    standard_refs: Vec::new(),
                });
            }

            let transitive_n = transitive_missing.len();
            if transitive_n > 0 {
                let denom = total.max(1);
                let pct = (transitive_n * 100) / denom;
                let severity = if matches!(self.level, ComplianceLevel::CraPhase2) && pct > 30 {
                    ViolationSeverity::Warning
                } else {
                    ViolationSeverity::Info
                };
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::SupplierInfo,
                    message: format!(
                        "[CRA Annex I, Part III / [PRE-7-RQ-03]] {transitive_n}/{denom} transitive dependencies ({pct}%) missing supplier (recommended): {}",
                        truncate_list(&transitive_missing, 5)
                    ),
                    element: None,
                    requirement: "CRA Annex I, Part III / prEN 40000-1-3 [PRE-7-RQ-03]: Transitive dependency supplier (recommended)"
                        .to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }

        // B4b: prEN 40000-1-3 [PRE-7-RQ-07-RE] — vendor hash carry-through
        // Vendor-supplied components (those with supplier/author and a non-synthetic
        // identifier) must carry the upstream-supplied cryptographic hash through
        // into the SBOM. Synthetic / format-specific IDs are excluded because they
        // typically aren't tied to an upstream artefact at all.
        {
            let metrics = crate::quality::HashQualityMetrics::from_sbom(sbom);
            if let Some(coverage) = metrics.vendor_hash_coverage() {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let pct = (coverage * 100.0).round() as usize;

                // Class-driven calibration overrides phase-based defaults
                // when the operator pinned a CRA product class. Otherwise,
                // fall through to the original Phase1/Phase2 thresholds for
                // backwards compatibility.
                let (severity, threshold_msg) = if self.has_explicit_product_class() {
                    let threshold = self.vendor_hash_threshold();
                    if coverage < threshold {
                        let sev = self
                            .class_severity(ClassCheck::VendorHashCoverage)
                            .unwrap_or(ViolationSeverity::Warning);
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        let thr_pct = (threshold * 100.0).round() as usize;
                        (
                            sev,
                            format!(
                                "below {thr_pct}% threshold for product class {}",
                                self.effective_product_class().label()
                            ),
                        )
                    } else {
                        (ViolationSeverity::Info, String::new())
                    }
                } else {
                    match self.level {
                        ComplianceLevel::CraPhase2 if coverage < 0.50 => {
                            (ViolationSeverity::Error, "below 50% threshold".to_string())
                        }
                        ComplianceLevel::CraPhase2 if coverage < 0.80 => {
                            (ViolationSeverity::Warning, "below 80% threshold".to_string())
                        }
                        ComplianceLevel::CraPhase1 if coverage < 0.50 => {
                            (ViolationSeverity::Warning, "below 50% threshold".to_string())
                        }
                        _ => (ViolationSeverity::Info, String::new()),
                    }
                };
                if !threshold_msg.is_empty() {
                    violations.push(Violation {
                        severity,
                        category: ViolationCategory::IntegrityInfo,
                        message: format!(
                            "[CRA Annex I, Part II / [PRE-7-RQ-07-RE]] Only {}/{} vendor-supplied components ({pct}%) carry an upstream hash — {threshold_msg}",
                            metrics.vendor_components_with_hash, metrics.vendor_components_total
                        ),
                        element: None,
                        requirement: "CRA Annex I Part II / prEN 40000-1-3 [PRE-7-RQ-07-RE]: Vendor hash carry-through".to_string(),
                        standard_refs: Vec::new(),
                    });
                }
            }
        }

        // B5: Annex III — Document signature/integrity
        // Check for document-level hash, signature, or attestation
        let has_doc_integrity = sbom.document.serial_number.is_some()
            || sbom.components.values().any(|comp| {
                comp.external_refs.iter().any(|r| {
                    matches!(
                        r.ref_type,
                        crate::model::ExternalRefType::Attestation
                            | crate::model::ExternalRefType::Certification
                    ) && !r.hashes.is_empty()
                })
            });
        if !has_doc_integrity {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::IntegrityInfo,
                message: "[CRA Annex III] Consider adding document-level integrity metadata \
                    (serial number, digital signature, or attestation with hash)"
                    .to_string(),
                element: None,
                requirement: "CRA Annex III: Document signature/integrity".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // B5b: Art. 13(2) — Documented risk-assessment reference
        // The CRA requires manufacturers to perform and document a risk
        // assessment. The SBOM (or sidecar) must reference it; absence is a
        // soft Warning under CraPhase2 (Annex V technical-doc requirement).
        if matches!(self.level, ComplianceLevel::CraPhase2) {
            let has_ref_in_sbom = sbom.components.values().any(|comp| {
                comp.external_refs
                    .iter()
                    .any(|r| matches!(r.ref_type, crate::model::ExternalRefType::RiskAssessment))
            }) || sbom.document.creators.iter().any(|c| {
                // Some SBOMs encode the methodology in the creator comment
                c.name.to_lowercase().contains("risk assessment")
            });
            let sidecar_has_ref = self
                .sidecar
                .as_ref()
                .is_some_and(|s| s.risk_assessment_url.is_some());
            if !has_ref_in_sbom && !sidecar_has_ref {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "[CRA Art. 13(2)] No documented risk assessment referenced — add an externalReference of type 'risk-assessment' or supply riskAssessmentUrl in the CRA sidecar".to_string(),
                    element: None,
                    requirement: "CRA Art. 13(2): Documented risk assessment".to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }

        // B5c: Art. 14 reporting-readiness
        // Manufacturers must operate channels to:
        // - 24-hour early-warn ENISA / CSIRT for actively-exploited vulnerabilities (14(1))
        // - 72-hour incident report (14(2))
        // - Route through the ENISA single reporting platform (14(7))
        // Obligations apply from 11 September 2026; before that, missing
        // channels surface as Info ("prepare ahead"); after that, Warning.
        if self.level.is_cra() {
            self.check_article_14_readiness_at(chrono::Utc::now(), violations);
        }

        // B6: Art. 13(8) / Art. 13(11) — Component lifecycle / EOL detection
        // If EOL enrichment data is present, warn about EOL components
        let eol_count = sbom
            .components
            .values()
            .filter(|c| {
                c.eol
                    .as_ref()
                    .is_some_and(|e| e.status == crate::model::EolStatus::EndOfLife)
            })
            .count();
        if eol_count > 0 {
            let severity = if self.has_explicit_product_class() {
                self.class_severity(ClassCheck::EolComponents)
                    .unwrap_or(ViolationSeverity::Warning)
            } else {
                ViolationSeverity::Warning
            };
            violations.push(Violation {
                severity,
                category: ViolationCategory::SecurityInfo,
                message: format!(
                    "[CRA Art. 13(8)] {eol_count} component(s) have reached end-of-life and no longer receive security updates"
                ),
                element: None,
                requirement: "CRA Art. 13(8): Support period / lifecycle management".to_string(),
                standard_refs: Vec::new(),
            });
        }

        let approaching_eol_count = sbom
            .components
            .values()
            .filter(|c| {
                c.eol
                    .as_ref()
                    .is_some_and(|e| e.status == crate::model::EolStatus::ApproachingEol)
            })
            .count();
        if approaching_eol_count > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::SecurityInfo,
                message: format!(
                    "[CRA Art. 13(11)] {approaching_eol_count} component(s) are approaching end-of-life within 6 months"
                ),
                element: None,
                requirement: "CRA Art. 13(11): Component lifecycle monitoring".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // SPDX 3.0 profile conformance checks (Phase 6)
        if sbom.document.format == crate::model::SbomFormat::Spdx
            && sbom.document.spec_version.starts_with("3.")
        {
            // Check if Security profile is declared when vulnerabilities are present
            let has_vulns = sbom
                .components
                .values()
                .any(|c| !c.vulnerabilities.is_empty());
            let has_security_profile = sbom
                .document
                .distribution_classification
                .as_ref()
                .is_some_and(|p| p.to_lowercase().contains("security"));

            if has_vulns && !has_security_profile {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::DocumentMetadata,
                    message:
                        "[CRA Art. 13(6)] SPDX 3.0 document contains vulnerabilities but does not declare Security profile conformance; declare profileConformance: [\"security\"] for CRA Art. 13(6) compliance"
                            .to_string(),
                    element: None,
                    requirement: "CRA Art. 13(6): SPDX 3.0 Security profile conformance"
                        .to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // Check if SimpleLicensing profile is declared when licenses are tracked
            let has_licenses = sbom
                .components
                .values()
                .any(|c| !c.licenses.declared.is_empty() || c.licenses.concluded.is_some());
            let has_licensing_profile = sbom
                .document
                .distribution_classification
                .as_ref()
                .is_some_and(|p| {
                    p.to_lowercase().contains("simplelicensing")
                        || p.to_lowercase().contains("licensing")
                });

            if has_licenses && !has_licensing_profile {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::LicenseInfo,
                    message:
                        "[CRA Art. 13(5)] SPDX 3.0 document tracks licenses but does not declare SimpleLicensing profile conformance; declare profileConformance: [\"simpleLicensing\"] for completeness"
                            .to_string(),
                    element: None,
                    requirement: "CRA Art. 13(5): SPDX 3.0 SimpleLicensing profile conformance"
                        .to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }

        // CRA-P3.2: Class-conditional EUCC and Module-attestation references
        // (only fire when the operator pinned a product class — preserves
        // pre-P3.2 behavior for callers that didn't opt in).
        if self.has_explicit_product_class() {
            self.check_class_eucc_reference(sbom, violations);
            self.check_class_module_attestation(sbom, violations);
        }
    }

    /// EUCC (Common Criteria) certificate / Target-of-Evaluation reference.
    ///
    /// `ImportantClass2` → Info if missing (recommended); `Critical` → Error
    /// if missing (Annex IV mandates EUCC). Lower classes: skipped.
    fn check_class_eucc_reference(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        let Some(severity) = self.class_severity(ClassCheck::EuccReference) else {
            return;
        };
        let has_eucc_ref = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                let url_lower = r.url.to_lowercase();
                matches!(
                    r.ref_type,
                    crate::model::ExternalRefType::Certification
                        | crate::model::ExternalRefType::Attestation
                ) && (url_lower.contains("eucc")
                    || url_lower.contains("common-criteria")
                    || url_lower.contains("commoncriteria"))
            })
        });
        if !has_eucc_ref {
            violations.push(Violation {
                severity,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[CRA Annex IV / EUCC] Product class {} requires (or strongly recommends) a reference to a Common Criteria / EUCC certificate or Target of Evaluation",
                    self.effective_product_class().label()
                ),
                element: None,
                requirement: "CRA Annex IV: EUCC reference (Common Criteria certificate)"
                    .to_string(),
                standard_refs: Vec::new(),
            });
        }
    }

    /// Conformity-assessment-module attestation reference.
    ///
    /// Module B+C / H / EUCC routes require an attestation external reference
    /// (notified-body certificate, QA-system certification, EUCC certificate).
    /// Module A (self-assessment) is skipped. Severity scales with class.
    fn check_class_module_attestation(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        use crate::model::ConformityRoute as R;
        let Some(severity) = self.class_severity(ClassCheck::ModuleAttestation) else {
            return;
        };
        let route = self.effective_route();
        if matches!(route, R::ModuleA) {
            return; // Module A self-assessment doesn't require external attestation
        }
        let has_attestation = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                matches!(
                    r.ref_type,
                    crate::model::ExternalRefType::Attestation
                        | crate::model::ExternalRefType::Certification
                )
            })
        });
        if !has_attestation {
            violations.push(Violation {
                severity,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[CRA Annex VIII / {}] No attestation or certification external reference found — required for the {} conformity route",
                    route.label(),
                    route.label()
                ),
                element: None,
                requirement: format!(
                    "CRA Annex VIII: {} attestation reference",
                    route.label()
                ),
                standard_refs: Vec::new(),
            });
        }
    }

    /// CRA Article 14 reporting-readiness check.
    ///
    /// Verifies the manufacturer has documented channels for the obligations
    /// that apply from 11 September 2026:
    /// - 14(1) 24-hour early warning to ENISA/CSIRTs on actively-exploited vulns
    /// - 14(2) 72-hour incident report
    /// - 14(7) routing through the ENISA single reporting platform
    ///
    /// Pre-deadline: missing channels surface as Info (preparation guidance).
    /// Post-deadline: missing channels become Warning. The CRA never demands
    /// the channel reside *inside* the SBOM — most manufacturers will set
    /// these via `CraSidecarMetadata`.
    /// Internal entry point taking an explicit `now` so tests can pin it.
    fn check_article_14_readiness_at(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        violations: &mut Vec<Violation>,
    ) {
        // Article 14 reporting-obligation deadline.
        // CRA enters into force 2024-12-10; reporting obligations apply
        // 21 months later on 2026-09-11.
        let deadline: chrono::DateTime<chrono::Utc> =
            chrono::DateTime::parse_from_rfc3339("2026-09-11T00:00:00Z")
                .expect("hard-coded deadline literal is RFC-3339")
                .into();
        let art_14_active = now >= deadline;
        // Severity escalation by product class: when class is explicitly set
        // and ≥ ImportantClass2, post-deadline missing channels become Errors
        // rather than Warnings ([CRA-P3.2 calibration]).
        let post_deadline_severity = if art_14_active {
            if self.has_explicit_product_class() {
                self.class_severity(ClassCheck::Psirt)
                    .unwrap_or(ViolationSeverity::Warning)
            } else {
                ViolationSeverity::Warning
            }
        } else {
            ViolationSeverity::Info
        };

        let sidecar = self.sidecar.as_ref();

        let psirt_present = sidecar.is_some_and(|s| s.psirt_url.is_some());
        if !psirt_present {
            let prefix = if art_14_active {
                "[CRA Art. 14] PSIRT URL missing — required to handle external vulnerability reports"
            } else {
                "[CRA Art. 14] PSIRT URL missing — Article 14 obligations begin 2026-09-11; document the PSIRT channel ahead of the deadline"
            };
            violations.push(Violation {
                severity: post_deadline_severity,
                category: ViolationCategory::SecurityInfo,
                message: prefix.to_string(),
                element: None,
                requirement: "CRA Art. 14: PSIRT contact for external vulnerability reports"
                    .to_string(),
                standard_refs: Vec::new(),
            });
        }

        let ew_present = sidecar.is_some_and(|s| s.early_warning_contact.is_some());
        if !ew_present {
            let msg = if art_14_active {
                "[CRA Art. 14(1)] 24-hour early-warning channel missing — required when an actively-exploited vulnerability is identified"
            } else {
                "[CRA Art. 14(1)] 24-hour early-warning channel missing — document the ENISA/CSIRT contact before 2026-09-11"
            };
            violations.push(Violation {
                severity: post_deadline_severity,
                category: ViolationCategory::SecurityInfo,
                message: msg.to_string(),
                element: None,
                requirement: "CRA Art. 14(1): 24-hour early-warning channel".to_string(),
                standard_refs: Vec::new(),
            });
        }

        let ir_present = sidecar.is_some_and(|s| s.incident_report_contact.is_some());
        if !ir_present {
            let msg = if art_14_active {
                "[CRA Art. 14(2)] 72-hour incident-report channel missing — required for severe incidents impacting product security"
            } else {
                "[CRA Art. 14(2)] 72-hour incident-report channel missing — document this contact before 2026-09-11"
            };
            violations.push(Violation {
                severity: post_deadline_severity,
                category: ViolationCategory::SecurityInfo,
                message: msg.to_string(),
                element: None,
                requirement: "CRA Art. 14(2): 72-hour incident-report channel".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // ENISA single reporting platform (Art. 14(7)) — the official URL is
        // not yet published. We accept any sidecar identifier as a forward-
        // compatible placeholder and only surface as Info regardless of date.
        let enisa_present = sidecar.is_some_and(|s| s.enisa_reporting_platform_id.is_some());
        if !enisa_present {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::SecurityInfo,
                message: "[CRA Art. 14(7)] No ENISA single reporting platform identifier — track ENISA publication and add `enisaReportingPlatformId` to the CRA sidecar when available"
                    .to_string(),
                element: None,
                requirement: "CRA Art. 14(7): ENISA single reporting platform".to_string(),
                standard_refs: Vec::new(),
            });
        }
    }

    /// Hardware-SBOM (HBOM) compliance check.
    ///
    /// Implements CRA prEN 40000-1-3 `[PRE-8-RQ-02]`: hardware components must
    /// carry producer, component name, unique identifier, and firmware version
    /// where applicable. Operates on components classified as
    /// `Device`, `Firmware`, or `DeviceDriver`. The check is silent when the
    /// SBOM contains no hardware components, so software-only SBOMs are
    /// unaffected.
    fn check_hardware_components(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{ComponentType, IdSource};

        let is_hardware_kind = |t: &ComponentType| {
            matches!(
                t,
                ComponentType::Device | ComponentType::Firmware | ComponentType::DeviceDriver
            )
        };

        let hardware_components: Vec<_> = sbom
            .components
            .values()
            .filter(|c| is_hardware_kind(&c.component_type))
            .collect();

        if hardware_components.is_empty() {
            return;
        }

        for comp in hardware_components {
            // 1) Producer (supplier or author) must be set
            if comp.supplier.is_none() && comp.author.is_none() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::SupplierInfo,
                    message: format!(
                        "[CRA prEN 40000-1-3 [PRE-8-RQ-02]] Hardware component '{}' missing producer (supplier or author)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Hardware producer".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // 2) Identifier must be a real (non-synthetic / non-format-specific) one
            if matches!(
                comp.canonical_id.source(),
                IdSource::Synthetic | IdSource::FormatSpecific
            ) {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[CRA prEN 40000-1-3 [PRE-8-RQ-02]] Hardware component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Hardware identifier".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // 3) Firmware components must carry a version (the firmware version itself).
            if matches!(comp.component_type, ComponentType::Firmware) && comp.version.is_none() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[CRA prEN 40000-1-3 [PRE-8-RQ-02]] Firmware component '{}' missing firmware version",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Firmware version".to_string(),
                    standard_refs: Vec::new(),
                });
            }

            // 4) Devices: should declare a version, OR depend on a Firmware component.
            if matches!(comp.component_type, ComponentType::Device) && comp.version.is_none() {
                let has_firmware_dep = sbom.edges.iter().any(|e| {
                    e.from == comp.canonical_id
                        && sbom.components.get(&e.to).is_some_and(|child| {
                            matches!(child.component_type, ComponentType::Firmware)
                        })
                });
                if !has_firmware_dep {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::ComponentIdentification,
                        message: format!(
                            "[CRA prEN 40000-1-3 [PRE-8-RQ-02]] Device component '{}' has no version and no associated firmware component",
                            comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Device firmware association".to_string(),
                        standard_refs: Vec::new(),
                    });
                }
            }
        }
    }

    /// NIST SP 800-218 Secure Software Development Framework checks
    fn check_nist_ssdf(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::ExternalRefType;

        // PS.1 — Provenance: creator/tool information
        if sbom.document.creators.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message:
                    "SBOM must identify its creator (tool or organization) for provenance tracking"
                        .to_string(),
                element: None,
                requirement: "NIST SSDF PS.1: Provenance — creator identification".to_string(),
                standard_refs: Vec::new(),
            });
        }

        let has_tool_creator = sbom
            .document
            .creators
            .iter()
            .any(|c| c.creator_type == crate::model::CreatorType::Tool);
        if !has_tool_creator {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM should identify the generation tool for automated provenance"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PS.1: Provenance — tool identification".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // PS.2 — Build integrity: components should have hashes
        let total = sbom.components.len();
        let without_hash = sbom
            .components
            .values()
            .filter(|c| c.hashes.is_empty())
            .count();
        if without_hash > 0 {
            let pct = (without_hash * 100) / total.max(1);
            violations.push(Violation {
                severity: if pct > 50 {
                    ViolationSeverity::Error
                } else {
                    ViolationSeverity::Warning
                },
                category: ViolationCategory::IntegrityInfo,
                message: format!(
                    "{without_hash}/{total} components ({pct}%) missing cryptographic hashes for build integrity"
                ),
                element: None,
                requirement: "NIST SSDF PS.2: Build integrity — component hashes".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // PO.1 — VCS references: at least some components should reference their source
        let has_vcs_ref = sbom.components.values().any(|comp| {
            comp.external_refs
                .iter()
                .any(|r| matches!(r.ref_type, ExternalRefType::Vcs))
        });
        if !has_vcs_ref {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::ComponentIdentification,
                message: "No components reference a VCS repository; include source repository links for traceability"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PO.1: Source code provenance — VCS references".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // PO.3 — Build metadata: check for build system/meta references
        let has_build_ref = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                matches!(
                    r.ref_type,
                    ExternalRefType::BuildMeta | ExternalRefType::BuildSystem
                )
            })
        });
        if !has_build_ref {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DocumentMetadata,
                message: "No build metadata references found; include build system information for reproducibility"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PO.3: Build provenance — build metadata".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // PW.4 — Dependency management: dependency relationships required
        if sbom.components.len() > 1 && sbom.edges.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DependencyInfo,
                message: "SBOM with multiple components must include dependency relationships"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PW.4: Dependency management — relationships".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // PW.6 — Vulnerability information
        let has_vuln_info = sbom
            .components
            .values()
            .any(|c| !c.vulnerabilities.is_empty());
        let has_security_ref = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                matches!(
                    r.ref_type,
                    ExternalRefType::Advisories
                        | ExternalRefType::SecurityContact
                        | ExternalRefType::VulnerabilityAssertion
                )
            })
        });
        if !has_vuln_info && !has_security_ref {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::SecurityInfo,
                message: "No vulnerability or security advisory references found; \
                    include vulnerability data or security contact for incident response"
                    .to_string(),
                element: None,
                requirement: "NIST SSDF PW.6: Vulnerability information".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // RV.1 — Component identification: unique identifiers (PURL/CPE)
        let without_id = sbom
            .components
            .values()
            .filter(|c| {
                c.identifiers.purl.is_none()
                    && c.identifiers.cpe.is_empty()
                    && c.identifiers.swid.is_none()
            })
            .count();
        if without_id > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "{without_id}/{total} components missing unique identifier (PURL/CPE/SWID)"
                ),
                element: None,
                requirement: "NIST SSDF RV.1: Component identification — unique identifiers"
                    .to_string(),
                standard_refs: Vec::new(),
            });
        }

        // PS.3 — Supplier identification
        let without_supplier = sbom
            .components
            .values()
            .filter(|c| c.supplier.is_none() && c.author.is_none())
            .count();
        if without_supplier > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::SupplierInfo,
                message: format!(
                    "{without_supplier}/{total} components missing supplier/author information"
                ),
                element: None,
                requirement: "NIST SSDF PS.3: Supplier identification".to_string(),
                standard_refs: Vec::new(),
            });
        }
    }

    /// Executive Order 14028 Section 4 checks
    fn check_eo14028(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::ExternalRefType;

        // Sec 4(e) — Machine-readable format
        let format_ok = match sbom.document.format {
            crate::model::SbomFormat::CycloneDx => {
                let v = &sbom.document.spec_version;
                !(v.starts_with("1.0")
                    || v.starts_with("1.1")
                    || v.starts_with("1.2")
                    || v.starts_with("1.3"))
            }
            crate::model::SbomFormat::Spdx => {
                let v = &sbom.document.spec_version;
                v.starts_with("2.3") || v.starts_with("3.")
            }
        };
        if !format_ok {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::FormatSpecific,
                message: format!(
                    "SBOM format {} {} does not meet EO 14028 machine-readable requirements; \
                    use CycloneDX 1.4+, SPDX 2.3+, or SPDX 3.0+",
                    sbom.document.format, sbom.document.spec_version
                ),
                element: None,
                requirement: "EO 14028 Sec 4(e): Machine-readable SBOM format".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // Sec 4(e) — Automated generation: tool creator should be present
        let has_tool = sbom
            .document
            .creators
            .iter()
            .any(|c| c.creator_type == crate::model::CreatorType::Tool);
        if !has_tool {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM should be auto-generated by a tool; no tool creator identified"
                    .to_string(),
                element: None,
                requirement: "EO 14028 Sec 4(e): Automated SBOM generation".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // Sec 4(e) — Creator identification
        if sbom.document.creators.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM must identify its creator (vendor or tool)".to_string(),
                element: None,
                requirement: "EO 14028 Sec 4(e): SBOM creator identification".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // Sec 4(e) — Component identification with unique identifiers
        let total = sbom.components.len();
        let without_id = sbom
            .components
            .values()
            .filter(|c| {
                c.identifiers.purl.is_none()
                    && c.identifiers.cpe.is_empty()
                    && c.identifiers.swid.is_none()
            })
            .count();
        if without_id > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "{without_id}/{total} components missing unique identifier (PURL/CPE/SWID)"
                ),
                element: None,
                requirement: "EO 14028 Sec 4(e): Component unique identification".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // Sec 4(e) — Dependency relationships
        if sbom.components.len() > 1 && sbom.edges.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DependencyInfo,
                message: "SBOM with multiple components must include dependency relationships"
                    .to_string(),
                element: None,
                requirement: "EO 14028 Sec 4(e): Dependency relationships".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // Sec 4(e) — Version information
        let without_version = sbom
            .components
            .values()
            .filter(|c| c.version.is_none())
            .count();
        if without_version > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "{without_version}/{total} components missing version information"
                ),
                element: None,
                requirement: "EO 14028 Sec 4(e): Component version".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // Sec 4(e) — Cryptographic hashes for integrity
        let without_hash = sbom
            .components
            .values()
            .filter(|c| c.hashes.is_empty())
            .count();
        if without_hash > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::IntegrityInfo,
                message: format!("{without_hash}/{total} components missing cryptographic hashes"),
                element: None,
                requirement: "EO 14028 Sec 4(e): Component integrity verification".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // Sec 4(g) — Vulnerability disclosure
        let has_security_ref = sbom.document.security_contact.is_some()
            || sbom.document.vulnerability_disclosure_url.is_some()
            || sbom.components.values().any(|comp| {
                comp.external_refs.iter().any(|r| {
                    matches!(
                        r.ref_type,
                        ExternalRefType::SecurityContact | ExternalRefType::Advisories
                    )
                })
            });
        if !has_security_ref {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::SecurityInfo,
                message: "No security contact or vulnerability disclosure reference found"
                    .to_string(),
                element: None,
                requirement: "EO 14028 Sec 4(g): Vulnerability disclosure process".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // Sec 4(e) — Supplier identification
        let without_supplier = sbom
            .components
            .values()
            .filter(|c| c.supplier.is_none() && c.author.is_none())
            .count();
        if without_supplier > 0 {
            let pct = (without_supplier * 100) / total.max(1);
            if pct > 30 {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::SupplierInfo,
                    message: format!(
                        "{without_supplier}/{total} components ({pct}%) missing supplier information"
                    ),
                    element: None,
                    requirement: "EO 14028 Sec 4(e): Supplier identification".to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }
    }

    fn check_format_specific(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        match sbom.document.format {
            SbomFormat::CycloneDx => {
                self.check_cyclonedx_specific(sbom, violations);
            }
            SbomFormat::Spdx => {
                self.check_spdx_specific(sbom, violations);
            }
        }
    }

    fn check_cyclonedx_specific(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // CycloneDX specific checks
        let version = &sbom.document.spec_version;

        // Warn about older versions
        if version.starts_with("1.3") || version.starts_with("1.2") || version.starts_with("1.1") {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::FormatSpecific,
                message: format!("CycloneDX {version} is outdated, consider upgrading to 1.7+"),
                element: None,
                requirement: "Current CycloneDX version".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // Check for bom-ref on components (important for CycloneDX)
        for comp in sbom.components.values() {
            if comp.identifiers.format_id == comp.name {
                // Likely missing bom-ref
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::FormatSpecific,
                    message: format!("Component '{}' may be missing bom-ref", comp.name),
                    element: Some(comp.name.clone()),
                    requirement: "CycloneDX: bom-ref for dependency tracking".to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }
    }

    fn check_spdx_specific(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // SPDX specific checks
        let version = &sbom.document.spec_version;

        // Check version
        if !version.starts_with("2.") && !version.starts_with("3.") {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::FormatSpecific,
                message: format!("Unknown SPDX version: {version}"),
                element: None,
                requirement: "Valid SPDX version".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // SPDX requires element identifiers
        // SPDX 2.x uses SPDXRef- prefix; SPDX 3.0 uses URN-style IDs (e.g., urn:spdx:...)
        let is_spdx3 = version.starts_with("3.");
        for comp in sbom.components.values() {
            let valid_id = if is_spdx3 {
                // SPDX 3.0 uses URN/IRI identifiers
                comp.identifiers.format_id.contains(':')
            } else {
                comp.identifiers.format_id.starts_with("SPDXRef-")
            };
            if !valid_id {
                let expected = if is_spdx3 {
                    "SPDX 3.0: URN/IRI identifier format"
                } else {
                    "SPDX 2.x: SPDXRef- identifier format"
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::FormatSpecific,
                    message: format!(
                        "Component '{}' has non-standard SPDX identifier format",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: expected.to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // CNSA 2.0 compliance checks
    // ════════════════════════════════════════════════════════════════════

    fn check_cnsa2(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{ComponentType, CryptoAssetType};

        for comp in sbom.components.values() {
            if comp.component_type != ComponentType::Cryptographic {
                continue;
            }
            let Some(cp) = &comp.crypto_properties else {
                continue;
            };

            match cp.asset_type {
                CryptoAssetType::Algorithm => {
                    if let Some(algo) = &cp.algorithm_properties {
                        // CNSA2-ALG-007: quantum security level must be >= 5
                        if let Some(ql) = algo.nist_quantum_security_level
                            && ql < 5
                        {
                            // Check if it's a symmetric/hash (allowed at lower levels)
                            let is_symmetric_or_hash = matches!(
                                algo.primitive,
                                crate::model::CryptoPrimitive::Ae
                                    | crate::model::CryptoPrimitive::BlockCipher
                                    | crate::model::CryptoPrimitive::Hash
                                    | crate::model::CryptoPrimitive::Mac
                                    | crate::model::CryptoPrimitive::Kdf
                            );
                            if !is_symmetric_or_hash && ql == 0 {
                                violations.push(Violation {
                                        severity: ViolationSeverity::Error,
                                        category: ViolationCategory::CryptographyInfo,
                                        message: format!(
                                            "'{}' is quantum-vulnerable (level {}), must migrate to PQC",
                                            comp.name, ql
                                        ),
                                        element: Some(comp.name.clone()),
                                        requirement: "CNSA 2.0 PQC Migration".to_string(),
                                        standard_refs: Vec::new(),
                                    });
                            } else if !is_symmetric_or_hash && ql < 5 {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' quantum level {} < 5, CNSA 2.0 requires Level 5",
                                        comp.name, ql
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 Level 5".to_string(),
                                    standard_refs: Vec::new(),
                                });
                            }
                        }

                        // CNSA2-ALG-001: symmetric must be AES-256
                        if let Some(family) = &algo.algorithm_family {
                            let upper = family.to_uppercase();
                            if upper == "AES"
                                && let Some(param) = &algo.parameter_set_identifier
                                && param != "256"
                            {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' uses AES-{}, CNSA 2.0 requires AES-256 only",
                                        comp.name, param
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 Symmetric".to_string(),
                                    standard_refs: Vec::new(),
                                });
                            }

                            // CNSA2-ALG-002: hash must be SHA-384+
                            if (upper == "SHA-2" || upper == "SHA2")
                                && let Some(param) = &algo.parameter_set_identifier
                                && param == "256"
                            {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' uses SHA-256, CNSA 2.0 requires SHA-384 or SHA-512",
                                        comp.name
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 Hash".to_string(),
                                    standard_refs: Vec::new(),
                                });
                            }

                            // CNSA2-ALG-003: KEM must be ML-KEM-1024 only
                            if upper == "ML-KEM"
                                && let Some(param) = &algo.parameter_set_identifier
                                && param != "1024"
                            {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' uses ML-KEM-{}, CNSA 2.0 requires ML-KEM-1024 only",
                                        comp.name, param
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 KEM".to_string(),
                                    standard_refs: Vec::new(),
                                });
                            }

                            // CNSA2-ALG-004: signature must be ML-DSA-87 only
                            if upper == "ML-DSA"
                                && let Some(param) = &algo.parameter_set_identifier
                                && param != "87"
                            {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' uses ML-DSA-{}, CNSA 2.0 requires ML-DSA-87 only",
                                        comp.name, param
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 Signature".to_string(),
                                    standard_refs: Vec::new(),
                                });
                            }

                            // CNSA2-ALG-006: quantum-vulnerable families
                            const CNSA2_VULNERABLE: &[&str] = &[
                                "RSA", "DSA", "DH", "ECDSA", "ECDH", "EDDSA", "X25519", "X448",
                            ];
                            if CNSA2_VULNERABLE.iter().any(|v| upper == *v) {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' ({}) is quantum-vulnerable, must migrate to CNSA 2.0 approved algorithm",
                                        comp.name, family
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 PQC Migration".to_string(),
                                    standard_refs: Vec::new(),
                                });
                            }
                        }
                    }
                }
                CryptoAssetType::Certificate => {
                    // CNSA2-CERT-001: cert must use CNSA 2.0 signature algorithm
                    if let Some(cert) = &cp.certificate_properties
                        && let Some(sig_ref) = &cert.signature_algorithm_ref
                    {
                        // Check if the referenced algorithm is a quantum-vulnerable family
                        // Exclude ML-DSA (approved PQC) and SLH-DSA from false positives
                        let sig_lower = sig_ref.to_lowercase();
                        let is_pqc_sig = sig_lower.contains("ml-dsa")
                            || sig_lower.contains("slh-dsa")
                            || sig_lower.contains("lms")
                            || sig_lower.contains("xmss");
                        if !is_pqc_sig
                            && (sig_lower.contains("rsa")
                                || sig_lower.contains("ecdsa")
                                || sig_lower.contains("dsa"))
                        {
                            violations.push(Violation {
                                severity: ViolationSeverity::Error,
                                category: ViolationCategory::CryptographyInfo,
                                message: format!(
                                    "Certificate '{}' signed with non-CNSA 2.0 algorithm (ref: {})",
                                    comp.name, sig_ref
                                ),
                                element: Some(comp.name.clone()),
                                requirement: "CNSA 2.0 Certificate".to_string(),
                                standard_refs: Vec::new(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // BSI TR-03183-2 (German national SBOM guideline)
    // ════════════════════════════════════════════════════════════════════

    /// BSI TR-03183-2 compliance checks.
    ///
    /// TR-03183-2 is the German Federal Office for Information Security's
    /// SBOM technical guideline, free and ENISA-cited. It is functionally
    /// equivalent to the CRA Annex I Part II SBOM obligations but stricter
    /// than NTIA Minimum on hashes and identifiers.
    ///
    /// Reference: BSI TR-03183-2 v2.0.0 §5 (mandatory) and §6 (recommended).
    fn check_bsi_tr_03183_2(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{CreatorType, HashAlgorithm};

        // §5.1 — Author/creator identification (mandatory)
        if sbom.document.creators.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI TR-03183-2 §5.1] SBOM author/creator missing".to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.1: Author/creator identification".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // §5.1 — At least one tool creator (mandatory)
        let has_tool_creator = sbom
            .document
            .creators
            .iter()
            .any(|c| c.creator_type == CreatorType::Tool);
        if !has_tool_creator {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI TR-03183-2 §5.1] SBOM must identify the generation tool".to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.1: Tool identification".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // §5.2 — ISO-8601 timestamp (mandatory).
        // Our `DocumentMetadata::created` is `DateTime<Utc>`, always ISO-8601
        // when serialised; the practical risk is the `created` field being
        // unset in the source SBOM. NormalizedSbom default is Utc::now(), so
        // we look for tell-tale unix-epoch / very-old fallback values.
        let created = sbom.document.created;
        if created.timestamp() <= 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI TR-03183-2 §5.2] SBOM created timestamp missing or invalid"
                    .to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.2: ISO-8601 timestamp".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // §5.3 — Component name (mandatory) — already enforced globally;
        //         we add a BSI-specific message only if many components are
        //         missing names (extreme case).

        // §5.3 — Component identifier: PURL or other recognised ID (mandatory).
        // Stricter than CRA: BSI requires a PURL where the ecosystem applies.
        for comp in sbom.components.values() {
            if !comp.identifiers.has_cra_identifier() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[BSI TR-03183-2 §5.3] Component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "BSI TR-03183-2 §5.3: Component identifier".to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }

        // §5.4 — Cryptographic hash (SHA-256 or stronger) — mandatory.
        let strong = |a: &HashAlgorithm| {
            matches!(
                a,
                HashAlgorithm::Sha256
                    | HashAlgorithm::Sha384
                    | HashAlgorithm::Sha512
                    | HashAlgorithm::Sha3_256
                    | HashAlgorithm::Sha3_384
                    | HashAlgorithm::Sha3_512
                    | HashAlgorithm::Blake2b256
                    | HashAlgorithm::Blake2b384
                    | HashAlgorithm::Blake2b512
                    | HashAlgorithm::Blake3
            )
        };
        for comp in sbom.components.values() {
            let has_strong_hash = comp.hashes.iter().any(|h| strong(&h.algorithm));
            if !has_strong_hash {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::IntegrityInfo,
                    message: format!(
                        "[BSI TR-03183-2 §5.4] Component '{}' missing SHA-256+ cryptographic hash",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "BSI TR-03183-2 §5.4: Component cryptographic hash (SHA-256+)"
                        .to_string(),
                    standard_refs: Vec::new(),
                });
            }
        }

        // §5.5 — Dependencies (mandatory): explicit relationship graph required.
        if sbom.edges.is_empty() && sbom.components.len() > 1 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DependencyInfo,
                message: "[BSI TR-03183-2 §5.5] SBOM declares multiple components but no dependency relationships"
                    .to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.5: Dependency relationships".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // §6 — Recommended: license information per component
        let total = sbom.components.len();
        let without_license = sbom
            .components
            .values()
            .filter(|c| c.licenses.declared.is_empty() && c.licenses.concluded.is_none())
            .count();
        if without_license > 0 {
            let pct = (without_license * 100) / total.max(1);
            violations.push(Violation {
                severity: if pct > 50 {
                    ViolationSeverity::Warning
                } else {
                    ViolationSeverity::Info
                },
                category: ViolationCategory::LicenseInfo,
                message: format!(
                    "[BSI TR-03183-2 §6] {without_license}/{total} components ({pct}%) missing license information"
                ),
                element: None,
                requirement: "BSI TR-03183-2 §6: Component license (recommended)".to_string(),
                standard_refs: Vec::new(),
            });
        }

        // §6 — Recommended: supplier per component
        let without_supplier = sbom
            .components
            .values()
            .filter(|c| c.supplier.is_none() && c.author.is_none())
            .count();
        if without_supplier > 0 {
            let pct = (without_supplier * 100) / total.max(1);
            violations.push(Violation {
                severity: if pct > 50 {
                    ViolationSeverity::Warning
                } else {
                    ViolationSeverity::Info
                },
                category: ViolationCategory::SupplierInfo,
                message: format!(
                    "[BSI TR-03183-2 §6] {without_supplier}/{total} components ({pct}%) missing supplier information"
                ),
                element: None,
                requirement: "BSI TR-03183-2 §6: Component supplier (recommended)".to_string(),
                standard_refs: Vec::new(),
            });
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // NIST PQC Readiness checks
    // ════════════════════════════════════════════════════════════════════

    fn check_nist_pqc(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{ComponentType, CryptoAssetType};

        /// Broken/disallowed algorithms per SP 800-131A
        const BROKEN: &[&str] = &[
            "MD5", "MD4", "MD2", "SHA-1", "DES", "3DES", "TDEA", "RC2", "RC4", "BLOWFISH", "IDEA",
            "CAST5",
        ];

        for comp in sbom.components.values() {
            if comp.component_type != ComponentType::Cryptographic {
                continue;
            }
            let Some(cp) = &comp.crypto_properties else {
                continue;
            };

            if cp.asset_type == CryptoAssetType::Algorithm
                && let Some(algo) = &cp.algorithm_properties
            {
                // PQC-001: quantum-vulnerable algorithm
                if algo.nist_quantum_security_level == Some(0) {
                    violations.push(Violation {
                        severity: ViolationSeverity::Error,
                        category: ViolationCategory::CryptographyInfo,
                        message: format!(
                            "'{}' has nistQuantumSecurityLevel=0, quantum-vulnerable (IR 8547)",
                            comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "IR 8547: quantum-vulnerable".to_string(),
                        standard_refs: Vec::new(),
                    });
                }

                // PQC-012: missing quantum security level
                if algo.nist_quantum_security_level.is_none() {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::CryptographyInfo,
                        message: format!("'{}' missing nistQuantumSecurityLevel field", comp.name),
                        element: Some(comp.name.clone()),
                        requirement: "IR 8547: quantum assessment required".to_string(),
                        standard_refs: Vec::new(),
                    });
                }

                // PQC-005/006/007: broken algorithms
                if let Some(family) = &algo.algorithm_family {
                    let upper = family.to_uppercase();
                    if BROKEN.iter().any(|b| upper == *b) {
                        violations.push(Violation {
                            severity: ViolationSeverity::Error,
                            category: ViolationCategory::CryptographyInfo,
                            message: format!(
                                "'{}' ({}) is broken/disallowed per SP 800-131A",
                                comp.name, family
                            ),
                            element: Some(comp.name.clone()),
                            requirement: "SP 800-131A: disallowed".to_string(),
                            standard_refs: Vec::new(),
                        });
                    }
                }

                // PQC-008: ECB mode
                if algo.mode == Some(crate::model::CryptoMode::Ecb) {
                    violations.push(Violation {
                        severity: ViolationSeverity::Error,
                        category: ViolationCategory::CryptographyInfo,
                        message: format!(
                            "'{}' uses ECB mode, disallowed per SP 800-131A Rev 3",
                            comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "SP 800-131A Rev 3: ECB disallowed".to_string(),
                        standard_refs: Vec::new(),
                    });
                }

                // PQC-009: approved PQC (informational)
                if let Some(family) = &algo.algorithm_family {
                    let upper = family.to_uppercase();
                    if matches!(upper.as_str(), "ML-KEM" | "ML-DSA" | "SLH-DSA") {
                        violations.push(Violation {
                            severity: ViolationSeverity::Info,
                            category: ViolationCategory::CryptographyInfo,
                            message: format!(
                                "'{}' uses NIST-approved PQC algorithm (FIPS 203/204/205)",
                                comp.name
                            ),
                            element: Some(comp.name.clone()),
                            requirement: "FIPS 203/204/205: approved".to_string(),
                            standard_refs: Vec::new(),
                        });
                    }
                }

                // PQC-010: hybrid PQC combiner (informational)
                if algo.is_hybrid_pqc() {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::CryptographyInfo,
                        message: format!(
                            "'{}' is a hybrid PQC combiner — good migration practice",
                            comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "IR 8547: recommended transition".to_string(),
                        standard_refs: Vec::new(),
                    });
                }
            }

            // PQC-KEY-001: symmetric key < 128 bits
            if cp.asset_type == CryptoAssetType::RelatedCryptoMaterial
                && let Some(mat) = &cp.related_crypto_material_properties
                && let Some(size) = mat.size
            {
                let is_symmetric = matches!(
                    mat.material_type,
                    crate::model::CryptoMaterialType::SymmetricKey
                        | crate::model::CryptoMaterialType::SecretKey
                );
                if is_symmetric && size < 128 {
                    violations.push(Violation {
                        severity: ViolationSeverity::Error,
                        category: ViolationCategory::CryptographyInfo,
                        message: format!(
                            "'{}' symmetric key size {} bits < 128 minimum",
                            comp.name, size
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "NIST: minimum key size".to_string(),
                        standard_refs: Vec::new(),
                    });
                }
            }
        }
    }
}

impl Default for ComplianceChecker {
    fn default() -> Self {
        Self::new(ComplianceLevel::Standard)
    }
}

/// Simple email format validation (checks basic structure, not full RFC 5322)
/// Render a slice of names as a comma-separated list, truncated with
/// "…and N more" once `max` items are emitted. Keeps long-tail violation
/// messages bounded for terminal/SARIF output.
fn truncate_list(items: &[String], max: usize) -> String {
    if items.len() <= max {
        items.join(", ")
    } else {
        let head = items[..max].join(", ");
        let rest = items.len() - max;
        format!("{head}, …and {rest} more")
    }
}

fn is_valid_email_format(email: &str) -> bool {
    // Basic checks: contains @, has local and domain parts, no spaces
    if email.contains(' ') || email.is_empty() {
        return false;
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Local part must not be empty
    if local.is_empty() {
        return false;
    }

    // Domain must contain at least one dot and not start/end with dot
    if domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_level_names() {
        assert_eq!(ComplianceLevel::Minimum.name(), "Minimum");
        assert_eq!(ComplianceLevel::NtiaMinimum.name(), "NTIA Minimum Elements");
        assert_eq!(ComplianceLevel::CraPhase1.name(), "EU CRA Phase 1 (2027)");
        assert_eq!(ComplianceLevel::CraPhase2.name(), "EU CRA Phase 2 (2029)");
        assert_eq!(ComplianceLevel::NistSsdf.name(), "NIST SSDF (SP 800-218)");
        assert_eq!(ComplianceLevel::Eo14028.name(), "EO 14028 Section 4");
    }

    #[test]
    fn test_nist_ssdf_empty_sbom() {
        let sbom = NormalizedSbom::default();
        let checker = ComplianceChecker::new(ComplianceLevel::NistSsdf);
        let result = checker.check(&sbom);
        // Empty SBOM should have at least a creator violation
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.requirement.contains("PS.1"))
        );
    }

    #[test]
    fn test_eo14028_empty_sbom() {
        let sbom = NormalizedSbom::default();
        let checker = ComplianceChecker::new(ComplianceLevel::Eo14028);
        let result = checker.check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.requirement.contains("EO 14028"))
        );
    }

    #[test]
    fn test_compliance_result_counts() {
        let violations = vec![
            Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: "Error 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                standard_refs: Vec::new(),
            },
            Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::LicenseInfo,
                message: "Warning 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                standard_refs: Vec::new(),
            },
            Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::FormatSpecific,
                message: "Info 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                standard_refs: Vec::new(),
            },
        ];

        let result = ComplianceResult::new(ComplianceLevel::Standard, violations);
        assert!(!result.is_compliant);
        assert_eq!(result.error_count, 1);
        assert_eq!(result.warning_count, 1);
        assert_eq!(result.info_count, 1);
    }

    fn make_crypto_sbom(algos: &[(&str, &str, Option<&str>, Option<u8>)]) -> NormalizedSbom {
        use crate::model::{
            AlgorithmProperties, ComponentType, CryptoAssetType, CryptoPrimitive, CryptoProperties,
        };
        let mut sbom = NormalizedSbom::default();
        for (name, family, param, ql) in algos {
            let mut c = crate::model::Component::new(name.to_string(), format!("{name}@1.0"));
            c.component_type = ComponentType::Cryptographic;
            let mut algo = AlgorithmProperties::new(CryptoPrimitive::Ae)
                .with_algorithm_family(family.to_string());
            if let Some(p) = param {
                algo = algo.with_parameter_set_identifier(p.to_string());
            }
            if let Some(level) = ql {
                algo = algo.with_nist_quantum_security_level(*level);
            }
            c.crypto_properties = Some(
                CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(algo),
            );
            sbom.add_component(c);
        }
        sbom
    }

    #[test]
    fn test_cnsa2_aes128_violation() {
        let sbom = make_crypto_sbom(&[("AES-128-GCM", "AES", Some("128"), Some(1))]);
        let checker = ComplianceChecker::new(ComplianceLevel::Cnsa2);
        let result = checker.check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Error && v.message.contains("AES-128")),
            "CNSA 2.0 should flag AES-128"
        );
    }

    #[test]
    fn test_cnsa2_mlkem1024_passes() {
        let sbom = make_crypto_sbom(&[("ML-KEM-1024", "ML-KEM", Some("1024"), Some(5))]);
        let checker = ComplianceChecker::new(ComplianceLevel::Cnsa2);
        let result = checker.check(&sbom);
        let algo_errors: Vec<_> = result
            .violations
            .iter()
            .filter(|v| {
                v.severity == ViolationSeverity::Error
                    && v.element.as_deref() == Some("ML-KEM-1024")
            })
            .collect();
        assert!(algo_errors.is_empty(), "ML-KEM-1024 should pass CNSA 2.0");
    }

    #[test]
    fn test_pqc_quantum_vulnerable() {
        let sbom = make_crypto_sbom(&[("RSA-2048", "RSA", None, Some(0))]);
        let checker = ComplianceChecker::new(ComplianceLevel::NistPqc);
        let result = checker.check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Error
                    && v.message.contains("quantum-vulnerable")),
            "PQC should flag RSA-2048 as quantum-vulnerable"
        );
    }

    #[test]
    fn test_pqc_approved_algorithm_info() {
        let sbom = make_crypto_sbom(&[("ML-DSA-65", "ML-DSA", Some("65"), Some(3))]);
        let checker = ComplianceChecker::new(ComplianceLevel::NistPqc);
        let result = checker.check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.severity == ViolationSeverity::Info && v.message.contains("approved")),
            "PQC should report ML-DSA-65 as approved"
        );
    }

    fn make_violation(req: &str) -> Violation {
        Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DocumentMetadata,
            message: req.to_string(),
            element: None,
            requirement: req.to_string(),
            standard_refs: Vec::new(),
        }
    }

    #[test]
    fn standard_refs_extracts_cra_article() {
        let v = make_violation("CRA Art. 13(4): Machine-readable SBOM format");
        let refs = v.derive_standard_refs();
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::CraArticle && r.id == "Art. 13(4)"),
            "expected CRA Art. 13(4); got {refs:?}"
        );
    }

    #[test]
    fn standard_refs_infers_pren_id_from_art_13_4() {
        let v = make_violation("CRA Art. 13(4): Machine-readable SBOM format");
        let refs = v.derive_standard_refs();
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-04"),
            "expected prEN PRE-7-RQ-04; got {refs:?}"
        );
    }

    #[test]
    fn standard_refs_extracts_explicit_pren_id() {
        let v = make_violation(
            "CRA Annex I / prEN 40000-1-3 [PRE-7-RQ-07]: Unique component identifier",
        );
        let refs = v.derive_standard_refs();
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-07"),
            "expected explicit PRE-7-RQ-07; got {refs:?}"
        );
        // Should not double-list it
        let pren_count = refs
            .iter()
            .filter(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-07")
            .count();
        assert_eq!(pren_count, 1, "PRE-7-RQ-07 should appear exactly once");
    }

    #[test]
    fn standard_refs_extracts_annex_i_part_iii() {
        let v = make_violation("CRA Annex I, Part III: Supply chain transparency");
        let refs = v.derive_standard_refs();
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::CraAnnex && r.id == "Annex I Part III"),
            "expected Annex I Part III; got {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-01"),
            "expected PRE-7-RQ-01; got {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-03"),
            "expected PRE-7-RQ-03; got {refs:?}"
        );
    }

    #[test]
    fn standard_refs_recognises_csaf_in_art_13_7() {
        let v = make_violation("CRA Art. 13(7): Coordinated vulnerability disclosure policy");
        let refs = v.derive_standard_refs();
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "RLS-2-RQ-03-RE"),
            "expected RLS-2-RQ-03-RE; got {refs:?}"
        );
    }

    #[test]
    fn standard_refs_handles_nist_ssdf_practice() {
        let v = make_violation("NIST SSDF PS.2: Build integrity — component hashes");
        let refs = v.derive_standard_refs();
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::NistSsdf && r.id == "PS.2"),
            "expected NIST SSDF PS.2; got {refs:?}"
        );
    }

    #[test]
    fn check_populates_standard_refs_for_cra_violations() {
        let sbom = NormalizedSbom::default();
        let checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
        let result = checker.check(&sbom);
        let cra_violations: Vec<_> = result
            .violations
            .iter()
            .filter(|v| v.requirement.to_lowercase().contains("cra"))
            .collect();
        assert!(
            !cra_violations.is_empty(),
            "empty SBOM should produce some CRA violations"
        );
        for v in &cra_violations {
            assert!(
                !v.standard_refs.is_empty(),
                "CRA violation {:?} should have standard_refs populated",
                v.requirement
            );
        }
    }

    #[test]
    fn sidecar_supplies_security_contact_downgrades_art_13_6() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();

        // Without sidecar: Art. 13(6) is a Warning
        let bare = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let art_13_6_warning = bare.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(6)") && v.severity == ViolationSeverity::Warning
        });
        assert!(
            art_13_6_warning.is_some(),
            "Without sidecar, Art. 13(6) should be a Warning"
        );

        // With sidecar that supplies security_contact: same finding becomes Info
        let sidecar = CraSidecarMetadata {
            security_contact: Some("security@example.com".to_string()),
            ..Default::default()
        };
        let withsc = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let art_13_6_info = withsc.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(6)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            art_13_6_info.is_some(),
            "With sidecar, Art. 13(6) should be downgraded to Info"
        );
        assert!(
            !withsc
                .violations
                .iter()
                .any(|v| v.requirement.contains("Art. 13(6)")
                    && v.severity == ViolationSeverity::Warning),
            "With sidecar, no Warning-level Art. 13(6) violation should remain"
        );
    }

    #[test]
    fn sidecar_supplies_product_name_downgrades_art_13_12() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default(); // no document name

        let sidecar = CraSidecarMetadata {
            product_name: Some("Demo Product".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let downgraded = result.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(12)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            downgraded.is_some(),
            "Sidecar product_name should downgrade Art. 13(12) to Info"
        );
    }

    #[test]
    fn sidecar_supplies_manufacturer_downgrades_art_13_15() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            manufacturer_name: Some("Demo Corp".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let downgraded = result.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(15)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            downgraded.is_some(),
            "Sidecar manufacturer_name should downgrade Art. 13(15) to Info"
        );
    }

    #[test]
    fn sidecar_supplies_cvd_url_downgrades_art_13_7() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            vulnerability_disclosure_url: Some("https://example.com/security".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        let downgraded = result.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(7)") && v.severity == ViolationSeverity::Info
        });
        assert!(
            downgraded.is_some(),
            "Sidecar CVD URL should downgrade Art. 13(7) to Info"
        );
    }

    fn vendor_component(name: &str, with_hash: bool) -> crate::model::Component {
        use crate::model::{Component, Hash, HashAlgorithm, Organization};
        let mut c = Component::new(name.to_string(), name.to_string())
            .with_purl(format!("pkg:cargo/{name}@1.0.0"));
        c.supplier = Some(Organization::new("VendorCorp".to_string()));
        if with_hash {
            c.hashes.push(Hash::new(
                HashAlgorithm::Sha256,
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ));
        }
        c
    }

    fn hw_component(
        name: &str,
        kind: crate::model::ComponentType,
        with_purl: bool,
        with_supplier: bool,
        version: Option<&str>,
    ) -> crate::model::Component {
        use crate::model::{Component, Organization};
        let mut c = Component::new(name.to_string(), name.to_string());
        c.component_type = kind;
        if with_purl {
            c = c.with_purl(format!("pkg:generic/{name}"));
        }
        if with_supplier {
            c.supplier = Some(Organization::new("HardwareCorp".to_string()));
        }
        if let Some(v) = version {
            c = c.with_version(v.to_string());
        }
        c
    }

    #[test]
    fn hardware_check_skipped_for_software_only_sbom() {
        let mut sbom = NormalizedSbom::default();
        let c = vendor_component("software", true);
        sbom.components.insert(c.canonical_id.clone(), c);
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.requirement.contains("PRE-8-RQ-02")),
            "Software-only SBOM should produce no PRE-8-RQ-02 violations"
        );
    }

    #[test]
    fn hardware_check_passes_for_complete_firmware() {
        use crate::model::ComponentType;
        let mut sbom = NormalizedSbom::default();
        let c = hw_component(
            "router-fw",
            ComponentType::Firmware,
            true,
            true,
            Some("1.2.3"),
        );
        sbom.components.insert(c.canonical_id.clone(), c);
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.requirement.contains("PRE-8-RQ-02")),
            "Complete firmware component should pass [PRE-8-RQ-02]"
        );
    }

    #[test]
    fn hardware_check_flags_firmware_without_version() {
        use crate::model::ComponentType;
        let mut sbom = NormalizedSbom::default();
        let c = hw_component("router-fw", ComponentType::Firmware, true, true, None);
        sbom.components.insert(c.canonical_id.clone(), c);
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.requirement.contains("Firmware version") && v.severity == ViolationSeverity::Error
            }),
            "Firmware without version should produce an Error"
        );
    }

    #[test]
    fn hardware_check_flags_missing_producer() {
        use crate::model::ComponentType;
        let mut sbom = NormalizedSbom::default();
        let c = hw_component("router", ComponentType::Device, true, false, Some("1.0"));
        sbom.components.insert(c.canonical_id.clone(), c);
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.requirement.contains("Hardware producer")
                    && v.severity == ViolationSeverity::Error
            }),
            "Hardware without producer should produce an Error"
        );
    }

    #[test]
    fn hardware_check_flags_synthetic_identifier() {
        use crate::model::{Component, ComponentType, Organization};
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("router".to_string(), "router".to_string())
            .with_version("1.0".to_string());
        c.component_type = ComponentType::Device;
        c.supplier = Some(Organization::new("HardwareCorp".to_string()));
        // Note: no PURL/CPE/SWHID/SWID → falls back to synthetic
        sbom.components.insert(c.canonical_id.clone(), c);
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.requirement.contains("Hardware identifier")
                    && v.severity == ViolationSeverity::Error
            }),
            "Hardware with synthetic ID should produce an Error"
        );
    }

    #[test]
    fn hardware_check_device_with_firmware_dep_passes() {
        use crate::model::{ComponentType, DependencyEdge, DependencyType};
        let mut sbom = NormalizedSbom::default();
        let device = hw_component("router", ComponentType::Device, true, true, None);
        let firmware = hw_component(
            "router-fw",
            ComponentType::Firmware,
            true,
            true,
            Some("1.2.3"),
        );
        let device_id = device.canonical_id.clone();
        let firmware_id = firmware.canonical_id.clone();
        sbom.components.insert(device_id.clone(), device);
        sbom.components.insert(firmware_id.clone(), firmware);
        sbom.edges.push(DependencyEdge::new(
            device_id,
            firmware_id,
            DependencyType::DependsOn,
        ));
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| { v.requirement.contains("Device firmware association") }),
            "Device with firmware dependency should not trigger version warning"
        );
    }

    #[test]
    fn vendor_hash_coverage_full() {
        use crate::quality::HashQualityMetrics;
        let mut sbom = NormalizedSbom::default();
        for n in ["a", "b", "c", "d", "e"] {
            let c = vendor_component(n, true);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        let m = HashQualityMetrics::from_sbom(&sbom);
        assert_eq!(m.vendor_components_total, 5);
        assert_eq!(m.vendor_components_with_hash, 5);
        assert_eq!(m.vendor_hash_coverage(), Some(1.0));
    }

    #[test]
    fn vendor_hash_coverage_partial_triggers_warning() {
        let mut sbom = NormalizedSbom::default();
        // 7 with hashes, 3 without → 70% < 80% → Warning under CraPhase2
        for n in ["a", "b", "c", "d", "e", "f", "g"] {
            let c = vendor_component(n, true);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        for n in ["h", "i", "j"] {
            let c = vendor_component(n, false);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let v = result.violations.iter().find(|v| {
            v.requirement.contains("PRE-7-RQ-07-RE") && v.severity == ViolationSeverity::Warning
        });
        assert!(
            v.is_some(),
            "70% vendor-hash coverage should produce a Warning under CraPhase2"
        );
    }

    #[test]
    fn vendor_hash_coverage_below_50_triggers_error() {
        let mut sbom = NormalizedSbom::default();
        // 4 with hashes, 6 without → 40% < 50% → Error under CraPhase2
        for n in ["a", "b", "c", "d"] {
            let c = vendor_component(n, true);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        for n in ["e", "f", "g", "h", "i", "j"] {
            let c = vendor_component(n, false);
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let v = result.violations.iter().find(|v| {
            v.requirement.contains("PRE-7-RQ-07-RE") && v.severity == ViolationSeverity::Error
        });
        assert!(
            v.is_some(),
            "40% vendor-hash coverage should produce an Error under CraPhase2"
        );
    }

    #[test]
    fn vendor_hash_coverage_no_vendor_components_no_violation() {
        // SBOM with only synthetic-ID components — no vendor classification, no violation
        let mut sbom = NormalizedSbom::default();
        use crate::model::Component;
        for n in ["a", "b", "c"] {
            let c = Component::new(n.to_string(), n.to_string());
            sbom.components.insert(c.canonical_id.clone(), c);
        }
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.requirement.contains("PRE-7-RQ-07-RE")),
            "No vendor components → no [PRE-7-RQ-07-RE] violation"
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // P2 tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn art_13_2_warns_when_no_risk_assessment_referenced() {
        let sbom = NormalizedSbom::default();
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let v = result.violations.iter().find(|v| {
            v.requirement.contains("Art. 13(2)") && v.severity == ViolationSeverity::Warning
        });
        assert!(v.is_some(), "Empty SBOM should produce Art. 13(2) Warning");
    }

    #[test]
    fn art_13_2_silenced_by_sidecar_risk_assessment_url() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            risk_assessment_url: Some("https://example.com/ra.pdf".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.requirement.contains("Art. 13(2)")),
            "Sidecar risk_assessment_url should suppress Art. 13(2) violation"
        );
    }

    #[test]
    fn article_14_pre_deadline_emits_info_only() {
        // The check uses the wall clock; today's date in tests will be
        // before/after 2026-09-11 depending on when tests run. We assert
        // the *existence* of the readiness violations rather than exact
        // severity, then verify with-sidecar suppresses.
        let sbom = NormalizedSbom::default();
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let art14_count = result
            .violations
            .iter()
            .filter(|v| v.requirement.contains("Art. 14"))
            .count();
        assert!(
            art14_count >= 4,
            "Art. 14 readiness should produce ≥4 violations (PSIRT, 14(1), 14(2), 14(7)); got {art14_count}"
        );
    }

    /// Pre-deadline (mocked clock 2026-04-26): all four channels missing.
    /// PSIRT/14(1)/14(2) surface as Info; 14(7) (ENISA platform) is always Info.
    /// Total: 4 Infos, 0 Warnings, 0 Errors at Art. 14 level.
    #[test]
    fn article_14_pre_deadline_mocked_clock_emits_4_infos() {
        let checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
        let mut violations = Vec::new();
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-26T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        checker.check_article_14_readiness_at(now, &mut violations);

        let infos = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Info && v.requirement.contains("Art. 14"))
            .count();
        let warnings = violations
            .iter()
            .filter(|v| {
                v.severity == ViolationSeverity::Warning && v.requirement.contains("Art. 14")
            })
            .count();
        assert_eq!(
            infos, 4,
            "Pre-deadline expects 4 Info-level Art. 14 findings; got {infos} (full list: {violations:?})"
        );
        assert_eq!(
            warnings, 0,
            "Pre-deadline expects 0 Warning-level Art. 14 findings"
        );
    }

    /// Post-deadline (mocked clock 2026-12-01): same SBOM-less state, but
    /// PSIRT/14(1)/14(2) become Warnings; 14(7) stays Info.
    /// Total: 1 Info, 3 Warnings.
    #[test]
    fn article_14_post_deadline_mocked_clock_emits_3_warnings_1_info() {
        let checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
        let mut violations = Vec::new();
        let now = chrono::DateTime::parse_from_rfc3339("2026-12-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        checker.check_article_14_readiness_at(now, &mut violations);

        let infos = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Info && v.requirement.contains("Art. 14"))
            .count();
        let warnings = violations
            .iter()
            .filter(|v| {
                v.severity == ViolationSeverity::Warning && v.requirement.contains("Art. 14")
            })
            .count();
        assert_eq!(
            warnings, 3,
            "Post-deadline expects 3 Warning-level Art. 14 findings (PSIRT/14(1)/14(2)); got {warnings} (full: {violations:?})"
        );
        assert_eq!(
            infos, 1,
            "Post-deadline expects 1 Info-level Art. 14 finding (Art. 14(7) ENISA platform stays Info regardless of date)"
        );
    }

    #[test]
    fn article_14_sidecar_suppresses_psirt_warning() {
        use crate::model::CraSidecarMetadata;
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            psirt_url: Some("https://example.com/psirt".to_string()),
            early_warning_contact: Some("psirt@example.com".to_string()),
            incident_report_contact: Some("ir@example.com".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        // PSIRT, 14(1), 14(2) suppressed; 14(7) (ENISA platform) remains as Info.
        let art_14_psirt = result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Art. 14: PSIRT"));
        let art_14_1 = result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Art. 14(1)"));
        let art_14_2 = result
            .violations
            .iter()
            .any(|v| v.requirement.contains("Art. 14(2)"));
        assert!(
            !art_14_psirt,
            "Sidecar psirt_url should suppress PSIRT check"
        );
        assert!(
            !art_14_1,
            "Sidecar early_warning_contact should suppress 14(1)"
        );
        assert!(
            !art_14_2,
            "Sidecar incident_report_contact should suppress 14(2)"
        );
    }

    #[test]
    fn direct_dep_missing_supplier_is_error_under_cra_phase2() {
        use crate::model::{Component, DependencyEdge, DependencyType};
        let mut sbom = NormalizedSbom::default();
        // Primary "app" with one direct dep "lib" missing supplier.
        let app = Component::new("app".to_string(), "app".to_string())
            .with_purl("pkg:cargo/app@1.0".to_string());
        let lib = Component::new("lib".to_string(), "lib".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        let app_id = app.canonical_id.clone();
        let lib_id = lib.canonical_id.clone();
        sbom.primary_component_id = Some(app_id.clone());
        sbom.components.insert(app_id.clone(), app);
        sbom.components.insert(lib_id.clone(), lib);
        sbom.edges.push(DependencyEdge::new(
            app_id,
            lib_id,
            DependencyType::DependsOn,
        ));
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let v = result.violations.iter().find(|v| {
            v.requirement.contains("Direct dependency supplier")
                && v.severity == ViolationSeverity::Error
        });
        assert!(
            v.is_some(),
            "Direct dep without supplier should produce an Error under CraPhase2"
        );
    }

    #[test]
    fn transitive_dep_missing_supplier_is_softer_than_direct() {
        use crate::model::{Component, DependencyEdge, DependencyType, Organization};
        let mut sbom = NormalizedSbom::default();
        // app → lib (with supplier) → deep (no supplier)
        let mut app = Component::new("app".to_string(), "app".to_string())
            .with_purl("pkg:cargo/app@1.0".to_string());
        app.supplier = Some(Organization::new("AppCorp".to_string()));
        let mut lib = Component::new("lib".to_string(), "lib".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        lib.supplier = Some(Organization::new("LibCorp".to_string()));
        let deep = Component::new("deep".to_string(), "deep".to_string())
            .with_purl("pkg:cargo/deep@1.0".to_string());
        let app_id = app.canonical_id.clone();
        let lib_id = lib.canonical_id.clone();
        let deep_id = deep.canonical_id.clone();
        sbom.primary_component_id = Some(app_id.clone());
        sbom.components.insert(app_id.clone(), app);
        sbom.components.insert(lib_id.clone(), lib);
        sbom.components.insert(deep_id.clone(), deep);
        sbom.edges.push(DependencyEdge::new(
            app_id,
            lib_id.clone(),
            DependencyType::DependsOn,
        ));
        sbom.edges.push(DependencyEdge::new(
            lib_id,
            deep_id,
            DependencyType::DependsOn,
        ));
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let direct_err = result.violations.iter().any(|v| {
            v.requirement.contains("Direct dependency supplier")
                && v.severity == ViolationSeverity::Error
        });
        let transitive = result
            .violations
            .iter()
            .find(|v| v.requirement.contains("Transitive dependency supplier"));
        assert!(
            !direct_err,
            "No direct deps lack a supplier; should not error"
        );
        assert!(transitive.is_some(), "Transitive dep should be reported");
        assert_ne!(
            transitive.unwrap().severity,
            ViolationSeverity::Error,
            "Transitive supplier missing should never be Error (it's recommended, not mandatory)"
        );
    }

    #[test]
    fn bsi_tr_03183_2_empty_sbom_emits_errors() {
        let sbom = NormalizedSbom::default();
        let result = ComplianceChecker::new(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.requirement.contains("BSI TR-03183-2 §5.1")
                    && v.severity == ViolationSeverity::Error),
            "Empty SBOM should fail BSI §5.1"
        );
    }

    #[test]
    fn bsi_tr_03183_2_flags_missing_strong_hash() {
        use crate::model::{Component, Hash, HashAlgorithm};
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("lib".to_string(), "lib".to_string())
            .with_purl("pkg:cargo/lib@1.0".to_string());
        // Add only a weak hash
        c.hashes.push(Hash::new(HashAlgorithm::Md5, "0".repeat(32)));
        sbom.add_component(c);
        let result = ComplianceChecker::new(ComplianceLevel::BsiTr03183_2).check(&sbom);
        assert!(
            result.violations.iter().any(|v| {
                v.requirement.contains("BSI TR-03183-2 §5.4")
                    && v.severity == ViolationSeverity::Error
            }),
            "Component without SHA-256+ hash should fail BSI §5.4"
        );
    }

    #[test]
    fn bsi_tr_03183_2_passes_for_complete_component() {
        use crate::model::{
            Component, Creator, CreatorType, DependencyEdge, DependencyType, Hash, HashAlgorithm,
            LicenseExpression, Organization,
        };
        let mut sbom = NormalizedSbom::default();
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Tool,
            name: "sbom-tools".to_string(),
            email: None,
        });
        let mut a = Component::new("a".to_string(), "a".to_string())
            .with_purl("pkg:cargo/a@1.0".to_string())
            .with_version("1.0".to_string());
        a.hashes
            .push(Hash::new(HashAlgorithm::Sha256, "f".repeat(64)));
        a.supplier = Some(Organization::new("SupplierA".to_string()));
        a.licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        let mut b = Component::new("b".to_string(), "b".to_string())
            .with_purl("pkg:cargo/b@1.0".to_string())
            .with_version("1.0".to_string());
        b.hashes
            .push(Hash::new(HashAlgorithm::Sha256, "0".repeat(64)));
        b.supplier = Some(Organization::new("SupplierB".to_string()));
        b.licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        let a_id = a.canonical_id.clone();
        let b_id = b.canonical_id.clone();
        sbom.components.insert(a_id.clone(), a);
        sbom.components.insert(b_id.clone(), b);
        sbom.edges
            .push(DependencyEdge::new(a_id, b_id, DependencyType::DependsOn));

        let result = ComplianceChecker::new(ComplianceLevel::BsiTr03183_2).check(&sbom);
        let errors: Vec<_> = result
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "Complete BSI-compliant SBOM should produce no Errors; got: {errors:?}"
        );
    }

    #[test]
    fn bsi_tr_03183_2_in_compliance_level_all() {
        assert_eq!(ComplianceLevel::all().len(), 12);
        assert!(ComplianceLevel::all().contains(&ComplianceLevel::BsiTr03183_2));
    }

    #[test]
    fn sidecar_does_not_override_present_sbom_field() {
        use crate::model::{CraSidecarMetadata, Creator, CreatorType};
        let mut sbom = NormalizedSbom::default();
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Organization,
            name: "SbomDeclaredCorp".to_string(),
            email: None,
        });
        let sidecar = CraSidecarMetadata {
            manufacturer_name: Some("SidecarCorp".to_string()),
            ..Default::default()
        };
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2)
            .with_sidecar(sidecar)
            .check(&sbom);
        // No Art. 13(15) violation at all because SBOM provides org
        assert!(
            !result.violations.iter().any(|v| v
                .requirement
                .contains("Art. 13(15): Manufacturer identification")),
            "When SBOM provides manufacturer, no Art. 13(15) violation should be emitted"
        );
    }
}
