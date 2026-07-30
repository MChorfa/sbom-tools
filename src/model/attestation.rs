//! Normalized CycloneDX 1.6 Attestations (CDXA) evidence model.
//!
//! CycloneDX 1.6 introduced a root-level `declarations` object (CDXA) carrying
//! machine-readable conformance evidence — assessors, attestations, claims,
//! evidence, targets, and an affirmation — plus a root-level
//! `definitions.standards` list of machine-readable standard encodings whose
//! requirements the attestations map claims onto. This module is the
//! format-agnostic home for that evidence after parsing; the compliance engine
//! consumes it so rules that today rely on sidecar self-declarations or
//! external-reference presence bits can consume signed, machine-readable
//! evidence instead.
//!
//! Struct shapes were coded from the frozen CycloneDX 1.6 schema tag
//! (<https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json>).
//!
//! # Verification scope (phase 1): structural with signature PRESENCE only
//!
//! JSF signature objects (`declarations.signature`, and the `signature` slots
//! on claims, evidence, attestations, standards, the affirmation, and its
//! signatories) are parsed for PRESENCE — which algorithm they name, which
//! key/signatories they identify, how many signers — but are **never
//! cryptographically verified**. Every evidence level reported from this
//! module is therefore capped at [`EvidenceLevel::SignaturePresent`];
//! [`EvidenceLevel::SignatureVerified`] exists in the enum for output-schema
//! stability but is unreachable until a later phase implements JSF
//! verification.
//!
//! # Fail-closed reference resolution
//!
//! All CDXA refLinks (`claim.target`, `claim.evidence[]`, `attestation.map[]
//! .requirement`, …) are resolved at parse time against the declarations-local
//! bom-refs, the `definitions.standards` bom-refs, the `declarations.targets`
//! entries, and the BOM inventory (component/service bom-refs, including the
//! parser's purl-fallback keys). Unresolvable refs are kept and marked
//! [`CdxaResolution::Dangling`] — the parser's tolerance convention, never a
//! parse error — and fail closed at query time: a dangling ref can never help
//! satisfy a requirement (see [`AttestationDeclarations::supported_requirements`]).
//!
//! # Phase 2 (external in-toto / DSSE bundles) — out of scope here
//!
//! Ingestion of external in-toto attestation bundles (`*.intoto.jsonl`, DSSE
//! envelopes, SLSA provenance/VSA, test-result, vulns predicates) is a
//! separate, later phase and deliberately has no surface in this module.
//! Recorded for that phase (verified against
//! <https://github.com/in-toto/attestation/blob/main/spec/predicates/vuln.md>):
//! the in-toto vulns predicate marks `scanner.db.lastUpdate` as REQUIRED
//! (while `scanner.db.uri`/`scanner.db.version` are optional), and nests the
//! required result fields under an OPTIONAL `vulnerability` wrapper —
//! `scanner.result[*].vulnerability.id` / `.severity.method` /
//! `.severity.score` — with an empty result list being valid (no findings).
//! A phase-2 well-formedness check must model both or valid attestations will
//! be misclassified.

use super::{CanonicalId, Contact, ExternalReference, Organization};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How strongly a piece of compliance evidence is attested.
///
/// Ordered: `SelfDeclared < Structural < SignaturePresent < SignatureVerified`.
/// Phase 1 (this module) emits at most [`Self::SignaturePresent`] — signature
/// objects are recorded, never cryptographically verified — so
/// [`Self::SignatureVerified`] is currently unreachable and reserved for a
/// later verification phase.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum EvidenceLevel {
    /// Sidecar self-declaration or external-reference presence bit.
    #[default]
    SelfDeclared,
    /// Parsed machine-readable declarations without any signature.
    Structural,
    /// A JSF signature object exists and names a signatory; NOT verified.
    SignaturePresent,
    /// Cryptographically verified signature. Unreachable in phase 1/2.
    SignatureVerified,
}

impl std::fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SelfDeclared => write!(f, "self-declared"),
            Self::Structural => write!(f, "structural"),
            Self::SignaturePresent => write!(f, "signature-present"),
            Self::SignatureVerified => write!(f, "signature-verified"),
        }
    }
}

/// Structural record that a JSF (JSON Signature Format) signature object was
/// present, and what it names.
///
/// PRESENCE ONLY: the signature bytes are neither retained nor verified.
/// Consumers must treat this as [`EvidenceLevel::SignaturePresent`] at most.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignaturePresence {
    /// Signature algorithm named by the JSF object (e.g. "ES256"), when the
    /// object (or its first signer) declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// `keyId` named by the JSF object (or its first signer), when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Number of signers: 1 for the single-signature JSF form, the array
    /// length for the `signers`/`chain` multi-signature forms.
    pub signer_count: usize,
}

impl SignaturePresence {
    /// Structurally inspect a raw JSF signature value.
    ///
    /// Handles the three JSF top-level forms (single signature, `signers`
    /// array, `chain` array). Returns `None` for non-object values. No
    /// cryptographic verification is performed.
    #[must_use]
    pub fn from_jsf(value: &serde_json::Value) -> Option<Self> {
        let obj = value.as_object()?;
        for multi_key in ["signers", "chain"] {
            if let Some(entries) = obj.get(multi_key).and_then(|v| v.as_array()) {
                let first = entries.first().and_then(|v| v.as_object());
                return Some(Self {
                    algorithm: first
                        .and_then(|o| o.get("algorithm"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    key_id: first
                        .and_then(|o| o.get("keyId"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    signer_count: entries.len(),
                });
            }
        }
        Some(Self {
            algorithm: obj
                .get("algorithm")
                .and_then(|v| v.as_str())
                .map(String::from),
            key_id: obj.get("keyId").and_then(|v| v.as_str()).map(String::from),
            signer_count: 1,
        })
    }
}

/// Where a CDXA refLink resolved at parse time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CdxaResolution {
    /// A `declarations.claims[]` entry.
    Claim,
    /// A `declarations.evidence[]` entry.
    Evidence,
    /// A `declarations.assessors[]` entry.
    Assessor,
    /// A `definitions.standards[]` entry or one of its `requirements[]`.
    Requirement,
    /// A `declarations.targets` entry (organization/component/service listed
    /// as a claim target but not part of the BOM inventory).
    Target,
    /// A component or service in the BOM inventory, resolved by bom-ref or
    /// by the parser's purl-fallback key.
    Inventory(CanonicalId),
    /// Unresolvable anywhere in the document. Fail closed: a dangling ref
    /// never supports any requirement.
    Dangling,
}

/// A CDXA refLink with its parse-time resolution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CdxaRef {
    /// The raw refLink string as it appeared in the document.
    pub raw: String,
    /// What the refLink resolved to.
    pub resolution: CdxaResolution,
}

impl CdxaRef {
    /// Whether the ref resolved to anything in the document.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        !matches!(self.resolution, CdxaResolution::Dangling)
    }
}

/// A `declarations.assessors[]` entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeclaredAssessor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    /// `true` = assessor is outside the organization generating claims;
    /// `false` = self assessor; `None` = not stated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub third_party: Option<bool>,
    /// The entity issuing the assessment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<Organization>,
}

/// A `declarations.attestations[]` entry: an assessor's mapping of standard
/// requirements to claims.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AttestationAssertion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// refLink into `declarations.assessors[]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessor: Option<CdxaRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub map: Vec<AttestationMapEntry>,
    /// JSF signature presence (structural only, never verified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignaturePresence>,
}

/// One `attestations[].map[]` entry: requirement → claims, with the
/// attestor's declared conformance and confidence.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AttestationMapEntry {
    /// refLink to the requirement being attested to
    /// (`definitions.standards[].requirements[]` bom-ref).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirement: Option<CdxaRef>,
    /// refLinks to the claims being attested to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<CdxaRef>,
    /// refLinks to counter claims. Any entry contests the attestation:
    /// the map entry then satisfies nothing (surfaced, never silently passed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counter_claims: Vec<CdxaRef>,
    /// Conformance score in `0..=1`, where 1 is 100% conformance. Anything
    /// below 1 is partial conformance and never auto-satisfies a rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformance_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformance_rationale: Option<String>,
    /// refLinks to evidence describing mitigation strategies for conformance
    /// gaps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conformance_mitigation_strategies: Vec<CdxaRef>,
    /// Confidence score in `0..=1`, where 1 is 100% confidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_rationale: Option<String>,
}

/// A `declarations.claims[]` entry: a statement about a target.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeclaredClaim {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    /// refLink to the target the claim applies to. The schema permits any
    /// bom-ref'd element (team, process, business unit, …); this engine
    /// resolves against `declarations.targets` entries and the BOM inventory
    /// (a fail-closed design choice of this tool, not schema text).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<CdxaRef>,
    /// The specific statement or assertion about the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
    /// refLinks to evidence describing how weaknesses in the claim's
    /// evidence are mitigated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitigation_strategies: Vec<CdxaRef>,
    /// Why the evidence substantiates the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    /// refLinks into `declarations.evidence[]` supporting the claim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<CdxaRef>,
    /// refLinks to counter evidence. Any entry contests the claim: the claim
    /// then supports nothing (surfaced, never silently passed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counter_evidence: Vec<CdxaRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_refs: Vec<ExternalReference>,
    /// JSF signature presence (structural only, never verified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignaturePresence>,
}

/// One `evidence[].data[]` entry: output or analysis that supports claims.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EvidenceDataItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `contents.url` — where the data can be retrieved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Whether `contents.attachment` embedded the data inline (the attachment
    /// body itself is not retained in the normalized model).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_attachment: bool,
    /// Data classification tag (type/sensitivity/value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    /// Descriptions of any sensitive data included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_data: Vec<String>,
    /// Whether a `governance` block (custodians/stewards/owners) was present.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_governance: bool,
}

/// A `declarations.evidence[]` entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeclaredEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    /// CycloneDX Property Taxonomy reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data: Vec<EvidenceDataItem>,
    /// When the evidence was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    /// When the evidence stops being valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<Contact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<Contact>,
    /// JSF signature presence (structural only, never verified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignaturePresence>,
}

impl DeclaredEvidence {
    /// Whether the evidence may count toward satisfying a requirement at the
    /// evaluation instant `as_of` (the compliance engine's injectable clock,
    /// never an inline wall-clock read).
    ///
    /// Fail closed: evidence with `expires <= as_of` (expired) or
    /// `created > as_of` (anachronistic — created in the future relative to
    /// the evaluation instant) never counts. Missing timestamps impose no
    /// constraint.
    #[must_use]
    pub fn is_fresh(&self, as_of: DateTime<Utc>) -> bool {
        if let Some(expires) = self.expires
            && expires <= as_of
        {
            return false;
        }
        if let Some(created) = self.created
            && created > as_of
        {
            return false;
        }
        true
    }
}

/// One entry of `declarations.targets` (organization, component, or service
/// listed as a claim target). These are NOT part of the BOM inventory; only
/// their identity is retained so claim targets can resolve to them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeclarationTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The `declarations.targets` object.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeclarationTargets {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organizations: Vec<DeclarationTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<DeclarationTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<DeclarationTarget>,
}

/// A `declarations.affirmation.signatories[]` entry.
///
/// The 1.6 schema constrains each signatory with a `oneOf`: it must carry
/// either a JSF `signature` OR both `externalReference` and `organization`.
/// [`Self::has_complete_identity`] reports that constraint; violating
/// signatories have unusable identity and cannot raise the document's
/// evidence level.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AffirmationSignatory {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// JSF signature presence (structural only, never verified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignaturePresence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<Organization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_reference: Option<ExternalReference>,
}

impl AffirmationSignatory {
    /// Whether the signatory satisfies the schema's identity `oneOf`:
    /// a signature, or both an external reference and an organization.
    #[must_use]
    pub fn has_complete_identity(&self) -> bool {
        self.signature.is_some()
            || (self.external_reference.is_some() && self.organization.is_some())
    }
}

/// The `declarations.affirmation` object.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeclaredAffirmation {
    /// The statement affirmed regarding all declarations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatories: Vec<AffirmationSignatory>,
    /// JSF signature presence (structural only, never verified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignaturePresence>,
}

/// One `definitions.standards[].requirements[]` entry.
///
/// Field set follows the frozen 1.6 schema: `text` is a plain string,
/// `descriptions` is a PLURAL array of supplemental strings, `openCre` is an
/// array of `CRE:x-y` identifiers, `parent` is a refLink to a parent
/// requirement. (`properties` are not normalized in phase 1.)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DefinedRequirement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    /// The identifier used IN THE STANDARD (e.g. SSDF practice "PS.1") — not
    /// the bom-ref. This is what maps to engine rule families.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub descriptions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_cre: Vec<String>,
    /// refLink to the parent requirement (hierarchy), kept raw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_refs: Vec<ExternalReference>,
}

/// One `definitions.standards[]` entry: a machine-readable standard encoding.
/// (`levels` are not normalized in phase 1.)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DefinedStandard {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<DefinedRequirement>,
    /// JSF signature presence (structural only, never verified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignaturePresence>,
}

/// Normalized CDXA evidence: CycloneDX 1.6 `declarations` plus the
/// `definitions.standards` encodings its attestations map into.
///
/// Attached at [`crate::model::FormatExtensions::declarations`] (reachable
/// via [`crate::model::NormalizedSbom::declarations`]). Populated only by the
/// CycloneDX JSON parser for `specVersion >= 1.6` documents that carry these
/// sections; `None` for SPDX, older CycloneDX, and XML input — and skipped in
/// serialization when absent, so documents without declarations serialize
/// byte-identically to previous releases.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AttestationDeclarations {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assessors: Vec<DeclaredAssessor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<AttestationAssertion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<DeclaredClaim>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<DeclaredEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<DeclarationTargets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affirmation: Option<DeclaredAffirmation>,
    /// Document-level JSF signature presence over the declarations
    /// (structural only, never verified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignaturePresence>,
    /// `definitions.standards[]` — the standard encodings attestation map
    /// entries refLink their requirements into.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standards: Vec<DefinedStandard>,
}

/// Engine rule families that CDXA evidence can strengthen. Requirements whose
/// (standard, identifier) pair classifies into none of these are recorded but
/// satisfy nothing (unknown-content handling: fail-open for recognition,
/// fail-closed for satisfaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationRuleFamily {
    /// NIST SSDF practice rules (`SBOM-SSDF-*`).
    Ssdf,
    /// EO 14028 4(e) rules (`SBOM-EO14028-*`).
    Eo14028,
    /// EU CRA conformity rules (`SBOM-CRA-*`).
    Cra,
}

impl AttestationRuleFamily {
    /// Classify a (standard, requirement) pair into an engine rule family.
    ///
    /// Standard-level text wins over identifier shape so that, e.g., an
    /// EO 14028 encoding that reuses SSDF practice identifiers classifies as
    /// EO 14028; unlabeled standards fall back to the SSDF practice-identifier
    /// pattern (`PO.n` / `PS.n` / `PW.n` / `RV.n`). Returns `None` for
    /// unknown pairs — recorded, but never able to influence a verdict.
    #[must_use]
    pub fn classify(standard: &DefinedStandard, requirement: &DefinedRequirement) -> Option<Self> {
        let hay = format!(
            "{} {} {}",
            standard.name.as_deref().unwrap_or(""),
            standard.description.as_deref().unwrap_or(""),
            standard.owner.as_deref().unwrap_or("")
        )
        .to_lowercase();
        if hay.contains("ssdf") || hay.contains("secure software development framework") {
            return Some(Self::Ssdf);
        }
        if hay.contains("14028") || hay.contains("executive order") {
            return Some(Self::Eo14028);
        }
        if hay.contains("cyber resilience")
            || hay
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|token| token == "cra")
        {
            return Some(Self::Cra);
        }
        if Self::is_ssdf_practice_id(requirement.identifier.as_deref()) {
            return Some(Self::Ssdf);
        }
        None
    }

    /// SSDF practice identifier shape: `PO.n` / `PS.n` / `PW.n` / `RV.n`.
    fn is_ssdf_practice_id(identifier: Option<&str>) -> bool {
        let Some(identifier) = identifier else {
            return false;
        };
        let id = identifier.trim().to_ascii_uppercase();
        ["PO.", "PS.", "PW.", "RV."].iter().any(|prefix| {
            id.strip_prefix(prefix)
                .is_some_and(|rest| rest.chars().next().is_some_and(|c| c.is_ascii_digit()))
        })
    }
}

/// A standard requirement that resolved CDXA evidence fully supports at the
/// evaluation instant (see [`AttestationDeclarations::supported_requirements`]
/// for the fail-closed criteria). Borrows from the declarations it was
/// computed over; a query result, not a serialized artifact.
#[derive(Debug, Clone)]
pub struct SupportedRequirement<'a> {
    /// The standard encoding the requirement belongs to.
    pub standard: &'a DefinedStandard,
    /// The requirement itself (its `identifier` is the standard's own ID,
    /// e.g. SSDF "PS.1").
    pub requirement: &'a DefinedRequirement,
    /// The attestation asserting the mapping.
    pub attestation: &'a AttestationAssertion,
    /// The map entry connecting requirement to claims.
    pub map_entry: &'a AttestationMapEntry,
    /// The claims that survived fail-closed filtering (resolved target,
    /// no counter evidence, at least one resolving fresh evidence item).
    pub supporting_claims: Vec<&'a DeclaredClaim>,
    /// Evidence strength: [`EvidenceLevel::SignaturePresent`] when the
    /// declarations, the attestation, a supporting claim, or a supporting
    /// evidence item carries a JSF signature object; otherwise
    /// [`EvidenceLevel::Structural`]. Never `SignatureVerified` in phase 1.
    pub evidence_level: EvidenceLevel,
    /// Whether the asserting assessor resolved and declared
    /// `thirdParty: true`.
    pub third_party_assessed: bool,
}

impl AttestationDeclarations {
    /// Look up a claim by its bom-ref.
    #[must_use]
    pub fn claim_by_ref(&self, bom_ref: &str) -> Option<&DeclaredClaim> {
        self.claims
            .iter()
            .find(|c| c.bom_ref.as_deref() == Some(bom_ref))
    }

    /// Look up an evidence item by its bom-ref.
    #[must_use]
    pub fn evidence_by_ref(&self, bom_ref: &str) -> Option<&DeclaredEvidence> {
        self.evidence
            .iter()
            .find(|e| e.bom_ref.as_deref() == Some(bom_ref))
    }

    /// Look up an assessor by its bom-ref.
    #[must_use]
    pub fn assessor_by_ref(&self, bom_ref: &str) -> Option<&DeclaredAssessor> {
        self.assessors
            .iter()
            .find(|a| a.bom_ref.as_deref() == Some(bom_ref))
    }

    /// Resolve a requirement refLink to its (standard, requirement) pair.
    #[must_use]
    pub fn requirement_by_ref(
        &self,
        bom_ref: &str,
    ) -> Option<(&DefinedStandard, &DefinedRequirement)> {
        self.standards.iter().find_map(|standard| {
            standard
                .requirements
                .iter()
                .find(|req| req.bom_ref.as_deref() == Some(bom_ref))
                .map(|req| (standard, req))
        })
    }

    /// The document-wide evidence ceiling: [`EvidenceLevel::SignaturePresent`]
    /// when the declarations themselves, the affirmation, or any signatory
    /// carries a JSF signature object; [`EvidenceLevel::Structural`]
    /// otherwise. Never `SignatureVerified` — phase 1 records signature
    /// presence only.
    #[must_use]
    pub fn document_evidence_level(&self) -> EvidenceLevel {
        let affirmation_signed = self.affirmation.as_ref().is_some_and(|a| {
            a.signature.is_some() || a.signatories.iter().any(|s| s.signature.is_some())
        });
        if self.signature.is_some() || affirmation_signed {
            EvidenceLevel::SignaturePresent
        } else {
            EvidenceLevel::Structural
        }
    }

    /// The standard requirements this document's attestations fully support
    /// at the evaluation instant `as_of` (pass the compliance engine's
    /// injectable clock — `ComplianceChecker::now()` — never an inline
    /// wall-clock read).
    ///
    /// Fail-closed criteria — an attestation map entry supports its
    /// requirement only when ALL hold:
    ///
    /// 1. its `requirement` refLink resolves to a
    ///    `definitions.standards[].requirements[]` entry;
    /// 2. its declared conformance score is full (`>= 1.0`; the schema caps
    ///    at 1). Partial conformance is surfaced elsewhere, never
    ///    auto-satisfied;
    /// 3. it carries no `counterClaims`;
    /// 4. at least one `claims` refLink resolves to a claim whose target
    ///    resolves, that carries no `counterEvidence`, and that cites at
    ///    least one resolving evidence item fresh at `as_of`
    ///    ([`DeclaredEvidence::is_fresh`]).
    ///
    /// Dangling refs anywhere in the chain simply drop that path — the
    /// parser's tolerance convention keeps them in the model (marked
    /// [`CdxaResolution::Dangling`]) for rules that surface them.
    #[must_use]
    pub fn supported_requirements(&self, as_of: DateTime<Utc>) -> Vec<SupportedRequirement<'_>> {
        let mut supported = Vec::new();
        for attestation in &self.attestations {
            for entry in &attestation.map {
                let Some(requirement_ref) = &entry.requirement else {
                    continue;
                };
                if !matches!(requirement_ref.resolution, CdxaResolution::Requirement) {
                    continue;
                }
                let Some((standard, requirement)) = self.requirement_by_ref(&requirement_ref.raw)
                else {
                    continue;
                };
                if !entry.conformance_score.is_some_and(|score| score >= 1.0) {
                    continue;
                }
                if !entry.counter_claims.is_empty() {
                    continue;
                }

                let mut supporting_claims = Vec::new();
                let mut supporting_evidence_signed = false;
                for claim_ref in &entry.claims {
                    if !matches!(claim_ref.resolution, CdxaResolution::Claim) {
                        continue;
                    }
                    let Some(claim) = self.claim_by_ref(&claim_ref.raw) else {
                        continue;
                    };
                    if !claim.target.as_ref().is_some_and(CdxaRef::is_resolved) {
                        continue;
                    }
                    if !claim.counter_evidence.is_empty() {
                        continue;
                    }
                    let fresh_evidence: Vec<&DeclaredEvidence> = claim
                        .evidence
                        .iter()
                        .filter(|e| matches!(e.resolution, CdxaResolution::Evidence))
                        .filter_map(|e| self.evidence_by_ref(&e.raw))
                        .filter(|evidence| evidence.is_fresh(as_of))
                        .collect();
                    if fresh_evidence.is_empty() {
                        continue;
                    }
                    if claim.signature.is_some()
                        || fresh_evidence.iter().any(|e| e.signature.is_some())
                    {
                        supporting_evidence_signed = true;
                    }
                    supporting_claims.push(claim);
                }
                if supporting_claims.is_empty() {
                    continue;
                }

                let signature_present = self.signature.is_some()
                    || attestation.signature.is_some()
                    || supporting_evidence_signed;
                let evidence_level = if signature_present {
                    EvidenceLevel::SignaturePresent
                } else {
                    EvidenceLevel::Structural
                };
                let third_party_assessed = attestation
                    .assessor
                    .as_ref()
                    .filter(|a| matches!(a.resolution, CdxaResolution::Assessor))
                    .and_then(|a| self.assessor_by_ref(&a.raw))
                    .and_then(|a| a.third_party)
                    .unwrap_or(false);

                supported.push(SupportedRequirement {
                    standard,
                    requirement,
                    attestation,
                    map_entry: entry,
                    supporting_claims,
                    evidence_level,
                    third_party_assessed,
                });
            }
        }
        supported
    }

    /// [`Self::supported_requirements`] filtered to the requirements whose
    /// (standard, identifier) pair classifies into `family`
    /// ([`AttestationRuleFamily::classify`]). Unknown pairs never appear —
    /// they are recorded in the model but cannot influence a verdict.
    #[must_use]
    pub fn evidence_for_family(
        &self,
        family: AttestationRuleFamily,
        as_of: DateTime<Utc>,
    ) -> Vec<SupportedRequirement<'_>> {
        self.supported_requirements(as_of)
            .into_iter()
            .filter(|s| AttestationRuleFamily::classify(s.standard, s.requirement) == Some(family))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .expect("test timestamp must parse")
            .with_timezone(&Utc)
    }

    #[test]
    fn evidence_level_ordering_reflects_strength() {
        assert!(EvidenceLevel::SelfDeclared < EvidenceLevel::Structural);
        assert!(EvidenceLevel::Structural < EvidenceLevel::SignaturePresent);
        assert!(EvidenceLevel::SignaturePresent < EvidenceLevel::SignatureVerified);
    }

    #[test]
    fn signature_presence_handles_all_jsf_forms() {
        let single = serde_json::json!({"algorithm": "ES256", "keyId": "k1", "value": "sig"});
        let presence = SignaturePresence::from_jsf(&single).expect("object form");
        assert_eq!(presence.algorithm.as_deref(), Some("ES256"));
        assert_eq!(presence.key_id.as_deref(), Some("k1"));
        assert_eq!(presence.signer_count, 1);

        let signers = serde_json::json!({"signers": [
            {"algorithm": "Ed25519", "value": "a"},
            {"algorithm": "ES256", "value": "b"}
        ]});
        let presence = SignaturePresence::from_jsf(&signers).expect("signers form");
        assert_eq!(presence.algorithm.as_deref(), Some("Ed25519"));
        assert_eq!(presence.signer_count, 2);

        let chain = serde_json::json!({"chain": [{"algorithm": "RS256", "value": "a"}]});
        let presence = SignaturePresence::from_jsf(&chain).expect("chain form");
        assert_eq!(presence.signer_count, 1);
        assert_eq!(presence.algorithm.as_deref(), Some("RS256"));

        assert!(SignaturePresence::from_jsf(&serde_json::json!("not-an-object")).is_none());
    }

    #[test]
    fn evidence_freshness_fails_closed_on_expiry_and_future_creation() {
        let evidence = DeclaredEvidence {
            created: Some(ts("2026-01-10T00:00:00Z")),
            expires: Some(ts("2027-01-10T00:00:00Z")),
            ..DeclaredEvidence::default()
        };
        assert!(evidence.is_fresh(ts("2026-06-01T00:00:00Z")));
        // Expired: expires <= as_of.
        assert!(!evidence.is_fresh(ts("2027-01-10T00:00:00Z")));
        assert!(!evidence.is_fresh(ts("2027-06-01T00:00:00Z")));
        // Anachronistic: created in the future relative to the evaluation instant.
        assert!(!evidence.is_fresh(ts("2025-12-01T00:00:00Z")));
        // No timestamps: no constraint.
        assert!(DeclaredEvidence::default().is_fresh(ts("2026-06-01T00:00:00Z")));
    }

    #[test]
    fn rule_family_classification() {
        let ssdf = DefinedStandard {
            name: Some("NIST Secure Software Development Framework".to_string()),
            ..DefinedStandard::default()
        };
        let ps1 = DefinedRequirement {
            identifier: Some("PS.1".to_string()),
            ..DefinedRequirement::default()
        };
        assert_eq!(
            AttestationRuleFamily::classify(&ssdf, &ps1),
            Some(AttestationRuleFamily::Ssdf)
        );

        // Standard-level text wins over the SSDF identifier shape.
        let eo = DefinedStandard {
            name: Some("Executive Order 14028 4(e) attestation".to_string()),
            ..DefinedStandard::default()
        };
        assert_eq!(
            AttestationRuleFamily::classify(&eo, &ps1),
            Some(AttestationRuleFamily::Eo14028)
        );

        // Unlabeled standard falls back to the practice-identifier pattern.
        let unlabeled = DefinedStandard::default();
        assert_eq!(
            AttestationRuleFamily::classify(&unlabeled, &ps1),
            Some(AttestationRuleFamily::Ssdf)
        );

        // "CRA" must match as a token, not a substring (e.g. not "Scrappy").
        let scrappy = DefinedStandard {
            name: Some("Scrappy Custom Framework".to_string()),
            ..DefinedStandard::default()
        };
        let generic_req = DefinedRequirement {
            identifier: Some("REQ-1".to_string()),
            ..DefinedRequirement::default()
        };
        assert_eq!(
            AttestationRuleFamily::classify(&scrappy, &generic_req),
            None
        );
        let cra = DefinedStandard {
            name: Some("EU CRA Annex I encoding".to_string()),
            ..DefinedStandard::default()
        };
        assert_eq!(
            AttestationRuleFamily::classify(&cra, &generic_req),
            Some(AttestationRuleFamily::Cra)
        );
    }
}
