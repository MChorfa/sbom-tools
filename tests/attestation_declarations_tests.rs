//! CDXA (CycloneDX 1.6 Attestations) ingestion tests — phase 1.
//!
//! Covers: the `declarations` + `definitions.standards` fixture parsing into
//! the normalized model (claims/evidence/affirmation round out correctly),
//! refLink resolution through the parser's id_map (bom-ref first, purl
//! fallback), the parser's tolerance convention for unresolvable refs
//! (kept, marked `Dangling`, fail closed at query time), the specVersion
//! gate (declarations are never probed on <= 1.5 documents), and the
//! additive-serialization guarantee: documents WITHOUT declarations
//! serialize with no `declarations` key at all, so existing outputs stay
//! byte-identical.
//!
//! Scope check: signature objects surface as PRESENCE records only —
//! nothing in phase 1 verifies a JSF signature cryptographically, and the
//! reported evidence level is capped at `SignaturePresent`.

use chrono::{DateTime, Utc};
use sbom_tools::model::{AttestationRuleFamily, CdxaResolution, EvidenceLevel, NormalizedSbom};
use sbom_tools::{parse_sbom, parse_sbom_str};
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn parse_fixture(name: &str) -> NormalizedSbom {
    parse_sbom(&fixture_path(name)).expect("fixture must parse")
}

fn ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .expect("test timestamp must parse")
        .with_timezone(&Utc)
}

#[test]
fn fixture_declarations_parse_into_model() {
    let sbom = parse_fixture("cyclonedx/declarations-cdxa.cdx.json");
    let decls = sbom.declarations().expect("declarations must be populated");

    // Assessors
    assert_eq!(decls.assessors.len(), 1);
    let assessor = &decls.assessors[0];
    assert_eq!(assessor.bom_ref.as_deref(), Some("assessor-1"));
    assert_eq!(assessor.third_party, Some(true));
    assert_eq!(
        assessor.organization.as_ref().map(|o| o.name.as_str()),
        Some("Auditors Inc")
    );

    // Claims
    assert_eq!(decls.claims.len(), 3);
    let claim = decls
        .claim_by_ref("claim-provenance")
        .expect("claim-provenance");
    assert_eq!(
        claim.predicate.as_deref(),
        Some("Build provenance is generated and archived for every release build")
    );
    assert_eq!(
        claim.reasoning.as_deref(),
        Some("CI provenance archive reviewed during the 2026-01 audit")
    );
    assert_eq!(claim.evidence.len(), 1);
    assert_eq!(claim.evidence[0].raw, "ev-provenance");
    assert_eq!(claim.evidence[0].resolution, CdxaResolution::Evidence);
    // Signature PRESENCE only — algorithm recorded, nothing verified.
    let sig = claim.signature.as_ref().expect("claim signature presence");
    assert_eq!(sig.algorithm.as_deref(), Some("ES256"));
    assert_eq!(sig.signer_count, 1);

    // Evidence: timestamps, data, author round out.
    assert_eq!(decls.evidence.len(), 1);
    let evidence = decls
        .evidence_by_ref("ev-provenance")
        .expect("ev-provenance");
    assert_eq!(
        evidence.property_name.as_deref(),
        Some("internal:build:provenance")
    );
    assert_eq!(evidence.created, Some(ts("2026-01-10T00:00:00Z")));
    assert_eq!(evidence.expires, Some(ts("2027-01-10T00:00:00Z")));
    assert_eq!(evidence.data.len(), 1);
    assert_eq!(
        evidence.data[0].name.as_deref(),
        Some("provenance-2026-01.json")
    );
    assert_eq!(
        evidence.data[0].url.as_deref(),
        Some("https://evidence.acme.example/provenance/2026-01.json")
    );
    assert!(!evidence.data[0].has_attachment);
    assert_eq!(evidence.data[0].classification.as_deref(), Some("internal"));
    assert_eq!(
        evidence.author.as_ref().and_then(|a| a.email.as_deref()),
        Some("jane@acme.example")
    );
    assert!(evidence.signature.is_some());

    // Attestation map
    assert_eq!(decls.attestations.len(), 1);
    let attestation = &decls.attestations[0];
    assert_eq!(
        attestation.summary.as_deref(),
        Some("SSDF conformance attestation for acme-app 3.0.0")
    );
    let assessor_ref = attestation.assessor.as_ref().expect("assessor ref");
    assert_eq!(assessor_ref.resolution, CdxaResolution::Assessor);
    assert_eq!(attestation.map.len(), 3);
    let ps1_entry = &attestation.map[0];
    assert_eq!(ps1_entry.conformance_score, Some(1.0));
    assert_eq!(
        ps1_entry.conformance_rationale.as_deref(),
        Some("All code repositories enforce least privilege")
    );
    assert_eq!(ps1_entry.confidence_score, Some(0.9));

    // Affirmation: statement + signatory identity completeness (schema oneOf).
    let affirmation = decls.affirmation.as_ref().expect("affirmation");
    assert_eq!(
        affirmation.statement.as_deref(),
        Some("I certify, to the best of my knowledge, that all information is correct.")
    );
    assert_eq!(affirmation.signatories.len(), 2);
    assert!(affirmation.signatories[0].has_complete_identity());
    // Organization without externalReference and without signature violates
    // the schema oneOf: identity is unusable, flagged rather than rejected.
    assert!(!affirmation.signatories[1].has_complete_identity());

    // definitions.standards round out with requirement identifiers.
    assert_eq!(decls.standards.len(), 1);
    let standard = &decls.standards[0];
    assert_eq!(standard.version.as_deref(), Some("1.1"));
    assert_eq!(standard.requirements.len(), 2);
    let ps1 = &standard.requirements[0];
    assert_eq!(ps1.identifier.as_deref(), Some("PS.1"));
    assert_eq!(ps1.descriptions.len(), 1);
    assert_eq!(ps1.open_cre, vec!["CRE:764-507".to_string()]);

    // Targets
    let targets = decls.targets.as_ref().expect("targets");
    assert_eq!(targets.organizations.len(), 1);
    assert_eq!(
        targets.organizations[0].name.as_deref(),
        Some("Acme Product BU")
    );

    // Signature presence at document level: declarations root unsigned here,
    // but the affirmation signatory raises the ceiling to SignaturePresent.
    assert_eq!(
        decls.document_evidence_level(),
        EvidenceLevel::SignaturePresent
    );
}

#[test]
fn claim_targets_resolve_by_bom_ref_and_purl_fallback() {
    let sbom = parse_fixture("cyclonedx/declarations-cdxa.cdx.json");
    let decls = sbom.declarations().expect("declarations");

    // bom-ref target resolves to the primary component's canonical id.
    let by_bom_ref = decls
        .claim_by_ref("claim-provenance")
        .and_then(|c| c.target.as_ref())
        .expect("target");
    let primary_id = sbom
        .primary_component_id
        .clone()
        .expect("primary component");
    assert_eq!(
        by_bom_ref.resolution,
        CdxaResolution::Inventory(primary_id),
        "claim target must resolve through the same id_map as dependencies"
    );

    // purl target resolves through the id_map purl-fallback keys.
    let by_purl = decls
        .claim_by_ref("claim-purl-target")
        .and_then(|c| c.target.as_ref())
        .expect("target");
    let lib_id = sbom
        .components
        .values()
        .find(|c| c.name == "libalpha")
        .map(|c| c.canonical_id.clone())
        .expect("libalpha component");
    assert_eq!(by_purl.resolution, CdxaResolution::Inventory(lib_id));

    // Unresolvable refs are kept and marked Dangling (tolerance convention:
    // parse never fails), and fail closed at query time (next test).
    let dangling = decls.claim_by_ref("claim-dangling").expect("claim");
    assert_eq!(
        dangling.target.as_ref().map(|t| t.resolution.clone()),
        Some(CdxaResolution::Dangling)
    );
    assert_eq!(dangling.evidence[0].resolution, CdxaResolution::Dangling);
    // The map entry pointing at a requirement that exists nowhere dangles too.
    let unknown_req = &sbom.declarations().expect("declarations").attestations[0].map[2];
    assert_eq!(
        unknown_req
            .requirement
            .as_ref()
            .map(|r| r.resolution.clone()),
        Some(CdxaResolution::Dangling)
    );
}

#[test]
fn supported_requirements_fail_closed() {
    let sbom = parse_fixture("cyclonedx/declarations-cdxa.cdx.json");
    let decls = sbom.declarations().expect("declarations");

    // Within the evidence validity window: only PS.1 is supported.
    // PO.3 drops (its only claim's target and evidence dangle); the
    // unknown-requirement entry drops (dangling requirement ref).
    let supported = decls.supported_requirements(ts("2026-06-01T00:00:00Z"));
    assert_eq!(supported.len(), 1);
    let ps1 = &supported[0];
    assert_eq!(ps1.requirement.identifier.as_deref(), Some("PS.1"));
    assert_eq!(ps1.supporting_claims.len(), 2);
    assert!(ps1.third_party_assessed);
    // Signed claim + signed evidence: presence recorded, never "verified".
    assert_eq!(ps1.evidence_level, EvidenceLevel::SignaturePresent);
    assert_ne!(ps1.evidence_level, EvidenceLevel::SignatureVerified);

    // After evidence expiry: nothing is supported (expires <= as_of).
    assert!(
        decls
            .supported_requirements(ts("2027-06-01T00:00:00Z"))
            .is_empty()
    );
    // Before evidence creation: nothing is supported (created > as_of).
    assert!(
        decls
            .supported_requirements(ts("2025-12-01T00:00:00Z"))
            .is_empty()
    );
}

#[test]
fn evidence_for_family_maps_ssdf_only() {
    let sbom = parse_fixture("cyclonedx/declarations-cdxa.cdx.json");
    let decls = sbom.declarations().expect("declarations");
    let as_of = ts("2026-06-01T00:00:00Z");

    let ssdf = decls.evidence_for_family(AttestationRuleFamily::Ssdf, as_of);
    assert_eq!(ssdf.len(), 1);
    assert_eq!(
        ssdf[0].standard.name.as_deref(),
        Some("NIST Secure Software Development Framework")
    );
    assert!(
        decls
            .evidence_for_family(AttestationRuleFamily::Eo14028, as_of)
            .is_empty()
    );
    assert!(
        decls
            .evidence_for_family(AttestationRuleFamily::Cra, as_of)
            .is_empty()
    );
}

#[test]
fn declarations_survive_serde_round_trip() {
    // NormalizedSbom as a whole is not JSON-serializable (IndexMap keyed by
    // CanonicalId — the FFI layer converts to AbiNormalizedSbom for that);
    // the attachment point is `extensions`, so round-trip that subtree.
    let sbom = parse_fixture("cyclonedx/declarations-cdxa.cdx.json");
    let json = serde_json::to_string(&sbom.extensions).expect("serialize extensions");
    let restored: sbom_tools::model::FormatExtensions =
        serde_json::from_str(&json).expect("deserialize extensions");
    assert_eq!(
        restored.declarations.as_ref(),
        sbom.declarations(),
        "declarations must round out identically through serde"
    );
}

#[test]
fn absent_declarations_leave_serialized_output_unchanged() {
    for fixture in [
        "cyclonedx/minimal.cdx.json",
        "cyclonedx/cbom-1.6.cdx.json",
        "cyclonedx/with-vulnerabilities.cdx.json",
    ] {
        let sbom = parse_fixture(fixture);
        assert!(
            sbom.declarations().is_none(),
            "{fixture}: no declarations expected"
        );
        // The new field must be skipped entirely when absent so serialized
        // output for pre-existing documents stays byte-identical.
        let extensions = serde_json::to_value(&sbom.extensions).expect("serialize extensions");
        let extensions = extensions.as_object().expect("extensions object");
        assert!(
            !extensions.contains_key("declarations"),
            "{fixture}: serialized output must not gain a declarations key"
        );
    }
}

#[test]
fn declarations_are_not_probed_on_pre_1_6_documents() {
    // A 1.5 document carrying a declarations object: the 1.6-only section
    // must be ignored entirely (never probed on specVersion <= 1.5).
    let doc = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {"type": "library", "bom-ref": "c", "name": "libc", "version": "1.0"}
        ],
        "declarations": {
            "claims": [{"bom-ref": "claim-1", "target": "c", "predicate": "x"}]
        }
    }"#;
    let sbom = parse_sbom_str(doc).expect("1.5 document must parse");
    assert!(sbom.declarations().is_none());

    // The same content at 1.6 parses the section.
    let doc_16 = doc.replace("\"specVersion\": \"1.5\"", "\"specVersion\": \"1.6\"");
    let sbom = parse_sbom_str(&doc_16).expect("1.6 document must parse");
    let decls = sbom.declarations().expect("1.6 declarations parse");
    assert_eq!(decls.claims.len(), 1);
}

#[test]
fn declarations_change_content_hash_only_when_present() {
    // Same inventory with and without declarations: content hashes differ
    // (attestation changes must be visible to diff identity), while two
    // parses of the declaration-free document hash identically.
    let bare = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "bom-ref": "c", "name": "libc", "version": "1.0"}
        ]
    }"#;
    let with_decls = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "bom-ref": "c", "name": "libc", "version": "1.0"}
        ],
        "declarations": {
            "claims": [{"bom-ref": "claim-1", "target": "c", "predicate": "x"}]
        }
    }"#;
    let bare_a = parse_sbom_str(bare).expect("parse");
    let bare_b = parse_sbom_str(bare).expect("parse");
    let decorated = parse_sbom_str(with_decls).expect("parse");
    assert_eq!(bare_a.content_hash, bare_b.content_hash);
    assert_ne!(bare_a.content_hash, decorated.content_hash);
}
