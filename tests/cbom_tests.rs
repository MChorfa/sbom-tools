//! CBOM (Cryptographic Bill of Materials) integration tests.
//!
//! Tests end-to-end parsing of CBOM fixtures, crypto property extraction,
//! PQC compliance checking (CNSA 2.0, NIST PQC), and diff engine crypto changes.

use sbom_tools::{
    diff::DiffEngine,
    model::{ComponentType, CryptoAssetType},
    parsers::parse_sbom,
    quality::{ComplianceChecker, ComplianceLevel, CryptographyMetrics, ViolationSeverity},
};
use std::path::Path;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

// ============================================================================
// Parsing Tests
// ============================================================================

#[test]
fn parse_cbom_1_6_all_asset_types() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-1.6.cdx.json")).unwrap();
    let sbom = &parsed;

    // Count crypto components
    let crypto: Vec<_> = sbom
        .components
        .values()
        .filter(|c| c.component_type == ComponentType::Cryptographic)
        .collect();
    assert!(
        crypto.len() >= 10,
        "expected >=10 crypto components, got {}",
        crypto.len()
    );

    // Verify algorithms have crypto_properties
    let aes = crypto
        .iter()
        .find(|c| c.name == "AES-256-GCM")
        .expect("AES-256-GCM not found");
    let cp = aes
        .crypto_properties
        .as_ref()
        .expect("missing crypto_properties");
    assert_eq!(cp.asset_type, CryptoAssetType::Algorithm);
    assert_eq!(cp.oid.as_deref(), Some("2.16.840.1.101.3.4.1.46"));
    let algo = cp
        .algorithm_properties
        .as_ref()
        .expect("missing algorithm_properties");
    assert_eq!(algo.classical_security_level, Some(256));
    assert_eq!(algo.nist_quantum_security_level, Some(1));
    assert!(algo.is_quantum_safe());
    assert!(!algo.is_weak());

    // Verify certificate
    let cert_comp = crypto
        .iter()
        .find(|c| c.name.contains("acme-webapp.example.com"))
        .expect("TLS cert not found");
    let cert_cp = cert_comp.crypto_properties.as_ref().unwrap();
    assert_eq!(cert_cp.asset_type, CryptoAssetType::Certificate);
    let cert = cert_cp
        .certificate_properties
        .as_ref()
        .expect("missing cert_properties");
    assert!(cert.subject_name.as_ref().unwrap().contains("acme-webapp"));
    assert!(cert.not_valid_after.is_some());

    // Verify key material
    let key = crypto
        .iter()
        .find(|c| c.name.contains("webapp-tls-public-key"))
        .expect("TLS public key not found");
    let key_cp = key.crypto_properties.as_ref().unwrap();
    assert_eq!(key_cp.asset_type, CryptoAssetType::RelatedCryptoMaterial);
    let mat = key_cp.related_crypto_material_properties.as_ref().unwrap();
    assert_eq!(mat.size, Some(2048));

    // Verify protocol
    let proto = crypto
        .iter()
        .find(|c| c.name == "TLS 1.2")
        .expect("TLS 1.2 not found");
    let proto_cp = proto.crypto_properties.as_ref().unwrap();
    assert_eq!(proto_cp.asset_type, CryptoAssetType::Protocol);
    let proto_props = proto_cp.protocol_properties.as_ref().unwrap();
    assert_eq!(proto_props.version.as_deref(), Some("1.2"));
    assert!(!proto_props.cipher_suites.is_empty());
}

#[test]
fn parse_cbom_1_7_provides_and_pqc() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-1.7.cdx.json")).unwrap();
    let sbom = &parsed;

    // Verify ML-KEM-1024 (post-quantum)
    let ml_kem = sbom
        .components
        .values()
        .find(|c| c.name == "ML-KEM-1024")
        .expect("ML-KEM-1024 not found");
    let algo = ml_kem
        .crypto_properties
        .as_ref()
        .unwrap()
        .algorithm_properties
        .as_ref()
        .unwrap();
    assert_eq!(algo.nist_quantum_security_level, Some(5));
    assert!(algo.is_quantum_safe());
    assert_eq!(algo.algorithm_family.as_deref(), Some("ML-KEM"));

    // Verify hybrid combiner
    let hybrid = sbom
        .components
        .values()
        .find(|c| c.name == "X25519-ML-KEM-768")
        .expect("Hybrid combiner not found");
    let hybrid_algo = hybrid
        .crypto_properties
        .as_ref()
        .unwrap()
        .algorithm_properties
        .as_ref()
        .unwrap();
    assert!(hybrid_algo.is_hybrid_pqc());
    assert_eq!(hybrid_algo.nist_quantum_security_level, Some(3));

    // Verify 'provides' edges exist
    let provides_edges: Vec<_> = sbom
        .edges
        .iter()
        .filter(|e| e.relationship == sbom_tools::model::DependencyType::Provides)
        .collect();
    assert!(
        !provides_edges.is_empty(),
        "expected Provides dependency edges from crypto-lib"
    );

    // Verify IKEv2 with transform types
    let ipsec = sbom
        .components
        .values()
        .find(|c| c.name.contains("IPsec"))
        .expect("IPsec protocol not found");
    let proto = ipsec
        .crypto_properties
        .as_ref()
        .unwrap()
        .protocol_properties
        .as_ref()
        .unwrap();
    assert!(proto.ikev2_transform_types.is_some());
    let ike = proto.ikev2_transform_types.as_ref().unwrap();
    assert!(!ike.encr.is_empty());
    assert!(!ike.ke.is_empty());
}

#[test]
fn parse_cbom_weak_crypto() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-weak-crypto.cdx.json")).unwrap();
    let sbom = &parsed;

    // Verify weak algorithms are detected
    let md5 = sbom
        .components
        .values()
        .find(|c| c.name == "MD5")
        .expect("MD5 not found");
    let algo = md5
        .crypto_properties
        .as_ref()
        .unwrap()
        .algorithm_properties
        .as_ref()
        .unwrap();
    assert!(algo.is_weak_by_name("MD5"));
    assert!(!algo.is_quantum_safe());

    // Verify expired certificate
    let expired = sbom
        .components
        .values()
        .find(|c| c.name.contains("expired"))
        .expect("expired cert not found");
    let cert = expired
        .crypto_properties
        .as_ref()
        .unwrap()
        .certificate_properties
        .as_ref()
        .unwrap();
    assert!(cert.is_expired());

    // Verify compromised key
    let compromised = sbom
        .components
        .values()
        .find(|c| c.name.contains("compromised"))
        .expect("compromised key not found");
    let mat = compromised
        .crypto_properties
        .as_ref()
        .unwrap()
        .related_crypto_material_properties
        .as_ref()
        .unwrap();
    assert_eq!(
        mat.state,
        Some(sbom_tools::model::CryptoMaterialState::Compromised)
    );
}

// ============================================================================
// Quality Metrics Tests
// ============================================================================

#[test]
fn crypto_metrics_quantum_ready() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-quantum-ready.cdx.json")).unwrap();
    let metrics = CryptographyMetrics::from_sbom(&parsed);

    assert!(metrics.has_data());
    assert!(metrics.algorithms_count >= 10);
    assert_eq!(metrics.weak_algorithm_count, 0);
    assert_eq!(metrics.expired_certificates, 0);
    assert_eq!(metrics.compromised_keys, 0);
    assert!(
        metrics.quantum_readiness_score() > 90.0,
        "expected >90% quantum readiness"
    );
    assert!(metrics.quality_score().unwrap() > 80.0);
}

#[test]
fn crypto_metrics_weak_crypto() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-weak-crypto.cdx.json")).unwrap();
    let metrics = CryptographyMetrics::from_sbom(&parsed);

    assert!(metrics.has_data());
    assert!(metrics.weak_algorithm_count >= 5, "expected >=5 weak algos");
    assert!(metrics.expired_certificates >= 1);
    assert!(metrics.compromised_keys >= 1);
    assert!(
        metrics.quantum_readiness_score() < 20.0,
        "expected <20% quantum readiness"
    );
    assert!(metrics.quality_score().unwrap() < 30.0);
}

#[test]
fn crypto_metrics_no_crypto_returns_none() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/minimal.cdx.json")).unwrap();
    let metrics = CryptographyMetrics::from_sbom(&parsed);

    assert!(!metrics.has_data());
    assert!(metrics.quality_score().is_none());
}

// ============================================================================
// Compliance Tests
// ============================================================================

#[test]
fn cnsa2_compliant_passes() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-cnsa2-compliant.cdx.json")).unwrap();
    let result = ComplianceChecker::new(ComplianceLevel::Cnsa2).check(&parsed);

    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "CNSA 2.0 compliant fixture should have 0 errors, got {}:\n{}",
        errors.len(),
        errors
            .iter()
            .map(|v| format!("  - {}", v.message))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn cnsa2_violations_detected() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-cnsa2-violations.cdx.json")).unwrap();
    let result = ComplianceChecker::new(ComplianceLevel::Cnsa2).check(&parsed);

    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.len() >= 5,
        "expected >=5 CNSA 2.0 errors, got {}:\n{}",
        errors.len(),
        errors
            .iter()
            .map(|v| format!("  - {}", v.message))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Verify specific violations
    let messages: Vec<_> = errors.iter().map(|v| v.message.as_str()).collect();
    assert!(
        messages.iter().any(|m| m.contains("AES-128")),
        "should flag AES-128"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("ML-KEM-768") || m.contains("ML-KEM-512")),
        "should flag ML-KEM sub-1024"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("RSA") || m.contains("ECDSA") || m.contains("ECDH")),
        "should flag quantum-vulnerable families"
    );
}

#[test]
fn nist_pqc_weak_crypto_violations() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-weak-crypto.cdx.json")).unwrap();
    let result = ComplianceChecker::new(ComplianceLevel::NistPqc).check(&parsed);

    let errors: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Error)
        .collect();
    assert!(
        errors.len() >= 5,
        "expected >=5 PQC errors for weak crypto, got {}",
        errors.len()
    );

    // Should detect broken algorithms
    let messages: Vec<_> = errors.iter().map(|v| v.message.as_str()).collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("MD5") || m.contains("SHA-1")),
        "should flag broken hashes"
    );
    assert!(
        messages.iter().any(|m| m.contains("quantum-vulnerable")),
        "should flag quantum-vulnerable algorithms"
    );
}

#[test]
fn nist_pqc_hybrid_transition_info() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-pqc-transition.cdx.json")).unwrap();
    let result = ComplianceChecker::new(ComplianceLevel::NistPqc).check(&parsed);

    // Should have info-level messages about hybrid combiners
    let infos: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Info)
        .collect();
    assert!(
        infos.iter().any(|v| v.message.contains("hybrid")),
        "should recognize hybrid PQC combiners as good practice"
    );

    // Should have info about approved PQC algorithms
    assert!(
        infos
            .iter()
            .any(|v| v.message.contains("NIST-approved PQC")),
        "should recognize approved PQC algorithms"
    );
}

// ============================================================================
// Diff Tests
// ============================================================================

#[test]
fn diff_weak_to_quantum_ready() {
    let old = parse_sbom(&fixture_path("cyclonedx/cbom-weak-crypto.cdx.json")).unwrap();
    let new = parse_sbom(&fixture_path("cyclonedx/cbom-quantum-ready.cdx.json")).unwrap();

    let engine = DiffEngine::default();
    let result = engine.diff(&old, &new).unwrap();

    // Should detect many changes (different algorithms entirely)
    assert!(
        result.summary.total_changes > 0,
        "diff between weak and quantum-ready should detect changes"
    );
}

#[test]
fn parse_all_cbom_fixtures_successfully() {
    let fixtures = [
        "cyclonedx/cbom-1.6.cdx.json",
        "cyclonedx/cbom-1.7.cdx.json",
        "cyclonedx/cbom-weak-crypto.cdx.json",
        "cyclonedx/cbom-quantum-ready.cdx.json",
        "cyclonedx/cbom-cnsa2-compliant.cdx.json",
        "cyclonedx/cbom-cnsa2-violations.cdx.json",
        "cyclonedx/cbom-pqc-transition.cdx.json",
    ];

    for fixture in &fixtures {
        let result = parse_sbom(&fixture_path(fixture));
        assert!(
            result.is_ok(),
            "Failed to parse {fixture}: {:?}",
            result.err()
        );

        let parsed = result.unwrap();
        let crypto_count = parsed
            .components
            .values()
            .filter(|c| c.component_type == ComponentType::Cryptographic)
            .count();
        assert!(crypto_count > 0, "{fixture} should have crypto components");
    }
}

// ============================================================================
// Bom-ref Index Tests
// ============================================================================

#[test]
fn bom_ref_index_resolves_crypto_refs() {
    let parsed = parse_sbom(&fixture_path("cyclonedx/cbom-1.6.cdx.json")).unwrap();
    let sbom = &parsed;
    let index = sbom.build_index();

    // The cert references an algorithm via signatureAlgorithmRef
    let cert = sbom
        .components
        .values()
        .find(|c| c.name.contains("acme-webapp.example.com"))
        .expect("cert not found");
    let sig_ref = cert
        .crypto_properties
        .as_ref()
        .unwrap()
        .certificate_properties
        .as_ref()
        .unwrap()
        .signature_algorithm_ref
        .as_deref()
        .expect("missing sig ref");

    // Resolve the bom-ref through the index
    let resolved = index.resolve_bom_ref(sig_ref);
    assert!(resolved.is_some(), "should resolve bom-ref '{sig_ref}'");
}
