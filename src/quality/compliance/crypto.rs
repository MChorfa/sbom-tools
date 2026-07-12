//! Cryptographic-suite compliance: NSA CNSA 2.0 and NIST PQC readiness.

use super::*;

/// Whether a SHA-2 hash of digest size < 384 bits is indicated, given the
/// uppercased family string and the parameter set.
///
/// CNSA 2.0 approves only SHA-384 and SHA-512. A weak SHA-2 digest can be
/// encoded as the family carrying the size (`SHA-224`, `SHA-256`) or as a
/// generic family (`SHA-2`/`SHA2`) with the size in the parameter. Both forms
/// (previously only the latter, and only for exactly "256") are caught.
fn is_weak_cnsa_hash(family_upper: &str, param: Option<&str>) -> bool {
    // Family carries the digest size directly.
    if matches!(family_upper, "SHA-224" | "SHA224" | "SHA-256" | "SHA256") {
        return true;
    }
    // Generic SHA-2 family with a weak size in the parameter.
    if matches!(family_upper, "SHA-2" | "SHA2") {
        return matches!(param, Some("224") | Some("256"));
    }
    false
}

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // CNSA 2.0 compliance checks
    // ════════════════════════════════════════════════════════════════════

    pub(crate) fn check_cnsa2(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{ComponentType, CryptoAssetType};

        let mut crypto_assets_evaluated = 0usize;

        for comp in sbom.components.values() {
            if comp.component_type != ComponentType::Cryptographic {
                continue;
            }
            let Some(cp) = &comp.crypto_properties else {
                continue;
            };
            crypto_assets_evaluated += 1;

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
                                        rule_id: "SBOM-CNSA2-ALG-006",
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
                                    rule_id: "SBOM-CNSA2-ALG-007",
                                    standard_refs: Vec::new(),
                                });
                            }
                        }

                        // CNSA2-ALG-001: symmetric must be AES-256. The key
                        // size may be carried in parameter_set_identifier OR in
                        // a RelatedCryptoMaterial key size; treat AES as
                        // non-compliant unless it is explicitly 256, so AES-128
                        // does not slip through on an absent parameter.
                        if let Some(family) = &algo.algorithm_family {
                            let upper = family.to_uppercase();
                            if upper == "AES" {
                                let is_256 = algo.parameter_set_identifier.as_deref()
                                    == Some("256")
                                    || algo.classical_security_level == Some(256);
                                if !is_256 {
                                    let shown = algo
                                        .parameter_set_identifier
                                        .as_deref()
                                        .map(str::to_string)
                                        .or_else(|| {
                                            algo.classical_security_level.map(|b| b.to_string())
                                        })
                                        .unwrap_or_else(|| "unspecified".to_string());
                                    violations.push(Violation {
                                        severity: ViolationSeverity::Error,
                                        category: ViolationCategory::CryptographyInfo,
                                        message: format!(
                                            "'{}' uses AES-{shown}, CNSA 2.0 requires AES-256 only",
                                            comp.name
                                        ),
                                        element: Some(comp.name.clone()),
                                        requirement: "CNSA 2.0 Symmetric".to_string(),
                                        rule_id: "SBOM-CNSA2-ALG-001",
                                        standard_refs: Vec::new(),
                                    });
                                }
                            }

                            // CNSA2-ALG-002: hash must be SHA-384 or SHA-512.
                            // Recognize SHA-2 at any digest size ≤ 256 whether
                            // the size is in the family string ("SHA-256",
                            // "SHA-224") or the parameter ("SHA-2"/param 256).
                            if is_weak_cnsa_hash(&upper, algo.parameter_set_identifier.as_deref()) {
                                violations.push(Violation {
                                    severity: ViolationSeverity::Error,
                                    category: ViolationCategory::CryptographyInfo,
                                    message: format!(
                                        "'{}' uses a SHA-2 digest < 384 bits, CNSA 2.0 requires SHA-384 or SHA-512",
                                        comp.name
                                    ),
                                    element: Some(comp.name.clone()),
                                    requirement: "CNSA 2.0 Hash".to_string(),
                                    rule_id: "SBOM-CNSA2-ALG-002",
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
                                    rule_id: "SBOM-CNSA2-ALG-003",
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
                                    rule_id: "SBOM-CNSA2-ALG-004",
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
                                    rule_id: "SBOM-CNSA2-ALG-006",
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
                                rule_id: "SBOM-CNSA2-CERT-001",
                                standard_refs: Vec::new(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        // CNSA2-000: no cryptographic inventory to evaluate — a "compliant"
        // verdict here would be a false CNSA 2.0 claim, so fail.
        if crypto_assets_evaluated == 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: "No cryptographic inventory (CBOM) found; CNSA 2.0 compliance \
                          cannot be asserted. Provide cryptographic asset components."
                    .to_string(),
                element: None,
                requirement: "CNSA 2.0: cryptographic inventory required".to_string(),
                rule_id: "SBOM-CNSA2-000",
                standard_refs: Vec::new(),
            });
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // NIST PQC Readiness checks
    // ════════════════════════════════════════════════════════════════════

    pub(crate) fn check_nist_pqc(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{ComponentType, CryptoAssetType};

        /// Broken/disallowed algorithms per SP 800-131A
        const BROKEN: &[&str] = &[
            "MD5", "MD4", "MD2", "SHA-1", "DES", "3DES", "TDEA", "RC2", "RC4", "BLOWFISH", "IDEA",
            "CAST5",
        ];

        // Track whether we actually evaluated any cryptographic asset. A tool
        // asserting PQC compliance must not report "compliant" when it found
        // no cryptographic inventory to evaluate.
        let mut crypto_assets_evaluated = 0usize;

        for comp in sbom.components.values() {
            if comp.component_type != ComponentType::Cryptographic {
                continue;
            }
            let Some(cp) = &comp.crypto_properties else {
                continue;
            };
            crypto_assets_evaluated += 1;

            if cp.asset_type == CryptoAssetType::Algorithm
                && let Some(algo) = &cp.algorithm_properties
            {
                // PQC-001: quantum-vulnerable algorithm. A classical public-key
                // primitive (RSA/ECDSA/ECDH/DH/DSA/EdDSA/ElGamal) is broken by
                // Shor's algorithm regardless of key size, so flag it on the
                // family alone — not only when nistQuantumSecurityLevel is an
                // explicit 0 (which real-world CBOMs rarely populate).
                if algo.nist_quantum_security_level == Some(0)
                    || algo.is_classical_quantum_vulnerable()
                {
                    violations.push(Violation {
                        severity: ViolationSeverity::Error,
                        category: ViolationCategory::CryptographyInfo,
                        message: format!(
                            "'{}' ({}) is quantum-vulnerable and must migrate to PQC (IR 8547)",
                            comp.name,
                            algo.algorithm_family.as_deref().unwrap_or("classical")
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "IR 8547: quantum-vulnerable".to_string(),
                        rule_id: "SBOM-PQC-001",
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
                        rule_id: "SBOM-PQC-012",
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
                            rule_id: "SBOM-PQC-005",
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
                        rule_id: "SBOM-PQC-008",
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
                            rule_id: "SBOM-PQC-009",
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
                        rule_id: "SBOM-PQC-010",
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
                        rule_id: "SBOM-PQC-KEY-001",
                        standard_refs: Vec::new(),
                    });
                }
            }
        }

        // PQC-000: no cryptographic inventory. Reporting "compliant" when there
        // was nothing to evaluate is a false PQC-readiness claim, so fail.
        if crypto_assets_evaluated == 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::CryptographyInfo,
                message: "No cryptographic inventory (CBOM) found; NIST PQC readiness \
                          cannot be asserted. Provide cryptographic asset components."
                    .to_string(),
                element: None,
                requirement: "IR 8547: cryptographic inventory required".to_string(),
                rule_id: "SBOM-PQC-000",
                standard_refs: Vec::new(),
            });
        }
    }
}
