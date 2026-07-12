//! Cryptographic Bill of Materials (CBOM) data structures.
//!
//! Format-agnostic representation of cryptographic assets as defined by
//! CycloneDX 1.6+ `cryptoProperties`. Supports four asset types:
//! algorithms, certificates, key material, and protocols.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Top-level CryptoProperties ──────────────────────────────────────────

/// Cryptographic properties for a component of type `cryptographic-asset`.
///
/// Mirrors the CycloneDX 1.6+ `cryptoProperties` object. Exactly one of
/// the four property sub-structs should be populated, matching `asset_type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CryptoProperties {
    /// The type of cryptographic asset.
    pub asset_type: CryptoAssetType,
    /// Object Identifier (OID) for unambiguous algorithm identification.
    pub oid: Option<String>,
    /// Properties specific to algorithm assets.
    pub algorithm_properties: Option<AlgorithmProperties>,
    /// Properties specific to certificate assets.
    pub certificate_properties: Option<CertificateProperties>,
    /// Properties specific to key material assets.
    pub related_crypto_material_properties: Option<RelatedCryptoMaterialProperties>,
    /// Properties specific to protocol assets.
    pub protocol_properties: Option<ProtocolProperties>,
}

impl CryptoProperties {
    /// Create new crypto properties with the given asset type.
    #[must_use]
    pub fn new(asset_type: CryptoAssetType) -> Self {
        Self {
            asset_type,
            oid: None,
            algorithm_properties: None,
            certificate_properties: None,
            related_crypto_material_properties: None,
            protocol_properties: None,
        }
    }

    #[must_use]
    pub fn with_oid(mut self, oid: String) -> Self {
        self.oid = Some(oid);
        self
    }

    #[must_use]
    pub fn with_algorithm_properties(mut self, props: AlgorithmProperties) -> Self {
        self.algorithm_properties = Some(props);
        self
    }

    #[must_use]
    pub fn with_certificate_properties(mut self, props: CertificateProperties) -> Self {
        self.certificate_properties = Some(props);
        self
    }

    #[must_use]
    pub fn with_related_crypto_material_properties(
        mut self,
        props: RelatedCryptoMaterialProperties,
    ) -> Self {
        self.related_crypto_material_properties = Some(props);
        self
    }

    #[must_use]
    pub fn with_protocol_properties(mut self, props: ProtocolProperties) -> Self {
        self.protocol_properties = Some(props);
        self
    }
}

// ── Asset Type ──────────────────────────────────────────────────────────

/// Type of cryptographic asset.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoAssetType {
    Algorithm,
    Certificate,
    RelatedCryptoMaterial,
    Protocol,
    Other(String),
}

impl std::fmt::Display for CryptoAssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Algorithm => write!(f, "algorithm"),
            Self::Certificate => write!(f, "certificate"),
            Self::RelatedCryptoMaterial => write!(f, "related-crypto-material"),
            Self::Protocol => write!(f, "protocol"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ── Algorithm Properties ────────────────────────────────────────────────

/// Properties of a cryptographic algorithm asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AlgorithmProperties {
    /// Cryptographic primitive category.
    pub primitive: CryptoPrimitive,
    /// Algorithm family name (e.g., "AES", "ML-KEM", "SHA-2"). CycloneDX 1.7+.
    pub algorithm_family: Option<String>,
    /// Parameter set identifier (e.g., "256", "1024", "P-384").
    pub parameter_set_identifier: Option<String>,
    /// Block cipher mode of operation.
    pub mode: Option<CryptoMode>,
    /// Padding scheme.
    pub padding: Option<CryptoPadding>,
    /// Cryptographic functions this algorithm supports.
    pub crypto_functions: Vec<CryptoFunction>,
    /// Execution environment.
    pub execution_environment: Option<ExecutionEnvironment>,
    /// Implementation platform.
    pub implementation_platform: Option<ImplementationPlatform>,
    /// Certification levels achieved.
    pub certification_level: Vec<CertificationLevel>,
    /// Classical security level in bits.
    pub classical_security_level: Option<u32>,
    /// NIST post-quantum security category (0 = vulnerable, 1-5 = increasing resistance).
    pub nist_quantum_security_level: Option<u8>,
    /// Elliptic curve identifier (CycloneDX 1.7+, e.g., "secg/secp521r1").
    pub elliptic_curve: Option<String>,
}

impl AlgorithmProperties {
    /// Create new algorithm properties with the given primitive.
    #[must_use]
    pub fn new(primitive: CryptoPrimitive) -> Self {
        Self {
            primitive,
            algorithm_family: None,
            parameter_set_identifier: None,
            mode: None,
            padding: None,
            crypto_functions: Vec::new(),
            execution_environment: None,
            implementation_platform: None,
            certification_level: Vec::new(),
            classical_security_level: None,
            nist_quantum_security_level: None,
            elliptic_curve: None,
        }
    }

    /// Returns `true` if this algorithm has post-quantum security
    /// (`nistQuantumSecurityLevel > 0`).
    #[must_use]
    pub fn is_quantum_safe(&self) -> bool {
        self.nist_quantum_security_level.is_some_and(|l| l > 0)
    }

    /// Returns `true` if this is a hybrid PQC scheme (combiner primitive).
    #[must_use]
    pub fn is_hybrid_pqc(&self) -> bool {
        self.primitive == CryptoPrimitive::Combiner
    }

    /// Returns `true` if this is a CLASSICAL public-key algorithm broken by a
    /// cryptographically-relevant quantum computer (Shor's algorithm): RSA,
    /// finite-field / elliptic-curve Diffie-Hellman, DSA/ECDSA/EdDSA, ElGamal.
    ///
    /// These are quantum-vulnerable regardless of key size or a declared
    /// `nistQuantumSecurityLevel` — the family alone is authoritative. Matched
    /// on `algorithm_family` (case-insensitive); the PQC families (ML-KEM,
    /// ML-DSA, SLH-DSA, …) are not in the list and correctly return `false`.
    #[must_use]
    pub fn is_classical_quantum_vulnerable(&self) -> bool {
        const CLASSICAL_PK: &[&str] = &[
            "RSA", "DSA", "DH", "DHE", "ECDH", "ECDHE", "ECDSA", "EDDSA", "ED25519", "ED448",
            "X25519", "X448", "ELGAMAL", "ECIES", "ECMQV",
        ];
        self.algorithm_family.as_deref().is_some_and(|f| {
            let upper = f.to_uppercase();
            CLASSICAL_PK.iter().any(|c| upper == *c)
        })
    }

    /// Returns `true` if the algorithm is considered broken or weak.
    /// Checks `algorithm_family` first, then falls back to matching
    /// common weak names in the `parameter_set_identifier`.
    #[must_use]
    pub fn is_weak(&self) -> bool {
        /// Unconditionally broken/weak algorithm families.
        const WEAK_FAMILIES: &[&str] = &[
            "MD5", "MD4", "MD2", "SHA-1", "DES", "3DES", "TDEA", "RC2", "RC4", "BLOWFISH", "IDEA",
            "CAST5",
        ];

        if let Some(family) = &self.algorithm_family {
            let upper = family.to_uppercase();
            if WEAK_FAMILIES.iter().any(|w| upper == *w) {
                return true;
            }
        }
        false
    }

    /// Returns `true` if the algorithm is considered broken or weak,
    /// using the component name as a fallback when `algorithm_family` is absent.
    #[must_use]
    pub fn is_weak_by_name(&self, component_name: &str) -> bool {
        if self.is_weak() {
            return true;
        }
        // Fallback: check component name for weak algorithm patterns
        let upper = component_name.to_uppercase();
        upper.starts_with("MD5")
            || upper.starts_with("MD4")
            || upper.starts_with("SHA-1")
            || upper.starts_with("DES")
            || upper.starts_with("3DES")
            || upper.starts_with("RC4")
            || upper.starts_with("RC2")
            || upper.starts_with("BLOWFISH")
    }

    /// Returns the classical security level in bits, if known.
    #[must_use]
    pub fn effective_security_bits(&self) -> Option<u32> {
        self.classical_security_level
    }

    #[must_use]
    pub fn with_algorithm_family(mut self, family: String) -> Self {
        self.algorithm_family = Some(family);
        self
    }

    #[must_use]
    pub fn with_parameter_set_identifier(mut self, id: String) -> Self {
        self.parameter_set_identifier = Some(id);
        self
    }

    #[must_use]
    pub fn with_mode(mut self, mode: CryptoMode) -> Self {
        self.mode = Some(mode);
        self
    }

    #[must_use]
    pub fn with_padding(mut self, padding: CryptoPadding) -> Self {
        self.padding = Some(padding);
        self
    }

    #[must_use]
    pub fn with_crypto_functions(mut self, funcs: Vec<CryptoFunction>) -> Self {
        self.crypto_functions = funcs;
        self
    }

    #[must_use]
    pub fn with_execution_environment(mut self, env: ExecutionEnvironment) -> Self {
        self.execution_environment = Some(env);
        self
    }

    #[must_use]
    pub fn with_implementation_platform(mut self, platform: ImplementationPlatform) -> Self {
        self.implementation_platform = Some(platform);
        self
    }

    #[must_use]
    pub fn with_certification_level(mut self, levels: Vec<CertificationLevel>) -> Self {
        self.certification_level = levels;
        self
    }

    #[must_use]
    pub fn with_classical_security_level(mut self, bits: u32) -> Self {
        self.classical_security_level = Some(bits);
        self
    }

    #[must_use]
    pub fn with_nist_quantum_security_level(mut self, level: u8) -> Self {
        self.nist_quantum_security_level = Some(level);
        self
    }

    #[must_use]
    pub fn with_elliptic_curve(mut self, curve: String) -> Self {
        self.elliptic_curve = Some(curve);
        self
    }
}

// ── Certificate Properties ──────────────────────────────────────────────

/// Properties of a digital certificate asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CertificateProperties {
    /// Certificate subject distinguished name.
    pub subject_name: Option<String>,
    /// Certificate issuer distinguished name.
    pub issuer_name: Option<String>,
    /// Start of validity period.
    pub not_valid_before: Option<DateTime<Utc>>,
    /// End of validity period.
    pub not_valid_after: Option<DateTime<Utc>>,
    /// Bom-ref of the signature algorithm component.
    pub signature_algorithm_ref: Option<String>,
    /// Bom-ref of the subject public key component.
    pub subject_public_key_ref: Option<String>,
    /// Certificate format (e.g., "X.509").
    pub certificate_format: Option<String>,
    /// Certificate file extension (e.g., "pem", "crt", "der").
    pub certificate_extension: Option<String>,
}

impl CertificateProperties {
    #[must_use]
    pub fn new() -> Self {
        Self {
            subject_name: None,
            issuer_name: None,
            not_valid_before: None,
            not_valid_after: None,
            signature_algorithm_ref: None,
            subject_public_key_ref: None,
            certificate_format: None,
            certificate_extension: None,
        }
    }

    /// Returns `true` if the certificate has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.not_valid_after
            .is_some_and(|expiry| expiry < Utc::now())
    }

    /// Returns `true` if the certificate expires within the given number of days.
    #[must_use]
    pub fn is_expiring_soon(&self, days: u32) -> bool {
        self.not_valid_after.is_some_and(|expiry| {
            let threshold = Utc::now() + chrono::Duration::days(i64::from(days));
            expiry <= threshold && expiry > Utc::now()
        })
    }

    /// Returns remaining days until expiry, or `None` if no expiry date is set.
    /// Returns negative values for already-expired certificates.
    #[must_use]
    pub fn validity_days(&self) -> Option<i64> {
        self.not_valid_after
            .map(|expiry| (expiry - Utc::now()).num_days())
    }

    #[must_use]
    pub fn with_subject_name(mut self, name: String) -> Self {
        self.subject_name = Some(name);
        self
    }

    #[must_use]
    pub fn with_issuer_name(mut self, name: String) -> Self {
        self.issuer_name = Some(name);
        self
    }

    #[must_use]
    pub fn with_not_valid_before(mut self, dt: DateTime<Utc>) -> Self {
        self.not_valid_before = Some(dt);
        self
    }

    #[must_use]
    pub fn with_not_valid_after(mut self, dt: DateTime<Utc>) -> Self {
        self.not_valid_after = Some(dt);
        self
    }

    #[must_use]
    pub fn with_signature_algorithm_ref(mut self, r: String) -> Self {
        self.signature_algorithm_ref = Some(r);
        self
    }

    #[must_use]
    pub fn with_subject_public_key_ref(mut self, r: String) -> Self {
        self.subject_public_key_ref = Some(r);
        self
    }

    #[must_use]
    pub fn with_certificate_format(mut self, fmt: String) -> Self {
        self.certificate_format = Some(fmt);
        self
    }

    #[must_use]
    pub fn with_certificate_extension(mut self, ext: String) -> Self {
        self.certificate_extension = Some(ext);
        self
    }
}

impl Default for CertificateProperties {
    fn default() -> Self {
        Self::new()
    }
}

// ── Related Crypto Material Properties ──────────────────────────────────

/// Properties of a cryptographic key or related material asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RelatedCryptoMaterialProperties {
    /// Type of key material.
    pub material_type: CryptoMaterialType,
    /// Unique identifier for the material.
    pub id: Option<String>,
    /// Lifecycle state of the material.
    pub state: Option<CryptoMaterialState>,
    /// Key size in bits.
    pub size: Option<u32>,
    /// Bom-ref of the associated algorithm component.
    pub algorithm_ref: Option<String>,
    /// How this material is protected.
    pub secured_by: Option<SecuredBy>,
    /// Key encoding format (e.g., "PEM", "DER").
    pub format: Option<String>,
    /// When the material was created.
    pub creation_date: Option<DateTime<Utc>>,
    /// When the material was activated.
    pub activation_date: Option<DateTime<Utc>>,
    /// When the material was last updated.
    pub update_date: Option<DateTime<Utc>>,
    /// When the material expires.
    pub expiration_date: Option<DateTime<Utc>>,
}

impl RelatedCryptoMaterialProperties {
    #[must_use]
    pub fn new(material_type: CryptoMaterialType) -> Self {
        Self {
            material_type,
            id: None,
            state: None,
            size: None,
            algorithm_ref: None,
            secured_by: None,
            format: None,
            creation_date: None,
            activation_date: None,
            update_date: None,
            expiration_date: None,
        }
    }

    #[must_use]
    pub fn with_id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    #[must_use]
    pub fn with_state(mut self, state: CryptoMaterialState) -> Self {
        self.state = Some(state);
        self
    }

    #[must_use]
    pub fn with_size(mut self, bits: u32) -> Self {
        self.size = Some(bits);
        self
    }

    #[must_use]
    pub fn with_algorithm_ref(mut self, r: String) -> Self {
        self.algorithm_ref = Some(r);
        self
    }

    #[must_use]
    pub fn with_secured_by(mut self, secured: SecuredBy) -> Self {
        self.secured_by = Some(secured);
        self
    }

    #[must_use]
    pub fn with_format(mut self, fmt: String) -> Self {
        self.format = Some(fmt);
        self
    }

    #[must_use]
    pub fn with_creation_date(mut self, dt: DateTime<Utc>) -> Self {
        self.creation_date = Some(dt);
        self
    }

    #[must_use]
    pub fn with_activation_date(mut self, dt: DateTime<Utc>) -> Self {
        self.activation_date = Some(dt);
        self
    }

    #[must_use]
    pub fn with_expiration_date(mut self, dt: DateTime<Utc>) -> Self {
        self.expiration_date = Some(dt);
        self
    }
}

// ── Protocol Properties ─────────────────────────────────────────────────

/// Properties of a cryptographic protocol asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProtocolProperties {
    /// Protocol type.
    pub protocol_type: ProtocolType,
    /// Protocol version (e.g., "1.3" for TLS).
    pub version: Option<String>,
    /// Cipher suites supported by this protocol.
    pub cipher_suites: Vec<CipherSuite>,
    /// IKEv2 transform types (for IPsec protocols).
    pub ikev2_transform_types: Option<Ikev2TransformTypes>,
    /// Bom-refs of related crypto assets used by this protocol.
    pub crypto_ref_array: Vec<String>,
}

impl ProtocolProperties {
    #[must_use]
    pub fn new(protocol_type: ProtocolType) -> Self {
        Self {
            protocol_type,
            version: None,
            cipher_suites: Vec::new(),
            ikev2_transform_types: None,
            crypto_ref_array: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    #[must_use]
    pub fn with_cipher_suites(mut self, suites: Vec<CipherSuite>) -> Self {
        self.cipher_suites = suites;
        self
    }

    #[must_use]
    pub fn with_ikev2_transform_types(mut self, types: Ikev2TransformTypes) -> Self {
        self.ikev2_transform_types = Some(types);
        self
    }

    #[must_use]
    pub fn with_crypto_ref_array(mut self, refs: Vec<String>) -> Self {
        self.crypto_ref_array = refs;
        self
    }
}

// ── Supporting Structs ──────────────────────────────────────────────────

/// A cipher suite within a protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherSuite {
    /// Cipher suite name (e.g., `"TLS_AES_256_GCM_SHA384"`).
    pub name: Option<String>,
    /// Bom-refs of the constituent algorithm components.
    pub algorithms: Vec<String>,
    /// IANA cipher suite identifiers (e.g., `["0x13", "0x02"]`).
    pub identifiers: Vec<String>,
}

/// IKEv2 transform types for IPsec protocols (RFC 9370).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ikev2TransformTypes {
    /// Encryption algorithm bom-refs.
    pub encr: Vec<String>,
    /// Pseudorandom function bom-refs.
    pub prf: Vec<String>,
    /// Integrity algorithm bom-refs.
    pub integ: Vec<String>,
    /// Key exchange method bom-refs.
    pub ke: Vec<String>,
}

/// How a cryptographic material is secured/protected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecuredBy {
    /// Protection mechanism (e.g., "Software", "HSM").
    pub mechanism: String,
    /// Bom-ref of the protection algorithm, if applicable.
    pub algorithm_ref: Option<String>,
}

// ── Enums ───────────────────────────────────────────────────────────────

/// Cryptographic primitive type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoPrimitive {
    /// Authenticated encryption (e.g., AES-GCM).
    Ae,
    /// Block cipher (e.g., AES-CBC).
    BlockCipher,
    /// Stream cipher (e.g., ChaCha20).
    StreamCipher,
    /// Hash function (e.g., SHA-256).
    Hash,
    /// Message authentication code (e.g., HMAC).
    Mac,
    /// Digital signature (e.g., ECDSA, ML-DSA).
    Signature,
    /// Public-key encryption (e.g., RSA).
    Pke,
    /// Key encapsulation mechanism (e.g., ML-KEM).
    Kem,
    /// Key derivation function (e.g., HKDF).
    Kdf,
    /// Key agreement (e.g., ECDH, X25519).
    KeyAgree,
    /// Extendable output function (e.g., SHAKE).
    Xof,
    /// Deterministic random bit generator.
    Drbg,
    /// Hybrid combiner (classical + PQC).
    Combiner,
    Other(String),
    Unknown,
}

impl std::fmt::Display for CryptoPrimitive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ae => write!(f, "ae"),
            Self::BlockCipher => write!(f, "block-cipher"),
            Self::StreamCipher => write!(f, "stream-cipher"),
            Self::Hash => write!(f, "hash"),
            Self::Mac => write!(f, "mac"),
            Self::Signature => write!(f, "signature"),
            Self::Pke => write!(f, "pke"),
            Self::Kem => write!(f, "kem"),
            Self::Kdf => write!(f, "kdf"),
            Self::KeyAgree => write!(f, "key-agree"),
            Self::Xof => write!(f, "xof"),
            Self::Drbg => write!(f, "drbg"),
            Self::Combiner => write!(f, "combiner"),
            Self::Other(s) => write!(f, "{s}"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Block cipher mode of operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoMode {
    Ecb,
    Cbc,
    Ofb,
    Cfb,
    Ctr,
    Gcm,
    Ccm,
    Xts,
    Other(String),
}

impl std::fmt::Display for CryptoMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ecb => write!(f, "ecb"),
            Self::Cbc => write!(f, "cbc"),
            Self::Ofb => write!(f, "ofb"),
            Self::Cfb => write!(f, "cfb"),
            Self::Ctr => write!(f, "ctr"),
            Self::Gcm => write!(f, "gcm"),
            Self::Ccm => write!(f, "ccm"),
            Self::Xts => write!(f, "xts"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Padding scheme.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoPadding {
    Pkcs5,
    Oaep,
    Pss,
    Other(String),
}

impl std::fmt::Display for CryptoPadding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pkcs5 => write!(f, "pkcs5"),
            Self::Oaep => write!(f, "oaep"),
            Self::Pss => write!(f, "pss"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Cryptographic function capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoFunction {
    Keygen,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Digest,
    Tag,
    KeyDerive,
    Encapsulate,
    Decapsulate,
    Wrap,
    Unwrap,
    Other(String),
}

impl std::fmt::Display for CryptoFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keygen => write!(f, "keygen"),
            Self::Encrypt => write!(f, "encrypt"),
            Self::Decrypt => write!(f, "decrypt"),
            Self::Sign => write!(f, "sign"),
            Self::Verify => write!(f, "verify"),
            Self::Digest => write!(f, "digest"),
            Self::Tag => write!(f, "tag"),
            Self::KeyDerive => write!(f, "keyderive"),
            Self::Encapsulate => write!(f, "encapsulate"),
            Self::Decapsulate => write!(f, "decapsulate"),
            Self::Wrap => write!(f, "wrap"),
            Self::Unwrap => write!(f, "unwrap"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Execution environment for the cryptographic implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ExecutionEnvironment {
    SoftwarePlainRam,
    SoftwareEncryptedRam,
    SoftwareTee,
    Hardware,
    Other(String),
}

impl std::fmt::Display for ExecutionEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SoftwarePlainRam => write!(f, "software-plain-ram"),
            Self::SoftwareEncryptedRam => write!(f, "software-encrypted-ram"),
            Self::SoftwareTee => write!(f, "software-tee"),
            Self::Hardware => write!(f, "hardware"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Hardware/software platform of the implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ImplementationPlatform {
    X86_32,
    X86_64,
    Armv7A,
    Armv7M,
    Armv8A,
    S390x,
    Generic,
    Other(String),
}

impl std::fmt::Display for ImplementationPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86_32 => write!(f, "x86_32"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Armv7A => write!(f, "armv7-a"),
            Self::Armv7M => write!(f, "armv7-m"),
            Self::Armv8A => write!(f, "armv8-a"),
            Self::S390x => write!(f, "s390x"),
            Self::Generic => write!(f, "generic"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Certification or validation level achieved.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CertificationLevel {
    None,
    Fips140_1L1,
    Fips140_1L2,
    Fips140_1L3,
    Fips140_1L4,
    Fips140_2L1,
    Fips140_2L2,
    Fips140_2L3,
    Fips140_2L4,
    Fips140_3L1,
    Fips140_3L2,
    Fips140_3L3,
    Fips140_3L4,
    CcEal1,
    CcEal2,
    CcEal3,
    CcEal4,
    CcEal5,
    CcEal6,
    CcEal7,
    Other(String),
}

impl std::fmt::Display for CertificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Fips140_1L1 => write!(f, "fips140-1-l1"),
            Self::Fips140_1L2 => write!(f, "fips140-1-l2"),
            Self::Fips140_1L3 => write!(f, "fips140-1-l3"),
            Self::Fips140_1L4 => write!(f, "fips140-1-l4"),
            Self::Fips140_2L1 => write!(f, "fips140-2-l1"),
            Self::Fips140_2L2 => write!(f, "fips140-2-l2"),
            Self::Fips140_2L3 => write!(f, "fips140-2-l3"),
            Self::Fips140_2L4 => write!(f, "fips140-2-l4"),
            Self::Fips140_3L1 => write!(f, "fips140-3-l1"),
            Self::Fips140_3L2 => write!(f, "fips140-3-l2"),
            Self::Fips140_3L3 => write!(f, "fips140-3-l3"),
            Self::Fips140_3L4 => write!(f, "fips140-3-l4"),
            Self::CcEal1 => write!(f, "cc-eal1"),
            Self::CcEal2 => write!(f, "cc-eal2"),
            Self::CcEal3 => write!(f, "cc-eal3"),
            Self::CcEal4 => write!(f, "cc-eal4"),
            Self::CcEal5 => write!(f, "cc-eal5"),
            Self::CcEal6 => write!(f, "cc-eal6"),
            Self::CcEal7 => write!(f, "cc-eal7"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Type of cryptographic key material.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoMaterialType {
    PublicKey,
    PrivateKey,
    SymmetricKey,
    SecretKey,
    KeyPair,
    Ciphertext,
    Signature,
    Digest,
    Iv,
    Nonce,
    Seed,
    Salt,
    SharedSecret,
    Tag,
    Password,
    Credential,
    Token,
    Other(String),
    Unknown,
}

impl std::fmt::Display for CryptoMaterialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PublicKey => write!(f, "public-key"),
            Self::PrivateKey => write!(f, "private-key"),
            Self::SymmetricKey => write!(f, "symmetric-key"),
            Self::SecretKey => write!(f, "secret-key"),
            Self::KeyPair => write!(f, "key-pair"),
            Self::Ciphertext => write!(f, "ciphertext"),
            Self::Signature => write!(f, "signature"),
            Self::Digest => write!(f, "digest"),
            Self::Iv => write!(f, "initialization-vector"),
            Self::Nonce => write!(f, "nonce"),
            Self::Seed => write!(f, "seed"),
            Self::Salt => write!(f, "salt"),
            Self::SharedSecret => write!(f, "shared-secret"),
            Self::Tag => write!(f, "tag"),
            Self::Password => write!(f, "password"),
            Self::Credential => write!(f, "credential"),
            Self::Token => write!(f, "token"),
            Self::Other(s) => write!(f, "{s}"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Lifecycle state of cryptographic material.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoMaterialState {
    PreActivation,
    Active,
    Suspended,
    Deactivated,
    Compromised,
    Destroyed,
}

impl std::fmt::Display for CryptoMaterialState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreActivation => write!(f, "pre-activation"),
            Self::Active => write!(f, "active"),
            Self::Suspended => write!(f, "suspended"),
            Self::Deactivated => write!(f, "deactivated"),
            Self::Compromised => write!(f, "compromised"),
            Self::Destroyed => write!(f, "destroyed"),
        }
    }
}

/// Cryptographic protocol type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProtocolType {
    Tls,
    Dtls,
    Ipsec,
    Ssh,
    Srtp,
    Wireguard,
    Ikev1,
    Ikev2,
    Zrtp,
    Mikey,
    Other(String),
    Unknown,
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls => write!(f, "tls"),
            Self::Dtls => write!(f, "dtls"),
            Self::Ipsec => write!(f, "ipsec"),
            Self::Ssh => write!(f, "ssh"),
            Self::Srtp => write!(f, "srtp"),
            Self::Wireguard => write!(f, "wireguard"),
            Self::Ikev1 => write!(f, "ikev1"),
            Self::Ikev2 => write!(f, "ikev2"),
            Self::Zrtp => write!(f, "zrtp"),
            Self::Mikey => write!(f, "mikey"),
            Self::Other(s) => write!(f, "{s}"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── Algorithm Classification ────────────────────────────────────────────
//
// Canonical, input-robust algorithm classification shared by the compliance
// checkers (`src/quality/compliance/crypto.rs`). Real-world CBOMs vary wildly
// in how they identify algorithms: CycloneDX 1.7 has `algorithmFamily`, 1.6
// does not (only name/OID/primitive/parameter), spellings drift ("SHA1" vs
// "SHA-1", "TDES" vs "3DES"), and pre-standardization PQC names (Kyber,
// Dilithium, SPHINCS+) are still common. [`classify_algorithm`] normalizes
// all of these into one structured classification so no checker needs its own
// family table. (`CryptographyMetrics` in `src/quality/metrics.rs` still uses
// the narrower `is_weak`/`is_classical_quantum_vulnerable` helpers below;
// prefer [`classify_algorithm`] for new code.)

/// NIST-standardized (or SP 800-208) post-quantum algorithm kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcKind {
    /// FIPS 203 module-lattice KEM (formerly CRYSTALS-Kyber).
    MlKem,
    /// FIPS 204 module-lattice signature (formerly CRYSTALS-Dilithium).
    MlDsa,
    /// FIPS 205 stateless hash-based signature (formerly SPHINCS+).
    SlhDsa,
    /// FN-DSA (Falcon) — selected by NIST but not yet standardized.
    FnDsa,
    /// SP 800-208 Leighton-Micali signature system.
    Lms,
    /// SP 800-208 eXtended Merkle signature scheme.
    Xmss,
    /// SP 800-208 hierarchical signature system.
    Hss,
}

/// Coarse security class produced by [`classify_algorithm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmClass {
    /// Classically broken or disallowed per SP 800-131A (MD5, SHA-1, DES,
    /// 3DES, RC2, RC4, Blowfish, IDEA, CAST5, …).
    Broken,
    /// Classical public-key algorithm broken by Shor's algorithm (RSA,
    /// DSA, DH/DHE, ECDH/ECDHE, ECDSA, EdDSA/Ed25519/Ed448, X25519/X448,
    /// ElGamal, ECIES, ECMQV, generic EC/ECC).
    ClassicalQuantumVulnerable,
    /// Modern symmetric cipher (AES, ChaCha20, Camellia, ARIA, …); strength
    /// judgments (e.g., CNSA 2.0's AES-256-only rule) are up to the caller.
    Symmetric,
    /// SHA-2 family hash; the digest size, when known, is in `parameter`.
    Sha2,
    /// SHA-3 family hash/XOF (SHA3-*, SHAKE, Keccak).
    Sha3,
    /// Recognized modern hash outside the SHA-2/SHA-3 families (SM3,
    /// GOST R 34.11 "Streebog", …) — not broken, but not on approval
    /// lists such as CNSA 2.0.
    OtherHash,
    /// Post-quantum algorithm; the parameter set, when known, is in
    /// `parameter` (e.g., "1024" for ML-KEM-1024, "87" for ML-DSA-87).
    PostQuantum(PqcKind),
    /// Not recognized — callers should treat as "cannot verify", never as
    /// implicitly compliant.
    Unknown,
}

impl AlgorithmClass {
    /// Rank for "report the most severe mention" selection (higher is
    /// worse): Broken > ClassicalQuantumVulnerable > recognized
    /// symmetric/hash (not necessarily approved) > post-quantum >
    /// Unknown. Used to pick the worst algorithm out of multi-algorithm
    /// identities like "sha384-rsa-cert-chain", where reporting the first
    /// token (SHA-384, CNSA-approved) would hide the quantum-vulnerable
    /// RSA.
    #[must_use]
    pub const fn severity_rank(self) -> u8 {
        match self {
            Self::Broken => 5,
            Self::ClassicalQuantumVulnerable => 4,
            Self::Symmetric | Self::Sha2 | Self::Sha3 | Self::OtherHash => 2,
            Self::PostQuantum(_) => 1,
            Self::Unknown => 0,
        }
    }
}

/// Structured result of [`classify_algorithm`]: canonical family name,
/// extracted parameter/size, and coarse security class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmClassification {
    /// Canonical family (e.g., "AES", "SHA-2", "ML-KEM", "RSA"), if known.
    pub family: Option<String>,
    /// Parameter set / key size / digest size (e.g., "256", "1024", "87").
    pub parameter: Option<String>,
    /// Coarse security class.
    pub class: AlgorithmClass,
}

impl AlgorithmClassification {
    /// An unknown classification (no recognizable identity).
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            family: None,
            parameter: None,
            class: AlgorithmClass::Unknown,
        }
    }

    /// The parameter parsed as a bit/size number, when numeric.
    #[must_use]
    pub fn parameter_bits(&self) -> Option<u32> {
        self.parameter.as_deref().and_then(|p| p.parse().ok())
    }

    /// Human-readable label, e.g. "AES-128", "SHA-384", "ML-KEM-1024", "RSA".
    #[must_use]
    pub fn label(&self) -> String {
        let Some(family) = self.family.as_deref() else {
            return "unclassified".to_string();
        };
        match (family, self.parameter.as_deref()) {
            // "SHA-2" + 384 reads better as "SHA-384".
            ("SHA-2", Some(p)) => format!("SHA-{p}"),
            ("SHA-3", Some(p)) => format!("SHA3-{p}"),
            (f, Some(p)) => format!("{f}-{p}"),
            (f, None) => f.to_string(),
        }
    }
}

/// Map a canonical family name to its security class.
fn family_class(canonical: &str) -> AlgorithmClass {
    use AlgorithmClass as C;
    match canonical {
        "MD2" | "MD4" | "MD5" | "SHA-1" | "DES" | "3DES" | "RC2" | "RC4" | "BLOWFISH" | "IDEA"
        | "CAST5" | "SKIPJACK" => C::Broken,
        "RSA" | "DSA" | "DH" | "ECDH" | "ECDSA" | "EDDSA" | "ED25519" | "ED448" | "X25519"
        | "X448" | "ELGAMAL" | "ECIES" | "ECMQV" | "EC" | "SM2" | "SM9" | "GOST-R-34.10" => {
            C::ClassicalQuantumVulnerable
        }
        "AES" | "CHACHA20" | "CAMELLIA" | "ARIA" | "SEED" | "SERPENT" | "TWOFISH" | "SM4"
        | "MAGMA" | "KUZNYECHIK" => C::Symmetric,
        "SHA-2" => C::Sha2,
        "SHA-3" => C::Sha3,
        "SM3" | "GOST-R-34.11" => C::OtherHash,
        "ML-KEM" => C::PostQuantum(PqcKind::MlKem),
        "ML-DSA" => C::PostQuantum(PqcKind::MlDsa),
        "SLH-DSA" => C::PostQuantum(PqcKind::SlhDsa),
        "FN-DSA" => C::PostQuantum(PqcKind::FnDsa),
        "LMS" => C::PostQuantum(PqcKind::Lms),
        "XMSS" => C::PostQuantum(PqcKind::Xmss),
        "HSS" => C::PostQuantum(PqcKind::Hss),
        _ => C::Unknown,
    }
}

/// Alias table: normalized token → (canonical family, implied parameter,
/// is-round-3-Dilithium). Tokens are uppercased with `_`, ` `, `/`, and `.`
/// already mapped to `-` by [`normalize_algo_token`].
fn alias_lookup(token: &str) -> Option<(&'static str, Option<&'static str>, bool)> {
    let hit: (&'static str, Option<&'static str>) = match token {
        // Broken / legacy.
        "MD2" => ("MD2", None),
        "MD4" => ("MD4", None),
        "MD5" => ("MD5", None),
        // Bare "SHA" appears in TLS cipher-suite names and means SHA-1.
        "SHA-1" | "SHA1" | "SHA" => ("SHA-1", None),
        "DES" => ("DES", None),
        "3DES" | "TDES" | "TDEA" | "DES3" | "DESEDE" | "DESEDE3" | "DES-EDE" | "DES-EDE2"
        | "DES-EDE3" | "3DES-EDE" | "TRIPLE-DES" | "TRIPLEDES" => ("3DES", None),
        "RC2" => ("RC2", None),
        "RC4" | "ARC4" | "ARCFOUR" => ("RC4", None),
        "BLOWFISH" => ("BLOWFISH", None),
        "IDEA" => ("IDEA", None),
        "CAST5" | "CAST-128" | "CAST128" => ("CAST5", None),
        "SKIPJACK" => ("SKIPJACK", None),
        // Classical public-key (quantum-vulnerable).
        "RSA" | "RSAES" | "RSASSA" | "RSA-PSS" | "RSA-OAEP" | "RSAES-OAEP" | "RSASSA-PSS" => {
            ("RSA", None)
        }
        "DSA" | "DSS" => ("DSA", None),
        "DH" | "DHE" | "FFDHE" | "EDH" | "ADH" | "DIFFIE-HELLMAN" => ("DH", None),
        "ECDH" | "ECDHE" | "XDH" => ("ECDH", None),
        "ECDSA" => ("ECDSA", None),
        "EDDSA" => ("EDDSA", None),
        "ED25519" => ("ED25519", None),
        "ED448" => ("ED448", None),
        "X25519" => ("X25519", None),
        "X448" => ("X448", None),
        "ELGAMAL" | "EL-GAMAL" => ("ELGAMAL", None),
        "ECIES" => ("ECIES", None),
        "ECMQV" => ("ECMQV", None),
        "EC" | "ECC" => ("EC", None),
        // National classical public-key algorithms (quantum-vulnerable):
        // Chinese SM2/SM9 and Russian GOST R 34.10. `normalize_algo_token`
        // maps '.'/' '/'_' to '-', so "GOST R 34.10" arrives as
        // "GOST-R-34-10"; bare "GOST" most commonly denotes the signature
        // scheme and is classified conservatively as such.
        "SM2" => ("SM2", None),
        "SM9" => ("SM9", None),
        "GOST" | "GOST3410" | "GOSTR3410" | "GOST-R-34-10" => ("GOST-R-34.10", None),
        // Symmetric.
        "AES" | "RIJNDAEL" => ("AES", None),
        "CHACHA" | "CHACHA20" | "XCHACHA20" | "CHACHA20-POLY1305" => ("CHACHA20", None),
        "CAMELLIA" => ("CAMELLIA", None),
        "ARIA" => ("ARIA", None),
        "SEED" => ("SEED", None),
        "SERPENT" => ("SERPENT", None),
        "TWOFISH" => ("TWOFISH", None),
        // National symmetric ciphers (SM4 is fixed 128-bit; GOST R 34.12
        // Magma/Kuznyechik).
        "SM4" => ("SM4", None),
        "MAGMA" => ("MAGMA", None),
        "KUZNYECHIK" | "KUZNECHIK" => ("KUZNYECHIK", None),
        // National hashes — recognized, but not CNSA 2.0-approved.
        "SM3" => ("SM3", None),
        "GOST3411" | "GOSTR3411" | "GOST-R-34-11" | "STREEBOG" => ("GOST-R-34.11", None),
        // SHA-2 (digest size carried in the token where present).
        "SHA-2" | "SHA2" => ("SHA-2", None),
        "SHA-224" | "SHA224" => ("SHA-2", Some("224")),
        "SHA-256" | "SHA256" => ("SHA-2", Some("256")),
        "SHA-384" | "SHA384" => ("SHA-2", Some("384")),
        "SHA-512" | "SHA512" => ("SHA-2", Some("512")),
        // FIPS 180-4 truncated variants ('/' is folded to '-' by
        // normalize_algo_token). These must classify by their truncated
        // OUTPUT size — SHA-512/256 is a 256-bit digest and NOT on the
        // CNSA 2.0 hash allowlist, unlike full SHA-512 (finding: the
        // generic rsplit branch preferred the alias-implied 512).
        "SHA-512-256" | "SHA512-256" => ("SHA-2", Some("256")),
        "SHA-512-224" | "SHA512-224" => ("SHA-2", Some("224")),
        // SHA-3 family.
        "SHA-3" | "SHA3" | "KECCAK" | "SHAKE" | "SHAKE128" | "SHAKE256" => ("SHA-3", None),
        "SHA3-224" => ("SHA-3", Some("224")),
        "SHA3-256" => ("SHA-3", Some("256")),
        "SHA3-384" => ("SHA-3", Some("384")),
        "SHA3-512" => ("SHA-3", Some("512")),
        // Post-quantum (final and round-3 names).
        "ML-KEM" | "MLKEM" | "KYBER" | "CRYSTALS-KYBER" => ("ML-KEM", None),
        "ML-DSA" | "MLDSA" => ("ML-DSA", None),
        "DILITHIUM" | "CRYSTALS-DILITHIUM" => {
            return Some(("ML-DSA", None, true));
        }
        "SLH-DSA" | "SLHDSA" | "SPHINCS" | "SPHINCS+" | "SPHINCSPLUS" => ("SLH-DSA", None),
        "FALCON" | "FN-DSA" | "FNDSA" => ("FN-DSA", None),
        "LMS" | "HSS-LMS" | "LMS-HSS" => ("LMS", None),
        "XMSS" | "XMSS-MT" | "XMSSMT" => ("XMSS", None),
        "HSS" => ("HSS", None),
        _ => return None,
    };
    Some((hit.0, hit.1, false))
}

/// Uppercase and map separator characters (`_`, ` `, `/`, `.`) to `-`.
fn normalize_algo_token(s: &str) -> String {
    s.trim()
        .chars()
        .map(|c| match c {
            '_' | ' ' | '/' | '.' => '-',
            other => other.to_ascii_uppercase(),
        })
        .collect()
}

/// Map round-3 Dilithium parameter sets to the final ML-DSA ones.
fn map_dilithium_param(p: &str) -> String {
    match p {
        "2" => "44".to_string(),
        "3" => "65".to_string(),
        "5" => "87".to_string(),
        other => other.to_string(),
    }
}

/// Classify one normalized token (a family string, or a joined name-token
/// span): direct alias, then trailing `-<digits>` size split, then a trailing
/// digit run without separator ("AES128").
fn classify_token(token: &str) -> Option<(&'static str, Option<String>)> {
    let t = normalize_algo_token(token);

    let finish = |family: &'static str, param: Option<String>, dilithium: bool| {
        let param = if dilithium {
            param.map(|p| map_dilithium_param(&p))
        } else {
            param
        };
        Some((family, param))
    };

    if let Some((family, param, dilithium)) = alias_lookup(&t) {
        return finish(family, param.map(str::to_string), dilithium);
    }

    // Brainpool named curves ("brainpoolP256r1", "brainpoolP384t1", …):
    // the whole RFC 5639 family is classical elliptic-curve crypto.
    if t.starts_with("BRAINPOOL") {
        return Some(("EC", None));
    }

    // Trailing "-<digits>" size: "ML-KEM-1024", "AES-128", "RSA-2048", "KYBER-768".
    if let Some((base, digits)) = t.rsplit_once('-')
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && let Some((family, param, dilithium)) = alias_lookup(base)
    {
        let param = param
            .map(str::to_string)
            .or_else(|| Some(digits.to_string()));
        return finish(family, param, dilithium);
    }

    // Trailing digit run without separator: "AES128", "KYBER768", "RSA2048".
    // (Counting trailing ASCII-digit bytes keeps the split on a char boundary
    // even for non-ASCII input.)
    let digit_start = t.len() - t.bytes().rev().take_while(u8::is_ascii_digit).count();
    if digit_start > 0 && digit_start < t.len() {
        let (alpha, digits) = t.split_at(digit_start);
        if let Some((family, param, dilithium)) = alias_lookup(alpha.trim_end_matches('-')) {
            let param = param
                .map(str::to_string)
                .or_else(|| Some(digits.to_string()));
            return finish(family, param, dilithium);
        }
    }

    None
}

/// Extract every recognizable algorithm mention from a free-form name using
/// word-boundary token matching (never bare substrings). Used for cipher-suite
/// names ("`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`") and as the guarded
/// name-based fallback for assets without `algorithmFamily`/OID.
///
/// Tokens are split on any non-alphanumeric character (keeping `+` for
/// "SPHINCS+"); spans of up to three adjacent tokens are joined with `-` and
/// matched longest-first, so "ML KEM 1024" and "AES 128" resolve as units.
/// Unrecognized tokens (GCM, CBC, TLS, WITH, …) are simply skipped.
#[must_use]
pub fn classify_algorithm_names(name: &str) -> Vec<AlgorithmClassification> {
    classify_names_impl(name, false)
}

/// Like [`classify_algorithm_names`], but drops the riskiest bare aliases
/// ("SEED", "EC"/"ECC") that collide with everyday words — "seed-expander"
/// is a DRBG utility, not the SEED block cipher, and "ec2" is not elliptic
/// curve crypto. Used for the name-only fallback and raw bom-ref scans,
/// where no structured identity backs the token; declared `algorithmFamily`
/// strings and cipher-suite names (where bare "SEED" really is the cipher)
/// keep the full alias table.
#[must_use]
pub fn classify_algorithm_names_guarded(name: &str) -> Vec<AlgorithmClassification> {
    classify_names_impl(name, true)
}

/// Whether a matched token span is too generic to trust in unstructured
/// text: the bare SEED / EC / ECC aliases (with or without a trailing
/// size digit run) collide with non-crypto words.
fn is_overgeneric_span(span: &str) -> bool {
    let base = span
        .trim_end_matches(|c: char| c.is_ascii_digit())
        .trim_end_matches('-');
    matches!(base, "SEED" | "EC" | "ECC")
}

fn classify_names_impl(name: &str, guarded: bool) -> Vec<AlgorithmClassification> {
    let upper = name.to_uppercase();
    let tokens: Vec<&str> = upper
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '+'))
        .filter(|t| !t.is_empty())
        .collect();

    let mut out: Vec<AlgorithmClassification> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        // A pure number can never start an algorithm mention.
        if tokens[i].bytes().all(|b| b.is_ascii_digit()) {
            i += 1;
            continue;
        }
        let max_span = 3.min(tokens.len() - i);
        let mut advanced = false;
        for span in (1..=max_span).rev() {
            let joined = tokens[i..i + span].join("-");
            if let Some((family, parameter)) = classify_token(&joined) {
                if guarded && is_overgeneric_span(&joined) {
                    continue;
                }
                let cls = AlgorithmClassification {
                    family: Some(family.to_string()),
                    parameter,
                    class: family_class(family),
                };
                if !out.contains(&cls) {
                    out.push(cls);
                }
                i += span;
                advanced = true;
                break;
            }
        }
        if !advanced {
            i += 1;
        }
    }
    out
}

/// The most severe classification among `mentions` (first wins on ties),
/// per [`AlgorithmClass::severity_rank`]. Callers that must reduce a
/// multi-algorithm identity ("sha384-rsa-cert-chain") to one verdict use
/// this so the worst algorithm is reported, never whichever token happened
/// to appear first.
#[must_use]
pub fn worst_classification(
    mentions: Vec<AlgorithmClassification>,
) -> Option<AlgorithmClassification> {
    let mut worst: Option<AlgorithmClassification> = None;
    for m in mentions {
        if worst
            .as_ref()
            .is_none_or(|w| m.class.severity_rank() > w.class.severity_rank())
        {
            worst = Some(m);
        }
    }
    worst
}

/// Classify an algorithm OID. Covers the common arcs emitted by real CBOM
/// generators; unknown OIDs return `None` (callers treat as unverifiable,
/// never as compliant).
fn classify_oid(oid: &str) -> Option<(&'static str, Option<String>)> {
    let o = oid.trim();

    // Exact matches first.
    let exact: Option<(&'static str, Option<&'static str>)> = match o {
        "1.3.14.3.2.26" => Some(("SHA-1", None)),
        "1.2.840.113549.2.2" => Some(("MD2", None)),
        "1.2.840.113549.2.4" => Some(("MD4", None)),
        "1.2.840.113549.2.5" => Some(("MD5", None)),
        "1.3.14.3.2.7" => Some(("DES", None)),
        "1.2.840.113549.3.7" => Some(("3DES", None)),
        "1.2.840.113549.3.2" => Some(("RC2", None)),
        "1.2.840.113549.3.4" => Some(("RC4", None)),
        "1.2.840.10040.4.1" | "1.2.840.10040.4.3" => Some(("DSA", None)),
        "1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => Some(("DH", None)),
        "1.3.101.110" => Some(("X25519", None)),
        "1.3.101.111" => Some(("X448", None)),
        "1.3.101.112" => Some(("ED25519", None)),
        "1.3.101.113" => Some(("ED448", None)),
        // NIST hash algorithm arc (2.16.840.1.101.3.4.2.*).
        "2.16.840.1.101.3.4.2.1" => Some(("SHA-2", Some("256"))),
        "2.16.840.1.101.3.4.2.2" => Some(("SHA-2", Some("384"))),
        "2.16.840.1.101.3.4.2.3" => Some(("SHA-2", Some("512"))),
        "2.16.840.1.101.3.4.2.4" => Some(("SHA-2", Some("224"))),
        "2.16.840.1.101.3.4.2.5" => Some(("SHA-2", Some("224"))), // SHA-512/224
        "2.16.840.1.101.3.4.2.6" => Some(("SHA-2", Some("256"))), // SHA-512/256
        "2.16.840.1.101.3.4.2.7" => Some(("SHA-3", Some("224"))),
        "2.16.840.1.101.3.4.2.8" => Some(("SHA-3", Some("256"))),
        "2.16.840.1.101.3.4.2.9" => Some(("SHA-3", Some("384"))),
        "2.16.840.1.101.3.4.2.10" => Some(("SHA-3", Some("512"))),
        "2.16.840.1.101.3.4.2.11" | "2.16.840.1.101.3.4.2.12" => Some(("SHA-3", None)), // SHAKE
        // SP 800-208 / RFC 8708 stateful hash-based signatures.
        "1.2.840.113549.1.9.16.3.17" => Some(("LMS", None)), // id-alg-hss-lms-hashsig
        "0.4.0.127.0.15.1.1.13.0" => Some(("XMSS", None)),
        _ => None,
    };
    if let Some((family, param)) = exact {
        return Some((family, param.map(str::to_string)));
    }

    // RSA arc: 1.2.840.113549.1.1.* (rsaEncryption, *WithRSAEncryption, PSS, OAEP).
    if o.starts_with("1.2.840.113549.1.1.") {
        return Some(("RSA", None));
    }
    // ANSI X9.62 elliptic-curve arc: keys, curves, and ECDSA signatures.
    if o.starts_with("1.2.840.10045.4.") {
        return Some(("ECDSA", None));
    }
    if o.starts_with("1.2.840.10045.") {
        return Some(("EC", None));
    }
    // SECG named curves (secp256k1, secp384r1, ...).
    if o.starts_with("1.3.132.") {
        return Some(("EC", None));
    }
    // NIST AES arc: 2.16.840.1.101.3.4.1.<n> — n encodes the key size.
    if let Some(rest) = o.strip_prefix("2.16.840.1.101.3.4.1.")
        && let Ok(n) = rest.parse::<u32>()
    {
        let bits = match n {
            1..=10 => Some("128"),
            21..=30 => Some("192"),
            41..=50 => Some("256"),
            _ => None,
        };
        return Some(("AES", bits.map(str::to_string)));
    }
    // NIST KEM arc: 2.16.840.1.101.3.4.4.<n> (ML-KEM-512/768/1024).
    if let Some(rest) = o.strip_prefix("2.16.840.1.101.3.4.4.")
        && let Ok(n) = rest.parse::<u32>()
    {
        let param = match n {
            1 => Some("512"),
            2 => Some("768"),
            3 => Some("1024"),
            _ => None,
        };
        return Some(("ML-KEM", param.map(str::to_string)));
    }
    // NIST signature-algorithm arc: 2.16.840.1.101.3.4.3.<n>.
    if let Some(rest) = o.strip_prefix("2.16.840.1.101.3.4.3.")
        && let Ok(n) = rest.parse::<u32>()
    {
        return match n {
            1..=8 => Some(("DSA", None)),    // dsa-with-sha2/sha3
            9..=12 => Some(("ECDSA", None)), // ecdsa-with-sha3
            13..=16 => Some(("RSA", None)),  // rsassa-pkcs1 with sha3
            17 => Some(("ML-DSA", Some("44".to_string()))),
            18 => Some(("ML-DSA", Some("65".to_string()))),
            19 => Some(("ML-DSA", Some("87".to_string()))),
            // Per the NIST CSOR registry only 20–31 are SLH-DSA parameter
            // sets; 32–34 are id-hash-ml-dsa-44/65/87-with-sha512 (pre-hash
            // ML-DSA, FIPS 204) and 35–46 the pre-hash SLH-DSA variants.
            20..=31 => Some(("SLH-DSA", None)),
            32 => Some(("ML-DSA", Some("44".to_string()))),
            33 => Some(("ML-DSA", Some("65".to_string()))),
            34 => Some(("ML-DSA", Some("87".to_string()))),
            35..=46 => Some(("SLH-DSA", None)),
            _ => None,
        };
    }
    // Chinese SM arcs (GM/T 0006): SM2 EC signature/KEX, SM3 hash, SM4
    // block cipher — SM2 is elliptic-curve crypto broken by Shor's
    // algorithm, exactly like ECDSA.
    if o == "1.2.156.10197.1.301" || o.starts_with("1.2.156.10197.1.301.") {
        return Some(("SM2", None));
    }
    if o == "1.2.156.10197.1.401" || o.starts_with("1.2.156.10197.1.401.") {
        return Some(("SM3", None));
    }
    if o == "1.2.156.10197.1.104" || o.starts_with("1.2.156.10197.1.104.") {
        return Some(("SM4", None));
    }
    // Russian GOST R 34.10 (quantum-vulnerable EC signature): 34.10-94/2001
    // keys and signatures plus the 34.10-2012 key (1.2.643.7.1.1.1.*) and
    // signature (1.2.643.7.1.1.3.*) arcs.
    if matches!(
        o,
        "1.2.643.2.2.19" | "1.2.643.2.2.20" | "1.2.643.2.2.3" | "1.2.643.2.2.4"
    ) || o.starts_with("1.2.643.7.1.1.1.")
        || o.starts_with("1.2.643.7.1.1.3.")
    {
        return Some(("GOST-R-34.10", None));
    }
    // GOST R 34.11 hashes (34.11-94 and the 34.11-2012 "Streebog" arc).
    if o == "1.2.643.2.2.9" || o.starts_with("1.2.643.7.1.1.2.") {
        return Some(("GOST-R-34.11", None));
    }
    // Brainpool named-curve arc (RFC 5639): classical EC crypto.
    if o.starts_with("1.3.36.3.3.2.8.1.") {
        return Some(("EC", None));
    }

    None
}

/// Classify a cryptographic algorithm from whatever identity a CBOM provides.
///
/// Sources are consulted in decreasing order of authority:
///
/// 1. `family` (CycloneDX 1.7 `algorithmFamily`), normalized through the
///    alias table (case, `_`/` `/`/` separators, "SHA1"→"SHA-1",
///    "TDES"→"3DES", "Kyber"→"ML-KEM", …) with trailing sizes extracted
///    ("ML-KEM-768" → ML-KEM + 768). A bare "SHA" family accompanied by a
///    SHA-2 digest size in `parameter_set` reads as SHA-2 of that size
///    (bare "SHA" means SHA-1 only in cipher-suite context).
/// 2. `oid` (CycloneDX 1.6+ `cryptoProperties.oid`) via [`classify_oid`].
/// 3. A declared-but-unrecognized `family` string is token-scanned as a
///    last resort ("DES-CBC", "AES-128-CBC", "RSA/ECB/PKCS1Padding"), and
///    the most severe mention wins — a mode/padding-qualified family must
///    not silently classify as Unknown.
/// 4. `elliptic_curve` (CycloneDX 1.7): any named curve marks the asset as
///    classical elliptic-curve crypto.
/// 5. `name`: word-boundary token matching via
///    [`classify_algorithm_names_guarded`], used **only** when both
///    `family` and `oid` are absent — bounding false positives to assets
///    that carry no structured identity at all. The most severe mention
///    wins ("sha384-rsa-signature" is RSA, not SHA-384). Callers should
///    only pass names of components that actually have `crypto_properties`.
///
/// The explicit `parameter_set` (CycloneDX `parameterSetIdentifier`) fills the
/// parameter when the identity source did not carry one; failing that, the
/// component name is mined for a size of the same family ("AES" + name
/// "AES-256-GCM" → 256). The CycloneDX `primitive` field is deliberately not
/// used for classification — it cannot distinguish, say, ML-DSA from ECDSA,
/// and callers that need primitive-based decisions (symmetric-vs-asymmetric
/// severity) already have it.
#[must_use]
pub fn classify_algorithm(
    family: Option<&str>,
    name: Option<&str>,
    oid: Option<&str>,
    parameter_set: Option<&str>,
    elliptic_curve: Option<&str>,
) -> AlgorithmClassification {
    let fill_parameter = |mut cls: AlgorithmClassification| {
        if cls.parameter.is_none() {
            cls.parameter = parameter_set
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string);
        }
        // Last resort: mine the component name for a size carried alongside
        // the same family ("AES" + "AES-256-GCM" → 256).
        if cls.parameter.is_none()
            && let Some(n) = name
            && let Some(named) = classify_algorithm_names(n)
                .into_iter()
                .find(|c| c.family == cls.family)
        {
            cls.parameter = named.parameter;
        }
        cls
    };

    // 1. Explicit algorithm family.
    if let Some(f) = family.map(str::trim).filter(|f| !f.is_empty()) {
        // Bare "SHA" means SHA-1 only in TLS cipher-suite names; a declared
        // family "SHA" with a SHA-2 digest size in parameterSetIdentifier
        // is that SHA-2 variant (finding: "SHA" + "384" was reported as the
        // broken, self-contradictory "SHA-1-384").
        if normalize_algo_token(f) == "SHA"
            && let Some(p @ ("224" | "256" | "384" | "512")) = parameter_set.map(str::trim)
        {
            return AlgorithmClassification {
                family: Some("SHA-2".to_string()),
                parameter: Some(p.to_string()),
                class: AlgorithmClass::Sha2,
            };
        }
        if let Some((canonical, parameter)) = classify_token(f) {
            return fill_parameter(AlgorithmClassification {
                family: Some(canonical.to_string()),
                parameter,
                class: family_class(canonical),
            });
        }
    } else if let Some(o) = oid.map(str::trim).filter(|o| !o.is_empty()) {
        // 2. OID (only consulted when no family is declared: a recognized
        //    family is authoritative over the OID).
        if let Some((canonical, parameter)) = classify_oid(o) {
            return fill_parameter(AlgorithmClassification {
                family: Some(canonical.to_string()),
                parameter,
                class: family_class(canonical),
            });
        }
    }

    // Family declared but unrecognized: still try the OID.
    if family.is_some()
        && let Some(o) = oid.map(str::trim).filter(|o| !o.is_empty())
        && let Some((canonical, parameter)) = classify_oid(o)
    {
        return fill_parameter(AlgorithmClassification {
            family: Some(canonical.to_string()),
            parameter,
            class: family_class(canonical),
        });
    }

    // 3. Family declared but not a single recognizable token: token-scan
    //    the family string itself, taking the most severe mention, so
    //    compound spellings carrying a mode/chaining/padding qualifier
    //    ("DES-CBC", "AES-128-CBC", "3DES-EDE-CBC", "RSA/ECB/PKCS1Padding")
    //    classify by their base algorithm instead of falling through to
    //    Unknown (which turned required CNSA2/PQC Errors into Warnings).
    //    The declared family is authoritative, so the scan is unguarded.
    if let Some(f) = family.map(str::trim).filter(|f| !f.is_empty())
        && let Some(cls) = worst_classification(classify_algorithm_names(f))
    {
        return fill_parameter(cls);
    }

    // 4. A named elliptic curve is authoritative that this is EC crypto.
    if let Some(curve) = elliptic_curve.map(str::trim).filter(|c| !c.is_empty()) {
        return AlgorithmClassification {
            family: Some("EC".to_string()),
            parameter: Some(curve.to_string()),
            class: AlgorithmClass::ClassicalQuantumVulnerable,
        };
    }

    // 5. Guarded name fallback: only when family and OID are both absent,
    //    with over-generic bare tokens (SEED/EC) dropped and the most
    //    severe mention reported.
    if family.is_none()
        && oid.is_none()
        && let Some(n) = name
        && let Some(cls) = worst_classification(classify_algorithm_names_guarded(n))
    {
        return fill_parameter(cls);
    }

    AlgorithmClassification {
        family: None,
        parameter: parameter_set.map(str::to_string),
        class: AlgorithmClass::Unknown,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_is_quantum_safe() {
        let algo =
            AlgorithmProperties::new(CryptoPrimitive::Kem).with_nist_quantum_security_level(5);
        assert!(algo.is_quantum_safe());

        let classical =
            AlgorithmProperties::new(CryptoPrimitive::Pke).with_nist_quantum_security_level(0);
        assert!(!classical.is_quantum_safe());

        let unknown = AlgorithmProperties::new(CryptoPrimitive::Pke);
        assert!(!unknown.is_quantum_safe());
    }

    #[test]
    fn algorithm_is_hybrid_pqc() {
        let hybrid = AlgorithmProperties::new(CryptoPrimitive::Combiner);
        assert!(hybrid.is_hybrid_pqc());

        let normal = AlgorithmProperties::new(CryptoPrimitive::Kem);
        assert!(!normal.is_hybrid_pqc());
    }

    #[test]
    fn algorithm_is_weak() {
        let md5 = AlgorithmProperties::new(CryptoPrimitive::Hash)
            .with_algorithm_family("MD5".to_string());
        assert!(md5.is_weak());

        let sha1 = AlgorithmProperties::new(CryptoPrimitive::Hash)
            .with_algorithm_family("SHA-1".to_string());
        assert!(sha1.is_weak());

        let des = AlgorithmProperties::new(CryptoPrimitive::BlockCipher)
            .with_algorithm_family("DES".to_string());
        assert!(des.is_weak());

        let rc4 = AlgorithmProperties::new(CryptoPrimitive::StreamCipher)
            .with_algorithm_family("RC4".to_string());
        assert!(rc4.is_weak());

        let aes =
            AlgorithmProperties::new(CryptoPrimitive::Ae).with_algorithm_family("AES".to_string());
        assert!(!aes.is_weak());

        let ml_kem = AlgorithmProperties::new(CryptoPrimitive::Kem)
            .with_algorithm_family("ML-KEM".to_string());
        assert!(!ml_kem.is_weak());
    }

    #[test]
    fn certificate_expiry() {
        let expired = CertificateProperties::new()
            .with_not_valid_after(Utc::now() - chrono::Duration::days(1));
        assert!(expired.is_expired());
        assert!(!expired.is_expiring_soon(90));

        let valid = CertificateProperties::new()
            .with_not_valid_after(Utc::now() + chrono::Duration::days(365));
        assert!(!valid.is_expired());
        assert!(!valid.is_expiring_soon(90));

        let expiring = CertificateProperties::new()
            .with_not_valid_after(Utc::now() + chrono::Duration::days(30));
        assert!(!expiring.is_expired());
        assert!(expiring.is_expiring_soon(90));
    }

    #[test]
    fn certificate_validity_days() {
        let no_expiry = CertificateProperties::new();
        assert!(no_expiry.validity_days().is_none());

        let expired = CertificateProperties::new()
            .with_not_valid_after(Utc::now() - chrono::Duration::days(10));
        assert!(expired.validity_days().unwrap() < 0);

        let future = CertificateProperties::new()
            .with_not_valid_after(Utc::now() + chrono::Duration::days(100));
        let days = future.validity_days().unwrap();
        assert!(days >= 99 && days <= 100);
    }

    #[test]
    fn crypto_properties_builder() {
        let props = CryptoProperties::new(CryptoAssetType::Algorithm)
            .with_oid("2.16.840.1.101.3.4.1.46".to_string())
            .with_algorithm_properties(
                AlgorithmProperties::new(CryptoPrimitive::Ae)
                    .with_algorithm_family("AES".to_string())
                    .with_mode(CryptoMode::Gcm)
                    .with_classical_security_level(256)
                    .with_nist_quantum_security_level(1),
            );

        assert_eq!(props.asset_type, CryptoAssetType::Algorithm);
        assert_eq!(props.oid.as_deref(), Some("2.16.840.1.101.3.4.1.46"));
        let algo = props.algorithm_properties.unwrap();
        assert_eq!(algo.primitive, CryptoPrimitive::Ae);
        assert_eq!(algo.algorithm_family.as_deref(), Some("AES"));
        assert_eq!(algo.mode, Some(CryptoMode::Gcm));
        assert_eq!(algo.classical_security_level, Some(256));
        assert!(algo.is_quantum_safe());
        assert!(!algo.is_weak());
    }

    #[test]
    fn display_impls() {
        assert_eq!(CryptoAssetType::Algorithm.to_string(), "algorithm");
        assert_eq!(
            CryptoAssetType::RelatedCryptoMaterial.to_string(),
            "related-crypto-material"
        );
        assert_eq!(CryptoPrimitive::Kem.to_string(), "kem");
        assert_eq!(CryptoPrimitive::Combiner.to_string(), "combiner");
        assert_eq!(CryptoMode::Gcm.to_string(), "gcm");
        assert_eq!(CryptoFunction::Encapsulate.to_string(), "encapsulate");
        assert_eq!(CryptoMaterialType::PublicKey.to_string(), "public-key");
        assert_eq!(CryptoMaterialState::Compromised.to_string(), "compromised");
        assert_eq!(ProtocolType::Tls.to_string(), "tls");
        assert_eq!(CertificationLevel::Fips140_3L1.to_string(), "fips140-3-l1");
        assert_eq!(ExecutionEnvironment::Hardware.to_string(), "hardware");
        assert_eq!(ImplementationPlatform::X86_64.to_string(), "x86_64");
    }

    #[test]
    fn protocol_builder() {
        let proto = ProtocolProperties::new(ProtocolType::Tls)
            .with_version("1.3".to_string())
            .with_cipher_suites(vec![CipherSuite {
                name: Some("TLS_AES_256_GCM_SHA384".to_string()),
                algorithms: vec!["algo/aes-256-gcm".to_string()],
                identifiers: vec!["0x13".to_string(), "0x02".to_string()],
            }]);

        assert_eq!(proto.protocol_type, ProtocolType::Tls);
        assert_eq!(proto.version.as_deref(), Some("1.3"));
        assert_eq!(proto.cipher_suites.len(), 1);
    }

    // ── classify_algorithm ──────────────────────────────────────────────

    fn cls(
        family: Option<&str>,
        name: Option<&str>,
        oid: Option<&str>,
        param: Option<&str>,
        curve: Option<&str>,
    ) -> AlgorithmClassification {
        classify_algorithm(family, name, oid, param, curve)
    }

    #[test]
    fn classify_family_spelling_variants() {
        // Aliases and separator styles all land on the canonical family.
        for (input, family, class) in [
            ("SHA1", "SHA-1", AlgorithmClass::Broken),
            ("sha-1", "SHA-1", AlgorithmClass::Broken),
            ("TDES", "3DES", AlgorithmClass::Broken),
            ("DES-EDE3", "3DES", AlgorithmClass::Broken),
            ("3DES-EDE", "3DES", AlgorithmClass::Broken),
            ("ARC4", "RC4", AlgorithmClass::Broken),
            ("ARCFOUR", "RC4", AlgorithmClass::Broken),
            (
                "Ed25519",
                "ED25519",
                AlgorithmClass::ClassicalQuantumVulnerable,
            ),
            ("ECIES", "ECIES", AlgorithmClass::ClassicalQuantumVulnerable),
            ("ECDHE", "ECDH", AlgorithmClass::ClassicalQuantumVulnerable),
            ("EC", "EC", AlgorithmClass::ClassicalQuantumVulnerable),
            ("ChaCha20", "CHACHA20", AlgorithmClass::Symmetric),
            ("Camellia", "CAMELLIA", AlgorithmClass::Symmetric),
        ] {
            let c = cls(Some(input), None, None, None, None);
            assert_eq!(c.family.as_deref(), Some(family), "family for {input}");
            assert_eq!(c.class, class, "class for {input}");
        }
    }

    #[test]
    fn classify_size_in_family_string() {
        let c = cls(Some("ML-KEM-768"), None, None, None, None);
        assert_eq!(c.family.as_deref(), Some("ML-KEM"));
        assert_eq!(c.parameter.as_deref(), Some("768"));
        assert_eq!(c.class, AlgorithmClass::PostQuantum(PqcKind::MlKem));

        let c = cls(Some("AES-128"), None, None, None, None);
        assert_eq!(c.family.as_deref(), Some("AES"));
        assert_eq!(c.parameter.as_deref(), Some("128"));

        let c = cls(Some("AES128"), None, None, None, None);
        assert_eq!(c.parameter.as_deref(), Some("128"));

        let c = cls(Some("RSA-2048"), None, None, None, None);
        assert_eq!(c.family.as_deref(), Some("RSA"));
        assert_eq!(c.parameter.as_deref(), Some("2048"));
        assert_eq!(c.class, AlgorithmClass::ClassicalQuantumVulnerable);

        // SHA sizes fold into the SHA-2 family.
        let c = cls(Some("SHA-256"), None, None, None, None);
        assert_eq!(c.family.as_deref(), Some("SHA-2"));
        assert_eq!(c.parameter.as_deref(), Some("256"));
        assert_eq!(c.class, AlgorithmClass::Sha2);
        assert_eq!(c.label(), "SHA-256");
    }

    #[test]
    fn classify_round3_pqc_names() {
        let c = cls(Some("Kyber"), None, None, Some("768"), None);
        assert_eq!(c.family.as_deref(), Some("ML-KEM"));
        assert_eq!(c.parameter.as_deref(), Some("768"));

        let c = cls(Some("Kyber-1024"), None, None, None, None);
        assert_eq!(c.parameter.as_deref(), Some("1024"));

        // Round-3 Dilithium parameter sets map to the final ML-DSA ones.
        let c = cls(Some("Dilithium-3"), None, None, None, None);
        assert_eq!(c.family.as_deref(), Some("ML-DSA"));
        assert_eq!(c.parameter.as_deref(), Some("65"));

        let c = cls(Some("SPHINCS+"), None, None, None, None);
        assert_eq!(c.class, AlgorithmClass::PostQuantum(PqcKind::SlhDsa));

        let c = cls(Some("Falcon"), None, None, None, None);
        assert_eq!(c.class, AlgorithmClass::PostQuantum(PqcKind::FnDsa));
    }

    #[test]
    fn classify_by_oid() {
        // RSA arc.
        let c = cls(None, None, Some("1.2.840.113549.1.1.1"), Some("2048"), None);
        assert_eq!(c.family.as_deref(), Some("RSA"));
        assert_eq!(c.parameter.as_deref(), Some("2048"));
        assert_eq!(c.class, AlgorithmClass::ClassicalQuantumVulnerable);

        // SHA-1 / MD5.
        assert_eq!(
            cls(None, None, Some("1.3.14.3.2.26"), None, None).class,
            AlgorithmClass::Broken
        );
        assert_eq!(
            cls(None, None, Some("1.2.840.113549.2.5"), None, None).class,
            AlgorithmClass::Broken
        );

        // AES arc encodes the key size: .2 = AES-128-CBC, .46 = AES-256-GCM.
        let c = cls(None, None, Some("2.16.840.1.101.3.4.1.2"), None, None);
        assert_eq!(c.family.as_deref(), Some("AES"));
        assert_eq!(c.parameter.as_deref(), Some("128"));
        let c = cls(None, None, Some("2.16.840.1.101.3.4.1.46"), None, None);
        assert_eq!(c.parameter.as_deref(), Some("256"));

        // SHA-2 arc.
        let c = cls(None, None, Some("2.16.840.1.101.3.4.2.2"), None, None);
        assert_eq!(c.class, AlgorithmClass::Sha2);
        assert_eq!(c.parameter.as_deref(), Some("384"));

        // ML-KEM / ML-DSA / SLH-DSA arcs.
        let c = cls(None, None, Some("2.16.840.1.101.3.4.4.3"), None, None);
        assert_eq!(c.class, AlgorithmClass::PostQuantum(PqcKind::MlKem));
        assert_eq!(c.parameter.as_deref(), Some("1024"));
        let c = cls(None, None, Some("2.16.840.1.101.3.4.3.19"), None, None);
        assert_eq!(c.class, AlgorithmClass::PostQuantum(PqcKind::MlDsa));
        assert_eq!(c.parameter.as_deref(), Some("87"));
        let c = cls(None, None, Some("2.16.840.1.101.3.4.3.24"), None, None);
        assert_eq!(c.class, AlgorithmClass::PostQuantum(PqcKind::SlhDsa));

        // Edwards / Montgomery curves.
        assert_eq!(
            cls(None, None, Some("1.3.101.112"), None, None)
                .family
                .as_deref(),
            Some("ED25519")
        );

        // ECDSA signature and EC curve arcs.
        assert_eq!(
            cls(None, None, Some("1.2.840.10045.4.3.2"), None, None).class,
            AlgorithmClass::ClassicalQuantumVulnerable
        );
        assert_eq!(
            cls(None, None, Some("1.2.840.10045.3.1.7"), None, None).class,
            AlgorithmClass::ClassicalQuantumVulnerable
        );
    }

    #[test]
    fn classify_name_fallback_only_without_family_and_oid() {
        // Name fallback fires when family and OID are both absent...
        let c = cls(None, Some("AES-128-CBC"), None, None, None);
        assert_eq!(c.family.as_deref(), Some("AES"));
        assert_eq!(c.parameter.as_deref(), Some("128"));

        let c = cls(None, Some("RSA-2048-PKCS1"), None, None, None);
        assert_eq!(c.family.as_deref(), Some("RSA"));

        // ...but never overrides a present (unrecognized) family or OID.
        let c = cls(
            Some("proprietary-frobnicator"),
            Some("RSA-2048"),
            None,
            None,
            None,
        );
        assert_eq!(c.class, AlgorithmClass::Unknown);
        let c = cls(None, Some("RSA-2048"), Some("9.9.9.9"), None, None);
        assert_eq!(c.class, AlgorithmClass::Unknown);

        // Word-boundary matching: "DESCRIPTOR" must not match DES.
        let c = cls(None, Some("DESCRIPTOR-HANDLER"), None, None, None);
        assert_eq!(c.class, AlgorithmClass::Unknown);
    }

    #[test]
    fn classify_elliptic_curve_field() {
        // The parsed-but-previously-unread ellipticCurve field marks the
        // asset as classical EC crypto even without family/OID/name.
        let c = cls(None, None, None, None, Some("secg/secp256r1"));
        assert_eq!(c.class, AlgorithmClass::ClassicalQuantumVulnerable);
        assert_eq!(c.family.as_deref(), Some("EC"));
        assert_eq!(c.parameter.as_deref(), Some("secg/secp256r1"));
    }

    #[test]
    fn classify_name_enriches_missing_parameter() {
        // Family without a parameter set picks the size up from the name.
        let c = cls(Some("AES"), Some("AES-256-GCM"), None, None, None);
        assert_eq!(c.parameter.as_deref(), Some("256"));
    }

    #[test]
    fn classify_cipher_suite_names() {
        let found = classify_algorithm_names("TLS_RSA_WITH_RC4_128_SHA");
        let families: Vec<_> = found.iter().filter_map(|c| c.family.as_deref()).collect();
        assert!(families.contains(&"RSA"), "{families:?}");
        assert!(families.contains(&"RC4"), "{families:?}");
        assert!(families.contains(&"SHA-1"), "{families:?}");

        // A CNSA 2.0 suite: everything recognized resolves to approved
        // algorithms, and the noise tokens (TLS/GCM) match nothing.
        let found = classify_algorithm_names("TLS_AES_256_GCM_SHA384_ML_KEM_1024");
        assert!(
            found.iter().any(
                |c| c.family.as_deref() == Some("AES") && c.parameter.as_deref() == Some("256")
            )
        );
        assert!(
            found
                .iter()
                .any(|c| c.family.as_deref() == Some("SHA-2")
                    && c.parameter.as_deref() == Some("384"))
        );
        assert!(found.iter().any(
            |c| c.family.as_deref() == Some("ML-KEM") && c.parameter.as_deref() == Some("1024")
        ));
        assert!(!found.iter().any(|c| c.class == AlgorithmClass::Broken));
    }

    /// Compound algorithmFamily strings carrying a mode/chaining/padding
    /// qualifier must classify by their base algorithm (+ key size), not
    /// fall through to Unknown (finding: "DES-CBC" passed CNSA2/PQC).
    #[test]
    fn classify_compound_family_mode_suffixes() {
        for (family, canonical, param, class) in [
            ("DES-CBC", "DES", None, AlgorithmClass::Broken),
            ("3DES-EDE-CBC", "3DES", None, AlgorithmClass::Broken),
            ("AES-128-CBC", "AES", Some("128"), AlgorithmClass::Symmetric),
            ("AES-256-GCM", "AES", Some("256"), AlgorithmClass::Symmetric),
            (
                "RSA/ECB/PKCS1Padding",
                "RSA",
                None,
                AlgorithmClass::ClassicalQuantumVulnerable,
            ),
        ] {
            let c = cls(Some(family), None, None, None, None);
            assert_eq!(c.family.as_deref(), Some(canonical), "family for {family}");
            assert_eq!(c.parameter.as_deref(), param, "parameter for {family}");
            assert_eq!(c.class, class, "class for {family}");
        }
        // The scan reports the most severe mention: a compound family
        // mixing a broken cipher with an approved hash is the cipher.
        let c = cls(Some("DES-CBC-HMAC-SHA384"), None, None, None, None);
        assert_eq!(c.family.as_deref(), Some("DES"));
        assert_eq!(c.class, AlgorithmClass::Broken);
        // Silent case: families with no recognizable token stay Unknown.
        for family in ["Hybrid-KEM", "proprietary-frobnicator"] {
            let c = cls(Some(family), None, None, None, None);
            assert_eq!(c.class, AlgorithmClass::Unknown, "class for {family}");
        }
    }

    /// FIPS 180-4 truncated SHA-2 must classify by the truncated OUTPUT
    /// size — SHA-512/256 is a 256-bit digest, not CNSA-approved SHA-512.
    #[test]
    fn classify_truncated_sha2_variants() {
        for (family, param) in [
            ("SHA-512/256", "256"),
            ("SHA-512/224", "224"),
            ("SHA512/256", "256"),
            ("sha-512/224", "224"),
        ] {
            let c = cls(Some(family), None, None, None, None);
            assert_eq!(c.family.as_deref(), Some("SHA-2"), "family for {family}");
            assert_eq!(c.parameter.as_deref(), Some(param), "param for {family}");
            assert_eq!(c.class, AlgorithmClass::Sha2);
        }
        // Full SHA-512 keeps its 512-bit reading, and the family-string
        // path now agrees with the OID path for the truncated variants.
        let c = cls(Some("SHA-512"), None, None, None, None);
        assert_eq!(c.parameter.as_deref(), Some("512"));
        let by_oid = cls(None, None, Some("2.16.840.1.101.3.4.2.6"), None, None);
        assert_eq!(by_oid.parameter.as_deref(), Some("256"));
    }

    /// The name fallback must report the most severe mention, not the
    /// first: "sha384-rsa-signature" is quantum-vulnerable RSA, not
    /// CNSA-approved SHA-384 (finding: token order hid RSA).
    #[test]
    fn classify_name_fallback_picks_most_severe() {
        let hash_first = cls(None, Some("sha384-rsa-signature"), None, None, None);
        let rsa_first = cls(None, Some("rsa-sha384-signature"), None, None, None);
        for c in [&hash_first, &rsa_first] {
            assert_eq!(c.family.as_deref(), Some("RSA"), "{c:?}");
            assert_eq!(c.class, AlgorithmClass::ClassicalQuantumVulnerable);
        }
        // Broken outranks quantum-vulnerable.
        let c = cls(None, Some("rsa-md5-legacy-signer"), None, None, None);
        assert_eq!(c.family.as_deref(), Some("MD5"));
        assert_eq!(c.class, AlgorithmClass::Broken);
        // Silent case: single-mention names are unaffected.
        let c = cls(None, Some("sha384-digest"), None, None, None);
        assert_eq!(c.class, AlgorithmClass::Sha2);
    }

    /// A declared family "SHA" with a SHA-2 digest size in the parameter
    /// set is SHA-2 of that size, not broken "SHA-1-384" (finding). Bare
    /// "SHA" without a disambiguating parameter keeps the SHA-1 reading
    /// (TLS cipher-suite convention).
    #[test]
    fn classify_bare_sha_with_parameter_set() {
        for param in ["224", "256", "384", "512"] {
            let c = cls(Some("SHA"), None, None, Some(param), None);
            assert_eq!(c.family.as_deref(), Some("SHA-2"), "family for SHA/{param}");
            assert_eq!(c.parameter.as_deref(), Some(param));
            assert_eq!(c.class, AlgorithmClass::Sha2);
        }
        let c = cls(Some("SHA"), None, None, None, None);
        assert_eq!(c.family.as_deref(), Some("SHA-1"));
        assert_eq!(c.class, AlgorithmClass::Broken);
        let c = cls(Some("SHA"), None, None, Some("160"), None);
        assert_eq!(c.family.as_deref(), Some("SHA-1"));
        assert_eq!(c.class, AlgorithmClass::Broken);
    }

    /// National quantum-vulnerable algorithms (SM2, GOST R 34.10,
    /// brainpool curves) must classify as such instead of Unknown, and
    /// SM4/GOST hashes get their proper classes (finding: SM2/GOST CBOMs
    /// passed NIST PQC with only a warning).
    #[test]
    fn classify_national_algorithms() {
        // By family/name alias.
        for (family, canonical) in [
            ("SM2", "SM2"),
            ("sm9", "SM9"),
            ("GOST", "GOST-R-34.10"),
            ("GOST R 34.10", "GOST-R-34.10"),
            ("GOST-R-34.10-2012", "GOST-R-34.10"),
            ("brainpoolP256r1", "EC"),
        ] {
            let c = cls(Some(family), None, None, None, None);
            assert_eq!(c.family.as_deref(), Some(canonical), "family for {family}");
            assert_eq!(
                c.class,
                AlgorithmClass::ClassicalQuantumVulnerable,
                "class for {family}"
            );
        }
        // By OID.
        for (oid, canonical, class) in [
            (
                "1.2.156.10197.1.301",
                "SM2",
                AlgorithmClass::ClassicalQuantumVulnerable,
            ),
            (
                "1.2.643.2.2.19",
                "GOST-R-34.10",
                AlgorithmClass::ClassicalQuantumVulnerable,
            ),
            (
                "1.2.643.7.1.1.1.1",
                "GOST-R-34.10",
                AlgorithmClass::ClassicalQuantumVulnerable,
            ),
            (
                "1.3.36.3.3.2.8.1.1.7",
                "EC",
                AlgorithmClass::ClassicalQuantumVulnerable,
            ),
            ("1.2.156.10197.1.104", "SM4", AlgorithmClass::Symmetric),
            (
                "1.2.643.7.1.1.2.2",
                "GOST-R-34.11",
                AlgorithmClass::OtherHash,
            ),
        ] {
            let c = cls(None, None, Some(oid), None, None);
            assert_eq!(c.family.as_deref(), Some(canonical), "family for {oid}");
            assert_eq!(c.class, class, "class for {oid}");
        }
        // Symmetric / hash aliases.
        assert_eq!(
            cls(Some("SM4"), None, None, None, None).class,
            AlgorithmClass::Symmetric
        );
        assert_eq!(
            cls(Some("Kuznyechik"), None, None, None, None).class,
            AlgorithmClass::Symmetric
        );
        assert_eq!(
            cls(Some("Streebog"), None, None, None, None).class,
            AlgorithmClass::OtherHash
        );
    }

    /// NIST CSOR sigAlgs 32–34 are pre-hash ML-DSA (HashML-DSA-44/65/87
    /// with SHA-512), not SLH-DSA (finding: wrong family + FIPS citation).
    #[test]
    fn classify_hash_ml_dsa_oids() {
        for (oid, param) in [
            ("2.16.840.1.101.3.4.3.32", "44"),
            ("2.16.840.1.101.3.4.3.33", "65"),
            ("2.16.840.1.101.3.4.3.34", "87"),
        ] {
            let c = cls(None, None, Some(oid), None, None);
            assert_eq!(
                c.class,
                AlgorithmClass::PostQuantum(PqcKind::MlDsa),
                "class for {oid}"
            );
            assert_eq!(c.parameter.as_deref(), Some(param), "param for {oid}");
        }
        // The SLH-DSA parameter-set range (20–31) and the pre-hash SLH-DSA
        // range (35–46) still classify as SLH-DSA.
        for oid in [
            "2.16.840.1.101.3.4.3.20",
            "2.16.840.1.101.3.4.3.31",
            "2.16.840.1.101.3.4.3.35",
        ] {
            assert_eq!(
                cls(None, None, Some(oid), None, None).class,
                AlgorithmClass::PostQuantum(PqcKind::SlhDsa),
                "class for {oid}"
            );
        }
    }

    /// The guarded name scan drops over-generic bare tokens (SEED, EC/ECC)
    /// that collide with everyday words, while the declared-family path and
    /// cipher-suite scan keep them (finding: 'seed-expander' was flagged as
    /// the SEED block cipher).
    #[test]
    fn guarded_name_scan_drops_overgeneric_tokens() {
        for name in ["seed-expander", "ec2-instance-agent", "ecc-memory-check"] {
            assert!(
                classify_algorithm_names_guarded(name).is_empty(),
                "guarded scan must ignore {name}"
            );
            assert_eq!(
                cls(None, Some(name), None, None, None).class,
                AlgorithmClass::Unknown,
                "name fallback must not classify {name}"
            );
        }
        // Distinctive tokens still classify through the guarded scan.
        assert_eq!(
            cls(None, Some("brainpoolP256r1-signer"), None, None, None).class,
            AlgorithmClass::ClassicalQuantumVulnerable
        );
        // The unguarded scan (cipher-suite names) keeps bare SEED, and the
        // declared family stays authoritative.
        assert!(
            classify_algorithm_names("TLS_RSA_WITH_SEED_CBC_SHA")
                .iter()
                .any(|c| c.family.as_deref() == Some("SEED"))
        );
        assert_eq!(
            cls(Some("SEED"), None, None, None, None).class,
            AlgorithmClass::Symmetric
        );
    }

    #[test]
    fn related_material_builder() {
        let key = RelatedCryptoMaterialProperties::new(CryptoMaterialType::PublicKey)
            .with_id("test-id".to_string())
            .with_state(CryptoMaterialState::Active)
            .with_size(2048)
            .with_algorithm_ref("algo/rsa-2048".to_string())
            .with_secured_by(SecuredBy {
                mechanism: "HSM".to_string(),
                algorithm_ref: Some("algo/aes-256".to_string()),
            });

        assert_eq!(key.material_type, CryptoMaterialType::PublicKey);
        assert_eq!(key.state, Some(CryptoMaterialState::Active));
        assert_eq!(key.size, Some(2048));
        assert!(key.secured_by.is_some());
    }
}
