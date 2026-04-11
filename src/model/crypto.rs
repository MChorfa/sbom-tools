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

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::manual_range_contains,
        clippy::uninlined_format_args,
        clippy::unnecessary_map_or,
        clippy::unwrap_used
    )]

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
