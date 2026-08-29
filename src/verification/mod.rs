//! SBOM integrity verification.
//!
//! Provides file hash verification, component hash auditing,
//! and SBOM signature/provenance checking.

mod audit;
mod fingerprint;
mod hash;
mod model_dir;
mod path_validation;
pub mod pipeline_receipt;
mod policy;

pub use audit::{HashAuditReport, HashAuditResult, audit_component_hashes};
pub use fingerprint::{lock_fingerprint, source_fingerprint};
pub use hash::{
    HashError, HashVerifyResult, compute_file_sha256, read_hash_file, verify_file_hash,
};
pub use model_dir::{
    ComponentModelVerification, ModelVerifyReport, ModelVerifyResult, verify_model_dir,
};
pub use pipeline_receipt::{
    AggregatePolicy, AggregateVerification, CheckOutcome, ExpectedContext,
    PIPELINE_SHARD_RECEIPT_SCHEMA, PipelineShardReceipt, ReceiptArtifact, ReceiptError,
    ReceiptInput, Sha256Digest, TargetIdentity, TrustContext, TrustedArtifact, VerificationCheck,
    aggregate_receipts, check_receipt, generate_receipt, read_receipt, validate_receipt,
    write_receipt,
};
