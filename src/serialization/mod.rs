//! SBOM serialization and transformation.
//!
//! Two complementary strategies live here:
//! - [`enricher`]/[`merger`]/[`pruner`] patch the *original* raw JSON in place,
//!   preserving the source format's structure exactly.
//! - [`emit`] *synthesizes* a fresh document from the canonical model, enabling
//!   cross-format conversion (e.g. SPDX → CycloneDX).
//! - [`normalized`] is the canonical model itself as JSON — the payload shared
//!   by the C ABI and `convert --to normalized`.

pub mod emit;
mod enricher;
mod merger;
mod normalized;
mod pruner;

pub use emit::{
    EmitError, EmitTarget, FidelityReport, emit, emit_cyclonedx, emit_spdx, preserve_source_json,
};
pub use enricher::enrich_sbom_json;
pub use merger::{DeduplicationStrategy, MergeConfig, MergeError, merge_sbom_json};
pub use normalized::{NormalizedComponentEntry, NormalizedSbomPayload, normalized_sbom_json};
pub use pruner::{TailorConfig, tailor_sbom_json};

use serde_json::Value;

/// Extension trait for convenient JSON field access.
pub(crate) trait ValueExt {
    /// Get a string field or return `""` if missing/not a string.
    fn str_field(&self, key: &str) -> &str;
}

impl ValueExt for Value {
    fn str_field(&self, key: &str) -> &str {
        self.get(key).and_then(Value::as_str).unwrap_or("")
    }
}
