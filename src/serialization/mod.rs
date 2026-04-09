//! SBOM serialization and transformation.
//!
//! Operates on raw JSON (`serde_json::Value`) to inject enrichment data,
//! filter components, or merge SBOMs — preserving the original format structure.

mod enricher;
mod merger;
mod pruner;

pub use enricher::enrich_sbom_json;
pub use merger::{DeduplicationStrategy, MergeConfig, MergeError, merge_sbom_json};
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
