//! AI-BOM generation from Hugging Face models.
//!
//! Turns a Hugging Face model — a local snapshot directory or a Hub repo id —
//! into a [`NormalizedSbom`](crate::model::NormalizedSbom) shaped as a
//! CycloneDX ML-BOM: the model as a `machine-learning-model` primary
//! component carrying a modelCard and the SHA-256 of every weight file,
//! per-file subcomponents for weights and configuration, and
//! training-dataset references from the model card.
//!
//! Generation is *honest by default*: only derivable facts are populated,
//! every hash records how it was obtained (computed locally vs declared by
//! the Hub), and everything the generator could not determine is listed as an
//! explicit known-unknown in the [`GenerationReport`] instead of being
//! fabricated. Model-card YAML is user-authored and treated as *declared*
//! metadata — acceptable here because generation documents the model's own
//! claims, unlike enrichment (which deliberately refuses `cardData`; see
//! `crate::enrichment::huggingface`).

mod builder;
mod card;
mod config_json;
mod description;
mod license_map;
mod local;
mod report;
mod safetensors_meta;

#[cfg(feature = "enrichment")]
mod hub;

pub use builder::build_sbom;
pub use card::{CardMetric, ModelCard};
pub use config_json::{AdapterConfig, ModelConfig};
pub use description::{FactSource, FileRole, ModelDescription, ModelFile, WeightFormat};
pub use license_map::{MappedLicense, map_hf_license};
pub use local::ingest_local_dir;
pub use report::{GenerationReport, KnownUnknown, RiskFlag};
pub use safetensors_meta::SafetensorsMeta;

#[cfg(feature = "enrichment")]
pub use hub::fetch_hub_model;

use std::path::PathBuf;

/// Where the model to describe comes from.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AibomSource {
    /// A local snapshot directory (plain layout or a HuggingFace cache
    /// layout). Weight hashes are computed locally.
    LocalDir(PathBuf),
    /// A Hub repo id (`org/name`), optionally pinned to a revision. Metadata
    /// and LFS weight hashes come from the Hub API without downloading.
    #[cfg(feature = "enrichment")]
    HubId {
        /// Repo id, `org/name` (or a single-segment canonical id).
        id: String,
        /// Git revision (branch, tag, or commit sha); `None` = default branch.
        revision: Option<String>,
    },
}

/// Options controlling generation.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AibomOptions {
    /// Operator-asserted sensitivity classification for the declared training
    /// datasets (e.g. `none`, `pii`). Never inferred: dataset sensitivity is
    /// a claim only the operator can make.
    pub dataset_sensitivity: Option<String>,
    /// Explicit revision for local directories whose commit sha cannot be
    /// detected from the directory layout.
    pub revision: Option<String>,
    /// Skip hashing local files (metadata-only BOM; hash absences are
    /// reported as known-unknowns).
    pub no_hash: bool,
    /// Base URL of the HuggingFace API (test seam). `None` = production.
    #[cfg(feature = "enrichment")]
    pub huggingface_url: Option<String>,
}

/// A generated AI-BOM plus the honesty report that accompanies it.
#[derive(Debug)]
pub struct GeneratedAibom {
    /// The generated SBOM, ready for `emit_cyclonedx`.
    pub sbom: crate::model::NormalizedSbom,
    /// Coverage, provenance, and known-unknown report.
    pub report: GenerationReport,
}

/// Errors that can occur during AI-BOM generation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AibomError {
    /// The model directory does not exist or is not a directory.
    #[error("model directory not found or not a directory: {0}")]
    ModelDirNotFound(PathBuf),
    /// The model directory contains no recognizable model files.
    #[error(
        "no model files found under {0} (expected weights such as *.safetensors, \
         *.bin, *.gguf, or a config.json)"
    )]
    NoModelFiles(PathBuf),
    /// File I/O error while reading the model directory.
    #[error("failed to read {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The provided Hub model id is not a well-formed `org/name` repo id.
    #[error("invalid HuggingFace model id: {0:?} (expected `name` or `org/name`)")]
    InvalidModelId(String),
    /// Hub metadata fetch failed.
    #[cfg(feature = "enrichment")]
    #[error("HuggingFace Hub fetch failed for {id}: {message}")]
    HubFetch {
        /// Repo id that failed.
        id: String,
        /// Human-readable failure description.
        message: String,
    },
}

/// Generate an AI-BOM from `source`.
///
/// # Errors
///
/// Returns [`AibomError`] when the source cannot be read (missing directory,
/// no model files, I/O failure) or, in Hub mode, when the API fetch fails.
pub fn generate_aibom(
    source: &AibomSource,
    options: &AibomOptions,
) -> Result<GeneratedAibom, AibomError> {
    let description = match source {
        AibomSource::LocalDir(dir) => ingest_local_dir(dir, options)?,
        #[cfg(feature = "enrichment")]
        AibomSource::HubId { id, revision } => {
            fetch_hub_model(id, revision.as_deref(), options)?
        }
    };
    Ok(build_sbom(&description, options))
}
