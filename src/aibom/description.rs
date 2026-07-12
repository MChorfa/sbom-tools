//! Source-agnostic model description — the contract between ingestion
//! (local directory / Hub API) and the SBOM builder.

use super::card::ModelCard;
use super::config_json::{AdapterConfig, ModelConfig};
use super::safetensors_meta::SafetensorsMeta;

/// How a fact (hash, parameter count) was obtained. Recorded per value so the
/// emitted BOM distinguishes measurements from claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactSource {
    /// Computed locally from the bytes (measured).
    Computed,
    /// Declared by the HuggingFace Hub API (LFS pointer / server-side).
    HubDeclared,
}

impl FactSource {
    /// Property-value spelling used in emitted `sbom-tools:aibom:*` properties.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Computed => "computed",
            Self::HubDeclared => "hub-declared",
        }
    }
}

/// Weight-file container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WeightFormat {
    /// Safetensors (safe, header-parsed).
    Safetensors,
    /// GGUF single-file quantized model.
    Gguf,
    /// Python pickle containers (`.bin`, `.pt`, `.pth`, `.ckpt`) —
    /// unsafe-deserialization risk.
    Pickle,
    /// ONNX graph.
    Onnx,
    /// TensorFlow H5 / SavedModel artifacts.
    Tensorflow,
    /// Flax msgpack.
    Flax,
    /// Recognized as weights but none of the above.
    Other,
}

/// Role of a repo file in the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileRole {
    /// Model weights / tensors.
    Weights(WeightFormat),
    /// Configuration: `config.json`, tokenizer files, generation config…
    Config,
    /// Python code shipped with the repo (`trust_remote_code` surface).
    Code,
    /// Documentation (README, LICENSE).
    Doc,
    /// Anything else.
    Other,
}

impl FileRole {
    /// Whether this file holds model weights.
    #[must_use]
    pub const fn is_weights(self) -> bool {
        matches!(self, Self::Weights(_))
    }
}

/// One file of the model repo/directory.
#[derive(Debug, Clone)]
pub struct ModelFile {
    /// Path relative to the model root, `/`-separated.
    pub rel_path: String,
    /// File size in bytes, when known.
    pub size: Option<u64>,
    /// Classified role.
    pub role: FileRole,
    /// SHA-256 (lowercase hex), when available.
    pub sha256: Option<String>,
    /// How the hash was obtained. `None` when `sha256` is `None`.
    pub hash_source: Option<FactSource>,
}

/// Everything ingestion learned about a model, ready for the builder.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ModelDescription {
    /// Repo id (`org/name` or single-segment), when known.
    pub id: Option<String>,
    /// Component-name fallback when no repo id is known (e.g. the directory
    /// basename for a plain local dir). Ignored when [`Self::id`] is set.
    pub name_hint: Option<String>,
    /// Git revision. A detected/API-resolved commit sha is *pinned*;
    /// an operator-supplied `--revision` is carried verbatim.
    pub revision: Option<String>,
    /// Whether `revision` is a resolved commit sha (not a moving ref).
    pub revision_pinned: bool,
    /// Model author / owning organization, when known.
    pub author: Option<String>,
    /// Parsed model card (README frontmatter + body excerpts).
    pub card: Option<ModelCard>,
    /// Parsed `config.json`.
    pub config: Option<ModelConfig>,
    /// Parsed `adapter_config.json` (PEFT adapter repos).
    pub adapter: Option<AdapterConfig>,
    /// Aggregated safetensors header metadata across shards.
    pub safetensors: Option<SafetensorsMeta>,
    /// How the parameter count in [`Self::safetensors`] was obtained.
    pub param_source: Option<FactSource>,
    /// Inventoried files.
    pub files: Vec<ModelFile>,
    /// Human-readable source description for the generation report
    /// (e.g. `local directory /models/bert`).
    pub source_desc: String,
    /// Hub-declared license tag from the API (not the card), hub mode only.
    pub hub_license: Option<String>,
    /// Hub `pipeline_tag` from the API, hub mode only.
    pub hub_pipeline_tag: Option<String>,
    /// Hub `lastModified` timestamp, hub mode only.
    pub last_modified: Option<String>,
    /// Gating status (`auto`/`manual`) reported by the Hub, hub mode only.
    pub gated: Option<String>,
}

impl ModelDescription {
    /// The org / namespace part of the repo id, when present.
    #[must_use]
    pub fn org(&self) -> Option<&str> {
        self.id.as_deref().and_then(|id| id.split_once('/')).map(|(org, _)| org)
    }

    /// Package URL for the model itself:
    /// `pkg:huggingface/{org}/{name}@{revision}`. Revision is lowercased per
    /// the purl-spec rule for the huggingface type. `None` without an id.
    #[must_use]
    pub fn purl(&self) -> Option<String> {
        let id = self.id.as_deref()?;
        match &self.revision {
            Some(rev) => Some(format!("pkg:huggingface/{id}@{}", rev.to_lowercase())),
            None => Some(format!("pkg:huggingface/{id}")),
        }
    }

    /// Package URL for a file inside the model repo, using the purl subpath
    /// fragment: `pkg:huggingface/{org}/{name}@{rev}#{path}`.
    #[must_use]
    pub fn file_purl(&self, rel_path: &str) -> Option<String> {
        self.purl().map(|purl| format!("{purl}#{rel_path}"))
    }

    /// URL of the model page / model card on the Hub, when the id is known.
    #[must_use]
    pub fn hub_url(&self) -> Option<String> {
        self.id.as_deref().map(|id| format!("https://huggingface.co/{id}"))
    }
}
