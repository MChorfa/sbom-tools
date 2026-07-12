//! Hub-mode model ingestion: `GET /api/models/{id}[/revision/{rev}]?blobs=true`.
//!
//! Fetches everything the generator needs in one call: the resolved commit
//! `sha` (the version pin), per-file LFS SHA-256 hashes (*hub-declared* —
//! nothing is downloaded), the server-parsed model card (`cardData`), the
//! config summary, and gating status. Requests reuse the hardened enrichment
//! plumbing (offline guard, bounded body, retry/backoff, schema-versioned
//! cache) and send `Authorization: Bearer $HF_TOKEN` when the environment
//! provides a token.
//!
//! This is deliberately separate from the enrichment client: enrichment
//! refuses `cardData` (low-confidence for third-party SBOM patching), while
//! generation documents the model's own declarations and wants all of it.

use serde::{Deserialize, Serialize};

use super::card::ModelCard;
use super::config_json::ModelConfig;
use super::description::{FactSource, FileRole, ModelDescription, ModelFile};
use super::local::classify_file;
use super::{AibomError, AibomOptions};
use crate::enrichment::huggingface::{HUGGINGFACE_API_URL, is_valid_hf_model_id};
use crate::enrichment::source::{
    JsonCache, get_with_retry_auth, http_client, key_to_filename, namespaced_cache_dir,
};

/// Environment variables consulted for the Hub token, in order.
const TOKEN_ENV_VARS: &[&str] = &["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"];

/// Cache namespace (separate from enrichment's `huggingface` cache: this
/// payload carries more fields).
const CACHE_NAMESPACE: &str = "huggingface-aibom";

/// Metadata cache TTL. Pinned-revision payloads are immutable in practice;
/// unpinned (`main`) payloads going stale for a week is acceptable because
/// the emitted BOM records the resolved commit sha it was built from.
const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// Wire shape of the model-info response (generator superset).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HubModelPayload {
    id: Option<String>,
    /// Commit sha of the resolved revision — the AIBOM version pin.
    sha: Option<String>,
    author: Option<String>,
    #[serde(rename = "lastModified")]
    last_modified: Option<String>,
    #[serde(rename = "pipeline_tag")]
    pipeline_tag: Option<String>,
    library_name: Option<String>,
    license: Option<String>,
    /// `false` | `"auto"` | `"manual"` on the wire.
    #[serde(default)]
    gated: serde_json::Value,
    #[serde(default)]
    tags: Vec<String>,
    /// Server-parsed README frontmatter.
    #[serde(rename = "cardData")]
    card_data: Option<serde_json::Value>,
    /// Config summary (`architectures`, `model_type`, …).
    config: Option<serde_json::Value>,
    /// Server-computed safetensors parameter counts.
    safetensors: Option<HubSafetensors>,
    #[serde(default)]
    siblings: Vec<HubSibling>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HubSafetensors {
    /// Per-dtype parameter counts (e.g. `{"F32": 137022720}`).
    #[serde(default)]
    parameters: std::collections::BTreeMap<String, u64>,
    total: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HubSibling {
    #[serde(rename = "rfilename")]
    filename: Option<String>,
    size: Option<u64>,
    lfs: Option<HubLfs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HubLfs {
    /// SHA-256 of the file content (`lfs.oid`; some payloads spell it `sha256`).
    #[serde(alias = "sha256")]
    oid: Option<String>,
    size: Option<u64>,
}

/// Fetch a model's metadata from the Hub and shape it as a
/// [`ModelDescription`].
///
/// # Errors
///
/// [`AibomError::InvalidModelId`] for malformed ids;
/// [`AibomError::HubFetch`] for network/API failures, including auth
/// failures on gated/private repos (the message says how to supply a token).
pub fn fetch_hub_model(
    id: &str,
    revision: Option<&str>,
    options: &AibomOptions,
) -> Result<ModelDescription, AibomError> {
    if !is_valid_hf_model_id(id) {
        return Err(AibomError::InvalidModelId(id.to_string()));
    }
    if let Some(rev) = revision
        && !is_valid_revision(rev)
    {
        return Err(AibomError::HubFetch {
            id: id.to_string(),
            message: format!("invalid revision {rev:?}"),
        });
    }

    let payload = fetch_payload(id, revision, options)?;
    Ok(description_from_payload(id, payload))
}

/// A revision is a branch/tag/sha drawn from the same conservative grammar as
/// repo-id segments — it is interpolated into the request URL and cache key.
fn is_valid_revision(rev: &str) -> bool {
    !rev.is_empty()
        && rev.len() <= 128
        && rev
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Fetch (or cache-load) the raw payload.
fn fetch_payload(
    id: &str,
    revision: Option<&str>,
    options: &AibomOptions,
) -> Result<HubModelPayload, AibomError> {
    let cache_key = key_to_filename(&format!("{id}@{}", revision.unwrap_or("~default")));
    let cache: Option<JsonCache<HubModelPayload>> =
        JsonCache::new(namespaced_cache_dir(CACHE_NAMESPACE), CACHE_TTL).ok();

    if let Some(cached) = cache.as_ref().and_then(|c| c.get_named(&cache_key)) {
        return Ok(cached);
    }

    let base = options
        .huggingface_url
        .as_deref()
        .unwrap_or(HUGGINGFACE_API_URL)
        .trim_end_matches('/');
    let url = match revision {
        Some(rev) => format!("{base}/api/models/{id}/revision/{rev}?blobs=true"),
        None => format!("{base}/api/models/{id}?blobs=true"),
    };

    let hub_error = |message: String| AibomError::HubFetch {
        id: id.to_string(),
        message,
    };

    let client = http_client(std::time::Duration::from_secs(30))
        .map_err(|e| hub_error(e.to_string()))?;
    let token = hub_token();
    let response = get_with_retry_auth(&client, &url, 3, token.as_deref())
        .map_err(|e| hub_error(e.to_string()))?;

    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        // Never cached: access may be granted later.
        return Err(hub_error(format!(
            "HTTP {status} — the repo is gated or private; set HF_TOKEN to a token \
             with accepted access"
        )));
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(hub_error(
            "HTTP 404 — model or revision not found".to_string(),
        ));
    }
    if !status.is_success() {
        return Err(hub_error(format!("HTTP {status}")));
    }

    let bytes = crate::enrichment::source::read_bounded(response)
        .map_err(|e| hub_error(e.to_string()))?;
    let payload: HubModelPayload =
        serde_json::from_slice(&bytes).map_err(|e| hub_error(format!("bad response: {e}")))?;

    if let Some(cache) = &cache {
        let _ = cache.set_named(&cache_key, &payload);
    }
    Ok(payload)
}

/// The Hub token from the environment, when set and non-empty.
fn hub_token() -> Option<String> {
    TOKEN_ENV_VARS.iter().find_map(|var| {
        std::env::var(var)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    })
}

/// Map the wire payload onto the source-agnostic description.
fn description_from_payload(requested_id: &str, payload: HubModelPayload) -> ModelDescription {
    let id = payload.id.clone().unwrap_or_else(|| requested_id.to_string());

    let card = payload
        .card_data
        .as_ref()
        .and_then(ModelCard::from_card_data);
    let config = payload
        .config
        .as_ref()
        .and_then(|c| serde_json::to_string(c).ok())
        .and_then(|s| ModelConfig::parse(&s));

    let mut safetensors: Option<super::safetensors_meta::SafetensorsMeta> = None;
    if let Some(hub_st) = &payload.safetensors {
        let mut meta = super::safetensors_meta::SafetensorsMeta {
            dtype_params: hub_st.parameters.clone(),
            ..Default::default()
        };
        meta.param_count = hub_st
            .total
            .unwrap_or_else(|| hub_st.parameters.values().sum());
        if meta.param_count > 0 {
            safetensors = Some(meta);
        }
    }
    let param_source = safetensors.as_ref().map(|_| FactSource::HubDeclared);

    let mut files: Vec<ModelFile> = payload
        .siblings
        .iter()
        .filter_map(|sibling| {
            let rel_path = sibling.filename.clone()?;
            let lfs = sibling.lfs.as_ref();
            let sha256 = lfs
                .and_then(|l| l.oid.clone())
                .map(|h| h.to_lowercase())
                .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()));
            let role = classify_file(&rel_path);
            Some(ModelFile {
                size: sibling.size.or_else(|| lfs.and_then(|l| l.size)),
                role,
                hash_source: sha256.as_ref().map(|_| FactSource::HubDeclared),
                sha256,
                rel_path,
            })
        })
        .collect();
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let gated = match &payload.gated {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Bool(true) => Some("true".to_string()),
        _ => None,
    };

    let author = payload
        .author
        .clone()
        .or_else(|| id.split_once('/').map(|(org, _)| org.to_string()));

    ModelDescription {
        name_hint: Some(id.clone()),
        revision_pinned: payload.sha.is_some(),
        revision: payload.sha,
        author,
        card,
        config,
        safetensors,
        param_source,
        files,
        source_desc: format!("HuggingFace Hub ({id})"),
        hub_license: payload.license,
        hub_pipeline_tag: payload.pipeline_tag,
        last_modified: payload.last_modified,
        gated,
        id: Some(id),
        ..ModelDescription::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(json: &str) -> HubModelPayload {
        serde_json::from_str(json).unwrap()
    }

    const SAMPLE: &str = r#"{
        "id": "demo-org/tiny",
        "sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        "author": "demo-org",
        "lastModified": "2026-01-01T00:00:00.000Z",
        "pipeline_tag": "text-classification",
        "license": "apache-2.0",
        "gated": false,
        "tags": ["sentiment"],
        "cardData": {"license": "apache-2.0", "datasets": ["imdb"]},
        "config": {"model_type": "bert", "architectures": ["BertModel"]},
        "safetensors": {"parameters": {"F32": 816}, "total": 816},
        "siblings": [
            {"rfilename": "config.json", "size": 570},
            {"rfilename": "model.safetensors", "size": 440401,
             "lfs": {"oid": "AABB00112233445566778899aabbccddeeff00112233445566778899aabbccdd",
                     "size": 440401}}
        ]
    }"#;

    #[test]
    fn payload_maps_to_description() {
        let desc = description_from_payload("demo-org/tiny", payload(SAMPLE));
        assert_eq!(desc.id.as_deref(), Some("demo-org/tiny"));
        assert!(desc.revision_pinned);
        assert_eq!(
            desc.revision.as_deref(),
            Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")
        );
        assert_eq!(desc.card.as_ref().unwrap().datasets, vec!["imdb"]);
        assert_eq!(
            desc.config.as_ref().unwrap().model_type.as_deref(),
            Some("bert")
        );
        assert_eq!(desc.safetensors.as_ref().unwrap().param_count, 816);
        assert_eq!(desc.param_source, Some(FactSource::HubDeclared));

        let weights = desc
            .files
            .iter()
            .find(|f| f.rel_path == "model.safetensors")
            .unwrap();
        assert!(weights.role.is_weights());
        assert_eq!(weights.hash_source, Some(FactSource::HubDeclared));
        // Hash normalized to lowercase hex.
        assert!(weights.sha256.as_deref().unwrap().starts_with("aabb0011"));
        // Non-LFS small file has no remote sha256.
        let config = desc
            .files
            .iter()
            .find(|f| f.rel_path == "config.json")
            .unwrap();
        assert!(config.sha256.is_none());
    }

    #[test]
    fn gated_string_form_is_kept() {
        let desc = description_from_payload(
            "a/b",
            payload(r#"{"gated": "manual", "siblings": []}"#),
        );
        assert_eq!(desc.gated.as_deref(), Some("manual"));
    }

    #[test]
    fn invalid_ids_and_revisions_rejected() {
        let options = AibomOptions::default();
        assert!(matches!(
            fetch_hub_model("../etc", None, &options),
            Err(AibomError::InvalidModelId(_))
        ));
        assert!(matches!(
            fetch_hub_model("org/name", Some("rev/../evil"), &options),
            Err(AibomError::HubFetch { .. })
        ));
    }

    #[test]
    fn malformed_lfs_hash_dropped() {
        let desc = description_from_payload(
            "a/b",
            payload(
                r#"{"siblings": [{"rfilename": "w.safetensors",
                     "lfs": {"oid": "not-a-hash"}}]}"#,
            ),
        );
        assert!(desc.files[0].sha256.is_none());
    }
}
