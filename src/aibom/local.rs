//! Local-directory model ingestion.
//!
//! Accepts three layouts:
//! - a plain model directory (`config.json`, `*.safetensors`, `README.md` at
//!   the root) — e.g. a `git clone` or manual download;
//! - a HuggingFace cache *repo* directory (`models--{org}--{name}` with
//!   `refs/`, `blobs/`, `snapshots/`) — the default branch snapshot is used;
//! - a HuggingFace cache *snapshot* directory
//!   (`…/models--{org}--{name}/snapshots/{sha}`) — id and revision are
//!   recovered from the path.
//!
//! Every file is streamed through SHA-256 locally (measured facts). Symlinks
//! are followed only while they resolve inside the trust boundary: the cache
//! repo directory for cache layouts (snapshot files point into `../../blobs`),
//! or the given directory itself for plain layouts.

use std::path::{Path, PathBuf};

use super::description::{FactSource, FileRole, ModelDescription, ModelFile, WeightFormat};
use super::{AibomError, AibomOptions};
use crate::verification::compute_file_sha256;

/// Ingest a local model directory into a [`ModelDescription`].
///
/// # Errors
///
/// Returns [`AibomError::ModelDirNotFound`] when `dir` is not a directory,
/// [`AibomError::NoModelFiles`] when nothing model-shaped is found, and
/// [`AibomError::Io`] on read failures of files that were expected to exist.
pub fn ingest_local_dir(
    dir: &Path,
    options: &AibomOptions,
) -> Result<ModelDescription, AibomError> {
    if !dir.is_dir() {
        return Err(AibomError::ModelDirNotFound(dir.to_path_buf()));
    }

    let layout = resolve_layout(dir);
    let root = layout.root.clone();

    // Trust boundary for symlink resolution: cache layouts must reach
    // ../../blobs, so the boundary is the repo dir; plain dirs bound to
    // themselves. Fall back to the path as given when canonicalization fails.
    let boundary = std::fs::canonicalize(&layout.boundary)
        .unwrap_or_else(|_| layout.boundary.clone());

    let mut description = ModelDescription {
        id: layout.id,
        name_hint: dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned()),
        revision: layout
            .revision
            .or_else(|| options.revision.clone()),
        revision_pinned: layout.revision_pinned,
        source_desc: format!("local directory {}", dir.display()),
        ..ModelDescription::default()
    };
    // An operator-supplied 40-hex revision is treated as a commit pin.
    if !description.revision_pinned
        && let Some(rev) = &description.revision
    {
        description.revision_pinned = looks_like_commit_sha(rev);
    }

    let mut files = Vec::new();
    let mut safetensors_agg: Option<super::safetensors_meta::SafetensorsMeta> = None;
    walk_files(&root, &boundary, &mut |abs, rel| {
        let role = classify_file(rel);
        let size = std::fs::metadata(abs).map(|m| m.len()).ok();

        let sha256 = if options.no_hash {
            None
        } else {
            compute_file_sha256(abs).ok()
        };

        if matches!(role, FileRole::Weights(WeightFormat::Safetensors))
            && let Some(meta) = super::safetensors_meta::SafetensorsMeta::read_from_file(abs)
        {
            match &mut safetensors_agg {
                Some(agg) => agg.merge(&meta),
                None => safetensors_agg = Some(meta),
            }
        }

        files.push(ModelFile {
            rel_path: rel.to_string(),
            size,
            role,
            hash_source: sha256.as_ref().map(|_| FactSource::Computed),
            sha256,
        });
    });

    if files.is_empty()
        || !files.iter().any(|f| {
            f.role.is_weights() || f.rel_path.eq_ignore_ascii_case("config.json")
        })
    {
        return Err(AibomError::NoModelFiles(dir.to_path_buf()));
    }

    // Deterministic component order regardless of directory-walk order.
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    description.files = files;
    description.param_source = safetensors_agg.as_ref().map(|_| FactSource::Computed);
    description.safetensors = safetensors_agg;

    // Root-level metadata files.
    if let Some(content) = read_root_file(&root, "config.json")? {
        description.config = super::config_json::ModelConfig::parse(&content);
    }
    if let Some(content) = read_root_file(&root, "adapter_config.json")? {
        description.adapter = super::config_json::AdapterConfig::parse(&content);
    }
    if let Some(content) = read_root_file(&root, "README.md")? {
        description.card = super::card::ModelCard::parse(&content);
    }

    // The repo org doubles as the author when nothing better is known.
    description.author = description.org().map(str::to_string);

    Ok(description)
}

/// Resolved directory layout.
struct Layout {
    /// Directory whose files make up the model snapshot.
    root: PathBuf,
    /// Symlink trust boundary (see module docs).
    boundary: PathBuf,
    /// Repo id recovered from cache naming, when applicable.
    id: Option<String>,
    /// Revision recovered from the layout, when applicable.
    revision: Option<String>,
    /// Whether that revision is a commit sha.
    revision_pinned: bool,
}

/// Work out which of the three supported layouts `dir` is.
fn resolve_layout(dir: &Path) -> Layout {
    // HF cache repo dir: models--{org}--{name}/ with refs/ + snapshots/.
    let refs_main = dir.join("refs").join("main");
    if refs_main.is_file() && dir.join("snapshots").is_dir() {
        let sha = std::fs::read_to_string(&refs_main)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| looks_like_commit_sha(s));
        if let Some(sha) = sha {
            let snapshot = dir.join("snapshots").join(&sha);
            if snapshot.is_dir() {
                return Layout {
                    root: snapshot,
                    boundary: dir.to_path_buf(),
                    id: repo_id_from_cache_name(dir),
                    revision: Some(sha),
                    revision_pinned: true,
                };
            }
        }
    }

    // HF cache snapshot dir: …/models--{org}--{name}/snapshots/{sha}.
    if let (Some(name), Some(parent), Some(repo_dir)) = (
        dir.file_name().and_then(|n| n.to_str()),
        dir.parent(),
        dir.parent().and_then(Path::parent),
    ) && looks_like_commit_sha(name)
        && parent.file_name().is_some_and(|p| p == "snapshots")
    {
        return Layout {
            root: dir.to_path_buf(),
            boundary: repo_dir.to_path_buf(),
            id: repo_id_from_cache_name(repo_dir),
            revision: Some(name.to_lowercase()),
            revision_pinned: true,
        };
    }

    // Plain directory.
    Layout {
        root: dir.to_path_buf(),
        boundary: dir.to_path_buf(),
        id: None,
        revision: None,
        revision_pinned: false,
    }
}

/// `models--{org}--{name}` → `org/name`; single-segment ids have no `--`.
fn repo_id_from_cache_name(repo_dir: &Path) -> Option<String> {
    let name = repo_dir.file_name()?.to_str()?;
    let mangled = name.strip_prefix("models--")?;
    Some(match mangled.split_once("--") {
        Some((org, rest)) => format!("{org}/{}", rest.replace("--", "/")),
        None => mangled.to_string(),
    })
}

/// A 40-char lowercase-hex git commit sha?
fn looks_like_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Depth-first walk calling `visit(absolute, relative)` per regular file.
///
/// Skips dotfiles/dot-dirs (`.gitattributes`, `.cache`, `.no_exist`) and
/// `*.incomplete` blobs from interrupted downloads. Symlinks are followed
/// only when their canonical target stays inside `boundary`; directory
/// cycles are broken with a visited set.
fn walk_files(root: &Path, boundary: &Path, visit: &mut impl FnMut(&Path, &str)) {
    let mut visited = std::collections::HashSet::new();
    walk_dir(root, root, boundary, &mut visited, visit);
}

fn walk_dir(
    dir: &Path,
    root: &Path,
    boundary: &Path,
    visited: &mut std::collections::HashSet<PathBuf>,
    visit: &mut impl FnMut(&Path, &str),
) {
    let canonical_dir = match std::fs::canonicalize(dir) {
        Ok(c) => c,
        Err(_) => return,
    };
    if !visited.insert(canonical_dir) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') || name.ends_with(".incomplete") {
            continue;
        }
        let path = entry.path();
        // Symlink-escape guard: the resolved path must stay inside the boundary.
        let Ok(resolved) = std::fs::canonicalize(&path) else {
            continue;
        };
        if !resolved.starts_with(boundary) {
            continue;
        }
        if resolved.is_dir() {
            walk_dir(&path, root, boundary, visited, visit);
        } else if resolved.is_file() {
            let rel = path
                .strip_prefix(root)
                .map(|p| {
                    p.components()
                        .map(|c| c.as_os_str().to_string_lossy())
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .unwrap_or_else(|_| name.to_string());
            visit(&path, &rel);
        }
    }
}

/// Classify a repo file by its path.
pub(crate) fn classify_file(rel_path: &str) -> FileRole {
    let basename = rel_path.rsplit('/').next().unwrap_or(rel_path);
    let lower = basename.to_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");

    match ext {
        "safetensors" => FileRole::Weights(WeightFormat::Safetensors),
        "gguf" | "ggml" => FileRole::Weights(WeightFormat::Gguf),
        "bin" | "pt" | "pth" | "ckpt" => FileRole::Weights(WeightFormat::Pickle),
        "onnx" => FileRole::Weights(WeightFormat::Onnx),
        "h5" | "pb" | "tflite" => FileRole::Weights(WeightFormat::Tensorflow),
        "msgpack" => FileRole::Weights(WeightFormat::Flax),
        "py" => FileRole::Code,
        "md" | "rst" => FileRole::Doc,
        // Tokenizer/config surface: JSON configs, vocab/merges text files,
        // sentencepiece models, chat templates.
        "json" | "txt" | "model" | "jinja" | "yaml" | "yml" | "toml" => FileRole::Config,
        _ if lower == "license" || lower == "notice" => FileRole::Doc,
        _ => FileRole::Other,
    }
}

/// Read a root-level file if present; missing files are `Ok(None)`, read
/// failures on *present* files are hard errors.
fn read_root_file(root: &Path, name: &str) -> Result<Option<String>, AibomError> {
    let path = root.join(name);
    if !path.is_file() {
        return Ok(None);
    }
    std::fs::read_to_string(&path)
        .map(Some)
        .map_err(|source| AibomError::Io { path, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, content: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn minimal_model(dir: &Path) {
        write(
            &dir.join("config.json"),
            br#"{"model_type": "bert", "architectures": ["BertModel"]}"#,
        );
        write(
            &dir.join("README.md"),
            b"---\nlicense: mit\npipeline_tag: fill-mask\n---\n# m\n",
        );
        let st = crate::aibom::safetensors_meta::tests::build_safetensors(&[(
            "w",
            "F32",
            &[4, 4],
        )]);
        write(&dir.join("model.safetensors"), &st);
    }

    #[test]
    fn plain_dir_ingests() {
        let tmp = tempfile::tempdir().unwrap();
        minimal_model(tmp.path());

        let desc = ingest_local_dir(tmp.path(), &AibomOptions::default()).unwrap();
        assert_eq!(desc.files.len(), 3);
        assert!(desc.card.is_some());
        assert_eq!(
            desc.config.as_ref().unwrap().model_type.as_deref(),
            Some("bert")
        );
        assert_eq!(desc.safetensors.as_ref().unwrap().param_count, 16);
        let weights = desc
            .files
            .iter()
            .find(|f| f.rel_path == "model.safetensors")
            .unwrap();
        assert!(weights.role.is_weights());
        assert_eq!(weights.hash_source, Some(FactSource::Computed));
        assert_eq!(weights.sha256.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn missing_dir_errors() {
        let err = ingest_local_dir(Path::new("/nonexistent-dir-xyz"), &AibomOptions::default());
        assert!(matches!(err, Err(AibomError::ModelDirNotFound(_))));
    }

    #[test]
    fn empty_dir_is_no_model_files() {
        let tmp = tempfile::tempdir().unwrap();
        let err = ingest_local_dir(tmp.path(), &AibomOptions::default());
        assert!(matches!(err, Err(AibomError::NoModelFiles(_))));
    }

    #[test]
    fn hf_cache_repo_layout_recovers_id_and_revision() {
        let tmp = tempfile::tempdir().unwrap();
        let sha = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
        let repo = tmp.path().join("models--demo-org--tiny-model");
        write(&repo.join("refs").join("main"), sha.as_bytes());
        let snapshot = repo.join("snapshots").join(sha);
        minimal_model(&snapshot);

        let desc = ingest_local_dir(&repo, &AibomOptions::default()).unwrap();
        assert_eq!(desc.id.as_deref(), Some("demo-org/tiny-model"));
        assert_eq!(desc.revision.as_deref(), Some(sha));
        assert!(desc.revision_pinned);
        assert_eq!(desc.author.as_deref(), Some("demo-org"));

        // Snapshot dir passed directly recovers the same identity.
        let desc2 = ingest_local_dir(&snapshot, &AibomOptions::default()).unwrap();
        assert_eq!(desc2.id.as_deref(), Some("demo-org/tiny-model"));
        assert_eq!(desc2.revision.as_deref(), Some(sha));
    }

    #[cfg(unix)]
    #[test]
    fn cache_symlinks_into_blobs_are_followed_but_escapes_are_not() {
        let tmp = tempfile::tempdir().unwrap();
        let sha = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
        let repo = tmp.path().join("models--demo-org--tiny-model");
        write(&repo.join("refs").join("main"), sha.as_bytes());
        let snapshot = repo.join("snapshots").join(sha);
        std::fs::create_dir_all(&snapshot).unwrap();

        // Blob + intra-boundary symlink (the HF cache shape).
        let st =
            crate::aibom::safetensors_meta::tests::build_safetensors(&[("w", "F32", &[2, 2])]);
        write(&repo.join("blobs").join("blobhash"), &st);
        std::os::unix::fs::symlink(
            repo.join("blobs").join("blobhash"),
            snapshot.join("model.safetensors"),
        )
        .unwrap();
        write(&snapshot.join("config.json"), br#"{"model_type": "x"}"#);

        // Escape symlink pointing outside the repo boundary.
        write(&tmp.path().join("outside.txt"), b"secret");
        std::os::unix::fs::symlink(
            tmp.path().join("outside.txt"),
            snapshot.join("escape.txt"),
        )
        .unwrap();

        let desc = ingest_local_dir(&repo, &AibomOptions::default()).unwrap();
        let names: Vec<_> = desc.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(names.contains(&"model.safetensors"));
        assert!(!names.contains(&"escape.txt"), "escape symlink must be skipped");
    }

    #[test]
    fn no_hash_skips_hashing() {
        let tmp = tempfile::tempdir().unwrap();
        minimal_model(tmp.path());
        let desc = ingest_local_dir(
            tmp.path(),
            &AibomOptions {
                no_hash: true,
                ..AibomOptions::default()
            },
        )
        .unwrap();
        assert!(desc.files.iter().all(|f| f.sha256.is_none()));
    }

    #[test]
    fn classification_covers_common_files() {
        assert_eq!(
            classify_file("model-00001-of-00002.safetensors"),
            FileRole::Weights(WeightFormat::Safetensors)
        );
        assert_eq!(
            classify_file("pytorch_model.bin"),
            FileRole::Weights(WeightFormat::Pickle)
        );
        assert_eq!(
            classify_file("quant/model.Q4_K_M.gguf"),
            FileRole::Weights(WeightFormat::Gguf)
        );
        assert_eq!(classify_file("tokenizer_config.json"), FileRole::Config);
        assert_eq!(classify_file("merges.txt"), FileRole::Config);
        assert_eq!(classify_file("spiece.model"), FileRole::Config);
        assert_eq!(classify_file("modeling_custom.py"), FileRole::Code);
        assert_eq!(classify_file("README.md"), FileRole::Doc);
        assert_eq!(classify_file("LICENSE"), FileRole::Doc);
    }
}
