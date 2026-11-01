//! Descriptor-driven receipt generation and hosted trust derivation.
use super::{
    pipeline_receipt::{
        HostedReceiptMetadata, PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA, PIPELINE_SHARD_RECEIPT_SCHEMA,
        PipelineShardReceipt, ReceiptArtifact, ReceiptArtifactInput, ReceiptError,
        ReceiptGenerationInput, ReceiptInput, Sha256Digest, TrustContext, validate_receipt,
    },
    pipeline_receipt_fingerprint::{lock_fingerprint, source_fingerprint, stream_into},
    pipeline_receipt_paths::{reject_symlink_components, validate_relative_path},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

pub fn generate_receipt(input: ReceiptInput) -> Result<PipelineShardReceipt, ReceiptError> {
    // Every field except the digests is caller-supplied: reject cheap semantic
    // errors (commit, timestamps, checks, target, artifact claims) before
    // walking and hashing the source tree.
    let mut receipt = receipt_without_digests(&input);
    validate_receipt(&receipt)?;
    receipt.source_fingerprint = source_fingerprint(&input.source_root)?;
    receipt.lock_digest = lock_fingerprint(&input.source_root, &input.lock_paths)?;
    validate_receipt(&receipt)?;
    Ok(receipt)
}

/// The receipt `input` describes, with placeholder digests (SHA-256 of the
/// empty string) standing in for the not-yet-computed fingerprints.
fn receipt_without_digests(input: &ReceiptInput) -> PipelineShardReceipt {
    PipelineShardReceipt {
        schema: PIPELINE_SHARD_RECEIPT_SCHEMA.into(),
        repository: input.repository.clone(),
        workflow: input.workflow.clone(),
        run_id: input.run_id.clone(),
        commit_sha: input.commit_sha.clone(),
        source_fingerprint: Sha256Digest::from_bytes(&[]),
        trust_context: input.trust_context,
        promotable: input.promotable,
        target: input.target.clone(),
        lock_digest: Sha256Digest::from_bytes(&[]),
        versions: input.versions.clone(),
        checks: input.checks.clone(),
        artifacts: input.artifacts.clone(),
        dagger_trace: input.dagger_trace.clone(),
        started_at: input.started_at.clone(),
        completed_at: input.completed_at.clone(),
        failure_classification: input.failure_classification.clone(),
    }
}

pub fn derive_trust_context(
    hosted: Option<&HostedReceiptMetadata>,
    local: bool,
) -> Result<(TrustContext, bool), ReceiptError> {
    if local {
        if hosted.is_some() {
            return Err(ReceiptError::Contract(
                "local mode must not include hosted metadata".into(),
            ));
        }
        return Ok((TrustContext::Local, false));
    }
    let metadata = hosted.ok_or_else(|| {
        ReceiptError::Contract("hosted metadata is required unless local mode is explicit".into())
    })?;
    validate_hosted_metadata(metadata)?;
    classify_hosted_event(metadata)
}

fn validate_hosted_metadata(metadata: &HostedReceiptMetadata) -> Result<(), ReceiptError> {
    if metadata.repository.is_empty()
        || metadata.default_branch.is_empty()
        || metadata.ref_name.is_empty()
    {
        return Err(ReceiptError::Contract(
            "hosted metadata is incomplete".into(),
        ));
    }
    Ok(())
}

fn classify_hosted_event(
    metadata: &HostedReceiptMetadata,
) -> Result<(TrustContext, bool), ReceiptError> {
    match metadata.event_name.as_str() {
        "pull_request_target" => Err(ReceiptError::Contract(
            "pull_request_target is unsupported: privileged base-context execution is not ordinary PR verification".into(),
        )),
        "pull_request"
            if is_pull_request_ref(&metadata.ref_name)
                && metadata
                    .head_repository
                    .as_deref()
                    .is_some_and(|r| !r.is_empty()) =>
        {
            Ok((TrustContext::PullRequest, false))
        }
        // Push runs require the full ref: a bare `main` is also the
        // `github.ref_name` of a tag called `main`.
        "push" if metadata.ref_name == format!("refs/heads/{}", metadata.default_branch) => {
            Ok((TrustContext::ProtectedMain, false))
        }
        "push"
            if metadata.ref_name.starts_with("refs/tags/")
                && metadata.ref_name.len() > "refs/tags/".len() =>
        {
            Ok((TrustContext::Release, false))
        }
        "pull_request" => Err(ReceiptError::Contract(
            "ambiguous pull request metadata".into(),
        )),
        // A bare `github.ref_name` for a push is just the branch or tag name,
        // and the two namespaces overlap — fail closed and point at the
        // canonical form instead of guessing.
        _ => Err(ReceiptError::Contract(
            "unsupported or ambiguous hosted event (push runs require the full \
             github.ref form, e.g. refs/heads/<branch> or refs/tags/<tag>)"
                .into(),
        )),
    }
}

/// Accept both the full `github.ref` form (`refs/pull/N/merge`) and the
/// `github.ref_name` short form (`N/merge`) for pull-request runs.
fn is_pull_request_ref(ref_name: &str) -> bool {
    let ref_name = ref_name.strip_prefix("refs/pull/").unwrap_or(ref_name);
    ref_name
        .strip_suffix("/merge")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Generate a receipt from a descriptor. Relative `source_root` and
/// `artifact_root` paths resolve against the process working directory.
pub fn generate_receipt_from_descriptor(
    descriptor: ReceiptGenerationInput,
) -> Result<PipelineShardReceipt, ReceiptError> {
    validate_descriptor(&descriptor)?;
    let (trust_context, promotable) =
        derive_trust_context(descriptor.hosted.as_ref(), descriptor.local)?;
    let target = canonical_target(descriptor.target)?;
    validate_artifact_inputs(&descriptor.artifacts)?;
    let mut input = ReceiptInput {
        repository: descriptor.repository,
        workflow: descriptor.workflow,
        run_id: descriptor.run_id,
        commit_sha: descriptor.commit_sha,
        trust_context,
        promotable,
        target,
        source_root: descriptor.source_root,
        lock_paths: descriptor.lock_paths,
        versions: descriptor.versions,
        checks: descriptor.checks,
        artifacts: Vec::new(),
        dagger_trace: descriptor.dagger_trace,
        started_at: descriptor.started_at,
        completed_at: descriptor.completed_at,
        failure_classification: descriptor.failure_classification,
    };
    // Fail on cheap descriptor errors before hashing any artifact bytes.
    validate_receipt(&receipt_without_digests(&input))?;
    input.artifacts = hash_artifacts(&descriptor.artifact_root, &descriptor.artifacts)?;
    generate_receipt(input)
}

fn validate_descriptor(descriptor: &ReceiptGenerationInput) -> Result<(), ReceiptError> {
    if descriptor.schema != PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA
        || descriptor.repository.is_empty()
        || descriptor.workflow.is_empty()
    {
        return Err(ReceiptError::Contract(
            "invalid generator input identity or schema".into(),
        ));
    }
    // The schema requires nonempty roots; an empty path would otherwise
    // surface as an I/O error (exit 3) instead of a contract verdict.
    if descriptor.source_root.as_os_str().is_empty()
        || descriptor.artifact_root.as_os_str().is_empty()
    {
        return Err(ReceiptError::Contract(
            "source_root and artifact_root must be nonempty".into(),
        ));
    }
    if let Some(hosted) = &descriptor.hosted {
        if hosted.sha != descriptor.commit_sha {
            return Err(ReceiptError::Contract(
                "hosted SHA does not match commit_sha".into(),
            ));
        }
        if hosted.repository != descriptor.repository {
            return Err(ReceiptError::Contract(
                "hosted repository does not match receipt repository".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn canonical_target(
    mut target: super::pipeline_receipt::TargetIdentity,
) -> Result<super::pipeline_receipt::TargetIdentity, ReceiptError> {
    target.features.sort();
    if target.features.iter().any(String::is_empty)
        || target.features.windows(2).any(|p| p[0] == p[1])
    {
        return Err(ReceiptError::Contract(
            "target features must be unique and nonempty".into(),
        ));
    }
    super::pipeline_receipt::validate_target(&target)?;
    Ok(target)
}

pub(crate) fn hash_artifacts(
    root: &Path,
    inputs: &[ReceiptArtifactInput],
) -> Result<Vec<ReceiptArtifact>, ReceiptError> {
    let meta = fs::symlink_metadata(root).map_err(|source| ReceiptError::Io {
        path: root.into(),
        source,
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(ReceiptError::Contract(
            "artifact root must be a regular directory".into(),
        ));
    }
    validate_artifact_inputs(inputs)?;
    let canonical_root = fs::canonicalize(root).map_err(|source| ReceiptError::Io {
        path: root.into(),
        source,
    })?;
    let mut artifacts = Vec::with_capacity(inputs.len());
    for input in inputs {
        reject_symlink_components(root, &input.path, "artifact path")?;
        let path = root.join(&input.path);
        artifacts.push(hash_one_artifact(&path, &canonical_root, input)?);
    }
    Ok(artifacts)
}

/// Lexical checks over every artifact claim, run before any file is hashed.
fn validate_artifact_inputs(inputs: &[ReceiptArtifactInput]) -> Result<(), ReceiptError> {
    let mut names = BTreeSet::new();
    for input in inputs {
        if input.name.is_empty() || !names.insert(&input.name) {
            return Err(ReceiptError::Contract(
                "artifact names must be unique and nonempty".into(),
            ));
        }
        validate_relative_path(&input.path, "artifact path")?;
    }
    Ok(())
}

fn hash_one_artifact(
    path: &Path,
    root: &Path,
    input: &ReceiptArtifactInput,
) -> Result<ReceiptArtifact, ReceiptError> {
    let resolved = fs::canonicalize(path).map_err(|source| ReceiptError::Io {
        path: path.into(),
        source,
    })?;
    if !resolved.starts_with(root) {
        return Err(ReceiptError::Contract(
            "artifact path escapes artifact root".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| ReceiptError::Io {
        path: path.into(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReceiptError::Contract(
            "artifact must be a regular file".into(),
        ));
    }
    let io_error = |source| ReceiptError::Io {
        path: path.into(),
        source,
    };
    let mut file = fs::File::open(path).map_err(io_error)?;
    let mut hasher = Sha256::new();
    let size = stream_into(&mut file, &mut hasher).map_err(io_error)?;
    Ok(ReceiptArtifact {
        name: input.name.clone(),
        path: input.path.clone(),
        size,
        sha256: Sha256Digest::from_hasher(hasher),
    })
}
