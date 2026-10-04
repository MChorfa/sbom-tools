use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{
    pipeline_receipt::{ReceiptError, Sha256Digest},
    pipeline_receipt_paths::{reject_symlink_components, validate_relative_path},
};

/// Compute a deterministic digest of source files, excluding generated and receipt directories.
pub fn source_fingerprint(root: &Path) -> Result<Sha256Digest, ReceiptError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| ReceiptError::Io {
        path: root.into(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReceiptError::Contract(
            "source root must be a regular directory".into(),
        ));
    }
    let mut files = Vec::new();
    collect_source_files(root, root, &mut files)?;
    fingerprint_files(root, files)
}

/// Compute a deterministic digest of explicitly selected lock files.
pub fn lock_fingerprint(root: &Path, paths: &[PathBuf]) -> Result<Sha256Digest, ReceiptError> {
    if paths.is_empty() {
        return Err(ReceiptError::Contract(
            "lock input list must not be empty".into(),
        ));
    }
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    for path in paths {
        let value = path
            .to_str()
            .ok_or_else(|| ReceiptError::Contract("lock path must be UTF-8".into()))?;
        validate_relative_path(value, "lock path")?;
        if !seen.insert(value) {
            return Err(ReceiptError::Contract(format!(
                "duplicate lock path: {value}"
            )));
        }
        reject_symlink_components(root, value, "lock path")?;
        let full = root.join(value);
        let meta = fs::symlink_metadata(&full).map_err(|source| ReceiptError::Io {
            path: full.clone(),
            source,
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(ReceiptError::Contract(
                "lock input must be a regular file".into(),
            ));
        }
        files.push(full);
    }
    fingerprint_files(root, files)
}

fn collect_source_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), ReceiptError> {
    for entry in fs::read_dir(dir).map_err(|source| ReceiptError::Io {
        path: dir.into(),
        source,
    })? {
        let path = entry
            .map_err(|source| ReceiptError::Io {
                path: dir.into(),
                source,
            })?
            .path();
        let rel = path
            .strip_prefix(root)
            .map_err(|_| ReceiptError::Contract("path escaped root".into()))?;
        // Symlinks are rejected before any exclusion so a symlink named after
        // an excluded directory cannot slip past the fail-closed check.
        let metadata = fs::symlink_metadata(&path).map_err(|source| ReceiptError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ReceiptError::Contract("symlink in source tree".into()));
        }
        // Exclusions are root-anchored: only the top-level .git, target/, and
        // receipts/ entries are generated state. A nested vendored
        // `foo/target/` or a source FILE named `receipts` is evidence and must
        // stay in the fingerprint. `.git` is excluded as a file too: worktree
        // and submodule checkouts store an absolute `gitdir:` pointer there,
        // which would make the fingerprint machine-specific.
        if rel.components().count() == 1 {
            let name = rel.as_os_str().to_str();
            if name == Some(".git")
                || (metadata.is_dir() && matches!(name, Some("target" | "receipts")))
            {
                continue;
            }
        }
        if rel.to_str().is_none_or(|value| value.is_empty()) {
            return Err(ReceiptError::Contract("non-UTF8 source path".into()));
        }
        if metadata.is_dir() {
            collect_source_files(root, &path, out)?;
        } else if metadata.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn fingerprint_files(root: &Path, mut files: Vec<PathBuf>) -> Result<Sha256Digest, ReceiptError> {
    let mut files = files
        .drain(..)
        .map(|path| {
            let identity = relative_path_identity(root, &path)?;
            Ok((identity, path))
        })
        .collect::<Result<Vec<_>, ReceiptError>>()?;
    files.sort_by(|(a, _), (b, _)| a.cmp(b));
    // Stream each record straight into the hasher: the digest is identical to
    // hashing the concatenated `len(rel) rel len(bytes) bytes` encoding, but
    // memory stays bounded regardless of tree size.
    let mut hasher = Sha256::new();
    for (rel, path) in files {
        hasher.update((rel.len() as u64).to_be_bytes());
        hasher.update(rel.as_bytes());
        hash_file_record(&path, &mut hasher)?;
    }
    Ok(Sha256Digest::from_hasher(hasher))
}

/// Hash `len(bytes) bytes` for one file. The length prefix comes from the open
/// handle's metadata and must equal the bytes actually read; a file that
/// changes size mid-hash is an operational error, never a silently wrong
/// digest.
fn hash_file_record(path: &Path, hasher: &mut Sha256) -> Result<(), ReceiptError> {
    let io_error = |source| ReceiptError::Io {
        path: path.into(),
        source,
    };
    let mut file = fs::File::open(path).map_err(io_error)?;
    let expected = file.metadata().map_err(io_error)?.len();
    hasher.update(expected.to_be_bytes());
    let read = stream_into(&mut file, hasher).map_err(io_error)?;
    if read != expected {
        return Err(io_error(std::io::Error::other(
            "file size changed while fingerprinting; supply a stable snapshot",
        )));
    }
    Ok(())
}

/// Feed a reader into the hasher in fixed-size chunks; returns bytes read.
pub(crate) fn stream_into(reader: &mut impl Read, hasher: &mut Sha256) -> std::io::Result<u64> {
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let n = match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        hasher.update(&buffer[..n]);
        total += n as u64;
    }
}

fn relative_path_identity(root: &Path, path: &Path) -> Result<String, ReceiptError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ReceiptError::Contract("path escaped root".into()))?;
    let components = relative
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| ReceiptError::Contract("non-UTF8 source path".into()))
        })
        .collect::<Result<Vec<_>, ReceiptError>>()?;
    if components.is_empty() {
        return Err(ReceiptError::Contract("empty relative path".into()));
    }
    Ok(components.join("/"))
}

#[cfg(test)]
mod tests {
    use super::relative_path_identity;
    use std::path::Path;

    #[test]
    fn relative_path_identity_uses_forward_slashes() {
        assert_eq!(
            relative_path_identity(Path::new("/workspace"), Path::new("/workspace/nested/file"))
                .unwrap(),
            "nested/file"
        );
    }
}
