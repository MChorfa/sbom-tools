use std::{
    fs,
    path::{Path, PathBuf},
};

use super::pipeline_receipt::ReceiptError;

/// Validate a manifest path against the portable relative-path grammar shared
/// with the published schemas (`$defs/relative_path`):
///
/// `^SEG(/SEG)*$` where each segment is nonempty, is not `.` or `..`, and
/// contains no `/`, `\`, `:`, or control characters.
///
/// The check is purely lexical so every OS accepts exactly the same strings;
/// tests/pipeline_receipt_schema_binding_tests.rs pins the agreement with the
/// schema pattern.
pub(crate) fn validate_relative_path(value: &str, label: &str) -> Result<(), ReceiptError> {
    let portable = !value.is_empty()
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment
                    .chars()
                    .any(|c| matches!(c, '\\' | ':' | '\u{0}'..='\u{1f}'))
        });
    if !portable {
        return Err(ReceiptError::Contract(format!(
            "{label} must be a portable relative path ('/'-separated segments, no '.', '..', '\\', ':', or control characters)"
        )));
    }
    Ok(())
}

/// Reject a validated relative path if the root or any component below it is a
/// symlink, so neither the final file nor an intermediate directory can
/// redirect hashing outside the declared tree.
pub(crate) fn reject_symlink_components(
    root: &Path,
    relative: &str,
    label: &str,
) -> Result<(), ReceiptError> {
    let mut current = PathBuf::from(root);
    for segment in relative.split('/') {
        current.push(segment);
        let metadata = fs::symlink_metadata(&current).map_err(|source| ReceiptError::Io {
            path: current.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ReceiptError::Contract(format!(
                "{label} contains a symlink"
            )));
        }
    }
    Ok(())
}
