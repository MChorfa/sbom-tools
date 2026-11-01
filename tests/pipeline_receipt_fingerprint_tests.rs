use sbom_tools::verification::{lock_fingerprint, source_fingerprint};
use std::path::{Path, PathBuf};

fn put(root: &Path, relative: &str, contents: &[u8]) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

#[test]
fn source_fingerprint_is_a_stable_nested_byte_vector() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "a.txt", b"A");
    put(root.path(), "nested/target/inside.txt", b"nested-target");
    put(root.path(), "nested/receipts", b"receipt-file");
    put(root.path(), "nested/vendor/receipts", b"vendor-receipts");
    put(root.path(), ".git/ignored", b"ignored");
    put(root.path(), "target/ignored", b"ignored");
    put(root.path(), "receipts/ignored", b"ignored");
    assert_eq!(
        source_fingerprint(root.path()).unwrap().as_str(),
        "sha256:355eb2ddd69e55a63cb206820e41dea3b2a076a7a81fa32a605e007919e56024"
    );
}

#[test]
fn lock_fingerprint_uses_only_enumerated_paths() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "Cargo.lock", b"lock-a\n");
    put(root.path(), "rust-toolchain.toml", b"lock-b\n");
    put(root.path(), "unlisted.txt", b"must-not-contribute");
    let paths = vec![
        PathBuf::from("rust-toolchain.toml"),
        PathBuf::from("Cargo.lock"),
    ];
    assert_eq!(
        lock_fingerprint(root.path(), &paths).unwrap().as_str(),
        "sha256:2e5999d0d9954355d5fec3e9b813697098f2aa11db4045cc59d0bd9eee501f7d"
    );
}

#[test]
fn source_fingerprint_changes_for_content_or_relative_path_changes() {
    let first = tempfile::tempdir().unwrap();
    put(first.path(), "src/file.txt", b"same");
    let baseline = source_fingerprint(first.path()).unwrap();
    put(first.path(), "src/file.txt", b"changed");
    assert_ne!(source_fingerprint(first.path()).unwrap(), baseline);
    let second = tempfile::tempdir().unwrap();
    put(second.path(), "renamed/file.txt", b"same");
    assert_ne!(source_fingerprint(second.path()).unwrap(), baseline);
}

#[cfg(unix)]
#[test]
fn source_fingerprint_rejects_symlinks_before_exclusion() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "real.txt", b"content");
    std::os::unix::fs::symlink(root.path().join("real.txt"), root.path().join("target")).unwrap();
    assert!(source_fingerprint(root.path()).is_err());
}

#[test]
fn top_level_git_file_is_excluded_like_the_git_directory() {
    // Worktree and submodule checkouts have a `.git` FILE holding an absolute
    // `gitdir:` path; hashing it would make the fingerprint machine-specific.
    let plain = tempfile::tempdir().unwrap();
    put(plain.path(), "src/lib.rs", b"code");
    let worktree = tempfile::tempdir().unwrap();
    put(worktree.path(), "src/lib.rs", b"code");
    put(
        worktree.path(),
        ".git",
        b"gitdir: /home/someone/repo/.git/worktrees/wt",
    );
    assert_eq!(
        source_fingerprint(plain.path()).unwrap(),
        source_fingerprint(worktree.path()).unwrap()
    );
    // Nested `.git` entries (e.g. vendored trees) remain evidence.
    put(worktree.path(), "vendor/.git", b"gitdir: elsewhere");
    assert_ne!(
        source_fingerprint(plain.path()).unwrap(),
        source_fingerprint(worktree.path()).unwrap()
    );
}

#[test]
fn lock_fingerprint_rejects_duplicate_paths() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "Cargo.lock", b"lock");
    let paths = vec![PathBuf::from("Cargo.lock"), PathBuf::from("Cargo.lock")];
    assert!(lock_fingerprint(root.path(), &paths).is_err());
}

#[cfg(unix)]
#[test]
fn lock_fingerprint_rejects_symlinked_intermediate_directories() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    put(outside.path(), "Cargo.lock", b"outside");
    std::os::unix::fs::symlink(outside.path(), root.path().join("vendor")).unwrap();
    assert!(lock_fingerprint(root.path(), &[PathBuf::from("vendor/Cargo.lock")]).is_err());
}
