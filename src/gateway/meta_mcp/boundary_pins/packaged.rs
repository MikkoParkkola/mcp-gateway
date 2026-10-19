// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8481: reading repository files from a pin test. `Cargo.toml` `include`
//! leaves repo tooling (scripts, the CI workflow) out of the published crate,
//! and the post-merge packaged suite runs the tests from the unpacked crate.
//! A pin that reads such a file goes through [`repo_file`]: it skips in a
//! packaged crate and fails in a checkout, so it can neither break the packaged
//! run nor pass vacuously.

use std::io::ErrorKind;
use std::path::Path;

pub(super) fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Whether `root` is the unpacked published crate: `cargo package` writes
/// `Cargo.toml.orig` into it, and an unpacked crate has no `.git`. A checkout
/// with a stray `Cargo.toml.orig` still has its `.git` (a file in a worktree,
/// a directory otherwise), so it is not mistaken for one.
fn packaged_crate_at(root: &Path) -> bool {
    root.join("Cargo.toml.orig").exists() && !root.join(".git").exists()
}

pub(super) fn is_packaged_crate() -> bool {
    packaged_crate_at(crate_root())
}

/// A repository file a pin reads: its text, or `None` when it is not found and
/// `packaged` says the crate is the unpacked published one. Only "not found"
/// is a skip; any other error (a directory, a permission) fails in both modes,
/// and so does a missing file in a checkout.
pub(super) fn read_or_skip(root: &Path, rel: &str, packaged: bool) -> Option<String> {
    match std::fs::read_to_string(root.join(rel)) {
        Ok(text) => Some(text),
        Err(e) if packaged && e.kind() == ErrorKind::NotFound => {
            eprintln!("skipped: {rel} is not in the packaged crate");
            None
        }
        Err(e) => panic!("{rel} could not be read (packaged: {packaged}): {e}"),
    }
}

/// [`read_or_skip`] on this crate's root.
pub(super) fn repo_file(rel: &str) -> Option<String> {
    read_or_skip(crate_root(), rel, is_packaged_crate())
}

/// A present file is read in either mode.
#[test]
fn a_present_file_is_read_in_both_modes() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::write(root.path().join("f.txt"), "x").expect("write");
    for packaged in [false, true] {
        assert_eq!(
            read_or_skip(root.path(), "f.txt", packaged).as_deref(),
            Some("x")
        );
    }
}

/// A missing file is a skip in a packaged crate.
#[test]
fn a_missing_file_is_skipped_in_a_packaged_crate() {
    let root = tempfile::tempdir().expect("tempdir");
    assert_eq!(read_or_skip(root.path(), "gone.txt", true), None);
}

/// A missing file in a checkout panics: the pin cannot pass vacuously.
#[test]
#[should_panic(expected = "gone.txt")]
fn a_missing_file_in_a_checkout_panics() {
    let root = tempfile::tempdir().expect("tempdir");
    let _ = read_or_skip(root.path(), "gone.txt", false);
}

/// Only "not found" is a skip: a pinned path that is not readable for another
/// reason (here, a directory) fails even in a packaged crate.
#[test]
#[should_panic(expected = "is_dir")]
fn an_unreadable_file_is_not_a_skip_in_a_packaged_crate() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(root.path().join("is_dir")).expect("mkdir");
    let _ = read_or_skip(root.path(), "is_dir", true);
}

/// The detector: the marker alone is a packaged crate; the marker beside a
/// `.git` (file or directory) is a checkout with a stray marker; neither is a
/// checkout.
#[test]
fn the_packaged_detector_needs_the_marker_and_no_git() {
    let root = tempfile::tempdir().expect("tempdir");
    assert!(!packaged_crate_at(root.path()), "neither");
    std::fs::write(root.path().join("Cargo.toml.orig"), "").expect("marker");
    assert!(packaged_crate_at(root.path()), "marker only");
    std::fs::write(root.path().join(".git"), "gitdir: x").expect("worktree .git");
    assert!(!packaged_crate_at(root.path()), "marker and a .git file");
    std::fs::remove_file(root.path().join(".git")).expect("rm");
    std::fs::create_dir(root.path().join(".git")).expect("mkdir");
    assert!(!packaged_crate_at(root.path()), "marker and a .git dir");
}

/// A stray `Cargo.toml.orig` in a checkout is an error of its own: it would
/// otherwise be silent, because the detector refuses to treat it as packaged.
#[test]
fn no_stray_cargo_toml_orig_in_a_checkout() {
    let root = crate_root();
    assert!(
        !(root.join("Cargo.toml.orig").exists() && root.join(".git").exists()),
        "Cargo.toml.orig beside .git: a leftover from a patch or merge tool; remove it"
    );
}

/// The vacuity guard: outside a packaged crate every file a pin reads through
/// [`repo_file`] exists, so the skip cannot be what a checkout run took.
#[test]
fn pinned_repo_files_are_read_in_a_checkout() {
    if is_packaged_crate() {
        return;
    }
    for rel in [
        "scripts/lint/registry-ban/clippy.toml",
        "scripts/dev/pre-push.sh",
        ".github/workflows/ci.yml",
    ] {
        assert!(
            crate_root().join(rel).is_file(),
            "{rel} missing in a checkout"
        );
    }
}
