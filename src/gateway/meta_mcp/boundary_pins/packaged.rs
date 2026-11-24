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
/// is a skip, and one the package's `include` makes on purpose, so it passes in
/// required mode too (`skip_unshipped`); any other error (a directory, a
/// permission) fails in both modes, and so does a missing file in a checkout.
pub(super) fn read_or_skip(root: &Path, rel: &str, packaged: bool) -> Option<String> {
    read_if_present(root, rel, packaged).or_else(|| {
        crate::test_wait::skip_unshipped(packaged, &format!("{rel} in the crate under test"));
        None
    })
}

/// The decision without the skip: `None` only when the file is not found and
/// the crate is the packaged one. Kept apart so the "missing in a packaged
/// crate" row tests it whatever the required mode is.
fn read_if_present(root: &Path, rel: &str, packaged: bool) -> Option<String> {
    match std::fs::read_to_string(root.join(rel)) {
        Ok(text) => Some(text),
        Err(e) if packaged && e.kind() == ErrorKind::NotFound => None,
        Err(e) => panic!("{rel} could not be read (packaged: {packaged}): {e}"),
    }
}

/// Every repository file a pin reads through [`repo_file`], or names by path
/// in a table while a walk reads it (the D12 launch files). A closed enum, so
/// a new read cannot bypass the list: it must add a variant, and the vacuity
/// guard's exhaustive `match` (no `_` arm) fails to compile until the new
/// variant gets a case.
#[derive(Clone, Copy)]
pub(super) enum PinnedFile {
    /// `scripts/lint/registry-ban/clippy.toml`, read by `t1f`.
    RegistryBanClippy,
    /// The root `clippy.toml`, read by `the_root_ban_span_is_the_root_config_list`.
    RootClippy,
    /// `scripts/dev/pre-push.sh`, read by `t1f`.
    PrePush,
    /// `.github/workflows/ci.yml`, read by `checked_in_workflow`.
    CiWorkflow,
    /// ADR-016, read by `b26_the_adr_and_crate_root_name_both_unsafe_modules`.
    UnsafeAdr,
    /// `scripts/release/check_identity_sources.py`, read by
    /// `the_table_names_every_case_the_scanner_catches`.
    IdentityScanner,
    /// The root `Makefile`, read by `every_image_launch_sets_dnt` (D12).
    RootMakefile,
    /// `scripts/ci/smoke-image.sh`: D12 reads it by walking `scripts/` and
    /// names it in its tables (its image is its first argument; its launches
    /// are counted).
    SmokeImage,
    /// `scripts/ci/smoke-full-image.sh`, named by D12 like `SmokeImage`.
    SmokeFullImage,
    /// `scripts/dev/docker-smoke.sh`, a D12 launch file.
    DockerSmoke,
    /// `scripts/dev/helm-kind-lifecycle.sh`, a D12 launch file.
    HelmKindLifecycle,
    /// `scripts/dev/helm-kind-real-image.sh`, a D12 launch file.
    HelmKindRealImage,
}

impl PinnedFile {
    /// The file's crate-root-relative path.
    pub(super) fn path(self) -> &'static str {
        match self {
            PinnedFile::RegistryBanClippy => "scripts/lint/registry-ban/clippy.toml",
            PinnedFile::RootClippy => "clippy.toml",
            PinnedFile::PrePush => "scripts/dev/pre-push.sh",
            PinnedFile::CiWorkflow => ".github/workflows/ci.yml",
            PinnedFile::UnsafeAdr => "docs/adr/ADR-016-scoped-unsafe-windows-acl.md",
            PinnedFile::IdentityScanner => "scripts/release/check_identity_sources.py",
            PinnedFile::RootMakefile => "Makefile",
            PinnedFile::SmokeImage => "scripts/ci/smoke-image.sh",
            PinnedFile::SmokeFullImage => "scripts/ci/smoke-full-image.sh",
            PinnedFile::DockerSmoke => "scripts/dev/docker-smoke.sh",
            PinnedFile::HelmKindLifecycle => "scripts/dev/helm-kind-lifecycle.sh",
            PinnedFile::HelmKindRealImage => "scripts/dev/helm-kind-real-image.sh",
        }
    }
}

/// [`read_or_skip`] on this crate's root, for a [`PinnedFile`].
pub(super) fn repo_file(file: PinnedFile) -> Option<String> {
    read_or_skip(crate_root(), file.path(), is_packaged_crate())
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
    assert_eq!(read_if_present(root.path(), "gone.txt", true), None);
}

/// Run only by `a_missing_packaged_file_passes_in_required_mode`, in a child with its own environment.
#[test]
#[ignore = "run by a_missing_packaged_file_passes_in_required_mode, in a child"]
fn read_or_skip_packaged_child() {
    let root = tempfile::tempdir().expect("tempdir");
    assert_eq!(read_or_skip(root.path(), "gone.txt", true), None);
}

/// `read_or_skip`'s own skip path, the one that failed the packaged suite, passes under
/// `TESTS_REQUIRE_ALL=1` in a packaged crate and says why. A child process, so the variable is
/// its own; the checkout side is `a_missing_file_in_a_checkout_panics`.
#[test]
fn a_missing_packaged_file_passes_in_required_mode() {
    let out = crate::test_home::test_binary()
        .args([
            "--ignored",
            "--exact",
            "gateway::meta_mcp::boundary_pins::packaged::read_or_skip_packaged_child",
            "--nocapture",
        ])
        .env("TESTS_REQUIRE_ALL", "1")
        .output()
        .expect("the child runs");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(
        err.contains(
            "skipped (not shipped in the packaged crate): gone.txt in the crate under test"
        ),
        "{err}"
    );
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
/// [`repo_file`] exists, so the skip cannot be what a checkout run took. The
/// array lists every variant and the `match` is exhaustive (no `_` arm), so a
/// new variant without a case fails to compile.
#[test]
fn pinned_repo_files_are_read_in_a_checkout() {
    if is_packaged_crate() {
        return;
    }
    for file in [
        PinnedFile::RegistryBanClippy,
        PinnedFile::RootClippy,
        PinnedFile::PrePush,
        PinnedFile::CiWorkflow,
        PinnedFile::UnsafeAdr,
        PinnedFile::IdentityScanner,
        PinnedFile::RootMakefile,
        PinnedFile::SmokeImage,
        PinnedFile::SmokeFullImage,
        PinnedFile::DockerSmoke,
        PinnedFile::HelmKindLifecycle,
        PinnedFile::HelmKindRealImage,
    ] {
        let rel = match file {
            PinnedFile::RegistryBanClippy => "scripts/lint/registry-ban/clippy.toml",
            PinnedFile::RootClippy => "clippy.toml",
            PinnedFile::PrePush => "scripts/dev/pre-push.sh",
            PinnedFile::CiWorkflow => ".github/workflows/ci.yml",
            PinnedFile::UnsafeAdr => "docs/adr/ADR-016-scoped-unsafe-windows-acl.md",
            PinnedFile::IdentityScanner => "scripts/release/check_identity_sources.py",
            PinnedFile::RootMakefile => "Makefile",
            PinnedFile::SmokeImage => "scripts/ci/smoke-image.sh",
            PinnedFile::SmokeFullImage => "scripts/ci/smoke-full-image.sh",
            PinnedFile::DockerSmoke => "scripts/dev/docker-smoke.sh",
            PinnedFile::HelmKindLifecycle => "scripts/dev/helm-kind-lifecycle.sh",
            PinnedFile::HelmKindRealImage => "scripts/dev/helm-kind-real-image.sh",
        };
        assert_eq!(rel, file.path(), "path() names the pinned file");
        assert!(
            crate_root().join(rel).is_file(),
            "{rel} missing in a checkout"
        );
    }
}

/// B26: ADR-016 and the crate root name both Windows modules allowed
/// `unsafe`, so neither still reads as if `win_acl` were the only one. The
/// ADR is not in the published crate, so a packaged run skips that half.
#[test]
fn b26_the_adr_and_crate_root_name_both_unsafe_modules() {
    let lib = std::fs::read_to_string(crate_root().join("src/lib.rs")).expect("read src/lib.rs");
    for module in ["win_acl", "win_cred"] {
        assert!(lib.contains(module), "src/lib.rs does not name {module}");
    }
    let Some(adr) = repo_file(PinnedFile::UnsafeAdr) else {
        return;
    };
    for module in ["win_acl", "win_cred"] {
        assert!(adr.contains(module), "ADR-016 does not name {module}");
    }
    assert!(
        adr.contains("are now `src/win_acl.rs` and `src/win_cred.rs`"),
        "ADR-016 lacks its ADR-028 amendment"
    );
}
