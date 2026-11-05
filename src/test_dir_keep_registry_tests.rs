// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The kept-dir registry's path rules: one normal form for every comparison,
//! containment per path component, the temp-dir filter on the report, the
//! format a parent process hands its kept dirs on in, and pruning
//! (MIK-8986 part 2, PR 1).

use std::path::{Path, PathBuf};

use super::{
    contains, expect_unkept, is_external_in, kept_tempdir, norm, parse_external, registered_paths,
    report_unkept,
};

/// A short-lived dir outside the process temp dir, in the crate root.
fn outside_temp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kept-dir-alias-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("a dir outside the temp dir")
}

fn canon(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).expect("an existing path")
}

/// R5. Only paths under the process temp dir are named, including one
/// reached through a symlinked alias; a path outside it never is.
/// Mutants: the outside-temp exclusion removed; containment on the raw path.
#[cfg(unix)]
#[test]
fn the_reporter_names_only_paths_under_the_temp_dir() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let inside = dir.path().join("audit.jsonl");
    // The alias lives outside the temp dir, so only its canonical form is
    // under it: a raw-path comparison misses it.
    let links = outside_temp();
    let alias = links.path().join("alias");
    std::os::unix::fs::symlink(dir.path(), &alias).expect("a symlink");
    let through_alias = alias.join("audit.jsonl");
    let outside = PathBuf::from("/nonexistent-root/a/b/audit.jsonl");
    let unkept = expect_unkept();
    report_unkept(&inside);
    report_unkept(&through_alias);
    report_unkept(&outside);
    let named: Vec<PathBuf> = unkept.recorded().into_iter().map(|(p, _)| p).collect();
    assert_eq!(
        named,
        vec![inside, through_alias],
        "only temp-dir paths are named"
    );
}

/// R6. `norm` canonicalises the deepest existing ancestor and keeps the
/// rest; a path with no existing ancestor but `/` is its own normal form.
/// Mutants: only the immediate parent canonicalised; a wrong fallback.
#[cfg(unix)]
#[test]
fn norm_resolves_the_deepest_existing_ancestor() {
    let target = tempfile::tempdir().expect("a temp dir");
    let links = tempfile::tempdir().expect("a dir for the alias");
    let link = links.path().join("link");
    std::os::unix::fs::symlink(target.path(), &link).expect("a symlink");
    assert_eq!(
        norm(&link.join("x").join("y").join("z.jsonl")),
        canon(target.path()).join("x").join("y").join("z.jsonl")
    );
    let nowhere = PathBuf::from("/nonexistent-root/a/b");
    assert_eq!(norm(&nowhere), nowhere);
}

/// R8. Containment compares whole components: `a` does not contain `ab/x`.
/// Mutant: a string-prefix comparison.
#[test]
fn a_prefix_sibling_is_not_contained() {
    assert!(!contains(Path::new("/r/a"), Path::new("/r/ab/x")));
    assert!(contains(Path::new("/r/a"), Path::new("/r/a/x")));
}

/// R9. The parent's kept dirs arrive in `join_paths` form and match through
/// an alias, never by prefix.
/// Mutants: a lexical match; the wrong separator.
#[cfg(unix)]
#[test]
fn external_kept_dirs_parse_and_match() {
    let a = tempfile::tempdir().expect("a temp dir");
    let b = tempfile::tempdir().expect("another temp dir");
    let list = std::env::join_paths([a.path(), b.path()]).expect("joinable paths");
    let external = parse_external(&list);
    assert_eq!(
        external,
        vec![a.path().to_path_buf(), b.path().to_path_buf()]
    );
    let links = tempfile::tempdir().expect("a dir for the alias");
    let alias = links.path().join("alias-of-b");
    std::os::unix::fs::symlink(b.path(), &alias).expect("a symlink");
    assert!(is_external_in(&external, &alias.join("audit.jsonl")));
    let sibling = PathBuf::from(format!("{}x", a.path().display())).join("audit.jsonl");
    assert!(
        !is_external_in(&external, &sibling),
        "a prefix sibling is not kept"
    );
}

/// R12 (control). A kept dir dropped by its last owner leaves no entry once
/// the next one registers. Only this row's own entry is checked: other
/// tests register and drop theirs in parallel.
/// Mutants: an `Arc` registry; no pruning.
#[test]
fn a_dropped_kept_dir_leaves_no_entry() {
    let dir = kept_tempdir();
    let mine = norm(dir.path());
    drop(dir);
    let _next = kept_tempdir();
    assert!(
        !registered_paths().contains(&mine),
        "the dropped dir's entry survived the next registration"
    );
}
