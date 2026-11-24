// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared source walk: which files it lists, that it adds to what a caller already holds, and that a directory
//! it cannot list stops the scan instead of reading as empty.

use std::path::{Path, PathBuf};

use super::test_source_files::rust_files;

fn plant(root: &Path, rel: &str) -> PathBuf {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("dirs");
    std::fs::write(&path, "").expect("planted file");
    path
}

/// Every `.rs` file at every depth, nothing else; added after what the caller held, each file once.
#[test]
fn the_walk_adds_every_rs_file_at_every_depth_and_nothing_else() {
    let tmp = tempfile::tempdir().expect("tmp");
    let root = tmp.path();
    let mut expected = vec![
        plant(root, "one/top.rs"),
        plant(root, "one/deep/er/still.rs"),
        plant(root, "two/side.rs"),
    ];
    // Not Rust source to the scans: another extension, a file named `rs`, an upper-case extension, a backup.
    let ignored = ["a.txt", "rs", "deep/X.RS", "b.rs.bak"];
    for name in ignored {
        plant(&root.join("one"), name);
    }
    std::fs::create_dir_all(root.join("two/empty")).expect("an empty dir");

    // A path already held, which the walk must keep: it adds, it never resets.
    let held = PathBuf::from("held/before.rs");
    let mut found = vec![held.clone()];
    rust_files(&root.join("one"), &mut found);
    rust_files(&root.join("two"), &mut found);
    assert_eq!(
        found.first(),
        Some(&held),
        "the held path stays first: the walk appends"
    );

    expected.push(held);
    found.sort();
    expected.sort();
    assert_eq!(
        found, expected,
        "the walk's files, sorted (no dedup: a file listed twice fails)"
    );
}

/// A directory the walk cannot list stops the scan, naming it: never an empty pass.
#[test]
fn a_directory_the_walk_cannot_list_panics_naming_it() {
    let tmp = tempfile::tempdir().expect("tmp");
    let missing = tmp.path().join("not-there");
    let Err(payload) = std::panic::catch_unwind(|| rust_files(&missing, &mut Vec::new())) else {
        let shown = missing.display();
        panic!("walking {shown} returned instead of panicking");
    };
    let owned = payload.downcast_ref::<String>();
    let literal = payload.downcast_ref::<&str>();
    let said = match (owned, literal) {
        (Some(text), _) => text.clone(),
        (None, Some(text)) => (*text).to_owned(),
        (None, None) => String::from("<a payload that is not text>"),
    };
    // The walk's own message, not any panic that happens to carry the path (an io error can name it too).
    let want = format!("cannot list {}: ", missing.display());
    assert!(
        said.starts_with(&want),
        "the panic should start {want:?}, it said: {said}"
    );
}
