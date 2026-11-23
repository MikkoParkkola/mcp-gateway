// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! H1-H2: the production read the history page and the restore route take.
//! A file that cannot be read or parsed is an error to the caller, never an
//! empty store; a revision stored twice resolves to its newest copy; a
//! memory-only store answers from what it holds.

use std::path::Path;

use super::{Bounds, ConfigHistory, Lookup, Snapshot, Source, StoredFile, applied_event};

/// The env file every version in these rows holds beside gateway.yaml.
const ENV_FILE: &str = "/srv/gw/app.env";

/// A version of `revision` whose env file holds `env`.
fn version(revision: &str, at: u64, env: &[u8]) -> Snapshot {
    Snapshot {
        files: vec![
            StoredFile {
                path: "gateway.yaml".into(),
                bytes: Some(b"environment: \"dev\"\n".to_vec()),
            },
            StoredFile {
                path: ENV_FILE.into(),
                bytes: Some(env.to_vec()),
            },
        ],
        pending_restart: vec![],
        source: Source::File,
        revision: revision.into(),
        at,
    }
}

/// Store `revision` as a version and the applied event that names it.
fn keep(store: &ConfigHistory, revision: &str, at: u64, env: &[u8]) {
    store.record(
        applied_event(at, Source::File, revision, false),
        Some(version(revision, at, env)),
        revision,
        at,
    );
}

/// A store on disk under `dir`, holding the one version r-one.
fn on_disk(dir: &Path) -> ConfigHistory {
    let store = ConfigHistory::open(dir, Bounds::default(), 1);
    keep(&store, "r-one", 1, b"K=1\n");
    store
}

/// The env file's bytes in a kept version.
fn env_bytes(found: &Lookup) -> Option<Vec<u8>> {
    let Lookup::Kept(snapshot) = found else {
        return None;
    };
    snapshot
        .files
        .iter()
        .find(|file| file.path == ENV_FILE)
        .and_then(|file| file.bytes.clone())
}

#[cfg(unix)]
#[test]
fn h1_a_linked_history_file_is_a_read_error_never_unknown() {
    let dir = tempfile::tempdir().expect("dir");
    let store = on_disk(dir.path());
    // Control: the real file reads its one version.
    assert!(matches!(store.lookup("r-one"), Ok(Lookup::Kept(_))));
    // The one defect: the history file becomes a link to its own bytes.
    let file = store.file();
    let moved = dir.path().join("moved.json");
    std::fs::rename(&file, &moved).expect("move the file aside");
    std::os::unix::fs::symlink(&moved, &file).expect("link it back");
    let read = store.lookup("r-one");
    assert!(read.is_err(), "{read:?}");
}

#[test]
fn h1b_a_history_file_that_does_not_parse_is_a_read_error() {
    let dir = tempfile::tempdir().expect("dir");
    let store = on_disk(dir.path());
    assert!(matches!(store.lookup("r-one"), Ok(Lookup::Kept(_))));
    // The one defect: the file is cut short in the middle of a version.
    crate::gateway::test_helpers::write_owner_only(
        store.file(),
        b"{\"snapshots\": [{\"revision\": \"r-",
    )
    .expect("cut the file short");
    let read = store.lookup("r-one");
    assert!(read.is_err(), "{read:?}");
}

#[test]
fn h1c_lookup_returns_the_newest_copy_of_a_revision() {
    let dir = tempfile::tempdir().expect("dir");
    let store = ConfigHistory::open(dir.path(), Bounds::default(), 1);
    keep(&store, "r-a", 1, b"K=older\n");
    keep(&store, "r-b", 2, b"K=between\n");
    keep(&store, "r-a", 3, b"K=newer\n");
    let found = store.lookup("r-a").expect("the store reads");
    assert_eq!(env_bytes(&found), Some(b"K=newer\n".to_vec()));
}

#[cfg(unix)]
#[test]
fn h2_a_memory_only_store_answers_lookup_from_what_it_holds() {
    let dir = tempfile::tempdir().expect("dir");
    // A history file that is a link is refused when the store opens, so the
    // store keeps what it records in memory; a read of the link would fail.
    let target = dir.path().join("target.json");
    std::fs::write(&target, b"{}").expect("target");
    std::os::unix::fs::symlink(&target, dir.path().join(ConfigHistory::FILE)).expect("link");
    let store = ConfigHistory::open(dir.path(), Bounds::default(), 1);
    keep(&store, "r-held", 1, b"K=1\n");
    store.record(
        applied_event(2, Source::File, "r-named", true),
        None,
        "r-held",
        2,
    );
    assert!(matches!(store.lookup("r-held"), Ok(Lookup::Kept(_))));
    assert!(matches!(store.lookup("r-named"), Ok(Lookup::NoLongerKept)));
    assert!(matches!(store.lookup("r-never"), Ok(Lookup::Unknown)));
}
