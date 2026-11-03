// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The upgrade's grant-row cleanup edits the file a CLI grant change edits,
//! the way that change does: under the journal lock, on the real file.

use std::path::Path;
use std::time::Duration;

use super::{GrantCleanup, remove_nameless_grant_rows};

const BODY: &str = "schema_version: identity_grants.v1\ngrants:\n- grant_id: g-empty\n  subject:\n    authority: api_key\n    subject: \"\"\n  agent: any\n  capability: calendar_read\n  scope: execute\n  provenance: p\n  reason: empty\n";

fn grants_in(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("grants.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, BODY).unwrap();
    path
}

/// While another writer holds the journal lock the cleanup does not touch
/// the file; once the lock is released it runs.
#[test]
fn the_cleanup_waits_for_the_journal_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = grants_in(dir.path());
    let lock = crate::identity_grants::journal::lock_path(&path);
    let held = crate::fs_lock::ExclusiveFileLock::acquire(&lock).unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let target = path.clone();
    let worker = std::thread::spawn(move || {
        let removed = remove_nameless_grant_rows(&target, GrantCleanup::Apply);
        done_tx.send(()).unwrap();
        removed
    });
    // ponytail: a bounded wait proves only "not within 300 ms"; the file
    // check below is what fails if the lock is skipped.
    assert!(
        done_rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the cleanup ran while the lock was held"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), BODY);
    drop(held);
    assert_eq!(worker.join().unwrap().unwrap().len(), 1);
    assert_ne!(std::fs::read_to_string(&path).unwrap(), BODY);
}

/// A grants path that is a symlink stays one: the real file is rewritten.
#[cfg(unix)]
#[test]
fn a_symlinked_grants_path_stays_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let real = grants_in(dir.path());
    let link = dir.path().join("link.yaml");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        remove_nameless_grant_rows(&link, GrantCleanup::Apply)
            .unwrap()
            .len(),
        1
    );
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_ne!(std::fs::read_to_string(&real).unwrap(), BODY);
}
