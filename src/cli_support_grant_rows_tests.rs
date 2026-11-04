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

/// A grants path that is a symlink into another directory stays one: the
/// real file is rewritten and backed up beside itself, not beside the link.
#[cfg(unix)]
#[test]
fn a_symlinked_grants_path_is_backed_up_beside_the_real_file() {
    let dir = tempfile::tempdir().unwrap();
    let (real_dir, link_dir) = (dir.path().join("real"), dir.path().join("links"));
    std::fs::create_dir_all(&real_dir).unwrap();
    std::fs::create_dir_all(&link_dir).unwrap();
    let real = grants_in(&real_dir);
    let link = link_dir.join("link.yaml");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let removed = remove_nameless_grant_rows(&link, GrantCleanup::Apply).unwrap();
    assert_eq!(removed.len(), 1);
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_ne!(std::fs::read_to_string(&real).unwrap(), BODY);
    assert_eq!(
        std::fs::read_to_string(real_dir.join("grants.yaml.bak.pre-4.0.0")).unwrap(),
        BODY,
        "the backup sits beside the real file"
    );
    assert!(
        !link_dir.join("link.yaml.bak.pre-4.0.0").exists(),
        "nothing is written beside the link"
    );
}
