// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Concurrent writers to one collection lose no update.
//!
//! `store_cas` holds an exclusive file lock across read-generation, check and
//! write. Each thread opens its own store on the shared directory. They share
//! one governance audit logger, because one process writes an audit log path
//! (a second logger on it is refused). With the lock a no-op (non-unix before
//! the fix), two writers read the same generation, both pass the check and
//! one write replaces the other, or the shared temp file is clobbered.

use super::*;

#[test]
fn concurrent_put_grant_keeps_every_grant() {
    const WRITERS: usize = 16;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let barrier = Arc::new(std::sync::Barrier::new(WRITERS));
    let audit = governance_logger(&root);
    let handles: Vec<_> = (0..WRITERS)
        .map(|i| {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            let audit = Arc::clone(&audit);
            std::thread::spawn(move || {
                let store =
                    FileControlPlaneStore::open(root.join("store"), audit).expect("open store");
                barrier.wait();
                store.put_grant(grant(&format!("g{i}"), ControlPlaneGrantStatus::Requested))
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap().expect("a locked write never fails");
    }
    let mut ids: Vec<String> = FileControlPlaneStore::open(root.join("store"), audit)
        .expect("open store")
        .list_grants()
        .unwrap()
        .into_iter()
        .map(|g| g.grant_id)
        .collect();
    ids.sort();
    let mut expected: Vec<String> = (0..WRITERS).map(|i| format!("g{i}")).collect();
    expected.sort();
    assert_eq!(
        ids, expected,
        "a concurrent write lost another writer's grant"
    );
}
