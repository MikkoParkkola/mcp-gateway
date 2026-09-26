// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Concurrent writers to one collection lose no update.
//!
//! `store_cas` holds an exclusive file lock across read-generation, check and
//! write. Each thread opens its own store on the shared directory, as a
//! separate process would. With the lock a no-op (non-unix before this
//! fix), two writers read the same generation, both pass the check and one
//! write replaces the other, or the shared temp file is clobbered mid-write.

use super::*;

#[test]
fn concurrent_put_grant_keeps_every_grant() {
    const WRITERS: usize = 16;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let barrier = Arc::new(std::sync::Barrier::new(WRITERS));
    let handles: Vec<_> = (0..WRITERS)
        .map(|i| {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = file_store(&root);
                barrier.wait();
                store.put_grant(grant(&format!("g{i}"), ControlPlaneGrantStatus::Requested))
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap().expect("a locked write never fails");
    }
    let mut ids: Vec<String> = file_store(&root)
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
