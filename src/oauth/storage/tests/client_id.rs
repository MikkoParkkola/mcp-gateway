// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Client-id storage: save, load, delete, first-writer-wins and self-heal.

#[cfg(windows)]
use super::TokenInfo;
use super::{PathBuf, TokenStorage, fs};

#[test]
fn client_id_round_trips_and_is_absent_before_registration() {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStorage::new(dir.path().to_path_buf()).expect("create store");
    let (backend, resource) = ("beeper", "http://127.0.0.1:23373/v0/mcp");

    // No client registered yet -> None (would trigger DCR + browser tab).
    assert_eq!(store.load_client_id(backend, resource), None);

    // Persist then reload -> stable id, so the next connection reuses it.
    let persisted = store
        .save_client_id(backend, resource, "persisted-client-123")
        .expect("save client_id");
    assert_eq!(persisted, "persisted-client-123");
    assert_eq!(
        store.load_client_id(backend, resource),
        Some("persisted-client-123".to_string())
    );

    // A different backend must not collide.
    assert_eq!(store.load_client_id("other", resource), None);
}

// POSIX mode bits: asserts 0600 owner-only; Windows enforces owner-only through DACLs (win_acl).
#[cfg(unix)]
#[test]
fn save_client_id_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let (backend, resource) = ("b", "http://localhost");

    store.save_client_id(backend, resource, "cid").unwrap();
    let path = store.client_path(backend, resource);
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "client_id file must be owner-only, got {mode:o}"
    );
}

#[cfg(windows)]
#[test]
fn saved_token_and_client_id_are_owner_only_in_an_open_directory() {
    // WT-ASSERT 1718-W2: both writers create their scratch file private.
    use crate::private_fs::test_support::{assert_owner_only, everyone_full_dir};
    let dir = everyone_full_dir("1718-W2");
    let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let (backend, resource) = ("b", "http://localhost");
    let token = TokenInfo::from_response("tok".into(), None, None, None, None);

    store.save(backend, resource, &token).unwrap();
    store.save_client_id(backend, resource, "cid").unwrap();

    // Relies on `create_file_private(.., Share::Exclusive)`: owner-only from creation, not repaired after.
    assert_owner_only("1718-W2 token", &store.token_path(backend, resource), false);
    assert_owner_only(
        "1718-W2 client",
        &store.client_path(backend, resource),
        false,
    );
}

#[test]
fn save_client_id_is_first_writer_wins() {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let (backend, resource) = ("b", "http://localhost");

    // First write wins and is returned verbatim.
    assert_eq!(
        store.save_client_id(backend, resource, "first").unwrap(),
        "first"
    );
    // A concurrent second write does NOT clobber; it adopts the existing id.
    assert_eq!(
        store.save_client_id(backend, resource, "second").unwrap(),
        "first"
    );
    assert_eq!(
        store.load_client_id(backend, resource),
        Some("first".to_string())
    );

    // After deletion, the next write wins again (re-registration path).
    store.delete_client_id(backend, resource).unwrap();
    assert_eq!(store.load_client_id(backend, resource), None);
    assert_eq!(
        store.save_client_id(backend, resource, "third").unwrap(),
        "third"
    );
}

#[test]
fn delete_client_id_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    // Deleting a non-existent record is a no-op, not an error.
    store.delete_client_id("nope", "http://localhost").unwrap();
}

#[test]
fn save_client_id_concurrent_same_backend_converges() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let (backend, resource) = ("b", "http://localhost");

    // Many threads register distinct ids for the SAME backend at once.
    let barrier = Arc::new(std::sync::Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .save_client_id(backend, resource, &format!("cid-{i}"))
                    .expect("save")
            })
        })
        .collect();
    let returned: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Every caller must observe the SAME authoritative id (first wins), and
    // it must match what is on disk.
    let on_disk = store.load_client_id(backend, resource).expect("persisted");
    assert!(
        returned.iter().all(|r| *r == on_disk),
        "callers disagreed with disk: returned={returned:?} disk={on_disk}"
    );

    // No temp files leaked.
    let leaked = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .count();
    assert_eq!(leaked, 0, "temp files leaked");
}

#[test]
fn save_client_id_self_heals_corrupt_final_file() {
    // GIVEN: an existing client_id file whose contents are corrupt
    // (not a valid JSON string), so load_client_id() returns None.
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let (backend, resource) = ("b", "http://localhost");
    let final_path = store.client_path(backend, resource);
    fs::write(&final_path, b"\x00\x00not json at all").unwrap();
    assert_eq!(
        store.load_client_id(backend, resource),
        None,
        "precondition: corrupt file must be unreadable"
    );

    // WHEN: we persist a fresh id over the corrupt file.
    let returned = store
        .save_client_id(backend, resource, "healed-id")
        .expect("self-heal should succeed");

    // THEN: the validated id is authoritative and readable from disk,
    // instead of silently diverging from a broken on-disk record.
    assert_eq!(returned, "healed-id");
    assert_eq!(
        store.load_client_id(backend, resource),
        Some("healed-id".to_string()),
        "disk must match the returned id after self-heal"
    );
}

#[test]
fn save_client_id_self_heals_zero_byte_final_file() {
    // GIVEN: a zero-byte final file (empty => not a valid JSON string).
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let (backend, resource) = ("b", "http://localhost");
    fs::write(store.client_path(backend, resource), b"").unwrap();

    // WHEN / THEN: save self-heals and returns a readable id.
    let returned = store.save_client_id(backend, resource, "cid").unwrap();
    assert_eq!(returned, "cid");
    assert_eq!(
        store.load_client_id(backend, resource),
        Some("cid".to_string())
    );
}

#[test]
fn repair_corrupt_final_adopts_valid_final_without_removing_it() {
    // GIVEN: the final file was corrupt when the *caller* first checked
    // it, but has since become valid — as if another process repaired it
    // between the caller's unlocked read and this call acquiring the
    // repair lock. This is exactly the review's Defect 1 race: without
    // a re-read-under-lock guard, this call would remove the other
    // repairer's freshly-written valid file and overwrite it with our
    // own, so a caller that already adopted "winner-id" would diverge
    // from what ends up on disk.
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let (backend, resource) = ("b", "http://localhost");
    let path = store.client_path(backend, resource);

    // The final is now VALID (as if another process just healed it).
    fs::write(&path, serde_json::to_string("winner-id").unwrap()).unwrap();

    // Our own (in this scenario, redundant) validated temp.
    let tmp = dir.path().join("our.tmp");
    fs::write(&tmp, serde_json::to_string("our-id").unwrap()).unwrap();

    // WHEN: we attempt to repair what we believed (from a stale read)
    // was corrupt.
    let held =
        crate::fs_lock::ExclusiveFileLock::acquire(&store.client_lock_path(backend, resource))
            .expect("repair lock");
    let result = store.repair_corrupt_final(backend, resource, &path, &tmp, "our-id", &held);

    // THEN: we adopt the winner instead of overwriting it...
    assert_eq!(result.unwrap(), "winner-id");
    // ...and the final file was never removed/replaced.
    assert_eq!(
        store.load_client_id(backend, resource),
        Some("winner-id".to_string()),
        "a final that became valid under the lock must never be removed"
    );
}

#[test]
fn save_client_id_self_heal_converges_under_thread_contention() {
    // GIVEN: a corrupt final, and many threads racing to self-heal it
    // with DIFFERENT ids at once (Defect 1).
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let (backend, resource) = ("b", "http://localhost");
    fs::write(store.client_path(backend, resource), b"\x00corrupt").unwrap();

    let barrier = Arc::new(std::sync::Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .save_client_id(backend, resource, &format!("heal-{i}"))
                    .expect("self-heal save")
            })
        })
        .collect();
    let returned: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // THEN: every caller converged on the SAME id, and it matches disk —
    // the advisory lock serializes repair so no two threads can diverge.
    let on_disk = store
        .load_client_id(backend, resource)
        .expect("healed and persisted");
    assert!(
        returned.iter().all(|r| *r == on_disk),
        "callers disagreed with disk after self-heal race: returned={returned:?} disk={on_disk}"
    );
}

#[test]
fn write_secret_tmp_removes_leaked_temp_on_write_failure() {
    // GIVEN: a temp file opened read-only, so writing through it fails
    // with EBADF -- simulating a real write/fsync failure (ENOSPC, EIO)
    // deterministically, without exhausting real disk space (minor
    // -- Defect 3: the write path used to return early via `?`
    // on failure without removing the temp, leaking a private 0600 file
    // under `base_dir` on every such error).
    let dir = tempfile::tempdir().unwrap();
    let tmp_path = dir.path().join("client.tmp.leak-check");
    // Create the file first (needs write access to create), then close
    // and reopen it read-only so the fd we hand to `write_secret_tmp`
    // has no write access at all.
    fs::File::create(&tmp_path).unwrap();
    let file = fs::OpenOptions::new().read(true).open(&tmp_path).unwrap();
    assert!(
        tmp_path.exists(),
        "precondition: temp file exists before the write attempt"
    );

    // WHEN: the write fails (the fd has no write permission).
    let result = TokenStorage::write_secret_tmp((file, tmp_path.clone()), "some-content");

    // THEN: the error propagates AND the temp file is gone -- nothing is
    // left behind on disk for an operator to notice weeks later.
    assert!(
        result.is_err(),
        "expected the write to fail on a read-only fd"
    );
    assert!(
        !tmp_path.exists(),
        "temp file must be removed when the write/fsync fails, not leaked"
    );
}

#[test]
fn save_client_id_never_truncates_a_leftover_tmp() {
    // GIVEN: leftover temp files (as if a prior run crashed mid-write),
    // seeded with sentinel content. O_EXCL create_new must never open —
    // and therefore never truncate — an existing path, whether or not the
    // nonce collides with one the writer picks.
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let (backend, resource) = ("b", "http://localhost");

    let file_name = store
        .client_path(backend, resource)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap()
        .to_string();
    let sentinel = b"DO-NOT-TRUNCATE";
    let leftovers: Vec<PathBuf> = (0..4)
        .map(|n| {
            let p = dir
                .path()
                .join(format!("{file_name}.tmp.{}.{n}", std::process::id()));
            fs::write(&p, sentinel).unwrap();
            p
        })
        .collect();

    // WHEN: we persist a client_id.
    let returned = store.save_client_id(backend, resource, "safe-id").unwrap();

    // THEN: the save produced a valid, readable authoritative id...
    assert_eq!(returned, "safe-id");
    assert_eq!(
        store.load_client_id(backend, resource),
        Some("safe-id".to_string())
    );
    // ...and every seeded leftover is byte-for-byte intact (never emptied).
    for p in &leftovers {
        assert_eq!(
            fs::read(p).unwrap(),
            sentinel,
            "leftover temp file was truncated/overwritten: {}",
            p.display()
        );
    }
}
