// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

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
    // repair lock. This is exactly the MIK-6750 r7 Defect 1 race: without
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
    // with DIFFERENT ids at once (MIK-6750 r7, Defect 1).
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
    // deterministically, without exhausting real disk space (MIK-6750
    // r8, minor -- Defect 3: the write path used to return early via `?`
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

// =========================================================================
// TokenInfo::from_response
// =========================================================================

#[test]
fn test_token_expiry() {
    // Token that expires in 1 hour
    let token = TokenInfo::from_response("test_token".to_string(), None, None, Some(3600), None);
    assert!(!token.is_expired());

    // Token that expired
    let mut expired = token.clone();
    expired.expires_at = Some(0);
    assert!(expired.is_expired());
}

#[test]
fn debug_redacts_secret_fields() {
    // The manual `Debug` impl must never leak the access token, refresh
    // token, or client secret into logs / traces / error context.
    let token = TokenInfo {
        access_token: "ACCESS-SECRET-VALUE".to_string(),
        token_type: "Bearer".to_string(),
        refresh_token: Some("REFRESH-SECRET-VALUE".to_string()),
        expires_at: Some(4_102_444_800),
        scope: Some("read write".to_string()),
        token_endpoint: Some("https://idp.example/token".to_string()),
        client_id: Some("public-client-id".to_string()),
        client_secret: Some("CLIENT-SECRET-VALUE".to_string()),
    };

    let dbg = format!("{token:?}");
    for secret in [
        "ACCESS-SECRET-VALUE",
        "REFRESH-SECRET-VALUE",
        "CLIENT-SECRET-VALUE",
    ] {
        assert!(!dbg.contains(secret), "Debug leaked secret {secret}: {dbg}");
    }
    assert!(
        dbg.contains("<redacted>"),
        "expected redaction marker: {dbg}"
    );
    // Non-secret metadata remains visible for diagnostics.
    assert!(dbg.contains("Bearer"), "token_type should stay visible");
    assert!(
        dbg.contains("public-client-id"),
        "client_id is not a secret"
    );
}

#[test]
fn test_token_no_expiry() {
    let token = TokenInfo::from_response("test_token".to_string(), None, None, None, None);
    assert!(!token.is_expired());
}

#[test]
fn from_response_sets_default_token_type() {
    let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
    assert_eq!(token.token_type, "Bearer");
}

#[test]
fn from_response_preserves_custom_token_type() {
    let token =
        TokenInfo::from_response("tok".to_string(), Some("MAC".to_string()), None, None, None);
    assert_eq!(token.token_type, "MAC");
}

#[test]
fn from_response_stores_refresh_token() {
    let token = TokenInfo::from_response(
        "access".to_string(),
        None,
        Some("refresh_123".to_string()),
        None,
        None,
    );
    assert_eq!(token.refresh_token, Some("refresh_123".to_string()));
}

#[test]
fn from_response_calculates_expiry() {
    let token = TokenInfo::from_response("tok".to_string(), None, None, Some(3600), None);
    assert!(token.expires_at.is_some());
    // Should be roughly now + 3600
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let diff = token.expires_at.unwrap() - now;
    assert!((3598..=3602).contains(&diff)); // allow 2 sec slack
}

#[test]
fn from_response_no_expiry_when_none() {
    let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
    assert!(token.expires_at.is_none());
}

#[test]
fn from_response_stores_scope() {
    let token = TokenInfo::from_response(
        "tok".to_string(),
        None,
        None,
        None,
        Some("read write".to_string()),
    );
    assert_eq!(token.scope, Some("read write".to_string()));
}

// =========================================================================
// TokenInfo::is_expired
// =========================================================================

#[test]
fn is_expired_with_60_second_buffer() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Token that "expires" in 30 seconds - within 60s buffer, so treated as expired
    let token = TokenInfo {
        expires_at: Some(now + 30),
        ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
    };
    assert!(token.is_expired());
}

#[test]
fn is_not_expired_beyond_buffer() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Token expires in 120 seconds - well beyond 60s buffer
    let token = TokenInfo {
        expires_at: Some(now + 120),
        ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
    };
    assert!(!token.is_expired());
}

// =========================================================================
// TokenInfo::time_until_expiry
// =========================================================================

#[test]
fn time_until_expiry_future_token() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = TokenInfo {
        expires_at: Some(now + 3600),
        ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
    };
    let ttl = token.time_until_expiry().unwrap();
    assert!(ttl.as_secs() >= 3598 && ttl.as_secs() <= 3601);
}

#[test]
fn time_until_expiry_expired_token() {
    let token = TokenInfo {
        expires_at: Some(0), // long expired
        ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
    };
    assert!(token.time_until_expiry().is_none());
}

#[test]
fn time_until_expiry_no_expiry() {
    let token = TokenInfo {
        expires_at: None,
        ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
    };
    assert!(token.time_until_expiry().is_none());
}

// =========================================================================
// TokenInfo serialization roundtrip
// =========================================================================

#[test]
fn token_info_serialization_roundtrip() {
    let original = TokenInfo::from_response(
        "access_token_xyz".to_string(),
        Some("Bearer".to_string()),
        Some("refresh_abc".to_string()),
        Some(7200),
        Some("read write".to_string()),
    );
    let json = serde_json::to_string(&original).unwrap();
    let restored: TokenInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.access_token, original.access_token);
    assert_eq!(restored.token_type, original.token_type);
    assert_eq!(restored.refresh_token, original.refresh_token);
    assert_eq!(restored.expires_at, original.expires_at);
    assert_eq!(restored.scope, original.scope);
}

// =========================================================================
// TokenStorage - storage_key
// =========================================================================

#[test]
fn storage_key_is_deterministic() {
    let k1 = TokenStorage::storage_key("backend1", "http://localhost");
    let k2 = TokenStorage::storage_key("backend1", "http://localhost");
    assert_eq!(k1, k2);
}

#[test]
fn storage_key_differs_for_different_inputs() {
    let k1 = TokenStorage::storage_key("backend1", "http://localhost");
    let k2 = TokenStorage::storage_key("backend2", "http://localhost");
    let k3 = TokenStorage::storage_key("backend1", "http://other");
    assert_ne!(k1, k2);
    assert_ne!(k1, k3);
}

#[test]
fn storage_key_has_expected_length() {
    let key = TokenStorage::storage_key("test", "http://example.com");
    assert_eq!(key.len(), 16); // first 16 hex chars of SHA256
}

// =========================================================================
// TokenStorage - save/load/delete roundtrip
// =========================================================================

#[test]
fn storage_save_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();

    let token = TokenInfo::from_response(
        "my_access_token".to_string(),
        Some("Bearer".to_string()),
        Some("my_refresh".to_string()),
        Some(3600),
        Some("read".to_string()),
    );

    storage
        .save("mybackend", "http://localhost:8080", &token)
        .unwrap();

    let loaded = storage.load("mybackend", "http://localhost:8080").unwrap();
    assert_eq!(loaded.access_token, "my_access_token");
    assert_eq!(loaded.refresh_token, Some("my_refresh".to_string()));
}

#[test]
fn storage_load_nonexistent_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    assert!(storage.load("nonexistent", "http://localhost").is_none());
}

#[test]
fn storage_delete_removes_token() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();

    let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
    storage.save("backend", "http://localhost", &token).unwrap();
    assert!(storage.load("backend", "http://localhost").is_some());

    storage.delete("backend", "http://localhost").unwrap();
    assert!(storage.load("backend", "http://localhost").is_none());
}

#[test]
fn storage_delete_nonexistent_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    // Should not error when deleting non-existent token
    storage
        .delete("no_such_backend", "http://localhost")
        .unwrap();
}

#[test]
fn storage_overwrite_updates_token() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();

    let token1 = TokenInfo::from_response("token_v1".to_string(), None, None, None, None);
    storage
        .save("backend", "http://localhost", &token1)
        .unwrap();

    let token2 = TokenInfo::from_response("token_v2".to_string(), None, None, None, None);
    storage
        .save("backend", "http://localhost", &token2)
        .unwrap();

    let loaded = storage.load("backend", "http://localhost").unwrap();
    assert_eq!(loaded.access_token, "token_v2");
}

#[test]
fn storage_creates_directory_if_missing() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("deeply").join("nested").join("oauth");
    let storage = TokenStorage::new(nested).unwrap();

    let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
    storage.save("b", "http://localhost", &token).unwrap();
    assert!(storage.load("b", "http://localhost").is_some());
}

/// The token file is REPLACED, never written into whatever already sits at
/// that path (Decision D, `docs/design/unauthenticated-network-posture.md`).
///
/// `fs::write` followed by `set_permissions` puts the access token inside a
/// file created at the process umask, or inside an existing file whose mode
/// somebody else chose, and only then tightens it. The secret is readable
/// for the whole write. A fresh inode is the observable proof that the
/// bytes never entered the old file: `rename` gives the destination the
/// scratch file's identity, an in-place write keeps the old one.
// Unix-only: compares (dev, ino) file identity via MetadataExt, which Windows std metadata does not expose.
#[cfg(unix)]
#[test]
fn saving_a_token_replaces_the_file_rather_than_writing_into_it() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let path = storage.token_path("b", "http://localhost");

    // A world-readable file already at the destination: a token left by an
    // older build, or a path an operator created.
    fs::write(&path, "{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let before = fs::metadata(&path).unwrap().ino();

    let token = TokenInfo::from_response("secret-token".to_string(), None, None, None, None);
    storage.save("b", "http://localhost", &token).unwrap();

    let after = fs::metadata(&path).unwrap();
    assert_ne!(
        before,
        after.ino(),
        "the token was written into the pre-existing world-readable file"
    );
    assert_eq!(
        after.permissions().mode() & 0o777,
        0o600,
        "the token file must be owner-only"
    );
}

/// MIK-8344: the async save gives up on a repair lock another process never
/// releases, at its bound, and leaves the final and no temp file behind.
#[tokio::test]
async fn a_polled_save_gives_up_on_a_held_repair_lock_at_its_bound() {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStorage::new(dir.path().to_path_buf()).expect("create store");
    let (backend, resource) = ("held", "http://127.0.0.1:1/mcp");
    let path = store.client_path(backend, resource);
    std::fs::write(&path, "not json").unwrap();
    let _held =
        crate::fs_lock::ExclusiveFileLock::acquire(&store.client_lock_path(backend, resource))
            .expect("another process holds the repair lock");

    let saved = store
        .save_client_id_polled(backend, resource, "ours", Duration::from_millis(200))
        .await;

    assert!(
        matches!(&saved, Err(Error::OAuth(m)) if m.contains("still held")),
        "{saved:?}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| name.contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}
