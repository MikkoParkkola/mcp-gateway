// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use std::thread;

// ── Helpers ───────────────────────────────────────────────────────────────

fn make_signer() -> MessageSigner {
    MessageSigner::new(
        b"a-test-secret-that-is-at-least-32-bytes-long!!".to_vec(),
        None,
        "test".to_string(),
    )
}

#[test]
fn debug_output_redacts_signing_secret() {
    // CWE-532 / MIK-6733 sibling: {:?} must never leak the HMAC secret.
    let signer = make_signer();
    let dbg = format!("{signer:?}");
    assert!(
        !dbg.contains("a-test-secret-that-is-at-least-32-bytes-long"),
        "Debug leaked the signing secret: {dbg}"
    );
    assert!(
        dbg.contains("<redacted>"),
        "expected redaction marker: {dbg}"
    );
    assert!(dbg.contains("test"), "key_id should remain visible");
}

// ── NonceStore ────────────────────────────────────────────────────────────

#[test]
fn nonce_store_accepts_fresh_nonce() {
    // GIVEN: an empty nonce store
    let store = NonceStore::new(Duration::from_secs(300));

    // WHEN: registering a new nonce
    // THEN: succeeds
    store
        .check_and_register("nonce-1")
        .expect("fresh nonce must be accepted");
}

#[test]
fn nonce_store_rejects_replayed_nonce() {
    // GIVEN: a store that has already seen a nonce
    let store = NonceStore::new(Duration::from_secs(300));
    store.check_and_register("nonce-replay").unwrap();

    // WHEN: the same nonce arrives again within the window
    let err = store
        .check_and_register("nonce-replay")
        .expect_err("replay must be rejected");

    // THEN: error code -32001
    assert!(
        matches!(err, Error::JsonRpc { code: -32001, .. }),
        "expected -32001, got {err:?}"
    );
}

#[test]
fn nonce_store_accepts_different_nonces_independently() {
    // GIVEN: a nonce store
    let store = NonceStore::new(Duration::from_secs(300));

    // WHEN: two distinct nonces are registered
    // THEN: both succeed
    store.check_and_register("n1").unwrap();
    store.check_and_register("n2").unwrap();
    assert_eq!(store.len(), 2);
}

#[test]
fn nonce_store_accepts_nonce_after_window_expiry() {
    // GIVEN: a store with an immediate expiry window
    let store = NonceStore::new(Duration::ZERO);
    store.check_and_register("n-expire").unwrap();

    // WHEN: the same nonce is presented after the window (elapsed > 0)
    // THEN: accepted (window is zero, so elapsed > window immediately)
    store
        .check_and_register("n-expire")
        .expect("nonce past TTL must be accepted");
}

#[test]
fn nonce_store_evict_expired_removes_old_entries() {
    // GIVEN: two real live entries admitted under a frozen monotonic clock.
    // Admission now reclaims elapsed entries immediately, so a zero-window
    // fixture cannot retain both until the explicit eviction under test.
    let store = NonceStore::with_clock_for_test(2, 2);
    store.check_and_register("old-1").unwrap();
    store.check_and_register("old-2").unwrap();
    assert_eq!(store.len(), 2);

    // WHEN: both entries expire and explicit eviction runs.
    store.advance_for_test(301);
    store.evict_expired();

    // THEN: all entries removed
    assert_eq!(store.len(), 0, "all elapsed entries must be evicted");
}

#[test]
fn nonce_store_evict_preserves_live_entries() {
    // GIVEN: a store with a long window containing two nonces
    let store = NonceStore::new(Duration::from_secs(3600));
    store.check_and_register("live-1").unwrap();
    store.check_and_register("live-2").unwrap();

    // WHEN: evict_expired is called
    store.evict_expired();

    // THEN: live entries are preserved
    assert_eq!(store.len(), 2, "live entries must not be evicted");
}

#[test]
fn nonce_store_is_thread_safe() {
    // GIVEN: a shared nonce store
    let store = Arc::new(NonceStore::new(Duration::from_secs(300)));
    let handles: Vec<_> = (0..20)
        .map(|i| {
            let s = Arc::clone(&store);
            thread::spawn(move || {
                s.check_and_register(&format!("thread-nonce-{i}")).unwrap();
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    assert_eq!(store.len(), 20);
}

// ── validate_secret ───────────────────────────────────────────────────────

#[test]
fn validate_secret_accepts_32_byte_secret() {
    // GIVEN: exactly 32 bytes
    let secret = [0u8; 32];
    // WHEN/THEN: no error
    validate_secret(&secret).expect("32-byte secret must be valid");
}

#[test]
fn validate_secret_accepts_longer_secret() {
    let secret = [0u8; 64];
    validate_secret(&secret).expect("64-byte secret must be valid");
}

#[test]
fn validate_secret_rejects_short_secret() {
    // GIVEN: 16-byte secret (below threshold)
    let secret = [0u8; 16];
    // WHEN/THEN: ConfigValidation error
    let err = validate_secret(&secret).expect_err("short secret must be rejected");
    assert!(matches!(err, Error::ConfigValidation(_)));
}

#[test]
fn validate_secret_rejects_empty_secret() {
    let err = validate_secret(&[]).expect_err("empty secret must be rejected");
    assert!(matches!(err, Error::ConfigValidation(_)));
}

// ── Cleanup task (tokio) ──────────────────────────────────────────────────

#[tokio::test]
async fn spawn_nonce_cleanup_task_evicts_expired() {
    // GIVEN: a store with zero-window entries
    let store = Arc::new(NonceStore::new(Duration::ZERO));
    store.check_and_register("task-nonce").unwrap();
    assert_eq!(store.len(), 1);

    // WHEN: cleanup task runs
    spawn_nonce_cleanup_task(Arc::clone(&store), Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // THEN: entry evicted
    assert_eq!(store.len(), 0, "cleanup task must evict expired nonces");
}
