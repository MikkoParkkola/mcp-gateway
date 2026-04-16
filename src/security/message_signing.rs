//! Inter-agent message signing — HMAC-SHA256 response integrity + nonce replay protection.
//!
//! Implements ADR-001: application-layer message authentication independent of TLS,
//! addressing OWASP ASI07 (Insecure Inter-Agent Communication).
//!
//! # Design
//!
//! - **Response signing**: every `gateway_invoke` response gains a `_signature` block
//!   containing `alg`, `sig`, `nonce`, `ts`, and `key_id`. The MAC covers
//!   `canonical_json(response_without_signature)`.
//! - **Nonce replay protection**: request nonces are checked against a
//!   `DashMap<String, Instant>` with TTL-based eviction, mirroring `src/idempotency.rs`.
//! - **Opt-in**: the whole subsystem is gated by `SecurityConfig::message_signing.enabled`.
//!   When disabled, zero extra allocations occur on the hot path.
//! - **Key rotation**: up to two active secrets (`shared_secret` + `previous_secret`).
//!   Current key is tried first; previous key allows seamless rotation windows.
//!
//! # OWASP Reference
//!
//! ASI07 threats mitigated:
//! 1. **Message injection** — HMAC verifies the gateway produced the response.
//! 2. **Message tampering** — MAC covers the entire canonical response body.
//! 3. **Replay attacks** — monotonic nonces rejected within the replay window.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use tracing::debug;

use crate::hashing::canonical_json;
use crate::{Error, Result};

// ── Type alias ───────────────────────────────────────────────────────────────

type HmacSha256 = Hmac<Sha256>;

// ── Constants ────────────────────────────────────────────────────────────────

/// Minimum secret length enforced at startup (32 bytes = 256 bits).
pub const MIN_SECRET_BYTES: usize = 32;

/// Background eviction interval for the nonce store.
pub const EVICTION_INTERVAL: Duration = Duration::from_secs(60);

// ── MessageSigner ────────────────────────────────────────────────────────────

/// Signs `gateway_invoke` responses with HMAC-SHA256.
///
/// Holds the active signing secret and an optional previous secret for
/// zero-downtime rotation. Thread-safe: wrap in `Arc` for shared ownership.
///
/// # Example
///
/// ```
/// use mcp_gateway::security::message_signing::MessageSigner;
/// use serde_json::json;
///
/// let secret = b"a-secret-that-is-at-least-32-bytes-long!!";
/// let signer = MessageSigner::new(secret.to_vec(), None, "v1".to_string());
/// let response = json!({"content": [{"type": "text", "text": "hello"}]});
/// let signed = signer.sign_response(response, Some("nonce-42"));
/// assert!(signed.get("_signature").is_some());
/// ```
#[derive(Debug, Clone)]
pub struct MessageSigner {
    secret: Vec<u8>,
    /// Retained for zero-downtime rotation; used in future `verify_response()` API.
    #[allow(dead_code)]
    previous_secret: Option<Vec<u8>>,
    key_id: String,
}

impl MessageSigner {
    /// Create a new signer.
    ///
    /// `secret` must be at least [`MIN_SECRET_BYTES`] long; callers must
    /// validate this at config load time via [`validate_secret`].
    #[must_use]
    pub fn new(secret: Vec<u8>, previous_secret: Option<Vec<u8>>, key_id: String) -> Self {
        Self {
            secret,
            previous_secret,
            key_id,
        }
    }

    /// Sign `response`, injecting a `_signature` block.
    ///
    /// The MAC is computed over `canonical_json(response)` **before** the
    /// `_signature` key is inserted, avoiding a circular dependency.
    /// Any pre-existing `_signature` key is removed prior to MAC computation.
    #[must_use]
    pub fn sign_response(&self, mut response: Value, nonce: Option<&str>) -> Value {
        // Remove any stale signature before computing the MAC.
        if let Some(obj) = response.as_object_mut() {
            obj.remove("_signature");
        }

        let canonical = canonical_json(&response);
        let sig = compute_hmac_hex(&self.secret, canonical.as_bytes());
        let ts = unix_timestamp_secs();

        let signature_block = build_signature_block(&sig, nonce, ts, &self.key_id);

        if let Some(obj) = response.as_object_mut() {
            obj.insert("_signature".to_string(), signature_block);
        }

        response
    }
}

// ── NonceStore ───────────────────────────────────────────────────────────────

/// Thread-safe replay-protection nonce store.
///
/// Nonces seen within `replay_window` are rejected; entries older than the
/// window are evicted by [`NonceStore::evict_expired`], which should be called
/// from a background task (see [`spawn_nonce_cleanup_task`]).
///
/// Memory bound: ~2.4 MB at 100 req/s with a 5-minute window (30 K entries × ~80 B).
#[derive(Debug)]
pub struct NonceStore {
    seen: DashMap<String, Instant>,
    replay_window: Duration,
}

impl NonceStore {
    /// Create a new nonce store with the given replay window.
    #[must_use]
    pub fn new(replay_window: Duration) -> Self {
        Self {
            seen: DashMap::new(),
            replay_window,
        }
    }

    /// Check and register `nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::json_rpc`] with code `-32001` when the nonce was
    /// already seen within the replay window (replay attack detected).
    pub fn check_and_register(&self, nonce: &str) -> Result<()> {
        // Check for an existing live entry atomically via DashMap entry API.
        use dashmap::mapref::entry::Entry;
        match self.seen.entry(nonce.to_string()) {
            Entry::Occupied(e) => {
                if e.get().elapsed() <= self.replay_window {
                    return Err(Error::json_rpc(-32001, "Nonce replay detected"));
                }
                // Stale — overwrite with fresh timestamp.
                e.replace_entry(Instant::now());
                Ok(())
            }
            Entry::Vacant(e) => {
                e.insert(Instant::now());
                Ok(())
            }
        }
    }

    /// Evict nonces older than the replay window.
    ///
    /// Called periodically by [`spawn_nonce_cleanup_task`] to bound memory.
    pub fn evict_expired(&self) {
        let stale: Vec<String> = self
            .seen
            .iter()
            .filter_map(|e| {
                (e.value().elapsed() > self.replay_window).then(|| e.key().clone())
            })
            .collect();

        let count = stale.len();
        for key in stale {
            self.seen.remove(&key);
        }
        if count > 0 {
            debug!(count, "Evicted expired nonce entries");
        }
    }

    /// Current number of tracked nonces.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Return `true` when the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ── Background cleanup ───────────────────────────────────────────────────────

/// Spawn a Tokio background task that periodically evicts expired nonces.
///
/// The task stops when the `Arc` reference count drops to 1 (shutdown signal),
/// matching the pattern established by `crate::idempotency::spawn_cleanup_task`.
pub fn spawn_nonce_cleanup_task(store: Arc<NonceStore>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if Arc::strong_count(&store) <= 1 {
                break;
            }
            store.evict_expired();
        }
    });
}

// ── Config validation ────────────────────────────────────────────────────────

/// Validate that `secret` meets the minimum entropy requirement.
///
/// # Errors
///
/// Returns `Err` when the secret is shorter than [`MIN_SECRET_BYTES`].
pub fn validate_secret(secret: &[u8]) -> Result<()> {
    if secret.len() < MIN_SECRET_BYTES {
        return Err(Error::ConfigValidation(format!(
            "message_signing.shared_secret must be at least {MIN_SECRET_BYTES} bytes \
             (got {}). Use a high-entropy random secret.",
            secret.len()
        )));
    }
    Ok(())
}

// ── Private helpers ──────────────────────────────────────────────────────────

fn compute_hmac_hex(secret: &[u8], message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_signature_block(sig: &str, nonce: Option<&str>, ts: u64, key_id: &str) -> Value {
    json!({
        "alg": "hmac-sha256",
        "sig": sig,
        "nonce": nonce,
        "ts": ts,
        "key_id": key_id,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::thread;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_signer() -> MessageSigner {
        MessageSigner::new(
            b"a-test-secret-that-is-at-least-32-bytes-long!!".to_vec(),
            None,
            "test".to_string(),
        )
    }

    // ── sign_response ─────────────────────────────────────────────────────────

    #[test]
    fn sign_response_injects_signature_block() {
        // GIVEN: a signer and a plain response
        let msg_signer = make_signer();
        let response = json!({"content": [{"type": "text", "text": "hello"}]});

        // WHEN: signing
        let out = msg_signer.sign_response(response, None);

        // THEN: _signature block is present with required fields
        let sig_block = out.get("_signature").expect("_signature must be present");
        assert_eq!(sig_block["alg"], "hmac-sha256");
        assert!(sig_block["sig"].as_str().is_some_and(|s| s.len() == 64));
        assert!(sig_block["ts"].as_u64().is_some_and(|t| t > 0));
        assert_eq!(sig_block["key_id"], "test");
    }

    #[test]
    fn sign_response_echoes_nonce_in_signature() {
        // GIVEN: a signer and a nonce
        let msg_signer = make_signer();
        let response = json!({"result": "ok"});

        // WHEN: signing with a nonce
        let out = msg_signer.sign_response(response, Some("nonce-42"));

        // THEN: the nonce is echoed in the _signature block
        let sig_block = out.get("_signature").unwrap();
        assert_eq!(sig_block["nonce"], "nonce-42");
    }

    #[test]
    fn sign_response_removes_existing_signature_before_signing() {
        // GIVEN: a response that already has a stale _signature
        let msg_signer = make_signer();
        let response = json!({"data": "x", "_signature": {"sig": "stale"}});

        // WHEN: signing
        let out = msg_signer.sign_response(response, None);

        // THEN: the new signature is not the stale one
        let sig_block = out.get("_signature").unwrap();
        assert_ne!(sig_block["sig"], "stale");
        assert_eq!(sig_block["alg"], "hmac-sha256");
    }

    #[test]
    fn sign_response_mac_covers_body_without_signature_field() {
        // GIVEN: two identical bodies — both signed with same secret and nonce
        let msg_signer = make_signer();
        let body = json!({"content": "test"});

        // WHEN: signing the same body twice
        let out_a = msg_signer.sign_response(body.clone(), Some("n1"));
        let out_b = msg_signer.sign_response(body.clone(), Some("n1"));

        // THEN: signatures match (deterministic canonical JSON + same secret)
        // NOTE: ts may differ by 1 second in rare cases; compare sig only
        let mac_a = out_a["_signature"]["sig"].as_str().unwrap();
        let mac_b = out_b["_signature"]["sig"].as_str().unwrap();
        assert_eq!(mac_a, mac_b, "MAC over identical bodies must be identical");
    }

    #[test]
    fn sign_response_different_bodies_produce_different_macs() {
        // GIVEN: two different responses
        let msg_signer = make_signer();
        let body_a = json!({"data": "alpha"});
        let body_b = json!({"data": "beta"});

        // WHEN: signing both
        let out_a = msg_signer.sign_response(body_a, None);
        let out_b = msg_signer.sign_response(body_b, None);

        // THEN: MACs differ
        assert_ne!(out_a["_signature"]["sig"], out_b["_signature"]["sig"]);
    }

    #[test]
    fn sign_response_different_secrets_produce_different_macs() {
        // GIVEN: two signers with different secrets
        let signer_a = MessageSigner::new(
            b"secret-one-at-least-32-bytes-long!!!!!".to_vec(),
            None,
            "k1".to_string(),
        );
        let signer_b = MessageSigner::new(
            b"secret-two-at-least-32-bytes-long!!!!!".to_vec(),
            None,
            "k2".to_string(),
        );
        let body = json!({"x": 1});

        // WHEN: both sign the same body
        let out_a = signer_a.sign_response(body.clone(), None);
        let out_b = signer_b.sign_response(body, None);

        // THEN: MACs differ (different secrets)
        assert_ne!(out_a["_signature"]["sig"], out_b["_signature"]["sig"]);
    }

    // ── NonceStore ────────────────────────────────────────────────────────────

    #[test]
    fn nonce_store_accepts_fresh_nonce() {
        // GIVEN: an empty nonce store
        let store = NonceStore::new(Duration::from_secs(300));

        // WHEN: registering a new nonce
        // THEN: succeeds
        store.check_and_register("nonce-1").expect("fresh nonce must be accepted");
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
        // GIVEN: a store with a zero-duration window (all entries expire instantly)
        let store = NonceStore::new(Duration::ZERO);
        store.check_and_register("old-1").unwrap();
        store.check_and_register("old-2").unwrap();
        assert_eq!(store.len(), 2);

        // WHEN: evict_expired is called
        store.evict_expired();

        // THEN: all entries removed
        assert_eq!(store.len(), 0, "all zero-window entries must be evicted");
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
}
