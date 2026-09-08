// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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
//! - **Nonce replay protection**: bounded nonce entries, per-principal counts,
//!   and a monotonic expiry queue share one lock for registration and cleanup.
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

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use parking_lot::Mutex;
use serde_json::{Value, json};
use sha2::Sha256;
use tracing::debug;

use crate::hashing::canonical_json;
use crate::{Error, Result};

#[path = "message_signing_v2.rs"]
mod v2;

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
#[derive(Clone)]
pub struct MessageSigner {
    secret: Vec<u8>,
    /// Retained for zero-downtime rotation; used in future `verify_response()` API.
    #[allow(dead_code)]
    previous_secret: Option<Vec<u8>>,
    key_id: String,
}

// Manual `Debug` that redacts the HMAC signing secret (CWE-532, mirrors MIK-6733).
// A derived `Debug` would print the raw signing material — leaking it lets an
// attacker forge signed responses. Only the key id is shown.
impl std::fmt::Debug for MessageSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSigner")
            .field("secret", &"<redacted>")
            .field(
                "previous_secret",
                &self.previous_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("key_id", &self.key_id)
            .finish()
    }
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
/// At most 100,000 live entries globally and 10,000 per principal. A nonce is
/// at most 256 UTF-8 bytes. Capacity never evicts live replay protection.
pub struct NonceStore {
    state: Mutex<NonceState>,
    replay_window: Duration,
    global_limit: usize,
    principal_limit: usize,
    #[cfg(test)]
    admission_pause: Option<nonce_tests::AdmissionPause>,
    #[cfg(test)]
    cleanup_pause: Option<nonce_tests::CleanupPause>,
    #[cfg(test)]
    test_clock: Option<nonce_tests::TestClock>,
}

#[derive(Default)]
struct NonceState {
    seen: HashMap<String, NonceEntry>,
    principal_counts: HashMap<String, usize>,
    // Admission obtains its monotonic timestamp under the same lock, so the
    // queue is ordered without a sort or a scan of live replay entries.
    expiries: VecDeque<(Instant, String)>,
}

struct NonceEntry {
    admitted_at: Instant,
    principal: String,
}

impl std::fmt::Debug for NonceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceStore")
            .field("live_entries", &self.len())
            .field("replay_window", &self.replay_window)
            .field("global_limit", &self.global_limit)
            .field("principal_limit", &self.principal_limit)
            .finish_non_exhaustive()
    }
}

// ── Nonce telemetry ──────────────────────────────────────────────────────────
//
// Two series, and deliberately nothing else. `reason` is the only label a
// refusal carries: a nonce, a principal or a digest attached here would
// republish through the metrics endpoint exactly what `QuotaPrincipal` and the
// `Debug` impls above exist to keep opaque, and a scrape target is read by more
// systems than a log is.

/// Bounded refusal reasons. Closed set: a new one is a deliberate cardinality
/// decision, not something a caller can introduce.
pub(crate) const NONCE_REASON_INVALID: &str = "invalid";
const NONCE_REASON_REPLAY: &str = "replay";
const NONCE_REASON_PRINCIPAL_CAPACITY: &str = "principal_capacity";
const NONCE_REASON_GLOBAL_CAPACITY: &str = "global_capacity";

/// Count one refused admission.
///
/// Crate-visible because the `gateway_invoke` boundary refuses a malformed raw
/// nonce before this store ever sees it, and that refusal belongs in the same
/// series — an operator watching two counters for one condition watches neither.
#[cfg(feature = "metrics")]
pub(crate) fn record_nonce_rejection(reason: &'static str) {
    telemetry_metrics::counter!("mcp_message_signing_nonce_rejections_total", "reason" => reason)
        .increment(1);
}

#[cfg(not(feature = "metrics"))]
#[inline]
pub(crate) fn record_nonce_rejection(_reason: &'static str) {}

/// Publish the aggregate live-entry count. No labels: occupancy is a property of
/// the store, not of any caller.
///
/// Callers MUST hold the state guard. An observation taken after releasing it
/// can be published out of order and leave a reader looking at a number a
/// concurrent operation has already superseded, with nothing to correct it.
#[cfg(feature = "metrics")]
fn publish_nonce_occupancy(state: &NonceState) {
    // Saturating rather than lossy: the global bound is 100_000, so the
    // conversion is exact in practice and a future bound cannot silently round.
    let live = u32::try_from(state.seen.len()).unwrap_or(u32::MAX);
    telemetry_metrics::gauge!("mcp_message_signing_nonce_entries").set(f64::from(live));
}

#[cfg(not(feature = "metrics"))]
#[inline]
fn publish_nonce_occupancy(_state: &NonceState) {}

impl NonceStore {
    /// Create a new nonce store with the given replay window.
    #[must_use]
    pub fn new(replay_window: Duration) -> Self {
        Self::with_limits(replay_window, 100_000, 10_000)
    }

    fn with_limits(replay_window: Duration, global_limit: usize, principal_limit: usize) -> Self {
        Self {
            state: Mutex::new(NonceState::default()),
            replay_window,
            global_limit,
            principal_limit,
            #[cfg(test)]
            admission_pause: None,
            #[cfg(test)]
            cleanup_pause: None,
            #[cfg(test)]
            test_clock: None,
        }
    }

    /// Check and register `nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::json_rpc`] with code `-32001` when the nonce was
    /// already seen within the replay window (replay attack detected).
    pub fn check_and_register(&self, nonce: &str) -> Result<()> {
        self.check_and_register_for_principal(nonce, "anonymous")
    }

    /// The principal must come from the authenticated transport, never request
    /// arguments or display labels. Nonce uniqueness is global across callers.
    pub(crate) fn check_and_register_for_principal(
        &self,
        nonce: &str,
        principal: &str,
    ) -> Result<()> {
        if nonce.is_empty() || nonce.len() > 256 {
            // Decided before the lock, so there is no occupancy to publish: the
            // store has not been consulted and cannot have changed.
            record_nonce_rejection(NONCE_REASON_INVALID);
            return Err(Error::json_rpc(-32602, "Invalid signing nonce"));
        }
        let mut state = self.state.lock();
        #[cfg(test)]
        self.pause_inside_admission_for_test(nonce);
        #[cfg(test)]
        let now = self.now();
        #[cfg(not(test))]
        let now = Instant::now();
        self.reclaim_expired(&mut state, now);
        // Every exit below publishes before releasing the guard: reclamation
        // above may already have moved the aggregate, so even a refusal leaves a
        // number a reader would otherwise never see corrected.
        if state.seen.contains_key(nonce) {
            record_nonce_rejection(NONCE_REASON_REPLAY);
            publish_nonce_occupancy(&state);
            return Err(Error::json_rpc(-32001, "Nonce replay detected"));
        }
        // The combined condition is split only so the two capacity refusals can
        // be told apart in telemetry. Order and error are unchanged: global is
        // still tested first, and both still refuse with the same message.
        if state.seen.len() >= self.global_limit {
            record_nonce_rejection(NONCE_REASON_GLOBAL_CAPACITY);
            publish_nonce_occupancy(&state);
            return Err(Error::json_rpc(-32001, "Signing nonce capacity exceeded"));
        }
        if state.principal_counts.get(principal).copied().unwrap_or(0) >= self.principal_limit {
            record_nonce_rejection(NONCE_REASON_PRINCIPAL_CAPACITY);
            publish_nonce_occupancy(&state);
            return Err(Error::json_rpc(-32001, "Signing nonce capacity exceeded"));
        }
        state.seen.insert(
            nonce.to_owned(),
            NonceEntry {
                admitted_at: now,
                principal: principal.to_owned(),
            },
        );
        *state
            .principal_counts
            .entry(principal.to_owned())
            .or_default() += 1;
        state.expiries.push_back((now, nonce.to_owned()));
        publish_nonce_occupancy(&state);
        Ok(())
    }

    /// Evict nonces older than the replay window.
    ///
    /// Called periodically by [`spawn_nonce_cleanup_task`] to bound memory.
    pub fn evict_expired(&self) {
        let mut state = self.state.lock();
        #[cfg(test)]
        let now = self.now();
        #[cfg(not(test))]
        let now = Instant::now();
        #[cfg(test)]
        if state
            .expiries
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > self.replay_window)
        {
            self.pause_cleanup_after_selection_for_test();
        }
        let before = state.seen.len();
        self.reclaim_expired(&mut state, now);
        let count = before - state.seen.len();
        publish_nonce_occupancy(&state);
        if count > 0 {
            debug!(count, "Evicted expired nonce entries");
        }
    }

    fn reclaim_expired(&self, state: &mut NonceState, now: Instant) {
        while state
            .expiries
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > self.replay_window)
        {
            let (at, nonce) = state.expiries.pop_front().expect("elapsed queue head");
            if state
                .seen
                .get(&nonce)
                .is_none_or(|entry| entry.admitted_at != at)
            {
                continue;
            }
            let entry = state
                .seen
                .remove(&nonce)
                .expect("matching live nonce entry");
            if let Some(count) = state.principal_counts.get_mut(&entry.principal) {
                *count -= 1;
                if *count == 0 {
                    state.principal_counts.remove(&entry.principal);
                }
            }
        }
    }

    #[cfg(test)]
    fn now(&self) -> Instant {
        if let Some(clock) = &self.test_clock {
            return clock.now();
        }
        Instant::now()
    }

    /// Current number of tracked nonces.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().seen.len()
    }

    /// Return `true` when the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state.lock().seen.is_empty()
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
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
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
#[path = "message_signing_v2_tests.rs"]
mod v2_tests;

#[cfg(test)]
#[path = "message_signing_nonce_tests.rs"]
mod nonce_tests;

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
}

#[cfg(all(test, feature = "metrics"))]
#[path = "message_signing_nonce_metrics_support.rs"]
pub(crate) mod nonce_metrics_support;

#[cfg(all(test, feature = "metrics"))]
#[path = "message_signing_nonce_metrics_tests.rs"]
mod nonce_metrics_tests;
