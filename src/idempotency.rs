//! Idempotency key support for `gateway_invoke`
//!
//! Prevents duplicate side effects when LLMs retry tool calls due to timeouts.
//!
//! # How it works
//!
//! 1. Client supplies an optional `idempotency_key` in `gateway_invoke` arguments.
//! 2. For side-effecting tools without an explicit key, one is auto-generated from
//!    `SHA-256(tool_name || canonical_json(arguments))`.
//! 3. Before dispatch the key is looked up:
//!    - Not found → mark `InFlight`, execute, store `Completed`.
//!    - `InFlight` and not timed-out → return `Err(Error::DuplicateRequest)`.
//!    - `Completed` → return cached result immediately (no re-execution).
//! 4. A background task periodically evicts stale entries to bound memory usage.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::{Error, Result};

// ── Public constants ──────────────────────────────────────────────────────────

/// TTL for completed results (24 hours).
pub const COMPLETED_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Timeout for in-flight markers (5 minutes).
///
/// If a tool call does not complete within this window the in-flight marker
/// is treated as stale and a new execution is allowed.
pub const IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

// ── State machine ─────────────────────────────────────────────────────────────

/// State of an idempotency entry.
#[derive(Debug, Clone)]
pub enum IdempotencyState {
    /// Tool call is currently executing.  Holds the instant it was registered.
    InFlight(Instant),
    /// Tool call completed successfully.  Holds the result and when it was stored.
    Completed(Value, Instant),
}

impl IdempotencyState {
    /// Return `true` when this entry is stale and should be evicted.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        match self {
            Self::InFlight(started) => started.elapsed() > IN_FLIGHT_TIMEOUT,
            Self::Completed(_, stored) => stored.elapsed() > COMPLETED_TTL,
        }
    }

    /// Return `true` when this is a live in-flight entry (not yet timed out).
    #[must_use]
    pub fn is_in_flight(&self) -> bool {
        matches!(self, Self::InFlight(t) if t.elapsed() <= IN_FLIGHT_TIMEOUT)
    }
}

// ── IdempotencyCache ──────────────────────────────────────────────────────────

/// Thread-safe cache that tracks in-flight and completed idempotent requests.
///
/// All operations are O(1) amortised thanks to the underlying `DashMap`.
///
/// # Example
///
/// ```
/// use mcp_gateway::idempotency::IdempotencyCache;
/// use serde_json::json;
///
/// let cache = IdempotencyCache::new();
/// let key = "my-idempotency-key";
///
/// // Mark as in-flight before dispatching
/// cache.mark_in_flight(key);
///
/// // After the call completes, store the result
/// cache.mark_completed(key, json!({"status": "ok"}));
///
/// // Subsequent calls with the same key return the cached result
/// let result = cache.check(key);
/// assert!(result.is_some());
/// ```
#[derive(Debug, Default)]
pub struct IdempotencyCache {
    entries: DashMap<String, IdempotencyState>,
}

/// Outcome of checking the idempotency cache before executing a tool call.
#[derive(Debug)]
pub enum CheckOutcome {
    /// Key not found (or stale in-flight) — proceed with execution.
    Proceed,
    /// A live in-flight entry exists — reject with 409.
    InFlight,
    /// A completed entry exists — return cached result.
    Completed(Value),
}

impl IdempotencyCache {
    /// Create a new, empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Check the cache state for `key` and return what the caller should do.
    ///
    /// Stale in-flight entries (exceeded [`IN_FLIGHT_TIMEOUT`]) are evicted and
    /// treated as `Proceed` so a fresh execution can start.
    pub fn check(&self, key: &str) -> CheckOutcome {
        let Some(entry) = self.entries.get(key) else {
            return CheckOutcome::Proceed;
        };

        match entry.value() {
            IdempotencyState::InFlight(started) if started.elapsed() <= IN_FLIGHT_TIMEOUT => {
                CheckOutcome::InFlight
            }
            IdempotencyState::InFlight(_) => {
                // Stale in-flight — drop the guard before mutating
                drop(entry);
                self.entries.remove(key);
                debug!(key, "Evicted stale in-flight idempotency entry");
                CheckOutcome::Proceed
            }
            IdempotencyState::Completed(value, stored)
                if stored.elapsed() <= COMPLETED_TTL =>
            {
                CheckOutcome::Completed(value.clone())
            }
            IdempotencyState::Completed(_, _) => {
                // Expired completed entry
                drop(entry);
                self.entries.remove(key);
                debug!(key, "Evicted expired completed idempotency entry");
                CheckOutcome::Proceed
            }
        }
    }

    /// Register `key` as in-flight.  Overwrites any stale entry.
    pub fn mark_in_flight(&self, key: &str) {
        self.entries
            .insert(key.to_string(), IdempotencyState::InFlight(Instant::now()));
    }

    /// Transition `key` from in-flight to completed with `result`.
    pub fn mark_completed(&self, key: &str, result: Value) {
        self.entries.insert(
            key.to_string(),
            IdempotencyState::Completed(result, Instant::now()),
        );
    }

    /// Remove `key` entirely (used when a call fails and should be retryable).
    pub fn remove(&self, key: &str) {
        self.entries.remove(key);
    }

    /// Evict all stale entries.  Called by the background maintenance task.
    pub fn evict_expired(&self) {
        let stale: Vec<String> = self
            .entries
            .iter()
            .filter_map(|e| e.value().is_expired().then(|| e.key().clone()))
            .collect();

        let count = stale.len();
        for key in stale {
            self.entries.remove(&key);
        }
        if count > 0 {
            debug!(count, "Evicted stale idempotency entries");
        }
    }

    /// Current number of tracked entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` when the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Key generation ────────────────────────────────────────────────────────────

/// Derive an idempotency key from `tool_name` and `arguments`.
///
/// The key is the hex-encoded SHA-256 digest of
/// `"{tool_name}\0{canonical_json(arguments)}"`.
/// Using a NUL separator prevents collisions between tool names that share a
/// common prefix and arguments.
///
/// The resulting key is stable: identical `(tool_name, arguments)` pairs
/// always produce the same key regardless of JSON key ordering.
#[must_use]
pub fn derive_key(tool_name: &str, arguments: &Value) -> String {
    let canonical = serde_json::to_string(arguments).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(tool_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ── Idempotency enforcement ───────────────────────────────────────────────────

/// Outcome of the idempotency guard.
#[derive(Debug)]
pub enum GuardOutcome {
    /// Proceed with execution; the key has been registered as in-flight.
    Proceed,
    /// Return the cached result — no execution needed.
    CachedResult(Value),
}

/// Check the idempotency cache and either return a cached result or register
/// the key as in-flight for execution.
///
/// # Errors
///
/// Returns [`Error::DuplicateRequest`] (HTTP 409 equivalent) when an identical
/// request is already in flight.
pub fn enforce(cache: &IdempotencyCache, key: &str) -> Result<GuardOutcome> {
    match cache.check(key) {
        CheckOutcome::Proceed => {
            cache.mark_in_flight(key);
            Ok(GuardOutcome::Proceed)
        }
        CheckOutcome::InFlight => Err(Error::json_rpc(
            409,
            format!("Duplicate request in progress for key: {key}"),
        )),
        CheckOutcome::Completed(value) => Ok(GuardOutcome::CachedResult(value)),
    }
}

/// Spawn a background tokio task that periodically evicts stale idempotency
/// entries from `cache`.
///
/// The task runs every `interval` and stops when the `Arc` reference count
/// drops to 1 (i.e., all other owners have dropped their handles).
pub fn spawn_cleanup_task(cache: Arc<IdempotencyCache>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            // Stop if we are the sole Arc holder (server is shutting down).
            if Arc::strong_count(&cache) <= 1 {
                break;
            }
            cache.evict_expired();
        }
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::thread;

    // ── derive_key ────────────────────────────────────────────────────────────

    #[test]
    fn derive_key_is_deterministic_for_same_inputs() {
        // GIVEN: identical tool name and arguments
        // WHEN: deriving the key twice
        // THEN: both keys are identical
        let k1 = derive_key("gmail_send_email", &json!({"to": "a@b.com", "body": "hi"}));
        let k2 = derive_key("gmail_send_email", &json!({"to": "a@b.com", "body": "hi"}));
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_is_64_hex_chars() {
        // GIVEN: any tool + arguments
        // WHEN: deriving the key
        // THEN: result is a 64-character hex string (SHA-256)
        let key = derive_key("my_tool", &json!({}));
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn derive_key_differs_for_different_tool_names() {
        // GIVEN: same arguments but different tool names
        // WHEN: deriving keys
        // THEN: keys are different
        let k1 = derive_key("tool_a", &json!({"x": 1}));
        let k2 = derive_key("tool_b", &json!({"x": 1}));
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_key_differs_for_different_arguments() {
        // GIVEN: same tool name but different arguments
        // WHEN: deriving keys
        // THEN: keys are different
        let k1 = derive_key("send", &json!({"to": "a@b.com"}));
        let k2 = derive_key("send", &json!({"to": "c@d.com"}));
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_key_prevents_prefix_collision() {
        // GIVEN: a tool whose name is a prefix of another (tool, tool_extended)
        // WHEN: deriving keys with the same suffix args
        // THEN: keys are different (NUL separator prevents collision)
        let k1 = derive_key("tool", &json!({"a": "extended"}));
        let k2 = derive_key("tool_extended", &json!({"a": ""}));
        assert_ne!(k1, k2);
    }

    // ── IdempotencyState ──────────────────────────────────────────────────────

    #[test]
    fn state_in_flight_is_not_expired_immediately() {
        // GIVEN: a freshly created InFlight state
        // WHEN: checking expiry
        // THEN: not expired
        let state = IdempotencyState::InFlight(Instant::now());
        assert!(!state.is_expired());
    }

    #[test]
    fn state_completed_is_not_expired_immediately() {
        // GIVEN: a freshly created Completed state
        // WHEN: checking expiry
        // THEN: not expired
        let state = IdempotencyState::Completed(json!({"ok": true}), Instant::now());
        assert!(!state.is_expired());
    }

    #[test]
    fn state_in_flight_is_live_immediately() {
        // GIVEN: a freshly created InFlight state
        // WHEN: checking is_in_flight
        // THEN: true
        let state = IdempotencyState::InFlight(Instant::now());
        assert!(state.is_in_flight());
    }

    #[test]
    fn state_completed_is_not_in_flight() {
        // GIVEN: a Completed state
        // WHEN: checking is_in_flight
        // THEN: false
        let state = IdempotencyState::Completed(json!(null), Instant::now());
        assert!(!state.is_in_flight());
    }

    // ── IdempotencyCache::check ───────────────────────────────────────────────

    #[test]
    fn check_returns_proceed_for_unknown_key() {
        // GIVEN: an empty cache
        // WHEN: checking an unknown key
        // THEN: Proceed
        let cache = IdempotencyCache::new();
        assert!(matches!(cache.check("unknown"), CheckOutcome::Proceed));
    }

    #[test]
    fn check_returns_in_flight_for_live_in_flight_key() {
        // GIVEN: cache with a live in-flight key
        // WHEN: checking the same key
        // THEN: InFlight
        let cache = IdempotencyCache::new();
        cache.mark_in_flight("key-1");
        assert!(matches!(cache.check("key-1"), CheckOutcome::InFlight));
    }

    #[test]
    fn check_returns_completed_result_for_completed_key() {
        // GIVEN: cache with a completed key
        // WHEN: checking the same key
        // THEN: Completed with the stored value
        let cache = IdempotencyCache::new();
        let result = json!({"issue_id": "LIN-42"});
        cache.mark_in_flight("key-2");
        cache.mark_completed("key-2", result.clone());
        match cache.check("key-2") {
            CheckOutcome::Completed(v) => assert_eq!(v, result),
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn check_evicts_stale_in_flight_and_returns_proceed() {
        // GIVEN: an in-flight entry whose timestamp is older than IN_FLIGHT_TIMEOUT
        // WHEN: checking the key
        // THEN: Proceed (stale entry evicted)
        let cache = IdempotencyCache::new();
        // Insert an entry with a timestamp in the distant past
        cache.entries.insert(
            "stale".to_string(),
            IdempotencyState::InFlight(Instant::now() - IN_FLIGHT_TIMEOUT - Duration::from_secs(1)),
        );
        assert!(matches!(cache.check("stale"), CheckOutcome::Proceed));
        assert_eq!(cache.len(), 0, "stale entry must be removed");
    }

    #[test]
    fn check_evicts_expired_completed_and_returns_proceed() {
        // GIVEN: a completed entry whose TTL has elapsed
        // WHEN: checking the key
        // THEN: Proceed (expired entry evicted)
        let cache = IdempotencyCache::new();
        cache.entries.insert(
            "old".to_string(),
            IdempotencyState::Completed(
                json!(null),
                Instant::now() - COMPLETED_TTL - Duration::from_secs(1),
            ),
        );
        assert!(matches!(cache.check("old"), CheckOutcome::Proceed));
        assert_eq!(cache.len(), 0, "expired entry must be removed");
    }

    // ── evict_expired ─────────────────────────────────────────────────────────

    #[test]
    fn evict_expired_removes_only_stale_entries() {
        // GIVEN: one fresh and one stale completed entry
        // WHEN: calling evict_expired
        // THEN: only the stale entry is removed
        let cache = IdempotencyCache::new();
        cache.mark_in_flight("fresh");
        cache.mark_completed("fresh", json!(1));
        cache.entries.insert(
            "stale".to_string(),
            IdempotencyState::Completed(
                json!(2),
                Instant::now() - COMPLETED_TTL - Duration::from_secs(1),
            ),
        );

        cache.evict_expired();

        assert_eq!(cache.len(), 1);
        assert!(matches!(cache.check("fresh"), CheckOutcome::Completed(_)));
    }

    // ── enforce ───────────────────────────────────────────────────────────────

    #[test]
    fn enforce_marks_in_flight_and_returns_proceed_for_new_key() {
        // GIVEN: an empty cache
        // WHEN: enforcing on a new key
        // THEN: Proceed, and the key is now in-flight
        let cache = IdempotencyCache::new();
        let outcome = enforce(&cache, "k1").expect("should not fail");
        assert!(matches!(outcome, GuardOutcome::Proceed));
        assert!(matches!(cache.check("k1"), CheckOutcome::InFlight));
    }

    #[test]
    fn enforce_returns_cached_result_for_completed_key() {
        // GIVEN: a completed key in cache
        // WHEN: enforcing on that key
        // THEN: CachedResult with the stored value
        let cache = IdempotencyCache::new();
        let expected = json!({"done": true});
        cache.mark_in_flight("k2");
        cache.mark_completed("k2", expected.clone());
        match enforce(&cache, "k2").expect("should not fail") {
            GuardOutcome::CachedResult(v) => assert_eq!(v, expected),
            GuardOutcome::Proceed => panic!("expected CachedResult"),
        }
    }

    #[test]
    fn enforce_returns_error_for_in_flight_key() {
        // GIVEN: a live in-flight key
        // WHEN: enforcing on the same key from a concurrent caller
        // THEN: Err with code 409
        let cache = IdempotencyCache::new();
        cache.mark_in_flight("k3");
        let err = enforce(&cache, "k3").expect_err("should return 409");
        match err {
            crate::Error::JsonRpc { code, .. } => assert_eq!(code, 409),
            _ => panic!("expected JsonRpc error"),
        }
    }

    // ── remove ────────────────────────────────────────────────────────────────

    #[test]
    fn remove_clears_key_making_it_retryable() {
        // GIVEN: an in-flight key
        // WHEN: calling remove (e.g. on tool failure)
        // THEN: key is gone and check returns Proceed
        let cache = IdempotencyCache::new();
        cache.mark_in_flight("fail-key");
        cache.remove("fail-key");
        assert!(matches!(cache.check("fail-key"), CheckOutcome::Proceed));
        assert_eq!(cache.len(), 0);
    }

    // ── concurrent access ─────────────────────────────────────────────────────

    #[test]
    fn concurrent_mark_completed_is_safe() {
        // GIVEN: cache shared across threads
        // WHEN: 10 threads each mark different keys completed
        // THEN: all entries are present without data races
        let cache = Arc::new(IdempotencyCache::new());
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let c = Arc::clone(&cache);
                thread::spawn(move || {
                    let key = format!("key-{i}");
                    c.mark_in_flight(&key);
                    c.mark_completed(&key, json!(i));
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(cache.len(), 10);
    }

    // ── is_empty / len ────────────────────────────────────────────────────────

    #[test]
    fn new_cache_is_empty() {
        let cache = IdempotencyCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn len_increases_on_insert() {
        let cache = IdempotencyCache::new();
        cache.mark_in_flight("a");
        cache.mark_in_flight("b");
        assert_eq!(cache.len(), 2);
        assert!(!cache.is_empty());
    }

    // ── cleanup task (tokio) ──────────────────────────────────────────────────

    #[tokio::test]
    async fn spawn_cleanup_task_evicts_expired_entries() {
        // GIVEN: a cache with one stale completed entry
        // WHEN: the cleanup task runs
        // THEN: the entry is evicted
        let cache = Arc::new(IdempotencyCache::new());
        cache.entries.insert(
            "stale".to_string(),
            IdempotencyState::Completed(
                json!(null),
                Instant::now() - COMPLETED_TTL - Duration::from_secs(1),
            ),
        );

        spawn_cleanup_task(Arc::clone(&cache), Duration::from_millis(10));

        // Wait a bit for the task to run
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(cache.len(), 0, "stale entry should have been evicted");
    }
}
