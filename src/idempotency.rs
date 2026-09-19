// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
//!    - Not found → mark `InFlight`, execute, store `Completed` or `Failed`.
//!    - `InFlight` while its owner is alive → return `Err(Error::DuplicateRequest)`.
//!    - `Completed` → return cached result immediately (no re-execution).
//!    - `Failed` → return the recorded error (no re-execution). A dispatched
//!      call that never resolved is a terminal outcome, not an absence of one;
//!      see ADR-012.
//! 4. A background task periodically evicts stale entries to bound memory usage.

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry as MapEntry;
use serde_json::Value;
use tracing::debug;

use crate::hashing::{canonical_json, sha256_hex_chunks};
use crate::{Error, Result};

// ── Public constants ──────────────────────────────────────────────────────────

/// TTL for completed results (24 hours).
///
/// **Stated assumption, flagged to the team lead (MIK-7272.SUB.4, 2026-09-07,
/// carried forward unchanged by the 2026-09-08 ruling).** Nobody has decided
/// how long a client may retry a side-effecting call and still be owed the
/// first result; 24 hours is a defensible default, not a settled requirement.
/// The 2026-09-08 ruling removed the config field that would have carried it,
/// so it lives here as a constant — that changed WHERE the assumption is
/// recorded, never that it is one. It takes CONTROL.4's shape: a value with a
/// defensible default, named as an assumption where a reader of the constant
/// finds it. Revisit if an operator reports either half of the failure — a
/// retry outside the window that duplicated a side effect, or memory pressure
/// from entries held this long.
pub const COMPLETED_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Timeout for in-flight markers (5 minutes).
///
/// If a tool call does not complete within this window the in-flight marker
/// is treated as stale and a new execution is allowed.
pub const IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Maximum number of tracked entries.
///
/// Mirrors the response cache bound (`src/config/features/cache.rs:12`). At the
/// bound the guard fails **closed**: a new protected side effect is refused
/// rather than an older entry evicted, because evicting readmits the duplicate
/// that entry existed to suppress. Entries already tracked stay servable.
pub const MAX_ENTRIES: usize = 10_000;

/// How often the background sweep evicts stale entries (1 minute).
///
/// Not a correctness bound — [`IN_FLIGHT_TIMEOUT`] and [`COMPLETED_TTL`] decide
/// what an entry means, and a lookup honours both whether or not the sweep has
/// run. This only decides how long a dead entry keeps occupying one of the
/// [`MAX_ENTRIES`] slots.
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

// ── State machine ─────────────────────────────────────────────────────────────

/// State of an idempotency entry.
#[derive(Debug, Clone)]
pub enum IdempotencyState {
    /// Tool call is currently executing.  Holds the instant it was registered.
    InFlight(Instant),
    /// Tool call completed successfully.  Holds the result and when it was stored.
    Completed(Value, Instant),
    /// Tool call was dispatched and came back with a terminal error. Holds the
    /// JSON-RPC error object (`{"code", "message"}`) and when it was stored.
    ///
    /// Terminal alongside [`Completed`](Self::Completed), not a flavour of
    /// in-flight: the backend was reached and never said whether it acted, so a
    /// retry is served this error rather than re-executing. Ages out on
    /// [`COMPLETED_TTL`].
    Failed(Value, Instant),
}

impl IdempotencyState {
    /// Return `true` when this state's clock has run out.
    ///
    /// A clock reading alone does not decide whether an entry may be evicted: an
    /// in-flight entry whose owner is still executing is not stale however long
    /// it has run. `Entry::is_expired` is the predicate the cache uses, and it
    /// consults the owner's liveness first.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        match self {
            Self::InFlight(started) => started.elapsed() > IN_FLIGHT_TIMEOUT,
            Self::Completed(_, stored) | Self::Failed(_, stored) => {
                stored.elapsed() > COMPLETED_TTL
            }
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
/// use mcp_gateway::idempotency::{IdempotencyCache, CheckOutcome};
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
/// assert!(matches!(result, CheckOutcome::Completed(_)));
/// ```
#[derive(Debug, Default)]
pub struct IdempotencyCache {
    entries: DashMap<String, Entry>,
}

/// One tracked key: its state, and the request it was minted for.
///
/// The fingerprint is stored beside the state rather than mixed into the key,
/// because a mismatch has to be *refused*. Folding it into the key would make
/// the second call a different key, and a different key executes — which is the
/// duplicate the client's key was meant to prevent.
#[derive(Debug)]
struct Entry {
    state: IdempotencyState,
    /// The request this key was admitted for, or empty when the entry came from
    /// [`IdempotencyCache::mark_in_flight`], which has no request to bind to.
    /// An empty fingerprint binds nothing and matches anything.
    fingerprint: String,
    /// Weak handle to the token the admitted caller holds for as long as its
    /// call is running. `None` for entries admitted without one, whose staleness
    /// can only be a clock reading.
    ///
    /// Installed in the same guarded write that admits the key, so an entry is
    /// never observable in-flight without its owner attached.
    owner: Option<Weak<()>>,
}

impl Entry {
    fn new(state: IdempotencyState, fingerprint: &str) -> Self {
        Self {
            state,
            fingerprint: fingerprint.to_string(),
            owner: None,
        }
    }

    /// An in-flight entry owned by the live caller holding `owner`.
    fn in_flight(fingerprint: &str, owner: &Arc<()>) -> Self {
        Self {
            state: IdempotencyState::InFlight(Instant::now()),
            fingerprint: fingerprint.to_string(),
            owner: Some(Arc::downgrade(owner)),
        }
    }

    /// Whether `fingerprint` is the request this entry was admitted for.
    fn matches(&self, fingerprint: &str) -> bool {
        self.fingerprint.is_empty() || self.fingerprint == fingerprint
    }

    /// Whether nobody is executing under this entry any more.
    ///
    /// An entry with no owner attached counts as unowned, so it stays subject to
    /// the clock alone — a reservation that never registered a token must not
    /// become immortal.
    fn owner_gone(&self) -> bool {
        self.owner.as_ref().is_none_or(|w| w.strong_count() == 0)
    }

    /// Whether this entry may be evicted.
    ///
    /// For an in-flight entry staleness is a liveness question, not a clock
    /// reading: a call still running past [`IN_FLIGHT_TIMEOUT`] keeps its entry.
    /// The timeout then does what it was introduced for — reclaiming entries
    /// whose owner is gone — and nothing else.
    fn is_expired(&self) -> bool {
        match &self.state {
            IdempotencyState::InFlight(_) => self.owner_gone() && self.state.is_expired(),
            IdempotencyState::Completed(..) | IdempotencyState::Failed(..) => {
                self.state.is_expired()
            }
        }
    }

    /// How admission and lookup should read this entry.
    fn classify(&self) -> CacheEntryStatus {
        let expired = self.is_expired();
        match &self.state {
            IdempotencyState::InFlight(_) if expired => CacheEntryStatus::StaleInFlight,
            IdempotencyState::InFlight(_) => CacheEntryStatus::LiveInFlight,
            IdempotencyState::Completed(..) if expired => CacheEntryStatus::ExpiredCompleted,
            IdempotencyState::Completed(..) => CacheEntryStatus::LiveCompleted,
            IdempotencyState::Failed(..) if expired => CacheEntryStatus::ExpiredFailed,
            IdempotencyState::Failed(..) => CacheEntryStatus::LiveFailed,
        }
    }
}

/// Outcome of checking the idempotency cache before executing a tool call.
#[derive(Debug)]
pub enum CheckOutcome {
    /// Key not found, or an entry aged out with no live owner — proceed.
    Proceed,
    /// A live in-flight entry exists — reject with 409.
    InFlight,
    /// A completed entry exists — return cached result.
    Completed(Value),
    /// A dispatched call settled as failed — return that error, do not execute.
    Failed(Value),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheEntryStatus {
    Missing,
    LiveInFlight,
    StaleInFlight,
    LiveCompleted,
    ExpiredCompleted,
    LiveFailed,
    ExpiredFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckPlan {
    Proceed,
    InFlight,
    Completed,
    Failed,
}

#[must_use]
pub(crate) fn decide_check_plan(status: CacheEntryStatus) -> (CheckPlan, bool) {
    match status {
        CacheEntryStatus::Missing => (CheckPlan::Proceed, false),
        CacheEntryStatus::LiveInFlight => (CheckPlan::InFlight, false),
        // ADR-012 consequence 3 maps this arm to `InFlight`, on the stated
        // premise that a background `evict_expired` sweep reclaims the entry
        // instead. No such sweep is wired in this tree — every `evict_expired`
        // call site is a test — so `InFlight` here would make an ownerless
        // entry immortal: a permanent in-flight answer on a key nothing is
        // executing, unbounded, where the ADR budgets a cost bounded by
        // `COMPLETED_TTL`. The arm therefore diverges deliberately.
        //
        // Defect 3 is closed by the other half of the same consequence.
        // Staleness is now a liveness question inside `Entry::is_expired`: a
        // call still running holds a live handle and classifies
        // `LiveInFlight`, so a retry beneath it is told in-flight and never
        // admitted. What reaches this arm is a reservation whose owner is dead
        // or was never registered — precisely what the ADR says the timeout
        // exists to reclaim, and nothing else.
        CacheEntryStatus::StaleInFlight => (CheckPlan::Proceed, true),
        CacheEntryStatus::LiveCompleted => (CheckPlan::Completed, false),
        CacheEntryStatus::LiveFailed => (CheckPlan::Failed, false),
        CacheEntryStatus::ExpiredCompleted | CacheEntryStatus::ExpiredFailed => {
            (CheckPlan::Proceed, true)
        }
    }
}

/// Outcome of the atomic admission step performed by [`IdempotencyCache::admit`].
#[derive(Debug)]
pub(crate) enum AdmitOutcome {
    /// The key is now registered in-flight for this caller alone. Carries the
    /// liveness token minted under the entry guard; the caller must hold it for
    /// as long as it executes, or the entry becomes reclaimable.
    Proceed(Arc<()>),
    /// Another caller holds a live in-flight entry.
    InFlight,
    /// A completed entry exists — return the cached result.
    Completed(Value),
    /// A dispatched call settled as failed — the caller is owed that error.
    Failed(Value),
    /// The cache is at [`MAX_ENTRIES`] and this key is not tracked yet.
    AtCapacity,
    /// The key is tracked, but for a different request.
    Mismatch,
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
            let (plan, evict) = decide_check_plan(CacheEntryStatus::Missing);
            debug_assert!(!evict);
            return match plan {
                CheckPlan::Proceed => CheckOutcome::Proceed,
                CheckPlan::InFlight => CheckOutcome::InFlight,
                CheckPlan::Completed | CheckPlan::Failed => {
                    unreachable!("missing entries cannot be terminal")
                }
            };
        };

        let status = entry.value().classify();

        let (decision, evict) = decide_check_plan(status);
        if evict {
            drop(entry);
            self.entries.remove(key);
            debug!(key, "Evicted stale idempotency entry");
            return CheckOutcome::Proceed;
        }

        match decision {
            CheckPlan::Proceed => CheckOutcome::Proceed,
            CheckPlan::InFlight => CheckOutcome::InFlight,
            CheckPlan::Completed => {
                let IdempotencyState::Completed(value, _) = &entry.value().state else {
                    unreachable!("live completed status must hold a completed value");
                };
                CheckOutcome::Completed(value.clone())
            }
            CheckPlan::Failed => {
                let IdempotencyState::Failed(error, _) = &entry.value().state else {
                    unreachable!("live failed status must hold an error value");
                };
                CheckOutcome::Failed(error.clone())
            }
        }
    }

    /// Atomically inspect `key` and, when nothing else owns it, register it as
    /// in-flight in the same operation.
    ///
    /// `check` followed by `mark_in_flight` is two independent `DashMap`
    /// operations, so two concurrent retries of one key could both observe
    /// `Proceed` and both execute. Holding a single entry guard across the
    /// inspect and the write closes that window.
    pub(crate) fn admit(&self, key: &str, fingerprint: &str) -> AdmitOutcome {
        // `DashMap::len` read-locks every shard, so it must be read *before*
        // the entry guard below takes a shard write lock — reading it inside
        // the guard's scope deadlocks. The count can therefore grow by at most
        // the number of callers racing admission of distinct new keys.
        let at_capacity = self.entries.len() >= MAX_ENTRIES;

        match self.entries.entry(key.to_string()) {
            MapEntry::Occupied(mut occupied) => {
                // Before the state: a live entry for another request must be
                // refused whether it is in flight or already completed, and a
                // stale one is replaced by this request anyway.
                let (plan, evict) = decide_check_plan(occupied.get().classify());
                if !matches!(plan, CheckPlan::Proceed) && !occupied.get().matches(fingerprint) {
                    return AdmitOutcome::Mismatch;
                }
                match plan {
                    CheckPlan::InFlight => AdmitOutcome::InFlight,
                    CheckPlan::Completed => {
                        let IdempotencyState::Completed(value, _) = &occupied.get().state else {
                            unreachable!("live completed status must hold a completed value");
                        };
                        AdmitOutcome::Completed(value.clone())
                    }
                    CheckPlan::Failed => {
                        let IdempotencyState::Failed(error, _) = &occupied.get().state else {
                            unreachable!("live failed status must hold an error value");
                        };
                        AdmitOutcome::Failed(error.clone())
                    }
                    CheckPlan::Proceed => {
                        debug_assert!(evict, "an occupied entry only proceeds after eviction");
                        // Replacing in place keeps the entry count flat, so an
                        // expired entry never costs a caller its admission.
                        let owner = Arc::new(());
                        occupied.insert(Entry::in_flight(fingerprint, &owner));
                        debug!(key, "Replaced expired idempotency entry");
                        AdmitOutcome::Proceed(owner)
                    }
                }
            }
            MapEntry::Vacant(vacant) => {
                if at_capacity {
                    return AdmitOutcome::AtCapacity;
                }
                // Minted here rather than by the caller: the weak handle has to
                // be installed by the same guarded write that admits the key, or
                // there is a window in which the entry is in-flight and unowned.
                let owner = Arc::new(());
                vacant.insert(Entry::in_flight(fingerprint, &owner));
                AdmitOutcome::Proceed(owner)
            }
        }
    }

    /// Register `key` as in-flight.  Overwrites any stale entry.
    pub fn mark_in_flight(&self, key: &str) {
        self.entries.insert(
            key.to_string(),
            Entry::new(IdempotencyState::InFlight(Instant::now()), ""),
        );
    }

    /// Transition `key` from in-flight to completed with `result`.
    ///
    /// A result the backend has not finished producing is *not* stored, and any
    /// in-flight entry for `key` is dropped so the call stays retryable. MCP
    /// 2026 marks such a result with a `resultType` other than `"complete"` —
    /// `"input_required"` being the case that matters, where the backend is
    /// waiting for the caller to supply something. Caching that would make
    /// every retry replay the request for input instead of running the call,
    /// so the exchange could never complete.
    ///
    /// The guard lives here rather than at each call site because the property
    /// belongs to the cache: nothing non-final should ever be servable from it,
    /// including from call sites not yet written.
    pub fn mark_completed(&self, key: &str, result: Value) -> bool {
        // The fingerprint survives the state transition: the completed result
        // belongs to the request that was admitted, not to whatever asks next.
        // A caller holding a reservation knows that fingerprint and passes it
        // to `mark_completed_bound`; this entry point can only recover it from
        // the entry, which is why it must not be used once the entry may be
        // gone.
        let fingerprint = self
            .entries
            .get(key)
            .map_or_else(String::new, |e| e.fingerprint.clone());
        self.mark_completed_bound(key, result, &fingerprint)
    }

    /// [`mark_completed`](Self::mark_completed) with the admitting request's
    /// fingerprint supplied rather than looked up.
    ///
    /// The lookup cannot recover it once the entry is gone — released by a
    /// failed dispatch, or swept after [`IN_FLIGHT_TIMEOUT`] — and an empty
    /// fingerprint matches every later request, so a result stored that way
    /// would answer any call reusing the key.
    pub(crate) fn mark_completed_bound(&self, key: &str, result: Value, fingerprint: &str) -> bool {
        if !crate::protocol::cacheable::is_final(&result) {
            self.entries.remove(key);
            debug!(key, "Refused to cache a non-final result");
            return false;
        }
        self.entries.insert(
            key.to_string(),
            Entry::new(
                IdempotencyState::Completed(result, Instant::now()),
                fingerprint,
            ),
        );
        true
    }

    /// Settle `key` as terminally failed, carrying the JSON-RPC `error` object a
    /// retry will be served.
    ///
    /// No finality check, unlike [`mark_completed_bound`](Self::mark_completed_bound):
    /// that guard exists to stop a *result* the backend has not finished
    /// producing from being served as though it were finished. An error is
    /// finished by construction — it is the end of this dispatch, and the only
    /// thing a retry can honestly be told.
    pub(crate) fn mark_failed_bound(&self, key: &str, error: Value, fingerprint: &str) {
        self.entries.insert(
            key.to_string(),
            Entry::new(IdempotencyState::Failed(error, Instant::now()), fingerprint),
        );
    }

    /// Remove `key` entirely (used when a call fails and should be retryable).
    pub fn remove(&self, key: &str) {
        self.entries.remove(key);
    }

    /// Evict all stale entries.  Called by the background maintenance task.
    ///
    /// The expiry test and the removal MUST happen under the same lock. A
    /// collect-then-remove pass leaves a window in which a fresh admission
    /// takes the key between the two halves and is then deleted as though it
    /// were the stale entry it displaced — silently unprotecting a call the
    /// client asked to protect. `retain` holds each shard's write lock across
    /// the predicate and the removal, so the window does not exist rather than
    /// being narrowed.
    pub fn evict_expired(&self) {
        let before = self.entries.len();
        // `Entry::is_expired`, not the state's clock: the sweep does not consult
        // `decide_check_plan`, so a running call would otherwise lose its entry
        // to the background task and the retry would be admitted.
        self.entries.retain(|_, entry| !entry.is_expired());
        let count = before.saturating_sub(self.entries.len());
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

#[cfg(kani)]
mod verification {
    use super::*;

    fn any_entry_status() -> CacheEntryStatus {
        match kani::any::<u8>() % 7 {
            0 => CacheEntryStatus::Missing,
            1 => CacheEntryStatus::LiveInFlight,
            2 => CacheEntryStatus::StaleInFlight,
            3 => CacheEntryStatus::LiveCompleted,
            4 => CacheEntryStatus::ExpiredCompleted,
            5 => CacheEntryStatus::LiveFailed,
            _ => CacheEntryStatus::ExpiredFailed,
        }
    }

    #[kani::proof]
    fn idempotency_decision_contract() {
        let status = any_entry_status();
        let (plan, evict) = decide_check_plan(status);

        match status {
            CacheEntryStatus::Missing => {
                assert_eq!(plan, CheckPlan::Proceed);
                assert!(!evict);
            }
            CacheEntryStatus::LiveInFlight => {
                assert_eq!(plan, CheckPlan::InFlight);
                assert!(!evict);
            }
            // An in-flight entry is stale only once its owner is gone, so
            // reclaiming it here is the timeout doing its one job. A running
            // call classifies LiveInFlight above and is refused.
            CacheEntryStatus::StaleInFlight => {
                assert_eq!(plan, CheckPlan::Proceed);
                assert!(evict);
            }
            CacheEntryStatus::LiveCompleted => {
                assert_eq!(plan, CheckPlan::Completed);
                assert!(!evict);
            }
            CacheEntryStatus::ExpiredCompleted | CacheEntryStatus::ExpiredFailed => {
                assert_eq!(plan, CheckPlan::Proceed);
                assert!(evict);
            }
            CacheEntryStatus::LiveFailed => {
                assert_eq!(plan, CheckPlan::Failed);
                assert!(!evict);
            }
        }
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
    let canonical = canonical_json(arguments);
    sha256_hex_chunks([tool_name.as_bytes(), &b"\0"[..], canonical.as_bytes()])
}

// ── Idempotency enforcement ───────────────────────────────────────────────────

/// Owned reservation of an admitted idempotency key.
///
/// Holding one is the right to execute the protected side effect exactly once.
/// Every exit path after admission reaches a terminal state, so no early return
/// can strand an entry as in-flight until [`IN_FLIGHT_TIMEOUT`]. Which terminal
/// state depends on whether the side effect has run: before
/// [`commit`](Self::commit) a drop releases the key so the call can be retried;
/// after it, a drop stores the committed result, because once the backend has
/// acted a retry must not execute it again.
#[derive(Debug)]
pub struct IdempotencyReservation {
    cache: Arc<IdempotencyCache>,
    key: String,
    /// The fingerprint the key was admitted for, so a result stored after the
    /// entry is gone stays bound to this request instead of matching any.
    fingerprint: String,
    settled: bool,
    on_drop: OnDrop,
    /// Liveness token for the cache entry. Held, never read: while this is
    /// alive the entry's weak handle upgrades, and the entry is not stale
    /// however long the call has run.
    _owner: Arc<()>,
}

/// What an unsettled [`IdempotencyReservation`] does when it is dropped.
#[derive(Debug)]
enum OnDrop {
    /// Nothing has been executed yet — free the key so the call can be retried.
    Release,
    /// The protected side effect has committed — settle with this result so a
    /// retry is served the cached value instead of re-executing.
    Complete(Value),
}

impl IdempotencyReservation {
    fn new(cache: Arc<IdempotencyCache>, key: &str, fingerprint: &str, owner: Arc<()>) -> Self {
        Self {
            cache,
            key: key.to_string(),
            fingerprint: fingerprint.to_string(),
            settled: false,
            on_drop: OnDrop::Release,
            _owner: owner,
        }
    }

    /// The key this reservation owns.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Settle by storing `result`. Returns whether it was cached — a non-final
    /// result is refused by [`IdempotencyCache::mark_completed`] and the key is
    /// released instead, so the call stays retryable.
    ///
    /// Callable after [`release`](Self::release): a failed dispatch releases the
    /// key first and may still store a structured error result afterwards, which
    /// is the behaviour the invoke path already relied on.
    pub fn complete(&mut self, result: &Value) -> bool {
        self.settled = true;
        self.cache
            .mark_completed_bound(&self.key, result.clone(), &self.fingerprint)
    }

    /// Record that the protected side effect has committed.
    ///
    /// After this, dropping the reservation unsettled stores `result` as the
    /// terminal state instead of releasing the key. Once a backend has acted, a
    /// post-dispatch early return must not readmit the retry that would execute
    /// it a second time. No-op once the reservation is already settled.
    pub fn commit(&mut self, result: &Value) {
        if !self.settled {
            self.on_drop = OnDrop::Complete(result.clone());
        }
    }

    /// Settle as terminally failed, storing `error` so a retry is served it
    /// rather than executing a second time.
    ///
    /// This is the outcome for a dispatched call the backend never resolved: it
    /// was reached, it did not say whether it acted, and the honest answer to a
    /// retry is the error — not a fresh execution. Use
    /// [`release`](Self::release) only when the request provably never left.
    pub fn fail(&mut self, error: &Value) {
        self.settled = true;
        self.cache
            .mark_failed_bound(&self.key, error.clone(), &self.fingerprint);
    }

    /// Settle by releasing the key so the call can be retried.
    ///
    /// Only correct when the request never left for the backend, or when the
    /// backend answered that it did not act.
    pub fn release(&mut self) {
        self.settled = true;
        self.cache.remove(&self.key);
    }
}

impl Drop for IdempotencyReservation {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        match std::mem::replace(&mut self.on_drop, OnDrop::Release) {
            OnDrop::Release => {
                self.cache.remove(&self.key);
                debug!(key = %self.key, "Released abandoned idempotency reservation");
            }
            OnDrop::Complete(result) => {
                if self
                    .cache
                    .mark_completed_bound(&self.key, result, &self.fingerprint)
                {
                    debug!(key = %self.key, "Settled abandoned idempotency reservation");
                } else {
                    // A non-final result is refused by `mark_completed`. Leaving
                    // the entry in flight is the one outcome this guard exists to
                    // prevent, so fall back to releasing the key.
                    self.cache.remove(&self.key);
                }
            }
        }
    }
}

/// Outcome of the idempotency guard.
#[derive(Debug)]
pub enum GuardOutcome {
    /// Proceed with execution, holding the reservation for the key.
    Proceed(IdempotencyReservation),
    /// Return the cached result — no execution needed.
    CachedResult(Value),
}

/// Check the idempotency cache and either return a cached result or register
/// the key as in-flight for execution.
///
/// # Errors
///
/// Returns the recorded error when a previous dispatch under `key` settled as
/// failed — the outcome was never established, so a retry is told so rather
/// than executing again. Returns a 409 error when an identical request is
/// already in flight (including one whose owner is still running past
/// [`IN_FLIGHT_TIMEOUT`]), a 409
/// error when `key` is already bound to a *different* request, and a 503 error
/// when the cache is at [`MAX_ENTRIES`] and the key is not yet tracked —
/// refusing rather than evicting, since eviction readmits a duplicate.
///
/// `fingerprint` identifies the request the key is being used for. A client key
/// is an opaque string it chose; nothing about the string says which call it
/// was minted for, so without binding, one key reused for a second, different
/// call is served the first call's result as though it were its own.
pub fn enforce(
    cache: &Arc<IdempotencyCache>,
    key: &str,
    fingerprint: &str,
) -> Result<GuardOutcome> {
    match cache.admit(key, fingerprint) {
        AdmitOutcome::Proceed(owner) => Ok(GuardOutcome::Proceed(IdempotencyReservation::new(
            Arc::clone(cache),
            key,
            fingerprint,
            owner,
        ))),
        AdmitOutcome::InFlight => Err(Error::json_rpc(
            409,
            format!("Duplicate request in progress for key: {key}"),
        )),
        AdmitOutcome::Completed(value) => Ok(GuardOutcome::CachedResult(value)),
        // The recorded error is handed back as the retry's own error, so it
        // carries the retry's request id rather than the original's.
        AdmitOutcome::Failed(error) => Err(Error::json_rpc(
            error
                .get("code")
                .and_then(Value::as_i64)
                .and_then(|c| i32::try_from(c).ok())
                .unwrap_or(-32603),
            error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Idempotent call failed after dispatch; outcome not established")
                .to_string(),
        )),
        AdmitOutcome::Mismatch => Err(Error::json_rpc(
            409,
            format!(
                "Idempotency key is already in use for a different request: {key}. \
                 A key identifies one call; reuse it only to repeat that same call."
            ),
        )),
        AdmitOutcome::AtCapacity => Err(Error::json_rpc(
            503,
            format!(
                "Idempotency cache at capacity ({MAX_ENTRIES} entries); \
                 refusing new protected request for key: {key}"
            ),
        )),
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

    // ── ADR-012: liveness, not the clock, decides in-flight staleness ────────

    /// An in-flight entry started long enough ago to be stale by the clock.
    fn back_dated_in_flight(fingerprint: &str, owner: Option<&Arc<()>>) -> Entry {
        let started = Instant::now()
            .checked_sub(IN_FLIGHT_TIMEOUT + Duration::from_secs(1))
            .expect("fixture needs a host booted longer ago than IN_FLIGHT_TIMEOUT");
        Entry {
            state: IdempotencyState::InFlight(started),
            fingerprint: fingerprint.to_string(),
            owner: owner.map(Arc::downgrade),
        }
    }

    #[test]
    fn a_running_call_past_the_timeout_is_told_in_flight_not_admitted() {
        // GIVEN: a call admitted more than IN_FLIGHT_TIMEOUT ago that is still
        // running — its owner token is alive
        let cache = IdempotencyCache::new();
        let owner = Arc::new(());
        cache
            .entries
            .insert("k".to_string(), back_dated_in_flight("fp", Some(&owner)));

        // WHEN/THEN: a second caller is refused, not admitted to execute
        assert!(matches!(cache.check("k"), CheckOutcome::InFlight));
        assert!(matches!(cache.admit("k", "fp"), AdmitOutcome::InFlight));
    }

    #[test]
    fn a_running_call_past_the_timeout_survives_the_sweep() {
        // GIVEN: the same still-running call. Asserted separately because
        // `evict_expired` does not consult `decide_check_plan` — the sweep is a
        // second way to lose the entry.
        let cache = IdempotencyCache::new();
        let owner = Arc::new(());
        cache
            .entries
            .insert("k".to_string(), back_dated_in_flight("fp", Some(&owner)));

        // WHEN: the background sweep runs
        cache.evict_expired();

        // THEN: the entry is still there
        assert_eq!(cache.len(), 1, "a live call must keep its entry");
        drop(owner);
    }

    #[test]
    fn an_abandoned_reservation_past_the_timeout_is_swept() {
        // GIVEN: the same entry, but its owner has gone
        let cache = IdempotencyCache::new();
        let owner = Arc::new(());
        cache
            .entries
            .insert("k".to_string(), back_dated_in_flight("fp", Some(&owner)));
        drop(owner);

        // WHEN: the sweep runs
        cache.evict_expired();

        // THEN: the timeout reclaims it — that is what it is for
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn an_unowned_in_flight_entry_still_expires_on_the_clock() {
        // GIVEN: an entry admitted without a liveness token (`mark_in_flight`),
        // back-dated past the timeout. Guards against making every ownerless
        // entry immortal.
        let cache = IdempotencyCache::new();
        cache
            .entries
            .insert("k".to_string(), back_dated_in_flight("", None));

        // WHEN: the sweep runs
        cache.evict_expired();

        // THEN: the clock alone reclaims it
        assert_eq!(cache.len(), 0);
    }

    // ── ADR-012: Failed is a terminal state ──────────────────────────────────

    #[test]
    fn a_failed_key_serves_its_error_instead_of_re_executing() {
        // GIVEN: a key settled as failed after dispatch
        let cache = Arc::new(IdempotencyCache::new());
        cache.mark_failed_bound("k", json!({"code": -32003, "message": "boom"}), "fp");

        // WHEN/THEN: a lookup reports the failure and admission refuses
        assert!(matches!(cache.check("k"), CheckOutcome::Failed(_)));
        let err = enforce(&cache, "k", "fp").expect_err("a failed key must not readmit");
        assert_eq!(err.to_rpc_code(), -32003);
        assert!(err.to_string().contains("boom"), "got: {err}");
    }

    #[test]
    fn an_expired_failed_key_is_a_first_attempt_again() {
        // GIVEN/THEN: a failed entry ages out under the same rule as a completed
        // one, so a failed key is never held past COMPLETED_TTL.
        //
        // Asserted on the mapping rather than by back-dating an `Instant`:
        // COMPLETED_TTL is 24 hours, and `Instant::now().checked_sub` of 24
        // hours returns `None` on any host booted more recently than that —
        // which is most of them.
        assert_eq!(
            decide_check_plan(CacheEntryStatus::ExpiredFailed),
            (CheckPlan::Proceed, true)
        );
        assert!(
            IdempotencyState::Failed(json!({"code": -1}), Instant::now()).is_expired()
                == IdempotencyState::Completed(json!({}), Instant::now()).is_expired(),
            "Failed must age on the same clock as Completed"
        );
    }

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
    fn check_reclaims_an_in_flight_key_whose_owner_is_gone() {
        // GIVEN: an in-flight entry past IN_FLIGHT_TIMEOUT with no live owner
        // WHEN: a second caller checks the key
        // THEN: proceed, and the dead entry is evicted. A live owner would have
        // classified LiveInFlight and been refused; only an abandoned
        // reservation is reclaimed, and nothing else reclaims it in this tree.
        let cache = IdempotencyCache::new();
        cache.entries.insert(
            "stale".to_string(),
            Entry::new(
                IdempotencyState::InFlight(
                    Instant::now()
                        .checked_sub(IN_FLIGHT_TIMEOUT)
                        .expect("fixture needs a host booted longer ago than IN_FLIGHT_TIMEOUT")
                        .checked_sub(Duration::from_secs(1))
                        .expect("fixture needs a host booted longer ago than IN_FLIGHT_TIMEOUT"),
                ),
                "",
            ),
        );
        assert!(
            matches!(cache.check("stale"), CheckOutcome::Proceed),
            "an abandoned reservation must not wedge the key forever"
        );
        assert_eq!(cache.len(), 0, "the dead entry must be evicted");
        assert_eq!(
            decide_check_plan(CacheEntryStatus::StaleInFlight),
            (CheckPlan::Proceed, true)
        );
    }

    #[test]
    fn check_evicts_expired_completed_and_returns_proceed() {
        // GIVEN: a completed entry whose TTL has elapsed
        // WHEN: checking the key
        // THEN: Proceed (expired entry evicted)
        let cache = IdempotencyCache::new();
        cache.entries.insert(
            "old".to_string(),
            Entry::new(
                IdempotencyState::Completed(
                    json!(null),
                    Instant::now()
                        .checked_sub(COMPLETED_TTL)
                        .unwrap()
                        .checked_sub(Duration::from_secs(1))
                        .unwrap(),
                ),
                "",
            ),
        );
        assert!(matches!(cache.check("old"), CheckOutcome::Proceed));
        assert_eq!(cache.len(), 0, "expired entry must be removed");
    }

    // ── evict_expired ─────────────────────────────────────────────────────────

    /// Repro harness for the eviction race gpt-review raised on 2026-09-08.
    ///
    /// A race has no honest single-shot failing test, so the repair protocol
    /// asks for a deterministic repro harness instead. The invariant is
    /// one-sided and holds under any interleaving: a freshly admitted entry is
    /// not expired, so `evict_expired` must never remove it. Under the previous
    /// collect-then-remove pass it could — the evictor selected the key while
    /// the old entry was stale and deleted whatever held the key afterwards.
    #[test]
    fn eviction_never_removes_a_fresh_entry_that_replaced_an_expired_one() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        // GIVEN: one key that keeps alternating between an expired entry the
        // evictor wants and a fresh entry it must leave alone
        let cache = Arc::new(IdempotencyCache::new());
        let stop = Arc::new(AtomicBool::new(false));
        let lost = Arc::new(AtomicUsize::new(0));
        let expired_at = Instant::now()
            .checked_sub(COMPLETED_TTL)
            .unwrap()
            .checked_sub(Duration::from_secs(1))
            .unwrap();

        // WHEN: the background evictor runs against that churn
        let evictor = {
            let cache = Arc::clone(&cache);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    cache.evict_expired();
                }
            })
        };

        let deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < deadline {
            cache.entries.insert(
                "k".to_string(),
                Entry::new(IdempotencyState::Completed(json!(null), expired_at), ""),
            );
            cache.entries.insert(
                "k".to_string(),
                Entry::new(IdempotencyState::InFlight(Instant::now()), ""),
            );
            if !cache.entries.contains_key("k") {
                lost.fetch_add(1, Ordering::Relaxed);
            }
        }
        stop.store(true, Ordering::Relaxed);
        evictor.join().unwrap();

        // THEN: the fresh entry survived every pass
        assert_eq!(
            lost.load(Ordering::Relaxed),
            0,
            "eviction deleted an entry that was not expired"
        );
    }

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
            Entry::new(
                IdempotencyState::Completed(
                    json!(2),
                    Instant::now()
                        .checked_sub(COMPLETED_TTL)
                        .unwrap()
                        .checked_sub(Duration::from_secs(1))
                        .unwrap(),
                ),
                "",
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
        let cache = Arc::new(IdempotencyCache::new());
        let outcome = enforce(&cache, "k1", "fp1").expect("should not fail");
        assert!(matches!(outcome, GuardOutcome::Proceed(_)));
        assert!(matches!(cache.check("k1"), CheckOutcome::InFlight));
    }

    #[test]
    fn enforce_returns_cached_result_for_completed_key() {
        // GIVEN: a completed key in cache
        // WHEN: enforcing on that key
        // THEN: CachedResult with the stored value
        let cache = Arc::new(IdempotencyCache::new());
        let expected = json!({"done": true});
        cache.mark_in_flight("k2");
        cache.mark_completed("k2", expected.clone());
        match enforce(&cache, "k2", "fp2").expect("should not fail") {
            GuardOutcome::CachedResult(v) => assert_eq!(v, expected),
            GuardOutcome::Proceed(_) => panic!("expected CachedResult"),
        }
    }

    #[test]
    fn enforce_returns_error_for_in_flight_key() {
        // GIVEN: a live in-flight key
        // WHEN: enforcing on the same key from a concurrent caller
        // THEN: Err with code 409
        let cache = Arc::new(IdempotencyCache::new());
        cache.mark_in_flight("k3");
        let err = enforce(&cache, "k3", "fp3").expect_err("should return 409");
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
            Entry::new(
                IdempotencyState::Completed(
                    json!(null),
                    Instant::now()
                        .checked_sub(COMPLETED_TTL)
                        .unwrap()
                        .checked_sub(Duration::from_secs(1))
                        .unwrap(),
                ),
                "",
            ),
        );

        spawn_cleanup_task(Arc::clone(&cache), Duration::from_millis(10));

        // Wait a bit for the task to run
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(cache.len(), 0, "stale entry should have been evicted");
    }

    #[test]
    fn released_then_completed_entry_stays_bound_to_its_own_request() {
        // GIVEN: a key admitted for request A, whose dispatch failed — the
        // invoke path releases the reservation and then still stores the
        // structured error result (`src/gateway/meta_mcp/invoke.rs:1480`,
        // `:1836`), which `complete` documents as deliberate.
        let cache = Arc::new(IdempotencyCache::new());
        let GuardOutcome::Proceed(mut reservation) = enforce(&cache, "k", "fp-A").unwrap() else {
            panic!("a fresh key is admitted");
        };
        reservation.release();
        assert!(reservation.complete(&json!({"isError": true})));

        // WHEN: a *different* request reuses the same client-supplied key
        let outcome = enforce(&cache, "k", "fp-B");

        // THEN: it is refused, not answered with request A's error. A stored
        // result carries the fingerprint it was admitted for; an entry that
        // binds nothing answers every later request for the whole TTL.
        let Err(err) = outcome else {
            panic!("key bound to fp-A must not serve fp-B");
        };
        // Named, not merely `is_err`: the in-flight and at-capacity refusals
        // are errors too, and neither would prove the binding held.
        let message = err.to_string();
        assert!(
            message.contains("already in use for a different request"),
            "expected the fingerprint-mismatch refusal, got: {message}"
        );
    }
}
