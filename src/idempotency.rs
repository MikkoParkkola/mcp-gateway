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
//!    - Not found → mark `InFlight`, execute, store `Completed`.
//!    - `InFlight` and not timed-out → return `Err(Error::DuplicateRequest)`.
//!    - `Completed` → return cached result immediately (no re-execution).
//! 4. A background task periodically evicts stale entries to bound memory usage.

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry as MapEntry;
use serde_json::Value;
use tracing::debug;

use crate::hashing::{canonical_json, sha256_hex_chunks};
use crate::{Error, Result};

#[path = "idempotency/admission.rs"]
pub(crate) mod admission;
mod guard;
// #1962: `disarm`, kept out of this file's size baseline.
mod reservation_arm;
pub use guard::{
    FIREWALL_REFUSAL_MARKER, GuardOutcome, cached_error_parts, enforce, spawn_cleanup_task,
};

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
    /// Tool call was dispatched and answered with an error.  Holds the JSON-RPC
    /// error object (`{"code", "message"}`) and when it was stored.
    ///
    /// A terminal alongside [`Completed`](Self::Completed), not a variant of
    /// in-flight: once a call has been dispatched, an error answer is an
    /// outcome, and a transport failure after the backend acted is
    /// indistinguishable from one before it. Releasing the key on failure would
    /// hand the caller's retry a clean key for a mutation that may already have
    /// committed (ADR-012).
    Failed(Value, Instant),
}

impl IdempotencyState {
    /// Return `true` when this entry is stale and should be evicted.
    ///
    /// A clock reading, and only that. Staleness of an *in-flight* entry is a
    /// liveness question rather than a clock one (ADR-012 amendment A2), and a
    /// state cannot see the owner that decides it: the cache classifies entries
    /// against their owner token instead, so neither admission nor the
    /// background sweep consults this method.
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

/// The liveness token an in-flight entry is judged against.
///
/// ADR-012 amendment A2: *"Liveness must therefore be a token held strongly
/// from before the admission is published until settlement has finished, not
/// the reservation's own refcount."* A `Weak<IdempotencyReservation>` cannot
/// express that rule — `Arc` drops the strong count to zero *before* running the
/// inner value's `Drop`, so the handle is already dead while `Drop` is still
/// storing the terminal state, and a sweep landing in that window frees a key
/// whose mutation may have committed.
///
/// A separate token closes the window by construction rather than by timing: it
/// is a *field* of [`IdempotencyReservation`], and a struct's fields are dropped
/// only once its `Drop::drop` body has returned, so the token outlives
/// settlement.
#[derive(Debug)]
pub(crate) struct OwnerToken;

/// One tracked key: its state, the request it was minted for, and a handle to
/// the reservation that owns it.
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
    /// The owner whose liveness decides whether an aged in-flight entry is
    /// stale. Dangling for every entry not published by a reservation — a
    /// terminal state ages out on the clock and never consults it.
    owner: Weak<OwnerToken>,
    /// MIK-7116.MIN.2: what the dispatch behind a completed result read
    /// before any transform, kept in the same entry as the result.
    read: Option<crate::security::tenant_reads::ReadAttribution>,
    /// MIK-7991: what the gateway wrote into a completed result on the call
    /// that stored it, restored on a replay so its receipt leaves it out.
    writes: crate::gateway::WriteRecord,
}

impl Entry {
    fn new(state: IdempotencyState, fingerprint: &str) -> Self {
        Self {
            state,
            fingerprint: fingerprint.to_string(),
            owner: Weak::new(),
            read: None,
            writes: crate::gateway::WriteRecord::default(),
        }
    }

    /// An in-flight entry published on behalf of a live reservation.
    fn in_flight(fingerprint: &str, owner: &Arc<OwnerToken>) -> Self {
        Self {
            state: IdempotencyState::InFlight(Instant::now()),
            fingerprint: fingerprint.to_string(),
            owner: Arc::downgrade(owner),
            read: None,
            writes: crate::gateway::WriteRecord::default(),
        }
    }

    /// Whether the reservation that published this entry is still running.
    ///
    /// `strong_count` rather than `upgrade` because the answer is the same and
    /// nothing here needs the value back.
    fn owner_is_live(&self) -> bool {
        self.owner.strong_count() > 0
    }

    /// Whether `fingerprint` is the request this entry was admitted for.
    fn matches(&self, fingerprint: &str) -> bool {
        self.fingerprint.is_empty() || self.fingerprint == fingerprint
    }
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
    /// A failed entry exists — return the cached JSON-RPC error object.
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
        // Both in-flight statuses refuse, which is half of the fix. ADR-012
        // consequence 3: "`decide_check_plan` maps `StaleInFlight` to
        // `CheckPlan::InFlight`, so the retry is told the call is still
        // running." A stale entry is one whose owner is *gone*, and reclaiming
        // it is the sweep's job alone — an admission that frees a key here is
        // the second execution on one key this ADR exists to stop.
        CacheEntryStatus::LiveInFlight | CacheEntryStatus::StaleInFlight => {
            (CheckPlan::InFlight, false)
        }
        CacheEntryStatus::LiveCompleted => (CheckPlan::Completed, false),
        CacheEntryStatus::LiveFailed => (CheckPlan::Failed, false),
        // A terminal entry ages out on the clock; no owner can still be using it.
        CacheEntryStatus::ExpiredCompleted | CacheEntryStatus::ExpiredFailed => {
            (CheckPlan::Proceed, true)
        }
    }
}

/// Outcome of the atomic admission step performed by [`IdempotencyCache::admit`].
#[derive(Debug)]
pub(crate) enum AdmitOutcome {
    /// The key is now registered in-flight for this caller alone.
    Proceed,
    /// Another caller holds a live in-flight entry.
    InFlight,
    /// A completed entry exists — return the cached result, with the
    /// reading (MIK-7116.MIN.2) and the gateway's write record (MIK-7991)
    /// kept beside it, read under the same lock.
    Completed(
        Value,
        Option<crate::security::tenant_reads::ReadAttribution>,
        crate::gateway::WriteRecord,
    ),
    /// A failed entry exists — return the cached JSON-RPC error object.
    Failed(Value),
    /// The cache is at [`MAX_ENTRIES`] and this key is not tracked yet.
    AtCapacity,
    /// The key is tracked, but for a different request.
    Mismatch,
}

/// The single staleness predicate, shared by admission and the sweep.
///
/// ADR-012 consequence 3 requires the two to agree: *"`evict_expired`
/// (`src/idempotency.rs:398`) sweeps on the same predicate, so a call running
/// past the timeout keeps its entry through the background cleanup as well as
/// through admission."* They differ in what they *do* with a stale entry — one
/// refuses, the other reclaims — but a second copy of the rule deciding *which*
/// entries are stale is the defect, so both route through here.
///
/// The direction, stated because it is exactly invertible: an aged in-flight
/// entry whose owner is still alive is **not** stale. The ADR mandates that
/// `is_expired` "reports an in-flight entry stale only once that handle is
/// dead". Aged *and* ownerless is stale; the timeout then "does what it was
/// introduced for — reclaiming entries whose owner is gone — and nothing else".
#[must_use]
fn classify(entry: &Entry) -> CacheEntryStatus {
    match &entry.state {
        IdempotencyState::InFlight(started)
            if entry.owner_is_live() || started.elapsed() <= IN_FLIGHT_TIMEOUT =>
        {
            CacheEntryStatus::LiveInFlight
        }
        IdempotencyState::InFlight(_) => CacheEntryStatus::StaleInFlight,
        IdempotencyState::Completed(_, stored) if stored.elapsed() <= COMPLETED_TTL => {
            CacheEntryStatus::LiveCompleted
        }
        IdempotencyState::Completed(_, _) => CacheEntryStatus::ExpiredCompleted,
        IdempotencyState::Failed(_, stored) if stored.elapsed() <= COMPLETED_TTL => {
            CacheEntryStatus::LiveFailed
        }
        IdempotencyState::Failed(_, _) => CacheEntryStatus::ExpiredFailed,
    }
}

/// Whether `status` names an entry no live owner can still be settling, and
/// which the sweep may therefore reclaim.
#[must_use]
fn is_reclaimable(status: CacheEntryStatus) -> bool {
    matches!(
        status,
        CacheEntryStatus::StaleInFlight
            | CacheEntryStatus::ExpiredCompleted
            | CacheEntryStatus::ExpiredFailed
    )
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
    /// An in-flight entry answers `InFlight` for as long as its owner is
    /// running, past [`IN_FLIGHT_TIMEOUT`] included; only expired *terminal*
    /// entries are evicted here and treated as `Proceed`. Reclaiming an
    /// in-flight entry whose owner is gone is left to `evict_expired`.
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

        let status = classify(entry.value());

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
                    unreachable!("live failed status must hold a failed value");
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
    pub(crate) fn admit(
        &self,
        key: &str,
        fingerprint: &str,
        owner: &Arc<OwnerToken>,
    ) -> AdmitOutcome {
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
                let (plan, evict) = decide_check_plan(classify(occupied.get()));
                if !matches!(plan, CheckPlan::Proceed) && !occupied.get().matches(fingerprint) {
                    return AdmitOutcome::Mismatch;
                }
                match plan {
                    CheckPlan::InFlight => AdmitOutcome::InFlight,
                    CheckPlan::Completed => {
                        let IdempotencyState::Completed(value, _) = &occupied.get().state else {
                            unreachable!("live completed status must hold a completed value");
                        };
                        AdmitOutcome::Completed(
                            value.clone(),
                            occupied.get().read.clone(),
                            occupied.get().writes.clone(),
                        )
                    }
                    CheckPlan::Failed => {
                        let IdempotencyState::Failed(error, _) = &occupied.get().state else {
                            unreachable!("live failed status must hold a failed value");
                        };
                        AdmitOutcome::Failed(error.clone())
                    }
                    CheckPlan::Proceed => {
                        debug_assert!(evict, "an occupied entry only proceeds after eviction");
                        // Replacing in place keeps the entry count flat, so a
                        // stale entry never costs a caller its admission.
                        occupied.insert(Entry::in_flight(fingerprint, owner));
                        debug!(key, "Replaced stale idempotency entry");
                        AdmitOutcome::Proceed
                    }
                }
            }
            MapEntry::Vacant(vacant) => {
                if at_capacity {
                    return AdmitOutcome::AtCapacity;
                }
                vacant.insert(Entry::in_flight(fingerprint, owner));
                AdmitOutcome::Proceed
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
        self.mark_completed_read(
            key,
            result,
            fingerprint,
            (None, crate::gateway::WriteRecord::default()),
        )
    }

    /// [`Self::mark_completed_bound`] with the dispatch's reading kept in the
    /// same entry (MIN.2).
    fn mark_completed_read(
        &self,
        key: &str,
        result: Value,
        fingerprint: &str,
        (read, writes): (
            Option<crate::security::tenant_reads::ReadAttribution>,
            crate::gateway::WriteRecord,
        ),
    ) -> bool {
        if !crate::protocol::cacheable::is_final(&result) {
            self.entries.remove(key);
            debug!(key, "Refused to cache a non-final result");
            return false;
        }
        let mut entry = Entry::new(
            IdempotencyState::Completed(result, Instant::now()),
            fingerprint,
        );
        entry.read = read;
        entry.writes = writes;
        self.entries.insert(key.to_string(), entry);
        true
    }

    /// Store `error` as the terminal outcome for `key`, bound to the admitting
    /// request's `fingerprint`.
    ///
    /// Unlike [`mark_completed_bound`](Self::mark_completed_bound) there is no
    /// finality test: an error answer is already terminal, and the `is_final`
    /// rule exists to keep an `input_required` interim retryable, which is a
    /// result and never reaches here.
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
        self.entries
            .retain(|_, entry| !is_reclaimable(classify(entry)));
        let count = before.saturating_sub(self.entries.len());
        if count > 0 {
            debug!(count, "Evicted stale idempotency entries");
        }
    }

    /// Age the in-flight entry for `key` by `by`, as though its call had been
    /// running that much longer. Returns whether an in-flight entry was aged.
    ///
    /// A test seam, and the only one: staleness is measured against the process
    /// clock, so the aged state the ADR-012 acceptance rows are stated against
    /// is otherwise reachable only by waiting out [`IN_FLIGHT_TIMEOUT`] in real
    /// time. It moves the start instant and touches nothing else — in
    /// particular not the owner handle — so it cannot change which rule those
    /// rows observe.
    #[doc(hidden)]
    pub fn age_in_flight(&self, key: &str, by: Duration) -> bool {
        let Some(mut entry) = self.entries.get_mut(key) else {
            return false;
        };
        let IdempotencyState::InFlight(started) = &mut entry.state else {
            return false;
        };
        let Some(aged) = started.checked_sub(by) else {
            return false;
        };
        *started = aged;
        true
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
mod verification;

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
/// acted a retry must not execute it again. A call that was dispatched and
/// answered with an error settles through [`fail`](Self::fail) instead — the
/// backend may have acted, and from here that is indistinguishable from not
/// having acted (ADR-012).
#[derive(Debug)]
pub struct IdempotencyReservation {
    cache: Arc<IdempotencyCache>,
    key: String,
    /// The fingerprint the key was admitted for, so a result stored after the
    /// entry is gone stays bound to this request instead of matching any.
    fingerprint: String,
    settled: bool,
    on_drop: OnDrop,
    /// The liveness token this reservation keeps alive. Held, never read: the
    /// cache entry's weak handle goes dead when this field is dropped, which
    /// happens only after `Drop::drop` has finished settling the key
    /// (ADR-012 A2).
    _owner: Arc<OwnerToken>,
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
    fn new(
        cache: Arc<IdempotencyCache>,
        key: &str,
        fingerprint: &str,
        owner: Arc<OwnerToken>,
    ) -> Self {
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

    /// Whether a settling call already stored or released the key.
    #[must_use]
    pub(crate) fn is_settled(&self) -> bool {
        self.settled
    }

    /// Settle by storing `result`. Returns whether it was cached — a non-final
    /// result is refused by [`IdempotencyCache::mark_completed`] and the key is
    /// released instead, so the call stays retryable.
    ///
    /// Callable after [`release`](Self::release): a failed dispatch releases the
    /// key first and may still store a structured error result afterwards, which
    /// is the behaviour the invoke path already relied on.
    pub fn complete(&mut self, result: &Value) -> bool {
        self.complete_read(result, (None, crate::gateway::WriteRecord::default()))
    }

    /// [`Self::complete`] with the dispatch's reading (MIN.2) and the
    /// gateway's write record (MIK-7991) kept in the entry.
    pub(crate) fn complete_read(
        &mut self,
        result: &Value,
        read: (
            Option<crate::security::tenant_reads::ReadAttribution>,
            crate::gateway::WriteRecord,
        ),
    ) -> bool {
        self.settled = true;
        self.cache
            .mark_completed_read(&self.key, result.clone(), &self.fingerprint, read)
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

    /// Settle by storing `error` as the terminal outcome, so a retry of the
    /// same key is served the same JSON-RPC error rather than readmitted.
    ///
    /// `error` is the error object the caller would otherwise have seen
    /// (`{"code", "message"}`). Use this — not [`release`](Self::release) — for
    /// any failure after dispatch: the backend may already have acted, and the
    /// two cases are indistinguishable from here (ADR-012 consequence 1).
    pub fn fail(&mut self, error: &Value) {
        self.settled = true;
        self.cache
            .mark_failed_bound(&self.key, error.clone(), &self.fingerprint);
    }

    /// Settle by releasing the key so the call can be retried.
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
