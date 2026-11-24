// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Per-client cost accounting for gateway tool calls.
//!
//! Tracks token usage and estimated spend per session and per API key,
//! with rolling time windows (24 h / 7 d / 30 d, to the hour) for reporting.
//! It enforces no limit: the enforced caps are the budget enforcer's
//! (`enforcer.rs`). Everything held is a running sum (tally.rs), so
//! memory never grows with the number of calls (MIK-8000).
//!
//! # Design
//!
//! ```text
//! CostTracker  (one global Arc, shared via AppState + MetaMcp)
//!   ├── per_session : DashMap<session_id, SessionCost>
//!   ├── per_key     : DashMap<api_key_name, KeyCost>
//!   └── per_caller  : session-less spend by caller key (caller.rs)
//! ```
//!
//! `record()` and `record_caller()` are the write paths; everything else is read-only.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use tally::{Series, Slot, ToolTally};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default price per million tokens (Claude Opus 4.6 input).
pub const DEFAULT_PRICE_PER_MILLION: f64 = 15.0;

// ── CostRecord ────────────────────────────────────────────────────────────────

/// A single recorded tool-call cost event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostRecord {
    /// Unix timestamp (seconds) of the call, `None` when the clock read
    /// before 1970 and the call could not be dated (MIK-8202 P4b).
    pub timestamp: Option<u64>,
    /// Backend server name.
    pub backend: String,
    /// Tool name.
    pub tool: String,
    /// Estimated token count (0 if unknown).
    pub token_count: u64,
    /// Estimated cost in USD.
    pub estimated_cost_usd: f64,
}

impl CostRecord {
    /// Create a new `CostRecord`, computing the cost from `token_count`.
    #[must_use]
    pub fn new(backend: &str, tool: &str, token_count: u64, price_per_million: f64) -> Self {
        #[allow(clippy::cast_precision_loss)]
        let estimated_cost_usd = token_count as f64 * price_per_million / 1_000_000.0;
        Self::charged(backend, tool, token_count, estimated_cost_usd)
    }

    /// A record priced by the caller: `cost_usd` is what the call was charged,
    /// dated now as every record is.
    pub(crate) fn charged(backend: &str, tool: &str, token_count: u64, cost_usd: f64) -> Self {
        let estimated_cost_usd = cost_usd;
        Self {
            timestamp: crate::clock::unix_secs().ok(),
            backend: backend.to_string(),
            tool: tool.to_string(),
            token_count,
            estimated_cost_usd,
        }
    }
}

// ── Report windows ────────────────────────────────────────────────────────────

/// A rolling time window of the per-key cost report. Reporting only: no limit is enforced over these windows; the
/// enforced caps are the budget enforcer's daily ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetWindow {
    /// 24-hour rolling window.
    Day,
    /// 7-day rolling window.
    Week,
    /// 30-day rolling window.
    Month,
}

impl BudgetWindow {
    fn secs(self) -> u64 {
        match self {
            Self::Day => 86_400,
            Self::Week => 7 * 86_400,
            Self::Month => 30 * 86_400,
        }
    }
}

// ── Per-session accumulator ───────────────────────────────────────────────────

/// Cost accumulator for a single client session.
#[derive(Debug)]
pub struct SessionCost {
    /// Session identifier.
    pub session_id: String,
    /// API-key name for this session (if any).
    pub api_key_name: Option<String>,
    /// Running per-tool sums: bounded by the catalog, never by the call count.
    by_tool: parking_lot::Mutex<ToolTally>,
    /// Running token total (fast path).
    total_tokens: AtomicU64,
    /// Running cost total (stored as micro-dollars to avoid fp atomics).
    total_cost_micro_usd: AtomicU64,
    /// Call count.
    call_count: AtomicU64,
    /// Session start time, `None` when the clock read before 1970 at the
    /// first call (MIK-8202 P4b).
    pub started_at: Option<u64>,
}

impl SessionCost {
    fn new(session_id: &str, api_key_name: Option<String>) -> Self {
        Self {
            session_id: session_id.to_string(),
            api_key_name,
            by_tool: parking_lot::Mutex::new(ToolTally::default()),
            total_tokens: AtomicU64::new(0),
            total_cost_micro_usd: AtomicU64::new(0),
            call_count: AtomicU64::new(0),
            started_at: crate::clock::unix_secs().ok(),
        }
    }

    fn record(&self, rec: &CostRecord) {
        self.total_tokens
            .fetch_add(rec.token_count, Ordering::Relaxed);
        let micro = tally::micro(rec.estimated_cost_usd);
        self.total_cost_micro_usd
            .fetch_add(micro, Ordering::Relaxed);
        self.call_count.fetch_add(1, Ordering::Relaxed);
        self.by_tool
            .lock()
            .add(&rec.backend, &rec.tool, rec.token_count, micro);
    }

    /// Snapshot the session cost.
    #[must_use]
    pub fn snapshot(&self) -> SessionCostSnapshot {
        let (by_backend, by_tool, _) = self.by_tool.lock().breakdown();
        #[allow(clippy::cast_precision_loss)]
        let total_cost_usd = self.total_cost_micro_usd.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        SessionCostSnapshot {
            session_id: self.session_id.clone(),
            api_key_name: self.api_key_name.clone(),
            started_at: self.started_at,
            call_count: self.call_count.load(Ordering::Relaxed),
            total_tokens: self.total_tokens.load(Ordering::Relaxed),
            total_cost_usd,
            by_backend,
            by_tool,
        }
    }
}

/// Serialisable snapshot of a session's cost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCostSnapshot {
    /// Session ID.
    pub session_id: String,
    /// API key name (if any).
    pub api_key_name: Option<String>,
    /// Session start (unix secs), `None` when undated (MIK-8202 P4b).
    pub started_at: Option<u64>,
    /// Total calls recorded.
    pub call_count: u64,
    /// Total tokens across all calls.
    pub total_tokens: u64,
    /// Total estimated cost (USD).
    pub total_cost_usd: f64,
    /// Cost breakdown by backend.
    pub by_backend: Vec<BackendCost>,
    /// Cost breakdown by tool.
    pub by_tool: Vec<ToolCost>,
}

// ── Per-API-key accumulator ───────────────────────────────────────────────────

/// Cost accumulator for a named API key, with rolling time windows.
#[derive(Debug)]
pub struct KeyCost {
    /// API key name.
    pub name: String,
    /// The key's hour and day series plus its lifetime per-tool sums. Their
    /// size follows the clock and the catalog, not how often the key calls
    /// (MIK-8000). Both series sit under this one lock, so a copy taken for a
    /// save holds each record in both or in neither.
    spend: parking_lot::Mutex<(Series, ToolTally)>,
    /// Unix second of the latest spend, for the idle sweep. Stored as 0
    /// when undated (a key born, or spending only, on a clock before 1970);
    /// 0 is never read as a time (MIK-8202 P4b).
    last_spend: AtomicU64,
}

impl KeyCost {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            spend: parking_lot::Mutex::default(),
            // A key is born active: a sweep between its creation and its
            // first spend must not take it for a month-idle one. Born on a
            // dark clock it is undated (0), which the sweep never reads as
            // a time, so it is never swept as idle either (MIK-8202 P4b).
            last_spend: AtomicU64::new(crate::clock::unix_secs().unwrap_or_default()),
        }
    }

    fn record(&self, rec: &CostRecord, now: Option<u64>) {
        let micro = tally::micro(rec.estimated_cost_usd);
        let mut spend = self.spend.lock();
        // An undated record counts in the lifetime sums but enters no time
        // window: it cannot be dated (MIK-8202 P4b).
        if let (Some(at), Some(now)) = (rec.timestamp, now) {
            spend.0.add(at, now, rec.token_count, micro);
        }
        spend.1.add(&rec.backend, &rec.tool, rec.token_count, micro);
        if let Some(at) = rec.timestamp {
            self.last_spend.fetch_max(at, Ordering::Relaxed);
        }
    }

    /// True once nothing the key holds is dated after its windows: its last
    /// spend is out of the hour buckets and the local dates. A key with no dated spend is never idle
    /// (MIK-8202 P4b).
    fn idle(&self, now: u64) -> bool {
        let last = self.last_spend.load(Ordering::Relaxed);
        // Both cuts the series age by: with a 25-hour day in the month the
        // dates outlast the hours, and the entry must outlast both.
        last != 0
            && (last / 3600).expired(now / 3600)
            && tally::local_date(last).expired(tally::local_date(now))
    }

    /// The key's spend rate over the last three complete hours before `now`,
    /// in USD per hour. The hour holding `now` is left out; an hour with no
    /// spend counts as zero.
    #[cfg(any(test, feature = "cost-governance"))]
    #[cfg_attr(not(feature = "webui"), allow(dead_code))]
    #[must_use]
    pub(crate) fn rate_3h(&self, now: u64) -> f64 {
        let hour = now / 3600;
        let first = hour.saturating_sub(3);
        let micro = self
            .spend
            .lock()
            .0
            .hours
            .rows()
            .into_iter()
            .filter(|(h, ..)| mutant!("s7-cur", (first..=hour).contains(h), (first..hour).contains(h)))
            .fold(0u64, |sum, (.., micro)| sum.saturating_add(micro));
        #[allow(clippy::cast_precision_loss)]
        let usd = micro as f64 / 1_000_000.0;
        usd / 3.0
    }

    /// Compute cost totals for a given rolling window, `None` when the clock
    /// cannot date the window (MIK-8202 P4b).
    fn window_totals(&self, window_secs: u64) -> Option<(u64, f64)> {
        let now = crate::clock::unix_secs().ok()?;
        Some(self.spend.lock().0.hours.totals(now, window_secs))
    }

    /// Produce a serialisable snapshot with all three time windows.
    #[must_use]
    pub fn snapshot(&self) -> KeyCostSnapshot {
        let window = |secs| {
            self.window_totals(secs).map_or(
                WindowStats {
                    tokens: None,
                    cost_usd: None,
                },
                |(tokens, cost_usd)| WindowStats {
                    tokens: Some(tokens),
                    cost_usd: Some(cost_usd),
                },
            )
        };

        // All-time per-tool sums.
        let (_, by_tool, _) = self.spend.lock().1.breakdown();

        KeyCostSnapshot {
            api_key_name: self.name.clone(),
            window_24h: window(BudgetWindow::Day.secs()),
            window_7d: window(BudgetWindow::Week.secs()),
            window_30d: window(BudgetWindow::Month.secs()),
            hard_limit_usd: None,
            budget_status: "Ok".to_string(),
            by_tool,
        }
    }
}

/// Aggregate stats for a rolling time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowStats {
    /// Total tokens in the window, `None` when the clock cannot date it
    /// (MIK-8202 P4b).
    pub tokens: Option<u64>,
    /// Total cost in USD, `None` when the clock cannot date it (MIK-8202 P4b).
    pub cost_usd: Option<f64>,
}

/// Serialisable snapshot for a single API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCostSnapshot {
    /// API key name.
    pub api_key_name: String,
    /// Spend in the past 24 hours. With cost governance built, the 24 h, 7 d
    /// and 30 d windows survive a restart through `spend-history.json`; the
    /// time the gateway was down stays a gap.
    pub window_24h: WindowStats,
    /// Spend in the past 7 days.
    pub window_7d: WindowStats,
    /// Spend in the past 30 days.
    pub window_30d: WindowStats,
    /// Always `null`: no per-key rolling limit is enforced. The field stays
    /// so the report's shape does not change; MIK-8863.API10.5 fills it from
    /// the budget enforcer, which holds the per-key daily caps that are
    /// enforced.
    pub hard_limit_usd: Option<f64>,
    /// Always `"Ok"`, for the same reason as `hard_limit_usd`: it judges no
    /// limit. Read the budget enforcer for a key's real standing.
    pub budget_status: String,
    /// Per-tool breakdown since this process started (never saved, so it
    /// starts at zero after a restart); tools past the row cap share
    /// `(other)`.
    pub by_tool: Vec<ToolCost>,
}

// ── Breakdown types ───────────────────────────────────────────────────────────

/// Per-backend cost breakdown entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCost {
    /// Backend name.
    pub backend: String,
    /// Number of calls.
    pub call_count: u64,
    /// Total token count.
    pub token_count: u64,
    /// Total cost in USD.
    pub cost_usd: f64,
}

/// Per-tool cost breakdown entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCost {
    /// "backend:tool" key.
    pub tool_key: String,
    /// Number of calls.
    pub call_count: u64,
    /// Total token count.
    pub token_count: u64,
    /// Total cost in USD.
    pub cost_usd: f64,
}

// ── CostTracker ───────────────────────────────────────────────────────────────

/// Global cost tracker — holds per-session and per-API-key accumulators.
///
/// Designed to be wrapped in `Arc` and shared across the gateway.
pub struct CostTracker {
    per_session: DashMap<String, Arc<SessionCost>>,
    per_key: DashMap<String, Arc<KeyCost>>,
    /// Totals of calls with no session, and of sessions since removed:
    /// `(calls, tokens, micro-USD)`. Counted in the admin aggregate only, never
    /// reported as anyone's session, and kept as counters because no session
    /// end would ever free records.
    sessionless: [AtomicU64; 3],
    /// Session-less spend by caller key (MIK-7653), for the caller's own report.
    per_caller: caller::CallerCosts,
    /// Spend that carries a date but no API key. A dated call adds to one
    /// series only, this or its key's; the gateway-wide series is computed
    /// from them when read.
    keyless: parking_lot::Mutex<Series>,
    /// Restored spend no key of this run holds: rows folded past the key cap
    /// in an earlier run, and keys since removed or renamed. Set by the
    /// restore and never by a save, so a fold is never counted twice.
    #[cfg(feature = "cost-governance")]
    carried: parking_lot::Mutex<Series>,
    /// Set when a refused history file could not be set aside: this run then
    /// never saves over it.
    #[cfg(feature = "cost-governance")]
    history_off: std::sync::atomic::AtomicBool,
    /// Where the history was last written and the SHA-256 of what was
    /// written, so a save of an unchanged state writes nothing.
    #[cfg(feature = "cost-governance")]
    history_last: parking_lot::Mutex<Option<(std::path::PathBuf, String)>>,
    /// When the next idle-key sweep may run (MIK-8000).
    next_key_sweep: AtomicU64,
}

impl CostTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_session: DashMap::new(),
            per_key: DashMap::new(),
            sessionless: <[AtomicU64; 3]>::default(),
            per_caller: caller::CallerCosts::default(),
            keyless: parking_lot::Mutex::default(),
            #[cfg(feature = "cost-governance")]
            carried: parking_lot::Mutex::default(),
            #[cfg(feature = "cost-governance")]
            history_off: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "cost-governance")]
            history_last: parking_lot::Mutex::new(None),
            next_key_sweep: AtomicU64::new(0),
        }
    }

    /// Record a tool-call cost event.
    ///
    /// `session_id` — MCP session identifier.
    /// `api_key_name` — the per-key cost name: the API key's name for an
    /// API-key caller, `None` for any other (anonymous, the static bearer, a
    /// dashboard session, an OIDC or key-server identity). MIK-8507.
    /// `backend` / `tool` — server and tool identifiers.
    /// `token_count` — estimated tokens (0 if unknown).
    /// `price_per_million` — USD per million tokens.
    pub fn record(
        &self,
        session_id: &str,
        api_key_name: Option<&str>,
        backend: &str,
        tool: &str,
        token_count: u64,
        price_per_million: f64,
    ) {
        let rec = CostRecord::new(backend, tool, token_count, price_per_million);
        self.record_charged(session_id, api_key_name, &rec);
    }

    /// [`Self::record`] for a record its caller priced: the dispatch passes
    /// the USD the budget enforcer charged, so these totals and the limits
    /// count one figure per call.
    pub(crate) fn record_charged(
        &self,
        session_id: &str,
        api_key_name: Option<&str>,
        rec: &CostRecord,
    ) {
        // Per-session. An empty id is no session (a 2026-07-28 request has
        // none): keying on it would pool every such caller into one bucket.
        if session_id.is_empty() {
            let micro = tally::micro(rec.estimated_cost_usd);
            for (total, add) in self.sessionless.iter().zip([1, rec.token_count, micro]) {
                total.fetch_add(add, Ordering::Relaxed);
            }
        } else {
            self.per_session
                .entry(session_id.to_string())
                .or_insert_with(|| {
                    Arc::new(SessionCost::new(session_id, api_key_name.map(String::from)))
                })
                .record(rec);
        }

        // Per-key (if we have a key name)
        if let Some(key_name) = api_key_name {
            self.per_key
                .entry(key_name.to_string())
                .or_insert_with(|| Arc::new(KeyCost::new(key_name)))
                .record(rec, rec.timestamp);
            // The entry guard is dropped above: `retain` takes every shard lock.
            // Housekeeping skips its pass when the record is undated (MIK-8202).
            if let Some(now) = rec.timestamp
                && tally::sweep_due(&self.next_key_sweep, now)
            {
                self.per_key.retain(|_, key| !key.idle(now));
            }
        } else if let Some(at) = rec.timestamp {
            let micro = tally::micro(rec.estimated_cost_usd);
            self.keyless.lock().add(at, at, rec.token_count, micro);
        }
    }

    /// Add one session-less call to `caller_key`'s own breakdown. The call
    /// is already in the aggregate and key totals through [`Self::record`],
    /// so this touches neither.
    pub fn record_caller(
        &self,
        caller_key: &str,
        backend: &str,
        tool: &str,
        token_count: u64,
        price_per_million: f64,
    ) {
        let rec = CostRecord::new(backend, tool, token_count, price_per_million);
        self.record_caller_charged(caller_key, &rec);
    }

    /// [`Self::record_caller`] for a record its caller priced.
    pub(crate) fn record_caller_charged(&self, caller_key: &str, rec: &CostRecord) {
        self.per_caller.record(caller_key, rec, rec.timestamp);
    }

    /// `caller_key`'s session-less breakdown, `None` when it has none.
    #[must_use]
    pub fn caller_snapshot(&self, caller_key: &str) -> Option<SessionCostSnapshot> {
        self.per_caller
            .snapshot(caller_key, crate::clock::unix_secs().ok())
    }

    /// Snapshot the cost for a session.
    #[must_use]
    pub fn session_snapshot(&self, session_id: &str) -> Option<SessionCostSnapshot> {
        if session_id.is_empty() {
            return None;
        }
        self.per_session.get(session_id).map(|sc| sc.snapshot())
    }

    /// Snapshot all sessions.
    #[must_use]
    pub fn all_sessions(&self) -> Vec<SessionCostSnapshot> {
        self.per_session
            .iter()
            .map(|e| e.value().snapshot())
            .collect()
    }

    /// [`Self::all_sessions`] with each id replaced by its fingerprint, for a
    /// view that only displays sessions (F9): a raw legacy session id works like
    /// a bearer handle, so it has no place in a UI. The admin APIs that inspect
    /// a session by id keep the raw id, which is their input.
    #[cfg(all(feature = "webui", feature = "cost-governance"))]
    #[must_use]
    pub(crate) fn all_sessions_fingerprinted(&self) -> Vec<SessionCostSnapshot> {
        let mut sessions = self.all_sessions();
        for session in &mut sessions {
            session.session_id = crate::gateway::session_id::session_fp(&session.session_id);
        }
        sessions
    }

    /// Snapshot the cost for a single API key.
    #[must_use]
    pub fn key_snapshot(&self, key_name: &str) -> Option<KeyCostSnapshot> {
        self.per_key.get(key_name).map(|kc| kc.snapshot())
    }

    /// `key_name`'s spend rate over the last three complete hours before
    /// `now`, USD per hour; `None` for a key with no entry.
    #[cfg(feature = "cost-governance")]
    #[cfg_attr(not(feature = "webui"), allow(dead_code))]
    #[must_use]
    pub(crate) fn key_rate_3h(&self, key_name: &str, now: u64) -> Option<f64> {
        self.per_key.get(key_name).map(|key| key.rate_3h(now))
    }

    /// Snapshot all API key accumulators.
    #[must_use]
    pub fn all_keys(&self) -> Vec<KeyCostSnapshot> {
        self.per_key.iter().map(|e| e.value().snapshot()).collect()
    }

    /// Aggregate total across all sessions.
    #[must_use]
    pub fn aggregate(&self) -> AggregateCost {
        let [calls, tokens, micro] = &self.sessionless;
        let mut total_calls = calls.load(Ordering::Relaxed);
        let mut total_tokens = tokens.load(Ordering::Relaxed);
        #[allow(clippy::cast_precision_loss)]
        let mut total_cost = micro.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        for entry in &self.per_session {
            let snap = entry.snapshot();
            total_calls += snap.call_count;
            total_tokens += snap.total_tokens;
            total_cost += snap.total_cost_usd;
        }
        AggregateCost {
            session_count: self.per_session.len() as u64,
            key_count: self.per_key.len() as u64,
            total_calls,
            total_tokens,
            total_cost_usd: total_cost,
        }
    }

    /// Remove a session (called when the MCP session is terminated). Its totals
    /// move into the aggregate-only counters, so ending a session never lowers
    /// the operator's usage total.
    pub fn remove_session(&self, session_id: &str) {
        let Some((_, session)) = self.per_session.remove(session_id) else {
            return;
        };
        let ended = [
            &session.call_count,
            &session.total_tokens,
            &session.total_cost_micro_usd,
        ];
        for (total, add) in self.sessionless.iter().zip(ended) {
            total.fetch_add(add.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }
}

impl Default for CostTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate stats across all sessions and keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateCost {
    /// Number of active sessions.
    pub session_count: u64,
    /// Number of distinct API keys seen.
    pub key_count: u64,
    /// Total tool calls recorded.
    pub total_calls: u64,
    /// Total token count across all calls.
    pub total_tokens: u64,
    /// Total estimated cost in USD.
    pub total_cost_usd: f64,
}

#[cfg(test)]
impl CostTracker {
    /// Entries `key_name` holds in memory: what another answered call can grow.
    pub(crate) fn key_retained(&self, key_name: &str) -> usize {
        self.per_key.get(key_name).map_or(0, |key| {
            let spend = key.spend.lock();
            spend.0.hours.len() + spend.0.days.len() + spend.1.len()
        })
    }

    /// `key_name`'s series as held, `None` when the key has no entry.
    pub(crate) fn key_series(&self, key_name: &str) -> Option<Series> {
        self.per_key
            .get(key_name)
            .map(|key| key.spend.lock().0.clone())
    }

    /// The series of dated spend with no API key.
    pub(crate) fn keyless_series(&self) -> Series {
        self.keyless.lock().clone()
    }

    /// The gateway's series: the sum of the keyless one, every key's and,
    /// with cost governance built, the carried overflow.
    pub(crate) fn gateway_series(&self, now: u64) -> Series {
        // Every input is settled at `now`, the caller's instant, before the
        // sum: a merge ends its window at the newest slot either side holds,
        // so one input holding a slot past another's window would age that
        // one's rows out of the total. Taken as an argument, never read from
        // the wall clock, so a fixture dated in the past stays inside it.
        let (hour, date) = (now / 3600, tally::local_date(now));
        let settled = |mut series: Series| {
            series.settle(hour, date);
            series
        };
        let mut total = settled(self.keyless_series());
        for key in &self.per_key {
            total.merge(&settled(key.spend.lock().0.clone()));
        }
        #[cfg(feature = "cost-governance")]
        total.merge(&settled(self.carried.lock().clone()));
        total
    }

    /// Entries `session_id` holds in memory.
    pub(crate) fn session_retained(&self, session_id: &str) -> usize {
        self.per_session
            .get(session_id)
            .map_or(0, |session| session.by_tool.lock().len())
    }
}

// ── Cost governance submodules ────────────────────────────────────────────────

pub mod caller;
mod tally;

#[cfg(feature = "cost-governance")]
pub mod config;
#[cfg(feature = "cost-governance")]
pub mod enforcer;
#[cfg(feature = "cost-governance")]
pub mod persistence;
#[cfg(feature = "cost-governance")]
pub mod registry;
#[cfg(feature = "cost-governance")]
pub(crate) mod spend_history;
#[cfg(feature = "cost-governance")]
pub mod suggestions;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(tp2)]
#[cfg(test)]
#[path = "clock_windows_tests.rs"]
mod clock_windows_tests;
#[cfg(tp2)]
#[cfg(test)]
mod tests;

#[cfg(tp2)]
#[cfg(test)]
#[path = "cost_clock_compile_red_tests.rs"]
mod cost_clock_compile_red_tests;

#[cfg(tp2)]
#[cfg(test)]
mod spend_history_tests;

#[cfg(tp2)]
#[cfg(test)]
#[path = "key_rate_tests.rs"]
mod key_rate_tests;
