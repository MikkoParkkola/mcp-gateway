//! Per-client cost accounting for gateway tool calls.
//!
//! Tracks token usage and estimated spend per session and per API key,
//! with rolling time windows (24 h / 7 d / 30 d) and optional hard/soft
//! budget limits.
//!
//! # Design
//!
//! ```text
//! CostTracker  (one global Arc, shared via AppState + MetaMcp)
//!   ├── per_session : DashMap<session_id, SessionCost>
//!   └── per_key     : DashMap<api_key_name, KeyCost>
//! ```
//!
//! `record()` is the single write path; everything else is read-only.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default soft-budget warning threshold (80 % of the hard cap).
const DEFAULT_WARNING_FRACTION: f64 = 0.80;

/// Default price per million tokens (Claude Opus 4.6 input).
pub const DEFAULT_PRICE_PER_MILLION: f64 = 15.0;

// ── CostRecord ────────────────────────────────────────────────────────────────

/// A single recorded tool-call cost event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostRecord {
    /// Unix timestamp (seconds) of the call.
    pub timestamp: u64,
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
        Self {
            timestamp: now_secs(),
            backend: backend.to_string(),
            tool: tool.to_string(),
            token_count,
            estimated_cost_usd,
        }
    }
}

// ── Budget limits ─────────────────────────────────────────────────────────────

/// Budget configuration for a single API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Hard limit in USD; `None` = unlimited.
    pub hard_limit_usd: Option<f64>,
    /// Fraction of the hard limit that triggers a soft warning (default 0.80).
    pub warning_fraction: f64,
    /// Rolling window over which the limit applies.
    pub window: BudgetWindow,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            hard_limit_usd: None,
            warning_fraction: DEFAULT_WARNING_FRACTION,
            window: BudgetWindow::Day,
        }
    }
}

/// Rolling time window for budget accounting.
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
    /// All recorded events (append-only; bounded by eviction in [`CostTracker`]).
    records: parking_lot::Mutex<Vec<CostRecord>>,
    /// Running token total (fast path).
    total_tokens: AtomicU64,
    /// Running cost total (stored as micro-dollars to avoid fp atomics).
    total_cost_micro_usd: AtomicU64,
    /// Call count.
    call_count: AtomicU64,
    /// Session start time.
    pub started_at: u64,
}

impl SessionCost {
    fn new(session_id: &str, api_key_name: Option<String>) -> Self {
        Self {
            session_id: session_id.to_string(),
            api_key_name,
            records: parking_lot::Mutex::new(Vec::new()),
            total_tokens: AtomicU64::new(0),
            total_cost_micro_usd: AtomicU64::new(0),
            call_count: AtomicU64::new(0),
            started_at: now_secs(),
        }
    }

    fn record(&self, rec: CostRecord) {
        self.total_tokens
            .fetch_add(rec.token_count, Ordering::Relaxed);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micro = (rec.estimated_cost_usd * 1_000_000.0) as u64;
        self.total_cost_micro_usd
            .fetch_add(micro, Ordering::Relaxed);
        self.call_count.fetch_add(1, Ordering::Relaxed);
        self.records.lock().push(rec);
    }

    /// Snapshot the session cost.
    #[must_use]
    pub fn snapshot(&self) -> SessionCostSnapshot {
        let records = self.records.lock().clone();
        #[allow(clippy::cast_precision_loss)]
        let total_cost_usd = self.total_cost_micro_usd.load(Ordering::Relaxed) as f64 / 1_000_000.0;

        // Breakdown by backend
        let mut by_backend: std::collections::HashMap<String, BackendCost> =
            std::collections::HashMap::new();
        for r in &records {
            let e = by_backend.entry(r.backend.clone()).or_insert(BackendCost {
                backend: r.backend.clone(),
                call_count: 0,
                token_count: 0,
                cost_usd: 0.0,
            });
            e.call_count += 1;
            e.token_count += r.token_count;
            e.cost_usd += r.estimated_cost_usd;
        }

        // Breakdown by tool
        let mut by_tool: std::collections::HashMap<String, ToolCost> =
            std::collections::HashMap::new();
        for r in &records {
            let key = format!("{}:{}", r.backend, r.tool);
            let e = by_tool.entry(key.clone()).or_insert(ToolCost {
                tool_key: key,
                call_count: 0,
                token_count: 0,
                cost_usd: 0.0,
            });
            e.call_count += 1;
            e.token_count += r.token_count;
            e.cost_usd += r.estimated_cost_usd;
        }

        SessionCostSnapshot {
            session_id: self.session_id.clone(),
            api_key_name: self.api_key_name.clone(),
            started_at: self.started_at,
            call_count: self.call_count.load(Ordering::Relaxed),
            total_tokens: self.total_tokens.load(Ordering::Relaxed),
            total_cost_usd,
            by_backend: by_backend.into_values().collect(),
            by_tool: by_tool.into_values().collect(),
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
    /// Session start (unix secs).
    pub started_at: u64,
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
    /// Budget limits.
    pub budget: BudgetConfig,
    /// Timestamped events (eviction loop trims old entries).
    records: parking_lot::Mutex<Vec<CostRecord>>,
}

impl KeyCost {
    fn new(name: &str, budget: BudgetConfig) -> Self {
        Self {
            name: name.to_string(),
            budget,
            records: parking_lot::Mutex::new(Vec::new()),
        }
    }

    fn record(&self, rec: CostRecord) {
        self.records.lock().push(rec);
    }

    /// Compute cost totals for a given rolling window.
    fn window_totals(&self, window_secs: u64) -> (u64, f64) {
        let cutoff = now_secs().saturating_sub(window_secs);
        let records = self.records.lock();
        records
            .iter()
            .filter(|r| r.timestamp >= cutoff)
            .fold((0u64, 0.0f64), |(tok, cost), r| {
                (tok + r.token_count, cost + r.estimated_cost_usd)
            })
    }

    /// Cost within the budget window (used for limit checks).
    fn budget_window_cost(&self) -> f64 {
        self.window_totals(self.budget.window.secs()).1
    }

    /// Check budget status.
    ///
    /// Returns `BudgetStatus::Ok` if within limits, `Warning` if approaching
    /// the hard cap, `Exceeded` if over it.
    #[must_use]
    pub fn budget_status(&self) -> BudgetStatus {
        let Some(hard) = self.budget.hard_limit_usd else {
            return BudgetStatus::Ok;
        };
        let spent = self.budget_window_cost();
        if spent >= hard {
            BudgetStatus::Exceeded { spent, limit: hard }
        } else if spent >= hard * self.budget.warning_fraction {
            BudgetStatus::Warning {
                spent,
                limit: hard,
                fraction: spent / hard,
            }
        } else {
            BudgetStatus::Ok
        }
    }

    /// Produce a serialisable snapshot with all three time windows.
    #[must_use]
    #[allow(clippy::similar_names)] // cost_24h / cost_7d / cost_30d are intentionally parallel
    pub fn snapshot(&self) -> KeyCostSnapshot {
        let (tokens_24h, cost_24h) = self.window_totals(BudgetWindow::Day.secs());
        let (tokens_7d, cost_7d) = self.window_totals(BudgetWindow::Week.secs());
        let (tokens_30d, cost_30d) = self.window_totals(BudgetWindow::Month.secs());

        // Breakdown by tool (all-time records kept in memory)
        let records = self.records.lock();
        let mut by_tool: std::collections::HashMap<String, ToolCost> =
            std::collections::HashMap::new();
        for r in &*records {
            let key = format!("{}:{}", r.backend, r.tool);
            let e = by_tool.entry(key.clone()).or_insert(ToolCost {
                tool_key: key,
                call_count: 0,
                token_count: 0,
                cost_usd: 0.0,
            });
            e.call_count += 1;
            e.token_count += r.token_count;
            e.cost_usd += r.estimated_cost_usd;
        }
        drop(records);

        KeyCostSnapshot {
            api_key_name: self.name.clone(),
            window_24h: WindowStats {
                tokens: tokens_24h,
                cost_usd: cost_24h,
            },
            window_7d: WindowStats {
                tokens: tokens_7d,
                cost_usd: cost_7d,
            },
            window_30d: WindowStats {
                tokens: tokens_30d,
                cost_usd: cost_30d,
            },
            hard_limit_usd: self.budget.hard_limit_usd,
            budget_status: format!("{:?}", self.budget_status()),
            by_tool: by_tool.into_values().collect(),
        }
    }

    /// Evict events older than 30 days (called periodically by [`CostTracker`]).
    fn evict_old(&self) {
        let cutoff = now_secs().saturating_sub(BudgetWindow::Month.secs());
        let mut records = self.records.lock();
        records.retain(|r| r.timestamp >= cutoff);
    }
}

/// Budget status enum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BudgetStatus {
    /// Within limits.
    Ok,
    /// Approaching the hard cap.
    Warning {
        /// Amount spent so far in the budget window (USD).
        spent: f64,
        /// Configured hard limit (USD).
        limit: f64,
        /// Fraction of the limit consumed (0.0–1.0).
        fraction: f64,
    },
    /// Hard cap exceeded.
    Exceeded {
        /// Amount spent so far in the budget window (USD).
        spent: f64,
        /// Configured hard limit (USD).
        limit: f64,
    },
}

/// Aggregate stats for a rolling time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowStats {
    /// Total tokens in the window.
    pub tokens: u64,
    /// Total cost in USD.
    pub cost_usd: f64,
}

/// Serialisable snapshot for a single API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCostSnapshot {
    /// API key name.
    pub api_key_name: String,
    /// Spend in the past 24 hours.
    pub window_24h: WindowStats,
    /// Spend in the past 7 days.
    pub window_7d: WindowStats,
    /// Spend in the past 30 days.
    pub window_30d: WindowStats,
    /// Configured hard limit (None = unlimited).
    pub hard_limit_usd: Option<f64>,
    /// Human-readable budget status.
    pub budget_status: String,
    /// Per-tool breakdown (all-time records retained in memory).
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
    /// Default budget applied to keys with no explicit config.
    default_budget: BudgetConfig,
}

impl CostTracker {
    /// Create a new tracker with no budget limits by default.
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_session: DashMap::new(),
            per_key: DashMap::new(),
            default_budget: BudgetConfig::default(),
        }
    }

    /// Pre-register a budget for a named API key.
    pub fn set_key_budget(&self, key_name: &str, budget: BudgetConfig) {
        self.per_key
            .entry(key_name.to_string())
            .and_modify(|kc| {
                // Swap the budget in-place on the existing Arc.
                // We can't mutate through Arc so we replace the entry.
                let _ = kc; // suppress unused warning
            })
            .or_insert_with(|| Arc::new(KeyCost::new(key_name, budget.clone())));
        // If the entry already existed we replace it entirely:
        if let Some(mut entry) = self.per_key.get_mut(key_name) {
            let existing = Arc::clone(&entry);
            if !Arc::ptr_eq(&existing, &Arc::new(KeyCost::new(key_name, budget.clone()))) {
                // Rebuild with new budget, preserving existing records
                let records = existing.records.lock().clone();
                let new_kc = KeyCost {
                    records: parking_lot::Mutex::new(records),
                    ..KeyCost::new(key_name, budget)
                };
                *entry = Arc::new(new_kc);
            }
        }
    }

    /// Record a tool-call cost event.
    ///
    /// `session_id` — MCP session identifier.
    /// `api_key_name` — authenticated client name (`None` for anonymous/bearer).
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

        // Per-session
        self.per_session
            .entry(session_id.to_string())
            .or_insert_with(|| {
                Arc::new(SessionCost::new(session_id, api_key_name.map(String::from)))
            })
            .record(rec.clone());

        // Per-key (if we have a key name)
        if let Some(key_name) = api_key_name {
            self.per_key
                .entry(key_name.to_string())
                .or_insert_with(|| Arc::new(KeyCost::new(key_name, self.default_budget.clone())))
                .record(rec);
        }
    }

    /// Check whether a key has exceeded its budget.
    ///
    /// Returns the `BudgetStatus` for the key (or `BudgetStatus::Ok` if unknown).
    #[must_use]
    pub fn check_budget(&self, api_key_name: &str) -> BudgetStatus {
        self.per_key
            .get(api_key_name)
            .map_or(BudgetStatus::Ok, |kc| kc.budget_status())
    }

    /// Snapshot the cost for a session.
    #[must_use]
    pub fn session_snapshot(&self, session_id: &str) -> Option<SessionCostSnapshot> {
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

    /// Snapshot the cost for a single API key.
    #[must_use]
    pub fn key_snapshot(&self, key_name: &str) -> Option<KeyCostSnapshot> {
        self.per_key.get(key_name).map(|kc| kc.snapshot())
    }

    /// Snapshot all API key accumulators.
    #[must_use]
    pub fn all_keys(&self) -> Vec<KeyCostSnapshot> {
        self.per_key.iter().map(|e| e.value().snapshot()).collect()
    }

    /// Aggregate total across all sessions.
    #[must_use]
    pub fn aggregate(&self) -> AggregateCost {
        let mut total_calls: u64 = 0;
        let mut total_tokens: u64 = 0;
        let mut total_cost: f64 = 0.0;
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

    /// Evict old per-key records (>30 days) to bound memory.
    ///
    /// Call this periodically (e.g., hourly) from a background task.
    pub fn evict_old_records(&self) {
        for entry in &self.per_key {
            entry.evict_old();
        }
    }

    /// Remove a session (called when the MCP session is terminated).
    pub fn remove_session(&self, session_id: &str) {
        self.per_session.remove(session_id);
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

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
