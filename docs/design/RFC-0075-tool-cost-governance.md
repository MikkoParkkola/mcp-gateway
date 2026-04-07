# RFC-0075: Tool Cost Governance

**Status**: Draft
**Author**: Mikko Parkkola
**Date**: 2026-03-13
**LOC Budget**: ~500-700
**Feature Gate**: `#[cfg(feature = "cost-governance")]` (default-enabled)

---

## Problem

When AI agents autonomously invoke paid APIs through the gateway, costs accumulate invisibly. Real production costs per tool call:

| Tool | Cost/call | 100 calls/day | Monthly |
|------|-----------|---------------|---------|
| Tavily search | $0.01 | $1.00 | $30 |
| Exa search | $0.005 | $0.50 | $15 |
| Brave search | $0.005 | $0.50 | $15 |
| Exa deep research | $0.05 | $5.00 | $150 |
| Combined (4 agents) | -- | -- | $840 |

Portkey, LiteLLM, and other gateways track LLM **token** costs. No MCP gateway tracks **tool-call** costs. The gateway routes ALL tool calls -- it is the single point that can provide unified cost visibility and enforcement.

The gateway already has `src/cost_accounting/mod.rs` with per-session and per-key `CostTracker`, `BudgetConfig`, and `BudgetStatus`. But this module:
1. Tracks only **token-based** costs (estimated from response size), not **per-invocation** costs
2. Has no tool-level cost configuration (costs are computed from token counts)
3. Has no budget enforcement in the invoke path (only read-only status checks)
4. Has no persistence (lost on restart)
5. Has no UI integration
6. Has no cost-optimization suggestions

This RFC extends the existing cost_accounting module into a complete governance system.

## Goals

1. Per-tool cost configuration via YAML (manual) and capability metadata (automatic)
2. Real-time budget enforcement in the `gateway_invoke` hot path (<0.1ms)
3. Three-tier alerting: log -> warn-in-response -> block
4. Persistence to `~/.mcp-gateway/costs.json` (survive restarts)
5. Cost analytics in `gateway_get_stats` and the web UI dashboard
6. Cost-optimization suggestions (suggest cheaper alternatives)

## Non-Goals

- Billing integration with Stripe/payment processors
- Per-user billing (this is operational governance, not billing)
- Automatic cost learning from billing APIs (future RFC)
- Sub-cent precision (f64 micro-dollar is sufficient)

## Architecture

### Data Flow

```
                       config.yaml
                          |
                    [CostRegistry]
                     tool -> cost
                          |
  gateway_invoke ----+----+----+
                     |         |
              [BudgetEnforcer] |
              check < 0.1ms   |
                     |         |
              pass/warn/block  |
                     |         |
            [existing invoke]  |
                     |         |
              [CostRecorder]---+
              atomic counters
                     |
               [Persistence]
               costs.json
                     |
        +------------+-------------+
        |            |             |
  gateway_get_stats  /ui/api/costs  CSV export
```

### Integration with Existing CostTracker

The existing `CostTracker` in `src/cost_accounting/mod.rs` already has:
- `record(session_id, api_key_name, backend, tool, token_count, price_per_million)` -- the write path
- `check_budget(api_key_name)` -> `BudgetStatus` -- the read path
- Per-session `SessionCost` and per-key `KeyCost` accumulators
- Rolling time windows (24h, 7d, 30d)
- `BudgetConfig` with hard limits and warning fractions

What we ADD:
- `CostRegistry` -- per-tool cost definitions (loaded from config.yaml)
- `BudgetEnforcer` -- middleware that checks budgets BEFORE invoke, not just after
- Per-tool daily budget limits (not just per-key)
- Persistence layer (save/load costs.json)
- Cost-aware search ranking integration
- Alert actions (log/notify/block) instead of just status enum
- Cost optimization suggestions

### Module Layout

```
src/cost_accounting/
    mod.rs                  -- existing CostTracker (extend, ~40 LOC added)
    tests.rs                -- existing tests (extend)
    registry.rs             -- CostRegistry: tool -> cost lookup (NEW, ~80 LOC)
    enforcer.rs             -- BudgetEnforcer: pre-invoke check (NEW, ~100 LOC)
    persistence.rs          -- save/load costs.json (NEW, ~80 LOC)
    suggestions.rs          -- cost optimization suggestions (NEW, ~60 LOC)
    config.rs               -- CostGovernanceConfig deserialization (NEW, ~80 LOC)
src/gateway/ui/costs.rs     -- /ui/api/costs endpoint (NEW, ~60 LOC)
src/commands/stats.rs       -- extend stats output with cost data (~20 LOC)
```

Total: ~520 LOC (within budget).

## Rust Type Definitions

```rust
// src/cost_accounting/config.rs

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Top-level cost governance configuration (lives under `cost_governance:` in config.yaml).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CostGovernanceConfig {
    /// Master enable switch.
    pub enabled: bool,
    /// Currency code (informational, always stored as USD internally).
    pub currency: String,
    /// Global budget limits.
    pub budgets: BudgetLimits,
    /// Alert thresholds and actions.
    pub alerts: Vec<AlertRule>,
    /// Per-tool invocation costs (tool_name -> USD per call).
    /// Overrides costs from capability YAML metadata.
    pub tool_costs: HashMap<String, f64>,
    /// Default cost for tools not in `tool_costs` and without
    /// `cost_per_call` in their capability YAML (default: 0.0).
    pub default_cost: f64,
    /// Configurable tool category equivalences for cost-optimization
    /// suggestions (category_name -> list of equivalent tool names).
    /// When set, replaces the compiled-in defaults.
    pub alternatives: Option<HashMap<String, Vec<String>>>,
}

impl Default for CostGovernanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            currency: "USD".to_string(),
            budgets: BudgetLimits::default(),
            alerts: vec![
                AlertRule { at_percent: 50, action: AlertAction::Log },
                AlertRule { at_percent: 80, action: AlertAction::Notify },
                AlertRule { at_percent: 100, action: AlertAction::Block },
            ],
            tool_costs: HashMap::new(),
            default_cost: 0.0,
            alternatives: None,
        }
    }
}

/// Budget limits at different scopes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BudgetLimits {
    /// Hard daily limit across ALL tools (USD). None = unlimited.
    pub daily: Option<f64>,
    /// Per-tool daily limits (tool_name -> USD). Overrides global daily.
    pub per_tool: HashMap<String, f64>,
    /// Per API-key daily limits (key_name -> USD). Overrides global daily.
    pub per_key: HashMap<String, f64>,
}

/// An alert rule triggered at a budget threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Percentage of budget consumed that triggers this alert (0-100).
    pub at_percent: u32,
    /// Action to take when threshold is reached.
    pub action: AlertAction,
}

/// Action taken when a budget threshold is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertAction {
    /// Log a warning (structured tracing event).
    Log,
    /// Log + include cost warning in the tool response JSON.
    Notify,
    /// Reject the tool call with a budget-exceeded error.
    Block,
}
```

```rust
// src/cost_accounting/registry.rs

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;

use super::config::CostGovernanceConfig;

/// Resolved per-tool cost lookup.
///
/// Built on startup from three sources (in priority order):
/// 1. `config.yaml` -> `cost_governance.tool_costs` (highest priority)
/// 2. Capability YAML -> `providers.primary.cost_per_call`
/// 3. `config.yaml` -> `cost_governance.default_cost` (fallback)
///
/// Thread-safe: read-heavy, write-rare (only on config reload).
pub struct CostRegistry {
    /// tool_name -> USD per invocation
    costs: DashMap<String, f64>,
    /// Fallback cost for unknown tools.
    default_cost: f64,
}

impl CostRegistry {
    /// Build registry from config + capability definitions.
    pub fn new(config: &CostGovernanceConfig) -> Self {
        let costs = DashMap::new();

        // Load explicit tool costs from config
        for (tool, cost) in &config.tool_costs {
            costs.insert(tool.clone(), *cost);
        }

        Self {
            costs,
            default_cost: config.default_cost,
        }
    }

    /// Register a cost from a capability definition's `cost_per_call` field.
    /// Does NOT override explicit config values.
    pub fn register_from_capability(&self, tool_name: &str, cost_per_call: f64) {
        self.costs.entry(tool_name.to_string()).or_insert(cost_per_call);
    }

    /// Look up the cost for a tool invocation.
    #[must_use]
    pub fn cost_for(&self, tool_name: &str) -> f64 {
        self.costs
            .get(tool_name)
            .map_or(self.default_cost, |v| *v)
    }

    /// Check if a tool is explicitly free (cost == 0.0).
    #[must_use]
    pub fn is_free(&self, tool_name: &str) -> bool {
        self.cost_for(tool_name) == 0.0
    }

    /// Snapshot all registered costs (for API/UI).
    #[must_use]
    pub fn snapshot(&self) -> HashMap<String, f64> {
        self.costs.iter().map(|e| (e.key().clone(), *e.value())).collect()
    }
}
```

```rust
// src/cost_accounting/enforcer.rs

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Serialize, Deserialize};

use super::config::{AlertAction, AlertRule, CostGovernanceConfig};
use super::registry::CostRegistry;

/// Pre-invoke budget enforcement.
///
/// Called BEFORE tool execution. Returns `EnforcementResult` indicating
/// whether the call should proceed, with optional warnings.
///
/// Performance target: <0.1ms (single DashMap lookup + atomic compare).
pub struct BudgetEnforcer {
    config: CostGovernanceConfig,
    registry: Arc<CostRegistry>,
    /// Per-tool daily spend: tool_name -> (day_number, accumulated_micro_usd)
    tool_daily: DashMap<String, DailyAccumulator>,
    /// Global daily spend
    global_daily: DailyAccumulator,
    /// Per-key daily spend
    key_daily: DashMap<String, DailyAccumulator>,
}

/// Atomic daily spend accumulator with day-boundary auto-reset.
pub struct DailyAccumulator {
    /// Current day number (days since epoch). Used for auto-reset.
    day: AtomicU64,
    /// Accumulated spend in micro-USD (1 USD = 1_000_000 micro-USD).
    micro_usd: AtomicU64,
}

impl DailyAccumulator {
    fn new() -> Self {
        Self {
            day: AtomicU64::new(current_day()),
            micro_usd: AtomicU64::new(0),
        }
    }

    /// Add spend. Auto-resets if the day has changed.
    ///
    /// Uses compare_exchange on the day field to prevent TOCTOU races:
    /// only the thread that wins the CAS resets the counter, others
    /// fall through to fetch_add on the (already-reset) counter.
    fn add(&self, micro: u64) -> u64 {
        let today = current_day();
        let stored = self.day.load(Ordering::Acquire);
        if stored != today {
            match self.day.compare_exchange(stored, today, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => {
                    // Won the reset race. Swap counter to 0, then add our spend.
                    // Any concurrent fetch_add between swap and our add is preserved.
                    self.micro_usd.swap(0, Ordering::AcqRel);
                    return self.micro_usd.fetch_add(micro, Ordering::AcqRel) + micro;
                }
                Err(_) => {
                    // Another thread already reset the day — fall through to add
                }
            }
        }
        self.micro_usd.fetch_add(micro, Ordering::AcqRel) + micro
    }

    /// Current daily spend in micro-USD (auto-resets on day boundary).
    fn current(&self) -> u64 {
        let today = current_day();
        if self.day.load(Ordering::Relaxed) != today {
            0
        } else {
            self.micro_usd.load(Ordering::Relaxed)
        }
    }
}

fn current_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() / 86_400
}

/// Result of a pre-invoke budget check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementResult {
    /// Whether the call is allowed to proceed.
    pub allowed: bool,
    /// Cost that would be incurred by this call (USD).
    pub cost_usd: f64,
    /// Active warnings to include in the response (if `AlertAction::Notify`).
    pub warnings: Vec<String>,
    /// If blocked, the reason message.
    pub block_reason: Option<String>,
}

impl BudgetEnforcer {
    pub fn new(config: CostGovernanceConfig, registry: Arc<CostRegistry>) -> Self {
        Self {
            config,
            registry,
            tool_daily: DashMap::new(),
            global_daily: DailyAccumulator::new(),
            key_daily: DashMap::new(),
        }
    }

    /// Check whether a tool call should proceed.
    ///
    /// This is the hot-path function. It must complete in <0.1ms.
    /// Design: one DashMap lookup + at most 3 atomic comparisons.
    pub fn check(
        &self,
        tool_name: &str,
        api_key_name: Option<&str>,
    ) -> EnforcementResult {
        if !self.config.enabled {
            return EnforcementResult {
                allowed: true,
                cost_usd: 0.0,
                warnings: Vec::new(),
                block_reason: None,
            };
        }

        let cost = self.registry.cost_for(tool_name);
        if cost == 0.0 {
            return EnforcementResult {
                allowed: true,
                cost_usd: 0.0,
                warnings: Vec::new(),
                block_reason: None,
            };
        }

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let cost_micro = (cost * 1_000_000.0) as u64;
        let mut warnings = Vec::new();
        let mut blocked = false;
        let mut block_reason = None;

        // Check 1: per-tool daily limit
        if let Some(&limit) = self.config.budgets.per_tool.get(tool_name) {
            let acc = self.tool_daily
                .entry(tool_name.to_string())
                .or_insert_with(DailyAccumulator::new);
            let current_micro = acc.current();
            #[allow(clippy::cast_precision_loss)]
            let current_usd = current_micro as f64 / 1_000_000.0;

            if let Some(action) = self.evaluate_alerts(current_usd + cost, limit) {
                match action {
                    AlertAction::Log => {
                        tracing::warn!(
                            tool = tool_name,
                            spent = current_usd + cost,
                            limit = limit,
                            "Tool approaching daily budget limit"
                        );
                    }
                    AlertAction::Notify => {
                        warnings.push(format!(
                            "Tool '{tool_name}' daily spend ${:.4} approaching limit ${:.2}",
                            current_usd + cost, limit
                        ));
                    }
                    AlertAction::Block => {
                        blocked = true;
                        block_reason = Some(format!(
                            "Tool '{tool_name}' daily budget exceeded: ${:.4} >= ${:.2}",
                            current_usd + cost, limit
                        ));
                    }
                }
            }
        }

        // Check 2: global daily limit
        if !blocked {
            if let Some(limit) = self.config.budgets.daily {
                #[allow(clippy::cast_precision_loss)]
                let current_usd = self.global_daily.current() as f64 / 1_000_000.0;

                if let Some(action) = self.evaluate_alerts(current_usd + cost, limit) {
                    match action {
                        AlertAction::Log => {
                            tracing::warn!(
                                spent = current_usd + cost,
                                limit = limit,
                                "Global daily spend approaching limit"
                            );
                        }
                        AlertAction::Notify => {
                            warnings.push(format!(
                                "Global daily spend ${:.4} approaching limit ${:.2}",
                                current_usd + cost, limit
                            ));
                        }
                        AlertAction::Block => {
                            blocked = true;
                            block_reason = Some(format!(
                                "Global daily budget exceeded: ${:.4} >= ${:.2}",
                                current_usd + cost, limit
                            ));
                        }
                    }
                }
            }
        }

        // Check 3: per-key daily limit
        if !blocked {
            if let Some(key_name) = api_key_name {
                if let Some(&limit) = self.config.budgets.per_key.get(key_name) {
                    let acc = self.key_daily
                        .entry(key_name.to_string())
                        .or_insert_with(DailyAccumulator::new);
                    #[allow(clippy::cast_precision_loss)]
                    let current_usd = acc.current() as f64 / 1_000_000.0;

                    if let Some(action) = self.evaluate_alerts(current_usd + cost, limit) {
                        match action {
                            AlertAction::Log => {
                                tracing::warn!(
                                    key = key_name,
                                    spent = current_usd + cost,
                                    limit = limit,
                                    "API key approaching daily budget limit"
                                );
                            }
                            AlertAction::Notify => {
                                warnings.push(format!(
                                    "API key '{key_name}' daily spend ${:.4} approaching limit ${:.2}",
                                    current_usd + cost, limit
                                ));
                            }
                            AlertAction::Block => {
                                blocked = true;
                                block_reason = Some(format!(
                                    "API key '{key_name}' daily budget exceeded: ${:.4} >= ${:.2}",
                                    current_usd + cost, limit
                                ));
                            }
                        }
                    }
                }
            }
        }

        EnforcementResult {
            allowed: !blocked,
            cost_usd: cost,
            warnings,
            block_reason,
        }
    }

    /// After a successful invocation, record the spend.
    pub fn record_spend(&self, tool_name: &str, api_key_name: Option<&str>, cost_usd: f64) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micro = (cost_usd * 1_000_000.0) as u64;

        self.global_daily.add(micro);

        self.tool_daily
            .entry(tool_name.to_string())
            .or_insert_with(DailyAccumulator::new)
            .add(micro);

        if let Some(key) = api_key_name {
            self.key_daily
                .entry(key.to_string())
                .or_insert_with(DailyAccumulator::new)
                .add(micro);
        }
    }

    /// Evaluate which alert action applies for a given spend vs limit.
    ///
    /// Uses f64 comparison to avoid truncation bugs: e.g., 99.7% must
    /// NOT be cast to 99u32 and miss a 100% threshold when it should
    /// match after rounding. The at_percent threshold is promoted to f64.
    fn evaluate_alerts(&self, spend: f64, limit: f64) -> Option<AlertAction> {
        if limit <= 0.0 {
            return None;
        }
        let percent = spend / limit * 100.0;

        // Find the highest-threshold rule that matches
        let mut best: Option<&AlertAction> = None;
        let mut best_threshold = 0.0_f64;

        for rule in &self.config.alerts {
            let threshold = f64::from(rule.at_percent);
            if percent >= threshold && threshold >= best_threshold {
                best = Some(&rule.action);
                best_threshold = threshold;
            }
        }

        best.copied()
    }

    /// Snapshot of all daily accumulators (for persistence/UI).
    #[must_use]
    pub fn snapshot(&self) -> EnforcerSnapshot {
        #[allow(clippy::cast_precision_loss)]
        let global_daily_usd = self.global_daily.current() as f64 / 1_000_000.0;

        let tool_daily: HashMap<String, f64> = self.tool_daily.iter()
            .map(|e| (e.key().clone(), e.value().current() as f64 / 1_000_000.0))
            .collect();

        let key_daily: HashMap<String, f64> = self.key_daily.iter()
            .map(|e| (e.key().clone(), e.value().current() as f64 / 1_000_000.0))
            .collect();

        EnforcerSnapshot {
            global_daily_usd,
            global_daily_limit: self.config.budgets.daily,
            tool_daily,
            tool_limits: self.config.budgets.per_tool.clone(),
            key_daily,
            key_limits: self.config.budgets.per_key.clone(),
        }
    }
}

use std::collections::HashMap;

/// Serializable snapshot of enforcer state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcerSnapshot {
    pub global_daily_usd: f64,
    pub global_daily_limit: Option<f64>,
    pub tool_daily: HashMap<String, f64>,
    pub tool_limits: HashMap<String, f64>,
    pub key_daily: HashMap<String, f64>,
    pub key_limits: HashMap<String, f64>,
}
```

```rust
// src/cost_accounting/persistence.rs

use std::path::Path;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Persisted cost state (saved on shutdown, loaded on startup).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedCosts {
    /// Unix timestamp of last save.
    pub saved_at: u64,
    /// Per-tool cumulative costs (all-time, for display).
    pub tool_totals: HashMap<String, ToolTotal>,
    /// Per-key cumulative costs (all-time).
    pub key_totals: HashMap<String, f64>,
}

/// Cumulative cost data for a single tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolTotal {
    /// Total invocations.
    pub call_count: u64,
    /// Total cost in USD.
    pub total_cost_usd: f64,
    /// Average cost per call.
    pub avg_cost_usd: f64,
}

/// Save cost state to disk.
///
/// Path: `~/.mcp-gateway/costs.json`
///
/// # Errors
/// Returns an error if the file cannot be written.
pub fn save(path: &Path, costs: &PersistedCosts) -> crate::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| crate::Error::Config(format!("Failed to create cost dir: {e}")))?;
    }
    let json = serde_json::to_string_pretty(costs)
        .map_err(|e| crate::Error::Config(format!("Failed to serialize costs: {e}")))?;
    std::fs::write(path, json)
        .map_err(|e| crate::Error::Config(format!("Failed to write costs: {e}")))?;
    tracing::info!(path = %path.display(), "Saved cost data");
    Ok(())
}

/// Load cost state from disk.
///
/// Returns `PersistedCosts::default()` if the file does not exist.
///
/// # Errors
/// Returns an error if the file exists but cannot be parsed.
pub fn load(path: &Path) -> crate::Result<PersistedCosts> {
    if !path.exists() {
        return Ok(PersistedCosts::default());
    }
    let json = std::fs::read_to_string(path)
        .map_err(|e| crate::Error::Config(format!("Failed to read costs: {e}")))?;
    let costs: PersistedCosts = serde_json::from_str(&json)
        .map_err(|e| crate::Error::Config(format!("Failed to parse costs: {e}")))?;
    tracing::info!(path = %path.display(), tools = costs.tool_totals.len(), "Loaded cost data");
    Ok(costs)
}
```

```rust
// src/cost_accounting/suggestions.rs

use std::collections::HashMap;

/// A cost-optimization suggestion.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CostSuggestion {
    /// Tool that was invoked.
    pub tool: String,
    /// Cost of the invoked tool.
    pub cost: f64,
    /// Cheaper alternative tool name.
    pub alternative: String,
    /// Cost of the alternative.
    pub alternative_cost: f64,
    /// Savings per call.
    pub savings_per_call: f64,
    /// Reason the alternative is comparable.
    pub reason: String,
}

/// Default tool category equivalences.
/// Tools in the same category with different costs trigger suggestions.
///
/// These defaults are used when `cost_governance.alternatives` is not
/// configured in config.yaml. When configured, the YAML values fully
/// replace these defaults.
const DEFAULT_CATEGORY_EQUIVALENCES: &[(&str, &[&str])] = &[
    ("web_search", &["tavily_search", "brave_search", "exa_search"]),
    ("deep_research", &["exa_deep_research", "tavily_research"]),
    ("code_search", &["exa_code_search", "brave_search"]),
];

/// Generate cost-optimization suggestions for a tool invocation.
///
/// If a cheaper tool exists in the same functional category, returns
/// a suggestion. Designed to be appended to the `gateway_invoke` response
/// when `AlertAction::Notify` is active.
pub fn suggest_cheaper(
    tool_name: &str,
    tool_cost: f64,
    all_costs: &HashMap<String, f64>,
    configured_alternatives: Option<&HashMap<String, Vec<String>>>,
) -> Option<CostSuggestion> {
    // Use configured alternatives if provided, otherwise fall back to defaults.
    // When using configured alternatives, iterate over them:
    if let Some(alternatives) = configured_alternatives {
        for (category, members) in alternatives {
            if !members.iter().any(|m| m == tool_name) {
                continue;
            }
            let mut cheapest: Option<(&str, f64)> = None;
            for member in members {
                if member == tool_name { continue; }
                if let Some(&cost) = all_costs.get(member.as_str()) {
                    if cost < tool_cost {
                        match cheapest {
                            None => cheapest = Some((member, cost)),
                            Some((_, c)) if cost < c => cheapest = Some((member, cost)),
                            _ => {}
                        }
                    }
                }
            }
            if let Some((alt_name, alt_cost)) = cheapest {
                return Some(CostSuggestion {
                    tool: tool_name.to_string(),
                    cost: tool_cost,
                    alternative: alt_name.to_string(),
                    alternative_cost: alt_cost,
                    savings_per_call: tool_cost - alt_cost,
                    reason: format!(
                        "Both in '{category}' category. {} saves ${:.4}/call",
                        alt_name, tool_cost - alt_cost
                    ),
                });
            }
        }
        return None;
    }

    // Fallback: use compiled-in defaults
    for &(category, members) in DEFAULT_CATEGORY_EQUIVALENCES {
        if !members.contains(&tool_name) {
            continue;
        }
        // Find the cheapest alternative in the same category
        let mut cheapest: Option<(&str, f64)> = None;
        for &member in members {
            if member == tool_name {
                continue;
            }
            if let Some(&cost) = all_costs.get(member) {
                if cost < tool_cost {
                    match cheapest {
                        None => cheapest = Some((member, cost)),
                        Some((_, c)) if cost < c => cheapest = Some((member, cost)),
                        _ => {}
                    }
                }
            }
        }

        if let Some((alt_name, alt_cost)) = cheapest {
            return Some(CostSuggestion {
                tool: tool_name.to_string(),
                cost: tool_cost,
                alternative: alt_name.to_string(),
                alternative_cost: alt_cost,
                savings_per_call: tool_cost - alt_cost,
                reason: format!(
                    "Both in '{category}' category. {} saves ${:.4}/call",
                    alt_name,
                    tool_cost - alt_cost
                ),
            });
        }
    }
    None
}
```

## Integration Points

### File: `src/config/mod.rs`

Add to `Config` struct:

```rust
/// Cost governance configuration.
#[serde(default)]
pub cost_governance: CostGovernanceConfig,
```

### File: `src/config/features.rs`

Re-export:

```rust
pub use crate::cost_accounting::config::CostGovernanceConfig;
```

### Existing CostTracker Integration

Both `CostTracker::record()` and `BudgetEnforcer::record_spend()` are called on every tool invocation. They serve complementary purposes:

- **`CostTracker::record()`** (existing) handles per-session and per-key rolling time windows (24h/7d/30d) for monitoring dashboards and `check_budget()` status queries. It tracks token-based cost estimates.
- **`BudgetEnforcer::record_spend()`** (new) handles per-tool daily budgets and enforcement (pre-invoke blocking). It tracks per-invocation costs.

Both calls appear in `invoke_tool_traced` — the enforcer runs BEFORE dispatch (to block), the tracker runs AFTER dispatch (to record).

### File: `src/gateway/meta_mcp/invoke.rs`

Complete invoke path showing both CostTracker and BudgetEnforcer calls:

```rust
// === PRE-INVOKE: Cost governance budget check ===
let cost_warnings = if let Some(ref enforcer) = self.budget_enforcer {
    let result = enforcer.check(tool, api_key_name);
    if !result.allowed {
        return Err(Error::json_rpc(
            -32003,
            result.block_reason.unwrap_or_else(|| "Budget exceeded".into()),
        ));
    }
    result.warnings
} else {
    Vec::new()
};

// === DISPATCH: existing tool invocation ===
let mut result = self.dispatch_tool(tool, params, ctx).await?;

// === POST-INVOKE: Record in BOTH systems ===

// 1. Existing CostTracker: per-session/per-key rolling windows (monitoring)
if let Some(ref tracker) = self.cost_tracker {
    tracker.record(session_id, api_key_name, backend, tool, token_count, price_per_million);
}

// 2. New BudgetEnforcer: per-tool daily budgets (enforcement + persistence)
if let Some(ref enforcer) = self.budget_enforcer {
    let cost = enforcer.registry.cost_for(tool);
    enforcer.record_spend(tool, api_key_name, cost);

    // Inject warnings into response if present
    if !cost_warnings.is_empty() {
        if let Some(obj) = result.as_object_mut() {
            obj.insert("_cost_warnings".to_string(), json!(cost_warnings));
        }
    }

    // Suggest cheaper alternative if available
    if let Some(suggestion) = suggestions::suggest_cheaper(
        tool, cost, &enforcer.registry.snapshot()
    ) {
        if let Some(obj) = result.as_object_mut() {
            obj.insert("_cost_suggestion".to_string(), json!({
                "message": suggestion.reason,
                "alternative": suggestion.alternative,
                "savings_per_call": suggestion.savings_per_call,
            }));
        }
    }
}
```

### File: `src/gateway/meta_mcp/mod.rs`

Add field to `MetaMcp`:

```rust
/// Budget enforcement engine (None if cost governance disabled).
budget_enforcer: Option<Arc<BudgetEnforcer>>,
```

### File: `src/gateway/meta_mcp/invoke.rs` (gateway_get_stats handler)

Extend the stats response with cost data:

```rust
// In build_stats_response, add:
if let Some(ref enforcer) = self.budget_enforcer {
    let snapshot = enforcer.snapshot();
    stats_json["cost_governance"] = json!({
        "global_daily_spend_usd": snapshot.global_daily_usd,
        "global_daily_limit_usd": snapshot.global_daily_limit,
        "tool_daily_spend": snapshot.tool_daily,
        "tool_daily_limits": snapshot.tool_limits,
        "key_daily_spend": snapshot.key_daily,
    });

    if let Some(ref registry) = self.cost_registry {
        stats_json["tool_costs"] = json!(registry.snapshot());
    }
}
```

### File: `src/gateway/ui/mod.rs`

Add costs route:

```rust
.route("/ui/api/costs", get(costs_handler))
```

### File: `src/gateway/ui/costs.rs` (NEW)

```rust
pub async fn costs_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let meta_mcp = &state.meta_mcp;

    let mut response = json!({
        "enabled": false,
        "global_daily_spend_usd": 0.0,
    });

    if let Some(ref enforcer) = meta_mcp.budget_enforcer {
        let snap = enforcer.snapshot();
        response = json!({
            "enabled": true,
            "global_daily_spend_usd": snap.global_daily_usd,
            "global_daily_limit_usd": snap.global_daily_limit,
            "tool_daily": snap.tool_daily,
            "tool_limits": snap.tool_limits,
            "key_daily": snap.key_daily,
            "key_limits": snap.key_limits,
        });
    }

    // Merge with existing CostTracker aggregate
    if let Some(ref tracker) = meta_mcp.cost_tracker {
        let agg = tracker.aggregate();
        response["aggregate"] = json!({
            "session_count": agg.session_count,
            "total_calls": agg.total_calls,
            "total_tokens": agg.total_tokens,
            "total_cost_usd": agg.total_cost_usd,
        });
    }

    Json(response)
}
```

### File: `src/gateway/server.rs` (startup + periodic persistence + graceful shutdown)

Spawn a periodic persistence task on startup (every 5 minutes) to guard against data loss on crash. Also persist on graceful shutdown.

```rust
// In server startup, after building MetaMcp:
if meta_mcp.budget_enforcer.is_some() {
    let enforcer = Arc::clone(meta_mcp.budget_enforcer.as_ref().unwrap());
    let costs_path = data_dir.join("costs.json");
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let persisted = build_persisted_costs(&enforcer);
            if let Err(e) = persistence::save(&costs_path, &persisted) {
                tracing::warn!(error = %e, "Periodic cost persistence failed");
            } else {
                tracing::debug!("Periodic cost data saved");
            }
        }
    });
}
```

```rust
// In graceful_shutdown(), after saving ranker + transitions:
if let Some(ref enforcer) = meta_mcp.budget_enforcer {
    let costs_path = data_dir.join("costs.json");
    // Build PersistedCosts from enforcer state + CostTracker state
    if let Err(e) = persistence::save(&costs_path, &persisted) {
        tracing::warn!(error = %e, "Failed to save cost data on shutdown");
    }
}
```

### File: `src/ranking/mod.rs`

Optionally factor cost into search ranking:

```rust
// In SearchRanker::rank(), after usage boost:
// If cost governance is enabled and cost data is available,
// apply a small penalty to expensive tools when cheaper
// alternatives scored similarly:
//
// if tool.cost > 0 && alt.cost < tool.cost && score_diff < 2.0 {
//     score *= 0.95;  // 5% penalty for expensive tool
// }
```

This is a FUTURE integration point, not in the initial 500-700 LOC scope.

### Cross-RFC: `cap import-url --cost-per-call` (RFC-0074)

RFC-0074's `cap import-url` command accepts a `--cost-per-call <USD>` flag that sets `cost_per_call` in the generated capability YAML. This provides automatic cost metadata for discovered APIs, which the `CostRegistry` picks up as a fallback when not overridden in `config.yaml`.

### File: `Cargo.toml`

No new dependencies. The enforcer uses only:
- `dashmap` (already present)
- `serde`/`serde_json` (already present)
- `tracing` (already present)
- `std::sync::atomic` (stdlib)

Feature gate:

```toml
[features]
default = ["webui", "cost-governance"]
cost-governance = []
```

## Config Schema (YAML)

```yaml
# config.yaml — cost_governance section

cost_governance:
  enabled: true
  currency: USD

  budgets:
    # Hard daily limit across ALL tools
    daily: 10.00

    # Per-tool daily limits
    per_tool:
      tavily_search: 2.00
      exa_search: 1.00
      exa_deep_research: 3.00

    # Per API-key daily limits
    per_key:
      dev_key: 5.00
      prod_key: 50.00

  alerts:
    - at_percent: 50
      action: log          # Just log a structured warning
    - at_percent: 80
      action: notify       # Log + inject warning into tool response
    - at_percent: 100
      action: block        # Reject the tool call with budget error

  tool_costs:
    # Per-invocation costs (USD)
    tavily_search: 0.01
    brave_search: 0.005
    exa_search: 0.005
    exa_deep_research: 0.05
    # Explicitly free tools
    weather_current: 0
    wikipedia_search: 0
    # Capability YAML cost_per_call is used if not listed here

  # Default cost for tools not listed above and without cost_per_call in YAML
  default_cost: 0

  # Configurable tool category equivalences for cost-optimization suggestions.
  # Tools in the same category trigger "use cheaper alternative" suggestions.
  # Omit to use built-in defaults (web_search, deep_research, code_search).
  alternatives:
    web_search:
      - tavily_search
      - brave_search
      - exa_search
    deep_research:
      - exa_deep_research
      - tavily_research
    code_search:
      - exa_code_search
      - brave_search
```

## Web UI Integration

### Dashboard Widget

Add a cost section to the existing `/dashboard` handler:

```
  +--------------------------------------------------+
  | COST GOVERNANCE                                  |
  |                                                  |
  | Daily spend: $4.32 / $10.00  [=========>  43%]   |
  |                                                  |
  | Top spenders today:                              |
  |   tavily_search     $1.80 / $2.00  [=====> 90%] |
  |   exa_search        $0.95 / $1.00  [=====> 95%] |
  |   brave_search      $0.72          (no limit)    |
  |   exa_deep_research $0.85 / $3.00  [==>   28%]  |
  |                                                  |
  | API key budgets:                                 |
  |   dev_key           $3.20 / $5.00  [====>  64%]  |
  |   prod_key          $12.50 / $50.00 [>     25%]  |
  +--------------------------------------------------+
```

### API endpoint

`GET /ui/api/costs` returns:

```json
{
  "enabled": true,
  "global_daily_spend_usd": 4.32,
  "global_daily_limit_usd": 10.00,
  "tool_daily": {
    "tavily_search": 1.80,
    "exa_search": 0.95,
    "brave_search": 0.72,
    "exa_deep_research": 0.85
  },
  "tool_limits": {
    "tavily_search": 2.00,
    "exa_search": 1.00,
    "exa_deep_research": 3.00
  },
  "key_daily": {
    "dev_key": 3.20,
    "prod_key": 12.50
  },
  "key_limits": {
    "dev_key": 5.00,
    "prod_key": 50.00
  },
  "aggregate": {
    "session_count": 3,
    "total_calls": 432,
    "total_tokens": 1250000,
    "total_cost_usd": 4.32
  }
}
```

### CLI stats extension

`mcp-gateway stats` output extended with:

```
Cost Governance:
  Daily spend:     $4.32 / $10.00 (43%)
  Top cost tools:  tavily_search ($1.80), exa_search ($0.95)
  Budget alerts:   1 tool at >80% (exa_search at 95%)
```

## Testing Strategy

### Unit Tests (~18 tests)

**CostRegistry (4 tests):**
1. `registry_explicit_config_overrides_capability` -- config.yaml cost wins over YAML cost_per_call
2. `registry_capability_fallback` -- YAML cost_per_call used when not in config
3. `registry_default_cost` -- unknown tool gets default_cost
4. `registry_is_free` -- 0.0 cost tools report as free

**BudgetEnforcer (8 tests):**
5. `enforcer_disabled_allows_all` -- enabled=false always returns allowed
6. `enforcer_free_tool_skips_checks` -- cost=0 tools skip budget checks
7. `enforcer_per_tool_block` -- blocks when tool daily limit exceeded
8. `enforcer_global_block` -- blocks when global daily limit exceeded
9. `enforcer_per_key_block` -- blocks when key daily limit exceeded
10. `enforcer_notify_at_80_percent` -- returns warning at 80% threshold
11. `enforcer_log_at_50_percent` -- logs at 50% (no warning in result)
12. `enforcer_day_boundary_resets` -- counters reset at UTC midnight

**Persistence (3 tests):**
13. `persist_save_and_load_roundtrip` -- save then load returns same data
14. `persist_load_missing_file` -- returns default when file absent
15. `persist_load_corrupt_file` -- returns error for invalid JSON

**Suggestions (3 tests):**
16. `suggest_cheaper_alternative` -- tavily ($0.01) suggests brave ($0.005)
17. `suggest_no_alternative` -- unique tool in category returns None
18. `suggest_already_cheapest` -- cheapest tool in category returns None

### Integration Tests (~5 tests)

19. `invoke_blocked_by_budget` -- gateway_invoke returns -32003 when budget exceeded
20. `invoke_includes_cost_warning` -- response contains `_cost_warnings` at 80%
21. `invoke_includes_suggestion` -- response contains `_cost_suggestion` when cheaper exists
22. `stats_includes_cost_data` -- gateway_get_stats includes cost_governance section
23. `costs_api_endpoint` -- GET /ui/api/costs returns correct JSON

### Performance Test

24. `enforcer_check_under_100_microseconds` -- benchmark: 10,000 checks < 1 second (< 0.1ms each)

## Design Characteristics

1. **Track tool-call costs alongside LLM token costs.** This closes the visibility gap between model usage and tool execution when operators budget end-to-end agent workflows.

2. **Three-tier alerting with response injection.** At 50% = silent log. At 80% = warning injected into the tool response so the LLM agent can see it and adapt behavior. At 100% = hard block. The "notify" tier gives the agent cost awareness without breaking its flow.

3. **Cost-optimization suggestions.** When an agent calls `tavily_search` ($0.01), the response can include "brave_search provides similar results for $0.005."

4. **Sub-100-microsecond hot path (<0.1ms).** The budget check is a single DashMap lookup + atomic compare. No locks, no allocations. The gateway's p99 invoke latency does not change measurably.

5. **Atomic day-boundary reset.** Daily accumulators auto-reset when the day changes, using compare_exchange to prevent TOCTOU races. No background timer, no locks.

6. **Cost data persists across restarts.** `costs.json` is saved every 5 minutes and on graceful shutdown, loaded on startup. Consistent with the existing `usage.json` and `transitions.json` patterns.

7. **Dual source of truth for tool costs.** Config YAML (`tool_costs:`) takes priority, but capability YAML `cost_per_call` provides automatic cost data. This means community capability YAMLs ship with cost metadata that works out of the box.

---

## ADR-0075: Cost Governance Design Decisions

### Context

AI agents making autonomous tool calls incur real costs with no visibility or control. The gateway is the single routing point for all tool calls, making it the natural enforcement point.

### Decision

Extend the existing `cost_accounting` module rather than build a separate system. Use atomic counters (not locks) in the hot path. Store per-invocation costs, not per-token costs, because tool APIs charge per call, not per byte.

**Alternatives considered:**

| Option | Pros | Cons | Decision |
|--------|------|------|----------|
| A. Token-based cost only (existing) | Already implemented | Wrong model: APIs charge per call, not per token | Extended, not replaced |
| B. External cost service (gRPC sidecar) | Separation of concerns | Adds latency, deployment complexity | Rejected |
| C. In-process atomic enforcement (chosen) | <0.1ms, zero deps, crash-consistent | Day-boundary reset is approximate (not UTC-exact) | **Selected** |
| D. Database-backed (SQLite/DuckDB) | Exact windowing, rich queries | Disk I/O in hot path, new dependency | Rejected |

**Key design decisions:**

1. **Per-invocation, not per-token.** APIs like Tavily charge $0.01 per call regardless of response size. Token-based estimation is misleading.

2. **DailyAccumulator with atomic day-boundary reset.** Instead of a background timer that resets counters at midnight, each atomic read checks the current day number. If it has changed, the counter resets. This is eventually consistent (a few calls might span the boundary) but never locks.

3. **Alert actions as enum, not percentages.** The config says "at 80%, do X" not "at 80%, severity = warning." This makes the behavior deterministic and avoids ambiguity about what "warning" means.

4. **Dual cost source: config > capability YAML.** Config YAML always wins, but capability YAML `cost_per_call` provides fallback. This means users who install community capabilities get cost tracking for free.

5. **Response injection, not separate notification channel.** Cost warnings are injected as `_cost_warnings` in the tool response JSON, not sent via a separate webhook or log channel. This ensures the LLM agent sees the warning in context and can adapt.

### Consequences

- Cost visibility for every tool call, regardless of backend type
- Agents can be given budget-aware behavior through response-injected warnings
- Day-boundary reset is approximate (up to a few seconds of overlap at midnight)
- The `_cost_warnings` and `_cost_suggestion` keys in responses must not collide with tool output fields (underscore prefix convention)
- Community capability YAMLs should include `cost_per_call` in their provider config

---

## Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|----|------|-----------|--------|------------|
| R1 | Atomic counter overflow (u64 micro-USD) | Negligible | None | u64 micro-USD overflows at $18.4 trillion. Not a concern. |
| R2 | Day-boundary race condition | Low | Low | compare_exchange on day field ensures only one thread resets the counter. The winning thread uses `swap(0)` + `fetch_add(micro)` instead of `store(micro)` to prevent overwriting concurrent `fetch_add` calls between the swap and our add. Losing CAS threads fall through to `fetch_add` on the already-reset counter. No spend is lost. |
| R3 | Cost data lost on crash (no graceful shutdown) | Low | Low | Periodic persistence every 5 minutes limits data loss to at most 5 minutes of spend data. Daily accumulators are in-memory atomics; after crash restart, daily spend resumes from 0 (undercounts, safe direction). |
| R4 | `_cost_warnings` key collides with tool output | Low | Low | Underscore prefix convention. If collision occurs, the cost data overwrites the tool's field. Could use `__gateway_cost_warnings` for stronger namespacing. |
| R5 | Stale cost config after hot-reload | Medium | Low | CostRegistry is rebuilt on config reload (existing hot-reload path). BudgetEnforcer accumulators are NOT reset on reload (preserves daily spend state). |
| R6 | LLM agent ignores cost warnings | High | Medium | This is an agent behavior issue, not a gateway issue. The `block` action provides hard enforcement for critical budgets. |
| R7 | Tool cost changes upstream without config update | High | Medium | Tool costs are manual config. Future RFC: integrate with billing APIs for auto-learn. For now, the `default_cost` provides a safety net. |
| R8 | Per-tool DashMap grows unbounded | Low | Low | Only tools that are actually invoked create entries. Gateway typically routes to <100 distinct tools. No eviction needed. |

**Session teardown**: Per-key accumulators persist across sessions (keys outlive sessions). No session teardown needed for cost state.

**Prerequisite**: Implement session disconnect callback in `src/gateway/server.rs` that notifies all per-session state holders. All RFCs adding per-session DashMap entries MUST register a cleanup handler.
