//! Per-tool cost registry.
//!
//! Resolves USD-per-invocation costs from three sources (priority order):
//! 1. `config.yaml` → `cost_governance.tool_costs` (highest)
//! 2. Capability YAML → `cost_per_call` (registered via `register_from_capability`)
//! 3. `config.yaml` → `cost_governance.default_cost` (fallback)

use std::collections::HashMap;

use dashmap::DashMap;

use super::config::CostGovernanceConfig;

/// Thread-safe per-tool cost lookup.
///
/// Read-heavy, write-rare (only on startup and config reload).
/// Backed by a `DashMap` so concurrent reads never block.
#[cfg(feature = "cost-governance")]
pub struct CostRegistry {
    /// `tool_name` -> USD per invocation
    costs: DashMap<String, f64>,
    /// Fallback cost for tools not explicitly registered.
    default_cost: f64,
}

#[cfg(feature = "cost-governance")]
impl CostRegistry {
    /// Build registry from `CostGovernanceConfig`.
    ///
    /// Explicit `tool_costs` from config are inserted with highest priority.
    pub fn new(config: &CostGovernanceConfig) -> Self {
        let costs = DashMap::new();
        for (tool, &cost) in &config.tool_costs {
            costs.insert(tool.clone(), cost);
        }
        Self {
            costs,
            default_cost: config.default_cost,
        }
    }

    /// Register a cost derived from a capability YAML `cost_per_call` field.
    ///
    /// Does **not** override values already set by `config.yaml` (config wins).
    pub fn register_from_capability(&self, tool_name: &str, cost_per_call: f64) {
        self.costs
            .entry(tool_name.to_string())
            .or_insert(cost_per_call);
    }

    /// Look up the per-invocation cost for `tool_name` (USD).
    ///
    /// Returns `default_cost` when the tool is not explicitly registered.
    #[must_use]
    pub fn cost_for(&self, tool_name: &str) -> f64 {
        self.costs.get(tool_name).map_or(self.default_cost, |v| *v)
    }

    /// Return `true` when the tool costs nothing (cost == 0.0).
    ///
    /// Free tools skip all budget checks in the enforcer hot path.
    #[must_use]
    pub fn is_free(&self, tool_name: &str) -> bool {
        self.cost_for(tool_name) == 0.0
    }

    /// Snapshot all explicitly registered costs (for API / UI display).
    #[must_use]
    pub fn snapshot(&self) -> HashMap<String, f64> {
        self.costs
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost_accounting::config::CostGovernanceConfig;

    fn cfg_with_costs(costs: &[(&str, f64)], default: f64) -> CostGovernanceConfig {
        let mut cfg = CostGovernanceConfig {
            default_cost: default,
            ..CostGovernanceConfig::default()
        };
        for &(name, cost) in costs {
            cfg.tool_costs.insert(name.to_string(), cost);
        }
        cfg
    }

    #[test]
    fn registry_explicit_config_overrides_capability() {
        // GIVEN: config sets tavily=$0.01, capability says $0.05
        let cfg = cfg_with_costs(&[("tavily_search", 0.01)], 0.0);
        let reg = CostRegistry::new(&cfg);
        reg.register_from_capability("tavily_search", 0.05);
        // THEN: config value wins
        assert!((reg.cost_for("tavily_search") - 0.01).abs() < 1e-9);
    }

    #[test]
    fn registry_capability_fallback_used_when_not_in_config() {
        // GIVEN: config has NO entry for exa_search; capability says $0.005
        let cfg = cfg_with_costs(&[], 0.0);
        let reg = CostRegistry::new(&cfg);
        reg.register_from_capability("exa_search", 0.005);
        // THEN: capability cost is used
        assert!((reg.cost_for("exa_search") - 0.005).abs() < 1e-9);
    }

    #[test]
    fn registry_default_cost_for_unknown_tool() {
        // GIVEN: default_cost = $0.001
        let cfg = cfg_with_costs(&[], 0.001);
        let reg = CostRegistry::new(&cfg);
        // THEN: unknown tool gets default
        assert!((reg.cost_for("unknown_tool") - 0.001).abs() < 1e-9);
    }

    #[test]
    fn registry_is_free_for_zero_cost_tool() {
        let cfg = cfg_with_costs(&[("wikipedia_search", 0.0)], 0.0);
        let reg = CostRegistry::new(&cfg);
        assert!(reg.is_free("wikipedia_search"));
        // Unknown tool with default 0.0 is also free
        assert!(reg.is_free("nonexistent"));
    }

    #[test]
    fn registry_snapshot_contains_registered_tools() {
        let cfg = cfg_with_costs(&[("brave_search", 0.005), ("exa_deep", 0.05)], 0.0);
        let reg = CostRegistry::new(&cfg);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get("brave_search"), Some(&0.005));
        assert_eq!(snap.get("exa_deep"), Some(&0.05));
    }

    #[test]
    fn registry_capability_registration_appears_in_snapshot() {
        let cfg = cfg_with_costs(&[], 0.0);
        let reg = CostRegistry::new(&cfg);
        reg.register_from_capability("my_api", 0.02);
        let snap = reg.snapshot();
        assert_eq!(snap.get("my_api"), Some(&0.02));
    }
}
