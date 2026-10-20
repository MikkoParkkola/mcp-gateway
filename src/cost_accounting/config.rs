// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Cost governance configuration types.
//!
//! Deserializes from `cost_governance:` section in `config.yaml`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Top-level cost governance configuration.
///
/// Lives under `cost_governance:` in `config.yaml`.
/// All fields default to disabled/zero so the config section is optional.
#[cfg(feature = "cost-governance")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CostGovernanceConfig {
    /// Master enable switch.  When `false`, all checks are bypassed.
    pub enabled: bool,
    /// Global and scoped budget limits.
    pub budgets: BudgetLimits,
    /// Alert thresholds and actions (sorted by `at_percent` ascending on load).
    pub alerts: Vec<AlertRule>,
    /// Per-tool invocation costs (`tool_name` -> USD per call).
    /// Overrides `cost_per_call` from capability YAML metadata.
    pub tool_costs: HashMap<String, f64>,
    /// Default cost applied to tools not listed in `tool_costs` and without
    /// `cost_per_call` in their capability YAML.  Default: `0.0`.
    pub default_cost: f64,
    /// Configurable tool-category equivalences for cost-optimization suggestions.
    ///
    /// Each entry maps a category name to a list of functionally equivalent tool
    /// names.  When `Some`, replaces the compiled-in defaults entirely.
    pub alternatives: Option<HashMap<String, Vec<String>>>,
}

#[cfg(feature = "cost-governance")]
impl Default for CostGovernanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            budgets: BudgetLimits::default(),
            alerts: vec![
                AlertRule {
                    at_percent: 50,
                    action: AlertAction::Log,
                },
                AlertRule {
                    at_percent: 80,
                    action: AlertAction::Notify,
                },
                AlertRule {
                    at_percent: 100,
                    action: AlertAction::Block,
                },
            ],
            tool_costs: HashMap::new(),
            default_cost: 0.0,
            alternatives: None,
        }
    }
}

/// Budget limits at different scopes.
#[cfg(feature = "cost-governance")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BudgetLimits {
    /// Hard daily limit across ALL tool calls (USD).  `None` = unlimited.
    pub daily: Option<f64>,
    /// Per-tool daily limits (`tool_name` -> USD).
    pub per_tool: HashMap<String, f64>,
    /// Per-API-key daily limits (`key_name` -> USD).
    pub per_key: HashMap<String, f64>,
}

#[cfg(feature = "cost-governance")]
impl BudgetLimits {
    /// The `per_key` entries no caller is ever charged under, sorted: only a
    /// configured API key is charged per key (MIK-8507), so with auth off every
    /// entry is one, and with auth on so is an entry naming no `api_keys` key
    /// (the static bearer, the dashboard, an OIDC or key-server identity).
    pub(crate) fn unmatched_per_key<'a>(&'a self, _auth: &crate::config::AuthConfig) -> Vec<&'a str> {
        Vec::new()
    }
}

/// An alert rule triggered at a budget consumption threshold.
#[cfg(feature = "cost-governance")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Percentage of budget consumed that triggers this alert (0–100).
    pub at_percent: u32,
    /// Action taken when the threshold is reached.
    pub action: AlertAction,
}

/// Action taken when a budget threshold is reached.
#[cfg(feature = "cost-governance")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertAction {
    /// Emit a structured `tracing::warn!` event.  No response injection.
    Log,
    /// Emit a warning AND inject `_cost_warnings` into the tool response.
    Notify,
    /// Reject the tool call with JSON-RPC error `-32003`.
    Block,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::float_cmp)]
    fn default_config_is_disabled() {
        let cfg = CostGovernanceConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.default_cost, 0.0);
        assert!(cfg.tool_costs.is_empty());
        assert!(cfg.alternatives.is_none());
    }

    #[test]
    fn default_alerts_have_three_tiers() {
        let cfg = CostGovernanceConfig::default();
        assert_eq!(cfg.alerts.len(), 3);
        assert_eq!(cfg.alerts[0].at_percent, 50);
        assert_eq!(cfg.alerts[0].action, AlertAction::Log);
        assert_eq!(cfg.alerts[1].at_percent, 80);
        assert_eq!(cfg.alerts[1].action, AlertAction::Notify);
        assert_eq!(cfg.alerts[2].at_percent, 100);
        assert_eq!(cfg.alerts[2].action, AlertAction::Block);
    }

    #[test]
    fn budget_limits_default_is_unlimited() {
        let limits = BudgetLimits::default();
        assert!(limits.daily.is_none());
        assert!(limits.per_tool.is_empty());
        assert!(limits.per_key.is_empty());
    }

    #[test]
    fn serde_roundtrip() {
        let mut cfg = CostGovernanceConfig {
            enabled: true,
            budgets: BudgetLimits {
                daily: Some(10.0),
                ..BudgetLimits::default()
            },
            ..CostGovernanceConfig::default()
        };
        cfg.tool_costs.insert("brave_search".to_string(), 0.005);

        let json = serde_json::to_string(&cfg).unwrap();
        let back: CostGovernanceConfig = serde_json::from_str(&json).unwrap();
        assert!(back.enabled);
        assert_eq!(back.budgets.daily, Some(10.0));
        assert_eq!(back.tool_costs.get("brave_search"), Some(&0.005));
    }

    /// MIK-8507: a `per_key` entry that names no configured API key can never
    /// limit anyone, so startup names it. With auth off, no entry can.
    #[test]
    fn a_per_key_entry_naming_no_api_key_is_unmatched() {
        let budgets = BudgetLimits {
            per_key: [("ci", 1.0), ("bearer", 1.0), ("anonymous", 1.0)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            ..BudgetLimits::default()
        };
        let auth = |enabled: bool| -> crate::config::AuthConfig {
            serde_json::from_value(serde_json::json!({
                "enabled": enabled,
                "api_keys": [{"name": "ci", "key": "secret-ci"}],
            }))
            .expect("an auth config")
        };
        assert_eq!(budgets.unmatched_per_key(&auth(true)), ["anonymous", "bearer"]);
        assert_eq!(
            budgets.unmatched_per_key(&auth(false)),
            ["anonymous", "bearer", "ci"]
        );
        assert!(BudgetLimits::default().unmatched_per_key(&auth(true)).is_empty());
    }
}
