// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cost governance that suggests a cheaper tool, for tests that need the
//! gateway to write its `_cost_suggestion` into an answer (MIK-7991).

use std::sync::Arc;

use super::MetaMcp;
use crate::cost_accounting::config::CostGovernanceConfig;
use crate::cost_accounting::enforcer::BudgetEnforcer;
use crate::cost_accounting::registry::CostRegistry;

impl MetaMcp {
    /// `dear` costs 1.0 and `cheap` 0.1, both in `category`: every answer to
    /// `dear` gets the gateway's `_cost_suggestion` naming the category.
    pub(crate) fn suggest_cheaper_for_test(&mut self, category: &str, dear: &str, cheap: &str) {
        let mut cfg = CostGovernanceConfig {
            enabled: true,
            ..Default::default()
        };
        cfg.tool_costs.insert(dear.to_string(), 1.0);
        cfg.tool_costs.insert(cheap.to_string(), 0.1);
        cfg.alternatives = Some(
            [(
                category.to_string(),
                vec![dear.to_string(), cheap.to_string()],
            )]
            .into_iter()
            .collect(),
        );
        let registry = Arc::new(CostRegistry::new(&cfg));
        self.budget_enforcer = Some(Arc::new(BudgetEnforcer::new(cfg, Arc::clone(&registry))));
        self.cost_registry = Some(registry);
    }
}
