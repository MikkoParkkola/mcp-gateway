// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The budget check a request runs under its pinned config: [`BudgetEnforcer::check_under`].

use super::{
    AlertAction, Arc, BudgetEnforcer, CostGovernanceConfig, DailyAccumulator, DeferredLog,
    EnforcementResult, SpendHold, evaluate_alerts, locked, usd,
};

impl BudgetEnforcer {
    /// [`Self::check`] with the budgets and alerts of `governance`, the config
    /// the request is pinned to.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn check_under(
        &self,
        governance: &CostGovernanceConfig,
        tool_name: &str,
        api_key_name: Option<&str>,
    ) -> EnforcementResult {
        if !self.config.enabled {
            return EnforcementResult {
                allowed: true,
                cost_usd: 0.0,
                warnings: Vec::new(),
                block_reason: None,
                hold: None,
            };
        }

        let cost = self.registry.cost_for(tool_name);
        if cost == 0.0 {
            // Free tools skip all budget checks
            return EnforcementResult {
                allowed: true,
                cost_usd: 0.0,
                warnings: Vec::new(),
                block_reason: None,
                hold: None,
            };
        }

        // The same conversion `record_spend` applies to this cost, and the
        // amount every projection below counts.
        let cost_micro = super::super::tally::micro(cost);
        let cost = usd(cost_micro);

        // One step from here to the reservation below. Nothing in it waits or
        // writes a log: alerts are recorded and emitted after the lock is gone.
        // One clock read for the day and for a key refusal's record.
        let now = crate::clock::unix_secs().ok();
        let today = now.map(|secs| self.day_key(secs));
        let mut pending = locked(&self.ledger);
        // A refusal under the key's own limit, recorded once the lock is gone.
        let mut key_refusal: Option<f64> = None;
        let mut logs: Vec<DeferredLog> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut blocked = false;
        let mut block_reason: Option<String> = None;

        // Check 1: per-tool daily limit
        if let Some(&limit) = governance.budgets.per_tool.get(tool_name) {
            let acc = self
                .tool_daily
                .entry(tool_name.to_string())
                .or_insert_with(|| DailyAccumulator::on(today));
            // The row, the figure a reload charged it with, and the pending.
            let (row, held) = (acc.current_on(today), pending.tool(tool_name));
            let current_usd = usd(self.tool_attribution.judged(tool_name, row, held, today));
            let projected = current_usd + cost;

            if let Some(action) = evaluate_alerts(&governance.alerts, projected, limit) {
                match action {
                    AlertAction::Log => logs.push(DeferredLog::Tool {
                        tool: tool_name.to_string(),
                        spent: projected,
                        limit,
                    }),
                    AlertAction::Notify => {
                        warnings.push(format!(
                            "Tool '{tool_name}' daily spend ${projected:.4} approaching limit ${limit:.2}"
                        ));
                    }
                    AlertAction::Block => {
                        blocked = mutant!(
                            "s5-tool",
                            {
                                key_refusal = Some(limit);
                                true
                            },
                            true
                        );
                        block_reason = Some(format!(
                            "Tool '{tool_name}' daily budget exceeded: ${projected:.4} >= ${limit:.2}"
                        ));
                    }
                }
            }
        }

        // Check 2: global daily limit
        if !blocked && let Some(limit) = governance.budgets.daily {
            let row = self.global_daily.current_on(today);
            let current_usd = usd(row.saturating_add(pending.global));
            let projected = current_usd + cost;

            if let Some(action) = evaluate_alerts(&governance.alerts, projected, limit) {
                match action {
                    AlertAction::Log => logs.push(DeferredLog::Global {
                        spent: projected,
                        limit,
                    }),
                    AlertAction::Notify => {
                        warnings.push(format!(
                            "Global daily spend ${projected:.4} approaching limit ${limit:.2}"
                        ));
                    }
                    AlertAction::Block => {
                        blocked = true;
                        block_reason = Some(format!(
                            "Global daily budget exceeded: ${projected:.4} >= ${limit:.2}"
                        ));
                    }
                }
            }
        }

        // Check 3: per-key daily limit
        if !blocked
            && let Some(key_name) = api_key_name
            && let Some(&limit) = governance.budgets.per_key.get(key_name)
        {
            let acc = self
                .key_daily
                .entry(key_name.to_string())
                .or_insert_with(|| DailyAccumulator::on(today));
            let (row, held) = (acc.current_on(today), pending.key(key_name));
            let current_usd = usd(self.key_attribution.judged(key_name, row, held, today));
            let projected = current_usd + cost;

            if let Some(action) = evaluate_alerts(&governance.alerts, projected, limit) {
                match action {
                    AlertAction::Log => logs.push(DeferredLog::Key {
                        key: key_name.to_string(),
                        spent: projected,
                        limit,
                    }),
                    AlertAction::Notify => {
                        warnings.push(format!(
                                    "API key '{key_name}' daily spend ${projected:.4} approaching limit ${limit:.2}"
                                ));
                    }
                    AlertAction::Block => {
                        blocked = true;
                        key_refusal = Some(limit);
                        block_reason = Some(format!(
                            "API key '{key_name}' daily budget exceeded: ${projected:.4} >= ${limit:.2}"
                        ));
                    }
                }
            }
        }

        let hold = (!blocked).then(|| {
            pending.add(tool_name, api_key_name, cost_micro);
            Arc::new(SpendHold {
                ledger: Arc::clone(&self.ledger),
                tool: tool_name.to_string(),
                key: api_key_name.map(str::to_string),
                micro: std::sync::atomic::AtomicU64::new(cost_micro),
            })
        });
        drop(pending);
        if let (Some(limit), Some(key), Some(today), Some(now)) =
            (key_refusal, api_key_name, today, now)
        {
            self.note_first_block(key, today, now, limit);
        }
        for log in logs {
            log.emit();
        }

        EnforcementResult {
            allowed: !blocked,
            cost_usd: cost,
            warnings,
            block_reason,
            hold,
        }
    }
}
