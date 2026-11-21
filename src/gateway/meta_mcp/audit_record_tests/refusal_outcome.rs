// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call the gateway itself refused is recorded as a refusal even when its
//! wire code is one the plain error mapping files under `error`: the record's
//! outcome has to agree with the check its decision names.

use serde_json::json;

use super::{api_key_caller, context, meta, ok_result, records};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::visible::memo::with_visibility_memo;

/// Spend governance where one `read` costs more than the caller's whole
/// allowance, so the first call is over budget.
#[cfg(feature = "cost-governance")]
fn spend_capped(meta: MetaMcp, account: &str) -> MetaMcp {
    use std::sync::Arc;

    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;
    let mut spend = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    spend.tool_costs.insert("read".to_owned(), 2.0);
    spend.budgets.per_key.insert(account.to_owned(), 1.0);
    let ledger = Arc::new(CostRegistry::new(&spend));
    let gate = Arc::new(BudgetEnforcer::new(spend, Arc::clone(&ledger)));
    meta.with_cost_governance(gate, ledger)
}

/// O1: the spend budget refuses the call with -32003; the one record says
/// `denied`, not `error`, beside its `cost_budget` decision.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn o1_a_spend_refusal_is_recorded_as_denied() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let mut who = api_key_caller();
    who.account = "over-budget".to_owned();
    let meta = spend_capped(meta(Ok(ok_result()), &dir), &who.account);
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let answer =
        with_visibility_memo(meta.invoke_tool(&args, None, &context(&AllowAll, &who))).await;
    let all = records(&dir);
    let [record] = all.as_slice() else {
        panic!("premise: one invocation record: {all:?}; answer {answer:?}");
    };
    assert_eq!(
        record["decision"]["kind"],
        json!("cost_budget"),
        "premise: the budget decided; answer {answer:?}; {record}"
    );
    assert_eq!(record["error_code"], json!(-32003), "{record}");
    assert_eq!(record["outcome"], json!("denied"), "{record}");
}
