// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7597 T3c, bridged half: a bridged input round draws on the same key
//! budget as a per-backend route call.
//!
//! Driven on the input-bridge harness of the parent module (the scripted
//! backend and accepting channel). The per-backend route's use of the same
//! spend stage is pinned by the router's T3 cell and the structural check, so
//! this cell ends at that shared stage rather than an HTTP call.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::{AcceptingChannel, ScriptedToolCallTransport, allow_all_ctx};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::dispatch_guards::BackendCall;

/// Limit 2.5 at 1.0 a call: the opening call and one bridged round both
/// dispatch (projected 1.0, 2.0); the next admission for the same key through
/// the shared spend stage is refused (projected 3.0).
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn t3c_a_bridged_round_and_a_direct_call_share_one_budget() {
    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;
    use crate::transport::Transport;

    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "asking_backend",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let script = Arc::new(ScriptedToolCallTransport::new(vec![
        json!({
            "resultType": "input_required",
            "inputRequests": {
                "k1": {
                    "method": "elicitation/create",
                    "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}
                }
            },
            "requestState": "backend-state-1"
        }),
        json!({"content": [{"type": "text", "text": "booked"}]}),
    ]));
    let transport: Arc<dyn Transport> = script.clone();
    backend.set_transport_for_test(transport);
    let _ = registry.register(backend);

    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..CostGovernanceConfig::default()
    };
    cfg.tool_costs.insert("book".to_string(), 1.0);
    cfg.budgets.per_key.insert("k-budget".to_string(), 2.5);
    let cost_registry = Arc::new(CostRegistry::new(&cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg, Arc::clone(&cost_registry)));
    let meta = MetaMcp::new(registry).with_cost_governance(enforcer, cost_registry);

    let channel = AcceptingChannel {
        asked: std::sync::Mutex::new(Vec::new()),
    };
    let mut ctx = allow_all_ctx();
    ctx.api_key_name = Some("k-budget");
    ctx.era = crate::protocol::meta::Era::Legacy;
    ctx.input_capabilities = crate::protocol::meta::classify_request(
        Some(&json!({
            "_meta": {
                crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
                crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}}
            }
        })),
        None,
    )
    .declared_capabilities();
    ctx.channel = &channel;

    meta.invoke_tool(
        &json!({"server": "asking_backend", "tool": "book", "arguments": {}}),
        Some("session-t3c"),
        &ctx,
    )
    .await
    .expect("the opening call and the bridged round both fit the budget");
    assert_eq!(
        script.calls().len(),
        2,
        "opening call plus one bridged round"
    );

    let direct = BackendCall {
        server: "asking_backend",
        tool: "book",
        session_id: None,
        api_key_name: Some("k-budget"),
        trace_id: "t3c",
    };
    let refused = meta
        .admit_spend_for(&direct)
        .expect_err("the key budget is spent by the bridged exchange");
    assert_eq!(refused.to_rpc_code(), -32003);
}
