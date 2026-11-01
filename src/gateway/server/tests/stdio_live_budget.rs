// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U19 PR3a T14: a budget lowered by a reload over stdio refuses the next
//! stdio call. Driven through `Gateway::run_stdio_on` over in-memory pipes
//! and the `gateway_reload_config` meta-tool, so the reload and the call
//! share the live config the serve loop built.

use serde_json::{Value, json};

use super::owner1_stdio_reload::{CAPABILITY, base_yaml, serve_with};

/// A per-tool budget of `limit` on the probe capability, priced at 1.0 a call.
fn governance(limit: f64) -> String {
    format!(
        "cost_governance:\n  enabled: true\n  tool_costs:\n    owner1_probe: 1.0\n  \
         budgets:\n    per_tool:\n      owner1_probe: {limit}\n"
    )
}

fn probe(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": "capabilities", "tool": "owner1_probe",
                      "arguments": {"query": "x"}}}})
}

/// The error code of a response, if it is an error.
fn code(response: &Value) -> Option<i64> {
    response.pointer("/error/code").and_then(Value::as_i64)
}

/// Started with a budget of 100, a reload to 0.5 makes the next call, priced
/// at 1.0, a budget refusal (-32003): the startup copy would have admitted it.
#[tokio::test]
async fn t14_a_reload_over_stdio_lowers_the_budget_of_the_next_call() {
    let mut serve = serve_with(&governance(100.0), Some(CAPABILITY)).await;
    let edited = format!(
        "{}{}",
        base_yaml(&serve.capabilities_dir()),
        governance(0.5)
    );
    crate::gateway::test_helpers::write_owner_only(serve.config_path(), edited)
        .expect("rewrite config");
    let reloaded = serve.call(1, "gateway_reload_config", None).await;
    assert!(reloaded.get("error").is_none(), "{reloaded}");
    serve.send(&probe(2)).await;
    let refused = serve.reply(2).await;
    assert_eq!(code(&refused), Some(-32003), "{refused}");
    serve.close().await;
}
