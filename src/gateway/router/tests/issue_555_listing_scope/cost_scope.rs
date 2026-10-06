// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A cost report covers the caller's own spend only, on the 2026-07-28
//! protocol too, where a request carries no session.

use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{Auth, fixture_with};

/// The meta route with cost governance on, so `gateway_cost_report` is served.
async fn governed() -> super::Fixture {
    fixture_with(Auth::Keys, |meta| {
        let config = crate::cost_accounting::config::CostGovernanceConfig::default();
        let registry =
            std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&config));
        let enforcer = std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
            config,
            std::sync::Arc::clone(&registry),
        ));
        meta.with_cost_governance(enforcer, registry)
    })
    .await
}

/// A 2026-07-28 `tools/call` of `name` on `/mcp` as `key`.
async fn modern_call(router: &axum::Router, key: &str, name: &str, args: Value) -> Value {
    let body = json!({
        "jsonrpc": "2.0",
        "id": "modern-cost",
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": args,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": { "name": "cost", "version": "1.0.0" },
                crate::protocol::mrtr::IDEMPOTENCY_KEY_META: format!("cost-{key}-{name}")
            }
        }
    });
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .header("authorization", format!("Bearer {key}"))
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    assert_eq!(response.status(), StatusCode::OK, "{name} as {key}");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn a_cost_report_shows_own_spend_and_no_other_callers() {
    let f = governed().await;
    // GIVEN: caller u1 spends on a backend over the 2026-07-28 protocol
    let spent = modern_call(
        &f.router,
        "u1",
        "gateway_invoke",
        json!({ "server": "alpha", "tool": "alpha_read", "arguments": {} }),
    )
    .await;
    assert!(spent.get("error").is_none(), "the spend call: {spent}");
    // Control: the spend was recorded, so the report below is not empty by accident
    let all_keys = modern_call(
        &f.router,
        "admin-key",
        "gateway_cost_report",
        json!({ "include_all_keys": true }),
    )
    .await;
    assert!(
        all_keys.to_string().contains("alpha_read"),
        "the spend was never recorded: {all_keys}"
    );

    // AND: caller u2 spends on another backend, also without a session
    let own = modern_call(
        &f.router,
        "u2",
        "gateway_invoke",
        json!({ "server": "beta", "tool": "beta_tool", "arguments": {} }),
    )
    .await;
    assert!(own.get("error").is_none(), "u2's spend call: {own}");

    // WHEN: u2 asks for its own report
    let report = modern_call(&f.router, "u2", "gateway_cost_report", json!({})).await;

    // THEN: it holds u2's own spend and none of u1's
    assert!(report.get("error").is_none(), "the report call: {report}");
    let text = report.to_string();
    assert!(
        text.contains("beta_tool"),
        "a session-less caller's own spend is missing from its report: {report}"
    );
    assert!(
        !text.contains("alpha_read"),
        "the report is not scoped to its caller: {report}"
    );
    assert!(
        !text.contains("\\\"u1\\\""),
        "the report names another key: {report}"
    );
}
