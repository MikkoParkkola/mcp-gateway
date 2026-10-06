// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A cost report covers the caller's own spend only, on the 2026-07-28
//! protocol too, where a request carries no session.

use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::meta_tools::payload;
use super::{Auth, fixture_with, post};

/// The meta route with cost governance on, so `gateway_cost_report` is served.
async fn governed(auth: Auth) -> super::Fixture {
    fixture_with(auth, |meta| {
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

/// A 2026-07-28 `tools/call` of `name` on `/mcp` as `key` (anonymous when `None`).
async fn modern_call(router: &axum::Router, key: Option<&str>, name: &str, args: Value) -> Value {
    let who = key.unwrap_or("anonymous");
    let mut body = json!({
        "jsonrpc": "2.0",
        "id": "modern-cost",
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": args,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": { "name": "cost", "version": "1.0.0" }
            }
        }
    });
    // A keyed call needs a verified principal, so an anonymous one goes unkeyed.
    if key.is_some() {
        body["params"]["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] =
            json!(format!("cost-{who}-{name}"));
    }
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name);
    if let Some(key) = key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    let request = builder
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    assert_eq!(response.status(), StatusCode::OK, "{name} as {who}");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn a_cost_report_shows_no_other_callers_spend() {
    let f = governed(Auth::Keys).await;
    // GIVEN: caller u1 spends on a backend over the 2026-07-28 protocol
    let spent = modern_call(
        &f.router,
        Some("u1"),
        "gateway_invoke",
        json!({ "server": "alpha", "tool": "alpha_read", "arguments": {} }),
    )
    .await;
    assert!(spent.get("error").is_none(), "the spend call: {spent}");
    // Control: the spend was recorded, so the report below is not empty by accident
    let all_keys = modern_call(
        &f.router,
        Some("admin-key"),
        "gateway_cost_report",
        json!({ "include_all_keys": true }),
    )
    .await;
    assert!(
        all_keys.to_string().contains("alpha_read"),
        "the spend was never recorded: {all_keys}"
    );

    // WHEN: another non-admin caller asks for its own report
    let report = modern_call(&f.router, Some("u2"), "gateway_cost_report", json!({})).await;

    // THEN: it holds only its own (empty) spend
    assert!(report.get("error").is_none(), "the report call: {report}");
    assert!(
        payload(&report)["caller"].is_null(),
        "u2 spent nothing, so it has no caller breakdown: {report}"
    );
    let text = report.to_string();
    assert!(
        !text.contains("alpha_read"),
        "the report is not scoped to its caller: {report}"
    );
    assert!(
        !text.contains("\\\"u1\\\""),
        "the report names another key: {report}"
    );
}

/// `(name, call_count)` of every row under `report.caller[part]`, sorted;
/// `field` names the row's key (`tool_key` or `backend`).
fn caller_rows(report: &Value, part: &str, field: &str) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = payload(report)["caller"][part]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            (
                row[field].as_str().unwrap_or_default().to_string(),
                row["call_count"].as_u64().unwrap_or_default(),
            )
        })
        .collect();
    rows.sort();
    rows
}

#[tokio::test]
async fn a_session_less_caller_sees_its_own_spend() {
    let f = governed(Auth::Keys).await;
    // GIVEN: u1 spends once over the 2026-07-28 protocol, which carries no session
    let call = json!({ "server": "alpha", "tool": "alpha_read", "arguments": {} });
    let spent = modern_call(&f.router, Some("u1"), "gateway_invoke", call).await;
    assert!(spent.get("error").is_none(), "the spend call: {spent}");

    // WHEN: u1 asks for its report
    let report = modern_call(&f.router, Some("u1"), "gateway_cost_report", json!({})).await;

    // THEN: the caller breakdown holds that one call, by tool and by backend
    assert_eq!(
        caller_rows(&report, "by_tool", "tool_key"),
        vec![("alpha:alpha_read".to_string(), 1)],
        "{report}"
    );
    assert_eq!(
        caller_rows(&report, "by_backend", "backend"),
        vec![("alpha".to_string(), 1)],
        "{report}"
    );
}

#[tokio::test]
async fn a_keyless_caller_has_no_breakdown_but_its_spend_is_counted() {
    let f = governed(Auth::Off).await;
    let tracker = f.state.meta_mcp.cost_tracker();
    let before = tracker.aggregate().total_calls;
    // GIVEN: auth is off and an anonymous caller spends with no session
    let call = json!({ "server": "alpha", "tool": "alpha_read", "arguments": {} });
    let spent = modern_call(&f.router, None, "gateway_invoke", call).await;
    assert!(spent.get("error").is_none(), "the spend call: {spent}");

    // WHEN: it asks for its report
    let report = modern_call(&f.router, None, "gateway_cost_report", json!({})).await;

    // THEN: no breakdown is keyed on a label every keyless caller shares,
    // and the gateway total still counts the call
    assert!(report.get("error").is_none(), "the report call: {report}");
    assert!(payload(&report)["caller"].is_null(), "{report}");
    assert_eq!(tracker.aggregate().total_calls, before + 1);
}

#[tokio::test]
async fn a_session_less_direct_call_is_charged_to_its_caller() {
    let f = governed(Auth::Keys).await;
    let tracker = f.state.meta_mcp.cost_tracker();
    let before = tracker.aggregate().total_calls;
    // GIVEN: u1 calls the backend's own route with no session header
    let call = json!({ "name": "alpha_read", "arguments": {} });
    let (status, answer) = post(&f.router, "/mcp/alpha", Some("u1"), "tools/call", call).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(answer.get("error").is_none(), "the direct call: {answer}");

    // WHEN: u1 asks for its report on the meta route
    let report = modern_call(&f.router, Some("u1"), "gateway_cost_report", json!({})).await;

    // THEN: the call reached the gateway total, u1's key totals and u1's breakdown
    assert_eq!(tracker.aggregate().total_calls, before + 1);
    let key_tools: Vec<(String, u64)> = tracker
        .key_snapshot("u1")
        .map(|k| {
            k.by_tool
                .into_iter()
                .map(|t| (t.tool_key, t.call_count))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(key_tools, vec![("alpha:alpha_read".to_string(), 1)]);
    assert_eq!(
        caller_rows(&report, "by_tool", "tool_key"),
        vec![("alpha:alpha_read".to_string(), 1)],
        "{report}"
    );
}
