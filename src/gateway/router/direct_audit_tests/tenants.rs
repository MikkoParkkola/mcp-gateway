// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.1: tenant attribution on the router's invocation records:
//! the direct route (T12, T26, T28) and the meta pre-dispatch refusal
//! record from #2421 (T2).

use super::*;
use crate::security::hash_argument;

fn h(id: &str) -> String {
    hash_argument(&json!(id))
}

fn sorted(ids: &[&str]) -> Value {
    let mut hashes: Vec<String> = ids.iter().map(|id| h(id)).collect();
    hashes.sort();
    json!(hashes)
}

/// A tool result whose text block is JSON naming `tenant`.
fn reply_naming(tenant: &str, note: &str) -> Value {
    let rows = json!({"rows": [{"customer_id": tenant}], "note": note});
    json!({"content": [{"type": "text", "text": rows.to_string()}], "isError": false})
}

/// A direct `tools/call` of `t` naming `customer_id`, optionally keyed.
fn direct_call(tenant: &str, idempotency_key: Option<&str>) -> String {
    let mut params = json!({"name": "t", "arguments": {"customer_id": tenant}});
    if let Some(key) = idempotency_key {
        params["_meta"] = json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key});
    }
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params}).to_string()
}

/// POST as a modern, anonymous client: the era that carries an idempotency key.
async fn post_modern(fx: &Fixture, uri: &str, body: &str) -> (StatusCode, Value) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// T12. The direct record names request and response tenants, hashed and
/// sorted, with the kernel's data classes: the direct route runs the same
/// response gates as the meta route.
#[tokio::test]
async fn direct_record_carries_tenants_and_data_classes() {
    let fx = fixture(Setup {
        reply: Some(reply_naming("cust-9", "")),
        tenant_limit: Some(0),
        ..Setup::default()
    })
    .await;
    let (status, answer) = post(
        &fx,
        "alpha",
        &direct_call("cust-1", None),
        &Caller::Anonymous,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let entry = only_invocation(&fx);
    assert_eq!(entry["route"], "direct", "{entry}");
    assert_eq!(entry["tenants"], sorted(&["cust-1", "cust-9"]), "{entry}");
    assert!(
        entry["data_classes"]
            .as_array()
            .is_some_and(|classes| !classes.is_empty()),
        "{entry}"
    );
    let text = std::fs::read_to_string(&fx.path).unwrap();
    assert!(
        !text.contains("cust-1") && !text.contains("cust-9"),
        "{text}"
    );
}

/// T26. A response the inspection gate refuses on the direct route keeps
/// its response tenants and has no data classes.
#[tokio::test]
async fn direct_gate_refusal_keeps_response_tenants() {
    let key = ["AKIA", "IOSFODNN7", "EXAMPLE"].concat();
    let fx = fixture(Setup {
        reply: Some(reply_naming("cust-9", &format!("AWS_ACCESS_KEY_ID={key}"))),
        tenant_limit: Some(0),
        inspection_action_mode: true,
        ..Setup::default()
    })
    .await;
    let _ = post(
        &fx,
        "alpha",
        &direct_call("cust-1", None),
        &Caller::Anonymous,
    )
    .await;
    let entry = only_invocation(&fx);
    assert_ne!(entry["outcome"], "ok", "{entry}");
    let tenants = entry["tenants"].as_array().cloned().unwrap_or_default();
    assert!(tenants.contains(&json!(h("cust-9"))), "{entry}");
    assert!(entry.get("data_classes").is_none(), "{entry}");
}

/// T28. A direct idempotent replay is answered before the gates; its record
/// carries the delivered value's tenants, marked as a cached delivery.
#[tokio::test]
async fn direct_idempotent_replay_record_carries_delivered_tenants() {
    let fx = fixture(Setup {
        reply: Some(reply_naming("cust-9", "")),
        tenant_limit: Some(0),
        idempotency: true,
        ..Setup::default()
    })
    .await;
    for _ in 0..2 {
        let (status, answer) =
            post_modern(&fx, "/mcp/alpha", &direct_call("cust-1", Some("k-min1"))).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
    }
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "the second call must replay"
    );
    let all = invocations(&fx);
    assert_eq!(all.len(), 2, "{all:?}");
    let replay = &all[1];
    assert_eq!(replay["attribution"], "cached_delivery", "{replay}");
    assert_eq!(replay["tenants"], sorted(&["cust-1", "cust-9"]), "{replay}");
    assert!(replay.get("data_classes").is_none(), "{replay}");
}

/// T2 (record half). A meta call the tenant guard refuses before dispatch:
/// the #2421 `denied` record names the tenants the request reached, and
/// carries no data classes (nothing was fetched).
#[tokio::test]
async fn meta_tenant_guard_refusal_record_names_the_tenants() {
    let fx = fixture(Setup {
        tenant_limit: Some(1),
        ..Setup::default()
    })
    .await;
    let arguments = json!({"server": "alpha", "tool": "t",
                           "arguments": {"rows": [{"customer_id": "cust-1"},
                                                  {"customer_id": "cust-2"}]}});
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                      "params": {"name": "gateway_invoke", "arguments": arguments}});
    let (status, answer) = post_to(&fx, "/mcp", &body.to_string(), &Caller::Session).await;
    assert_ne!(status, StatusCode::OK, "the guard must refuse: {answer}");
    let entry = only_invocation(&fx);
    assert_eq!(entry["route"], "meta", "{entry}");
    assert_eq!(entry["outcome"], "denied", "{entry}");
    assert_eq!(entry["tenants"], sorted(&["cust-1", "cust-2"]), "{entry}");
    assert!(entry.get("data_classes").is_none(), "{entry}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0);
}
