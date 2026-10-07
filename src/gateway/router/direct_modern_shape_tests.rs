// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8022: the direct route `POST /mcp/{name}` answers a 2026-07-28 client
//! with the result fields that revision requires, as `/mcp` and stdio do.
//!
//! DIRECT.1 is the capture: each failing row prints the body the route sent,
//! for a legacy backend and for one that already speaks 2026-07-28.

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture, send_with_headers};

const KEY: &str = "k-std";

/// A request written against 2026-07-28: the version header and its mirrors,
/// and the `_meta` declaration a modern client sends on every request.
async fn modern(fx: &Fx, method: &str, mut params: Value, name: Option<&str>) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    let mut headers = vec![
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", method),
    ];
    if let Some(name) = name {
        headers.push(("mcp-name", name));
    }
    let (_, body) = send_with_headers(fx, "/mcp/alpha", KEY, method, params, None, &headers).await;
    body
}

/// The 2026-07-28 fields a result is missing: `resultType` always, the cache
/// pair on a cacheable list.
fn missing(body: &Value, cacheable: bool) -> Vec<&'static str> {
    let result = &body["result"];
    let mut keys = vec!["resultType"];
    if cacheable {
        keys.extend(["ttlMs", "cacheScope"]);
    }
    keys.into_iter()
        .filter(|k| result.get(*k).is_none())
        .collect()
}

#[tokio::test]
async fn a_modern_tools_list_from_a_legacy_backend_carries_the_fields() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let body = modern(&fx, "tools/list", json!({}), None).await;
    assert!(body["result"]["tools"].is_array(), "a listing: {body}");
    let gone = missing(&body, true);
    assert!(gone.is_empty(), "missing {gone:?}: {body}");
}

#[tokio::test]
async fn a_modern_tools_list_from_a_modern_backend_keeps_the_fields() {
    let fx = fixture(Answer::ModernList, |_| {}).await;
    let body = modern(&fx, "tools/list", json!({}), None).await;
    assert!(body["result"]["tools"].is_array(), "a listing: {body}");
    let gone = missing(&body, true);
    assert!(gone.is_empty(), "missing {gone:?}: {body}");
}

#[tokio::test]
async fn a_modern_tools_call_carries_the_result_type() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let params = json!({"name": "read", "arguments": {"cmd": "x"}});
    let body = modern(&fx, "tools/call", params, Some("read")).await;
    assert!(
        body["result"]["content"].is_array(),
        "a call result: {body}"
    );
    let gone = missing(&body, false);
    assert!(gone.is_empty(), "missing {gone:?}: {body}");
}

/// DIRECT.3 guard: a legacy client gains none of the fields.
#[tokio::test]
async fn a_legacy_tools_list_gains_no_fields() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let (_, body) =
        send_with_headers(&fx, "/mcp/alpha", KEY, "tools/list", json!({}), None, &[]).await;
    assert!(body["result"]["tools"].is_array(), "a listing: {body}");
    for key in ["resultType", "ttlMs", "cacheScope"] {
        assert!(
            body["result"].get(key).is_none(),
            "legacy gained {key}: {body}"
        );
    }
}
