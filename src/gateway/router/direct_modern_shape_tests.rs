// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8022: the direct route `POST /mcp/{name}` answers a 2026-07-28 client
//! with the result fields that revision requires, as `/mcp` and stdio do, and
//! a legacy client exactly as before.
//!
//! `alpha` takes the sanitized dispatch arm on `tools/call`; `alpha-pt`
//! (passthrough) takes the plain one. Rows that call run on both.

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::Fx;

const KEY: &str = "k-std";
const BACKENDS: [&str; 2] = ["alpha", "alpha-pt"];
const CACHEABLE: [&str; 5] = [
    "tools/list",
    "prompts/list",
    "resources/list",
    "resources/templates/list",
    "resources/read",
];

/// One request to `/mcp/{backend}`, modern or legacy, with request id `id`
/// and `meta` merged into `params._meta`.
async fn post(
    fx: &Fx,
    (backend, method): (&str, &str),
    (modern, id): (bool, i64),
    mut params: Value,
    meta: Value,
) -> Value {
    let mut merged = meta.as_object().cloned().unwrap_or_default();
    if modern {
        merged.insert(
            "io.modelcontextprotocol/protocolVersion".into(),
            json!("2026-07-28"),
        );
        merged.insert(
            "io.modelcontextprotocol/clientCapabilities".into(),
            json!({}),
        );
    }
    if !merged.is_empty() {
        params["_meta"] = Value::Object(merged);
    }
    let name = params["name"].as_str().map(str::to_owned);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{backend}"))
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/json");
    if modern {
        request = request
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method);
        if let Some(name) = name {
            request = request.header("mcp-name", name);
        }
    }
    let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let request = request
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn modern(fx: &Fx, backend: &str, method: &str, params: Value) -> Value {
    post(fx, (backend, method), (true, 1), params, json!({})).await
}

async fn legacy(fx: &Fx, backend: &str, method: &str, params: Value) -> Value {
    post(fx, (backend, method), (false, 1), params, json!({})).await
}

fn call_params() -> Value {
    json!({"name": "read", "arguments": {"cmd": "x"}})
}

fn params_for(method: &str) -> Value {
    if method == "resources/read" {
        json!({"uri": "res://x"})
    } else {
        json!({})
    }
}

/// The 2026-07-28 fields a result is missing: `resultType` always, the cache
/// pair on a cacheable result.
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

#[path = "direct_modern_shape_rows.rs"]
mod rows;
