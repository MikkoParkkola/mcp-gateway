// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1756: the shipped binary's firewall learns from the calls it serves.
//!
//! Before the fix, both firewall constructions held an empty tracker that
//! nothing wrote to, so every call scored the neutral 0.5 and no threshold
//! above it ever blocked. These tests drive real calls through the built
//! binary, on both routes that score requests, and train nothing by hand.
#![cfg(feature = "firewall")]

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use serde_json::{Value, json};
use signing_gateway::{BACKEND, BackendFixture, HttpGateway};

const ROUNDS: usize = 25;
const TOKEN: &str = "anomaly-e2e-token-0123456789abcdef0123";

async fn start() -> (BackendFixture, HttpGateway) {
    let backend = BackendFixture::start(json!({"content": [{"type": "text", "text": "ok"}]})).await;
    let tools: Vec<Value> = ["tool_a", "tool_b", "tool_c"]
        .iter()
        .map(|name| json!({"name": name, "description": "fixture tool", "inputSchema": {"type": "object"}}))
        .collect();
    backend.set_tools(json!({ "tools": tools }));
    let mut gateway = HttpGateway::start(json!({
        "server": {"host": "127.0.0.1", "modern_protocol": true},
        "auth": {"enabled": true, "bearer_token": TOKEN},
        "cache": {"enabled": false},
        "backends": {(BACKEND): {"http_url": backend.url, "streamable_http": true}},
        "security": {
            "trust_configured_backends": true,
            // Auth on needs the audit log; relative to the child's own directory.
            "transparency_log": {"enabled": true, "path": "audit.jsonl"},
            "firewall": {
                "enabled": true,
                "anomaly_detection": true,
                "anomaly_threshold": 0.7,
                "anomaly_block_threshold": 0.95
            }
        }
    }))
    .await;
    // On HTTP the detector needs a caller key, so the calls carry a credential.
    let mut headers = reqwest::header::HeaderMap::new();
    let bearer = format!("Bearer {TOKEN}").parse().expect("header value");
    headers.insert(reqwest::header::AUTHORIZATION, bearer);
    gateway.client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("HTTP client");
    (backend, gateway)
}

/// The ASI10 refusal code, required on every route: a caller must be able to
/// tell an anomaly block from any other refusal by the code alone.
fn refused_as_anomaly(body: &Value) -> bool {
    body.get("error")
        .is_some_and(|error| error["code"] == -32002)
}

async fn direct(gateway: &HttpGateway, session: &str, tool: &str) -> Value {
    let response = gateway
        .client
        .post(format!("{}/mcp/{BACKEND}", gateway.url))
        .header("mcp-session-id", session)
        .json(
            &json!({"jsonrpc": "2.0", "id": tool, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}}),
        )
        .send()
        .await
        .expect("direct route HTTP");
    response.json().await.expect("direct route JSON")
}

async fn meta(gateway: &HttpGateway, session: &str, tool: &str) -> Value {
    gateway
        .call(
            session,
            &json!({"jsonrpc": "2.0", "id": tool, "method": "tools/call", "params": {
                "name": "gateway_invoke",
                "arguments": {"server": BACKEND, "tool": tool, "arguments": {}}
            }}),
        )
        .await
}

#[tokio::test]
async fn real_direct_calls_train_the_router_firewall() {
    let (_backend, gateway) = start().await;
    let session = gateway.initialize().await;
    for round in 0..ROUNDS {
        for tool in ["tool_a", "tool_b"] {
            let body = direct(&gateway, &session, tool).await;
            assert!(
                body.get("result").is_some(),
                "round {round}: {tool} must be served while learning: {body}; logs={}",
                gateway.logs()
            );
        }
    }
    assert!(
        direct(&gateway, &session, "tool_a")
            .await
            .get("result")
            .is_some()
    );
    let body = direct(&gateway, &session, "tool_c").await;
    assert!(
        refused_as_anomaly(&body),
        "after {ROUNDS} a->b, a never-seen a->c must be refused as an anomaly: {body}"
    );
}

#[tokio::test]
async fn real_meta_calls_train_the_router_firewall() {
    let (_backend, gateway) = start().await;
    let session = gateway.initialize().await;
    for round in 0..ROUNDS {
        for tool in ["tool_a", "tool_b"] {
            let body = meta(&gateway, &session, tool).await;
            assert!(
                !refused_as_anomaly(&body) && body.get("result").is_some(),
                "round {round}: {tool} must be served while learning: {body}; logs={}",
                gateway.logs()
            );
        }
    }
    assert!(!refused_as_anomaly(
        &meta(&gateway, &session, "tool_a").await
    ));
    let body = meta(&gateway, &session, "tool_c").await;
    assert!(
        refused_as_anomaly(&body),
        "after {ROUNDS} a->b, a never-seen a->c must be refused with -32002: {body}"
    );
}
