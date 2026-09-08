// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5: real HTTP authentication must own nonce quotas, not session labels.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use serde_json::{Value, json};
use signing_gateway::{BackendFixture, HttpGateway, fixture_config, invoke};

const ALICE: &str = "quota-alice-key-0123456789abcdef";
const BOB: &str = "quota-bob-key-0123456789abcdef";
const PRIMARY: &str = "quota-primary-key-0123456789abcdef";
const LIMIT: usize = 10_000;

async fn start(public: bool, enabled: bool) -> (BackendFixture, HttpGateway) {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let mut config = fixture_config(&backend.url);
    config["idempotency"] = json!({"read_only_tools": [{
        "server": signing_gateway::BACKEND, "tool": signing_gateway::TOOL
    }]});
    config["auth"] = json!({
        "enabled": enabled, "bearer_token": PRIMARY,
        "public_paths": if public { vec!["/health", "/mcp"] } else { vec!["/health"] },
        "api_keys": [
            {"key": ALICE, "name": "same-label", "rate_limit": 0},
            {"key": BOB, "name": "same-label", "rate_limit": 0}
        ]
    });
    // Repeated identical calls hit the real response cache. Nonces must still
    // be admitted for every delivery, before that cache can return a result.
    config["cache"]["enabled"] = json!(true);
    let gateway = HttpGateway::start(config).await;
    (backend, gateway)
}

async fn call(gateway: &HttpGateway, token: Option<&str>, nonce: &str) -> Value {
    let mut request = invoke(json!(nonce), json!(nonce), json!({}));
    request["params"]["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let mut http = gateway
        .client
        .post(format!("{}/mcp", gateway.url))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        // A caller-controlled label must never create a new quota owner.
        .header("x-agent-id", nonce)
        .json(&request);
    if let Some(token) = token {
        http = http.bearer_auth(token);
    }
    let response = http.send().await.expect("quota HTTP request");
    let status = response.status();
    let body: Value = response.json().await.expect("quota JSON response");
    assert_eq!(
        status,
        if body.get("error").is_some() {
            400
        } else {
            200
        },
        "modern transport status must match the RPC outcome: {body}"
    );
    body
}

fn accepted(response: &Value, nonce: &str) {
    assert!(
        response.get("error").is_none(),
        "signed invocation failed: {response}"
    );
    assert_eq!(response["result"]["_signature"]["nonce"], nonce);
    assert_eq!(response["result"]["_signature"]["version"], 2);
}

fn refused(response: &Value, message: &str) {
    assert_eq!(response["error"]["code"], -32001, "{response}");
    assert_eq!(response["error"]["message"], message, "{response}");
    assert!(response.get("result").is_none());
}

async fn fill(gateway: &HttpGateway, token: Option<&str>) {
    for i in 0..LIMIT {
        let nonce = format!("fill-{i}");
        accepted(&call(gateway, token, &nonce).await, &nonce);
    }
    refused(
        &call(gateway, token, "over-cap").await,
        "Signing nonce capacity exceeded",
    );
}

#[tokio::test]
async fn signing_quota_protected_keys_with_equal_labels_are_independent() {
    let (backend, gateway) = start(false, true).await;
    fill(&gateway, Some(ALICE)).await;
    let calls = backend.calls().len();
    assert!(calls > 0, "fixture never dispatched");
    refused(
        &call(&gateway, Some(BOB), "fill-0").await,
        "Nonce replay detected",
    );
    assert_eq!(backend.calls().len(), calls, "replay reached backend");
    accepted(&call(&gateway, Some(BOB), "bob-fresh").await, "bob-fresh");
    accepted(
        &call(&gateway, Some(PRIMARY), "primary-fresh").await,
        "primary-fresh",
    );
    refused(
        &call(&gateway, Some(ALICE), "alice-still-full").await,
        "Signing nonce capacity exceeded",
    );
}

#[tokio::test]
async fn signing_quota_public_anonymous_cannot_starve_valid_static_credentials() {
    let (backend, gateway) = start(true, true).await;
    fill(&gateway, None).await;
    assert!(!backend.calls().is_empty(), "fixture never dispatched");
    refused(
        &call(&gateway, Some("invalid-key"), "invalid-fresh").await,
        "Signing nonce capacity exceeded",
    );
    accepted(
        &call(&gateway, Some(PRIMARY), "primary-fresh").await,
        "primary-fresh",
    );
    accepted(
        &call(&gateway, Some(ALICE), "alice-fresh").await,
        "alice-fresh",
    );
    accepted(&call(&gateway, Some(BOB), "bob-fresh").await, "bob-fresh");
}

#[tokio::test]
async fn signing_quota_auth_disabled_does_not_mint_static_credential_buckets() {
    let (backend, gateway) = start(true, false).await;
    fill(&gateway, Some(ALICE)).await;
    let calls = backend.calls().len();
    assert!(calls > 0, "fixture never dispatched");
    for token in [None, Some(BOB), Some(PRIMARY)] {
        refused(
            &call(&gateway, token, "disabled-fresh").await,
            "Signing nonce capacity exceeded",
        );
    }
    assert_eq!(
        backend.calls().len(),
        calls,
        "capacity refusal reached backend"
    );
}
