// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7406 / MIK-7377.SIGNING: production startup and delivered-wire falsifiers.
//!
//! Initial tests deliberately use existing public behavior; a fixture compile
//! or startup failure is not accepted as behavioral red evidence.

#[path = "common/signing_gateway.rs"]
mod signing_gateway;

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use signing_gateway::{BACKEND, BackendFixture, HttpGateway, KEY, TOOL, fixture_config, invoke};
use tokio::io::AsyncWriteExt as _;

fn backend_result() -> serde_json::Value {
    json!({"content": [{"type": "text", "text": "signing delivery sentinel"}]})
}

fn assert_delivered_payload(response: &serde_json::Value) {
    assert!(
        response.get("error").is_none(),
        "unexpected error: {response}"
    );
    assert_eq!(response["result"]["isError"], false);
    let content = response["result"]["content"]
        .as_array()
        .expect("wrapped content array must survive delivery");
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["type"], "text");
    let inner: serde_json::Value = serde_json::from_str(
        content[0]["text"]
            .as_str()
            .expect("wrapped text must survive delivery"),
    )
    .expect("gateway_invoke preserves its JSON-text envelope");
    assert_eq!(inner["content"], backend_result()["content"]);
}

#[test]
fn signing_2_enabled_config_rejects_short_and_zero_keys() {
    let mut config = mcp_gateway::config::Config::default();
    config.security.message_signing.enabled = true;
    config.security.message_signing.shared_secret = "k".repeat(32);
    assert!(config.validate().is_ok(), "valid configuration control");

    for key in [
        "short-signing-key".to_owned(),
        "k".repeat(31),
        "\0".repeat(32),
    ] {
        config.security.message_signing.shared_secret = key;
        assert!(
            config.validate().is_err(),
            "SIGNING.2 enabled key policy must run during normal Config validation"
        );
    }
}

#[tokio::test]
async fn signing_1_real_http_startup_installs_the_configured_signer() {
    let backend = BackendFixture::start(backend_result()).await;
    let gateway = HttpGateway::start(fixture_config(&backend.url)).await;
    let session = gateway.initialize().await;
    let started = chrono::Utc::now().timestamp();
    let wire = call_wire(
        &gateway,
        &session,
        &invoke(json!(41), json!("startup-nonce"), json!({})),
    )
    .await;
    let response: Value = serde_json::from_str(&wire).expect("delivered JSON");

    assert_eq!(
        backend.calls().len(),
        1,
        "real dispatch is required before grading signer wiring: {response}"
    );
    assert!(
        response.get("result").is_some(),
        "fixture dispatch refused: {response}"
    );
    let signature = response["result"]
        .get("_signature")
        .expect("SIGNING.1 enabled production startup must sign the delivered result");
    assert_eq!(signature["version"], 2);
    assert_eq!(signature["nonce"], "startup-nonce");
    assert_eq!(signature["key_id"], "signing-test-current");
    assert_eq!(signature["alg"], "hmac-sha256");
    let timestamp = signature["ts"].as_i64().expect("integer signing timestamp");
    assert!(
        (started..=chrono::Utc::now().timestamp()).contains(&timestamp),
        "signing timestamp must describe this delivery: {signature}"
    );
    let mac = signature["sig"]
        .as_str()
        .expect("signature must contain a MAC");
    assert_eq!(mac.len(), 64, "SHA256 MAC length: {signature}");
    assert!(
        mac.bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "MAC must be lowercase hexadecimal: {signature}"
    );
    assert_delivered_payload(&response);
    // VERIFY.1: the MAC over the delivered bytes verifies with the configured
    // key, and one changed byte of the body makes it fail.
    let id = json!({"kind": "number", "value": "41"});
    assert!(
        oracle_accepts(&wire, &id, "startup-nonce").await,
        "the delivered MAC must verify with the configured key: {wire}"
    );
    let tampered = wire.replacen("delivery sentinel", "delivery sentinem", 1);
    assert_ne!(
        tampered, wire,
        "the sentinel must be in the delivered bytes"
    );
    assert!(
        !oracle_accepts(&tampered, &id, "startup-nonce").await,
        "a tampered byte must fail the MAC: {tampered}"
    );
}

/// POST `request` and return the delivered body exactly as received.
async fn call_wire(gateway: &HttpGateway, session: &str, request: &Value) -> String {
    gateway
        .client
        .post(format!("{}/mcp", gateway.url))
        .header("mcp-session-id", session)
        .json(request)
        .send()
        .await
        .expect("gateway HTTP response")
        .text()
        .await
        .expect("gateway response body")
}

/// Whether the independent ECMAScript oracle (`tests/common/signing_verifier.mjs`,
/// no gateway code) accepts `wire` as signed with [`KEY`] for `id` and `nonce`.
async fn oracle_accepts(wire: &str, id: &Value, nonce: &str) -> bool {
    let verifier =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/common/signing_verifier.mjs");
    let mut child = tokio::process::Command::new("node")
        .arg(verifier)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("node is required for the independent signing oracle");
    let input = json!({"wire": wire, "options": {"key": KEY, "keyId": "signing-test-current",
        "expectedId": id, "expectedNonce": nonce, "now": chrono::Utc::now().timestamp()}});
    let mut stdin = child.stdin.take().expect("oracle stdin");
    stdin
        .write_all(input.to_string().as_bytes())
        .await
        .expect("write oracle stdin");
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .expect("bounded oracle")
        .expect("oracle process")
        .success()
}

#[tokio::test]
async fn signing_4_oversized_numeric_id_is_refused_without_dispatch() {
    let backend = BackendFixture::start(backend_result()).await;
    let gateway = HttpGateway::start(fixture_config(&backend.url)).await;
    let session = gateway.initialize().await;

    for (index, id) in [(i64::MAX as u64) + 1, u64::MAX].into_iter().enumerate() {
        let response = gateway
            .call(
                &session,
                &invoke(json!(id), json!(format!("id-boundary-{index}")), json!({})),
            )
            .await;
        assert_eq!(
            response["error"]["code"], -32600,
            "SIGNING.4 unsupported numeric ID must be rejected, never wrapped: {response}"
        );
        assert!(response.get("result").is_none());
        assert!(
            response.get("id").is_some_and(serde_json::Value::is_null),
            "invalid ID cannot be replaced with a different numeric ID: {response}"
        );
    }
    assert!(
        backend.calls().is_empty(),
        "invalid IDs reached the backend"
    );
}

#[tokio::test]
async fn signing_5_malformed_nonce_refuses_before_backend_dispatch() {
    let backend = BackendFixture::start(backend_result()).await;
    let gateway = HttpGateway::start(fixture_config(&backend.url)).await;
    let session = gateway.initialize().await;

    for (index, nonce) in [json!(null), json!(17), json!(""), json!("x".repeat(257))]
        .into_iter()
        .enumerate()
    {
        let response = gateway
            .call(&session, &invoke(json!(index), nonce, json!({})))
            .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "SIGNING.5 malformed present nonce must reject: {response}"
        );
        assert_eq!(response["error"]["message"], "Invalid signing nonce");
        assert!(response.get("result").is_none());
    }
    assert!(
        backend.calls().is_empty(),
        "malformed nonces reached the backend"
    );
}

#[tokio::test]
async fn signing_6_disabled_dormant_secret_preserves_unsigned_calls() {
    let backend = BackendFixture::start(backend_result()).await;
    backend.set_result(backend_result());
    backend.set_tools(json!({"tools": [{"name": signing_gateway::TOOL,
        "description": "disabled compatibility fixture", "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": true}}]}));
    let mut config = fixture_config(&backend.url);
    config["security"]["message_signing"]["enabled"] = json!(false);
    config["security"]["message_signing"]["shared_secret"] =
        json!("env:SIGNING_MISSING_DORMANT_KEY");
    let gateway = HttpGateway::start(config).await;
    let session = gateway.initialize().await;

    for id in [1, 2] {
        let response = gateway
            .call(
                &session,
                &invoke(json!(id), json!("same-disabled-nonce"), json!({})),
            )
            .await;
        assert!(
            response.get("result").is_some(),
            "disabled call refused: {response}"
        );
        assert!(
            response["result"].get("_signature").is_none(),
            "disabled gateway signed: {response}"
        );
        assert_delivered_payload(&response);
    }
    assert!(
        !backend.calls().is_empty(),
        "disabled fixture never dispatched"
    );
}

const PLAYBOOK: &str = "name: sig6
description: one backend step
steps:
  - name: echo
    tool: echo
    server: signing_fixture
    arguments: {}
";

/// SIGNING.6: with `require_nonce` on, a surfaced (named) tool, a Code Mode
/// execute and a playbook step each succeed without a nonce and arrive
/// unsigned; only `gateway_invoke` is signed, so only it demands a nonce.
#[tokio::test]
async fn signing_6_required_nonce_leaves_other_surfaces_unsigned() {
    let backend = BackendFixture::start(backend_result()).await;
    let playbooks = tempfile::TempDir::new().expect("playbook directory");
    std::fs::write(playbooks.path().join("sig6.yaml"), PLAYBOOK).expect("write playbook");
    let mut config = fixture_config(&backend.url);
    assert_eq!(config["security"]["message_signing"]["require_nonce"], true);
    config["meta_mcp"] = json!({"surfaced_tools": [{"server": BACKEND, "tool": TOOL}]});
    config["playbooks"] = json!({"enabled": true, "directories": [playbooks.path()]});
    let named = HttpGateway::start(config.clone()).await;
    config["code_mode"] = json!({"enabled": true});
    let code_mode = HttpGateway::start(config).await;

    let unsigned_invoke = json!({"jsonrpc": "2.0", "id": 60, "method": "tools/call", "params": {
        "name": "gateway_invoke", "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {}}}});
    let session = named.initialize().await;
    let refused = named.call(&session, &unsigned_invoke).await;
    assert_eq!(
        refused["error"]["code"], -32001,
        "control: require_nonce must be live here: {refused}"
    );
    let calls = [
        (&named, "named tool", json!({"name": TOOL, "arguments": {}})),
        (
            &named,
            "playbook step",
            json!({"name": "gateway_run_playbook",
            "arguments": {"name": "sig6"}}),
        ),
        (
            &code_mode,
            "Code Mode execute",
            json!({"name": "gateway_execute",
            "arguments": {"chain": [{"tool": format!("{BACKEND}:{TOOL}"), "arguments": {}}]}}),
        ),
    ];
    for (id, (gateway, surface, params)) in (61..).zip(calls) {
        let dispatched = backend.calls().len();
        let session = gateway.initialize().await;
        let request = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params});
        let response = gateway.call(&session, &request).await;
        assert!(
            response.get("error").is_none() && response["result"]["isError"] != true,
            "{surface} must succeed without a nonce: {response}"
        );
        assert!(
            response["result"].get("_signature").is_none(),
            "{surface} must arrive unsigned: {response}"
        );
        assert_eq!(
            backend.calls().len(),
            dispatched + 1,
            "{surface} must reach the backend once: {response}"
        );
    }
}
