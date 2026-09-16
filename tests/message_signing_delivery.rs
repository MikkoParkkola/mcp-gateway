// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7406 / MIK-7377.SIGNING: production startup and delivered-wire falsifiers.
//!
//! Initial tests deliberately use existing public behavior; a fixture compile
//! or startup failure is not accepted as behavioral red evidence.

#[path = "common/signing_gateway.rs"]
mod signing_gateway;

use serde_json::json;
use signing_gateway::{BackendFixture, HttpGateway, fixture_config, invoke};

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
    let response = gateway
        .call(
            &session,
            &invoke(json!(41), json!("startup-nonce"), json!({})),
        )
        .await;

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
