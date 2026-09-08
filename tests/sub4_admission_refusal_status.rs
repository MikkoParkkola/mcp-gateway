// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SUB4 current authorization: admission refusals preserve their HTTP status.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use reqwest::StatusCode;
use serde_json::{Value, json};
use signing_gateway::{BACKEND, BackendFixture, HttpGateway, TOOL, fixture_config};

const CREDENTIAL: &str = "profile-status-fixture-credential-0123456789";
const BROADER: &str = "profile-status-reachability-credential-0123456789";
const FORBIDDEN: &str = "forbidden-backend";

async fn call(gateway: &HttpGateway, modern: bool, name: &str, token: &str) -> (StatusCode, Value) {
    let id = format!("status-{modern}-{name}");
    let mut request = json!({"jsonrpc":"2.0", "id":id, "method":"tools/call",
        "params":{"name":"gateway_run_playbook", "arguments":{"name":name, "arguments":{}},
            "_meta":{"io.mcp-gateway/idempotency-key":format!("key-{modern}-{name}-{token}")}}});
    let mut http = gateway
        .client
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(token);
    if modern {
        request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2026-07-28");
        request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
        http = http
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "gateway_run_playbook");
    } else {
        http = http.header("mcp-protocol-version", "2025-06-18");
    }
    let response = http
        .json(&request)
        .send()
        .await
        .expect("real gateway response");
    let status = response.status();
    let body: Value = response.json().await.expect("JSON-RPC response");
    assert_eq!(
        body["id"], id,
        "current transport identity must be preserved"
    );
    assert_eq!(body["jsonrpc"], "2.0");
    (status, body)
}

async fn refusal_status(modern: bool) {
    let backend =
        BackendFixture::start(json!({"content":[{"type":"text","text":"permitted"}]})).await;
    let forbidden =
        BackendFixture::start(json!({"content":[{"type":"text","text":"forbidden"}]})).await;
    let directory = tempfile::tempdir().expect("isolated playbook directory");
    for (name, server) in [("denied", FORBIDDEN), ("allowed", BACKEND)] {
        let definition = json!({"name":name,"description":"HTTP status fixture",
            "steps":[{"name":"step","server":server,"tool":TOOL}]});
        std::fs::write(
            directory.path().join(format!("{name}.yaml")),
            serde_yaml::to_string(&definition).unwrap(),
        )
        .unwrap();
    }
    let mut config = fixture_config(&backend.url);
    config["backends"][FORBIDDEN] = json!({"http_url": forbidden.url, "streamable_http": true});
    config["security"]["message_signing"]["enabled"] = json!(false);
    config["auth"] = json!({"enabled":true,"public_paths":["/health"],
    "api_keys":[
        {"key":CREDENTIAL,"name":"scoped","backends":[BACKEND]},
        {"key":BROADER,"name":"reachability","backends":[BACKEND, FORBIDDEN]}
    ]});
    config["playbooks"] = json!({"enabled":true,"directories":[directory.path()]});
    let gateway = HttpGateway::start(config).await;

    // The permitted control proves valid credentials, protocol and real dispatch.
    let (status, allowed) = call(&gateway, modern, "allowed", CREDENTIAL).await;
    assert_eq!(status, StatusCode::OK, "{allowed}");
    assert!(allowed["result"].is_object(), "{allowed}");
    assert_eq!(backend.calls().len(), 1, "permitted playbook must dispatch");
    assert_eq!(
        forbidden.calls().len(),
        0,
        "permitted playbook must not reach the forbidden backend"
    );
    let (status, denied) = call(&gateway, modern, "denied", CREDENTIAL).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["error"]["code"], -32003, "{denied}");
    assert!(denied.get("result").is_none(), "{denied}");
    assert_eq!(backend.calls().len(), 1, "refused target must not dispatch");
    let forbidden_after_denial = forbidden.calls().len();
    assert_eq!(
        forbidden_after_denial, 0,
        "scoped credential must not dispatch the registered forbidden backend"
    );

    // A real ordinary error must keep400; mapping every admission error to403
    // would pass the denial assertion but fail this control.
    let (status, missing) = call(&gateway, modern, "missing", CREDENTIAL).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{missing}");
    assert_eq!(missing["error"]["code"], -32602, "{missing}");
    assert_eq!(backend.calls().len(), 1);
    assert_eq!(forbidden.calls().len(), forbidden_after_denial);

    let (status, reachable) = call(&gateway, modern, "denied", BROADER).await;
    assert_eq!(status, StatusCode::OK, "{reachable}");
    assert!(reachable["result"].is_object(), "{reachable}");
    assert_eq!(
        forbidden_after_denial, 0,
        "positive reachability must not rewrite the denial baseline"
    );
    assert_eq!(
        forbidden.calls().len(),
        1,
        "broader credential must prove the forbidden backend is live"
    );
    assert_eq!(backend.calls().len(), 1);
}

#[tokio::test]
async fn sub4_modern_admission_refusal_preserves_http_status() {
    refusal_status(true).await;
}

#[tokio::test]
async fn sub4_legacy_keyed_admission_refusal_preserves_http_status() {
    refusal_status(false).await;
}
