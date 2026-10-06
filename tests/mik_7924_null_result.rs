// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7924.NULLRES.3: an HTTP backend that answers `tools/call` with
//! `"result": null` reaches the client on the direct route with
//! `"result": null`, not with a frame carrying neither `result` nor `error`
//! (JSON-RPC 2.0 section 5).

mod common;

use common::{Arc, Body, Request, ServiceExt, StatusCode, Value, create_router, json};
use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};

const BACKEND: &str = "backend";

/// A loopback backend whose `tools/call` answer is `null`.
async fn spawn_backend() -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(|axum::Json(request): axum::Json<Value>| async move {
            let result = match request["method"].as_str().unwrap_or_default() {
                "initialize" => json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "fixture", "version": "0" }
                }),
                "tools/list" => json!({ "tools": [
                    { "name": "tool", "description": "d", "inputSchema": { "type": "object" } }
                ]}),
                "tools/call" => Value::Null,
                _ => json!({}),
            };
            axum::Json(json!({
                "jsonrpc": "2.0",
                "id": request.get("id").cloned().unwrap_or(Value::Null),
                "result": result
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture backend binds a loopback port");
    let address = listener.local_addr().expect("the bound port is known");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/")
}

async fn direct_tool_call(passthrough: bool) -> (StatusCode, Value) {
    let url = spawn_backend().await;
    let (state, _dir) = common::state(common::Fixture::default()).await;
    let config = BackendConfig {
        enabled: true,
        passthrough,
        transport: TransportConfig::Http {
            http_url: url,
            streamable_http: Some(true),
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    let backend = Backend::new(
        BACKEND,
        config,
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    );
    assert!(state.backends.register(Arc::new(backend)));
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "tool", "arguments": {} }
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let response = create_router(Arc::clone(&state))
        .oneshot(request)
        .await
        .expect("router must answer");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    (status, serde_json::from_slice(&bytes).expect("a JSON body"))
}

fn assert_null_result(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "must be a success: {body}");
    assert_eq!(body.get("result"), Some(&Value::Null), "{body}");
}

/// The sanitized-dispatch arm.
#[tokio::test]
async fn a_null_tools_call_result_reaches_the_client_sanitized() {
    let (status, body) = direct_tool_call(false).await;
    assert_null_result(status, &body);
}

/// The passthrough arm.
#[tokio::test]
async fn a_null_tools_call_result_reaches_the_client_passthrough() {
    let (status, body) = direct_tool_call(true).await;
    assert_null_result(status, &body);
}
