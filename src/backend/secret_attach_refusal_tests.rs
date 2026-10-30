// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call carrying an injected value is refused when the transport that
//! would carry it holds no redaction set (MIK-9035 DELTA-10), for every
//! injection kind a `secrets:` rule has: an argument over HTTP, stdio and
//! WebSocket, and a header over HTTP. Nothing reaches the backend.
//!
//! The other kinds the ruling names cannot carry a rule's value at all, and
//! their refusals are pinned elsewhere: a query rule and a header rule on a
//! transport without request headers (`secret_send_tests`), any rule on an
//! A2A backend (`config::a2a_secrets_tests`). Connect-time headers and
//! spawn-time env come from `headers:` and `env:`, not from `secrets:`.

use std::sync::Arc;
use std::time::Duration;

use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::secret_injection::CredentialRule;
use crate::secrets::SecretResolver;

const SECRET: &str = "unattached-secret-3c71";

/// Every `tools/call` the peer received.
type Calls = Arc<parking_lot::Mutex<Vec<Value>>>;

fn rule(target: &str) -> CredentialRule {
    serde_json::from_value(json!({
        "name": format!("{target}-key"), "value": SECRET,
        "inject_as": target, "inject_key": if target == "header" { "X-Api-Key" } else { "api_key" }
    }))
    .expect("rule parses")
}

/// A Streamable HTTP MCP peer that records each `tools/call`.
async fn http_peer(calls: Calls) -> String {
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let calls = Arc::clone(&calls);
            async move {
                let method = request["method"].as_str().unwrap_or_default().to_owned();
                if method == "tools/call" {
                    calls.lock().push(request.clone());
                }
                let result = match method.as_str() {
                    "initialize" => json!({"protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}}, "serverInfo": {"name": "p", "version": "0"}}),
                    "tools/list" => json!({"tools": [{"name": "echo",
                        "inputSchema": {"type": "object"}}]}),
                    _ => json!({"content": []}),
                };
                if request.get("id").is_none() {
                    return axum::http::StatusCode::ACCEPTED.into_response();
                }
                axum::Json(json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
                    .into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/mcp")
}

/// A backend over `transport` with `rules`, its resolver stamped but its
/// redaction set never attached: the state a construction site that skipped
/// the attach leaves.
fn unattached(transport: TransportConfig, rules: Vec<CredentialRule>) -> Backend {
    let backend = Backend::new(
        "unattached",
        BackendConfig {
            transport,
            secrets: rules,
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(30),
    );
    backend.stamp_secret_resolver(Arc::new(SecretResolver::new()));
    backend
}

async fn first_call(backend: &Backend) -> crate::Result<crate::protocol::JsonRpcResponse> {
    backend
        .request_with_headers(
            "tools/call",
            Some(json!({"name": "echo", "arguments": {"q": "hi"}})),
            &[],
            None,
        )
        .await
}

fn assert_refused(kind: &str, outcome: &crate::Result<crate::protocol::JsonRpcResponse>) {
    let Err(crate::Error::JsonRpc { code, message, .. }) = outcome else {
        panic!("{kind}: not refused: {outcome:?}");
    };
    assert_eq!(*code, -32603, "{kind}");
    assert!(message.contains("cannot redact"), "{kind}: {message}");
    assert!(!message.contains(SECRET), "{kind}: {message}");
}

#[tokio::test]
async fn an_unattached_http_transport_refuses_argument_and_header_rules() {
    for target in ["argument", "header"] {
        let calls = Calls::default();
        let url = http_peer(Arc::clone(&calls)).await;
        let backend = unattached(
            TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            vec![rule(target)],
        );
        let outcome = first_call(&backend).await;
        assert_refused(&format!("http {target}"), &outcome);
        assert!(
            calls.lock().is_empty(),
            "http {target}: the call reached the backend"
        );
    }
}

#[tokio::test]
async fn an_unattached_websocket_transport_refuses_an_argument_rule() {
    use crate::transport::websocket_test_server::{Behaviour, WsPeer};
    let peer = WsPeer::start(Behaviour::Normal).await;
    let backend = unattached(
        TransportConfig::WebSocket {
            ws_url: peer.url.clone(),
            protocol_version: None,
        },
        vec![rule("argument")],
    );
    let outcome = first_call(&backend).await;
    assert_refused("websocket argument", &outcome);
    assert!(
        peer.seen.calls.lock().is_empty(),
        "the call reached the backend"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn an_unattached_stdio_transport_refuses_an_argument_rule() {
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("calls.log");
    let script = dir.path().join("peer.py");
    std::fs::write(
        &script,
        format!(
            r#"import json, sys
for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "tools/call":
        open({log:?}, "a").write(line)
    if "id" not in req:
        continue
    m = req.get("method")
    if m == "initialize":
        r = {{"protocolVersion": "2025-06-18", "capabilities": {{"tools": {{}}}},
             "serverInfo": {{"name": "p", "version": "0"}}}}
    elif m == "tools/list":
        r = {{"tools": [{{"name": "echo", "inputSchema": {{"type": "object"}}}}]}}
    else:
        r = {{"content": []}}
    print(json.dumps({{"jsonrpc": "2.0", "id": req["id"], "result": r}}), flush=True)
"#,
            log = log.display().to_string()
        ),
    )
    .expect("write the peer");
    let backend = unattached(
        TransportConfig::Stdio {
            command: format!("python3 {}", script.display()),
            cwd: None,
            protocol_version: None,
        },
        vec![rule("argument")],
    );
    let outcome = first_call(&backend).await;
    assert_refused("stdio argument", &outcome);
    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(logged.is_empty(), "the call reached the backend: {logged}");
    let _ = backend.stop().await;
}
