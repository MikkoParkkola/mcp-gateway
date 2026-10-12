// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8044.SURF.2: `backends.<name>.protocol_version` is an AUTO key, a
//! hidden override that is still honoured. Set in a gateway.yaml and loaded
//! through the config path, it must reach the HTTP transport: `initialize`
//! proposes the pinned revision and the following `tools/call` carries it in
//! `MCP-Protocol-Version`. Unset, the gateway proposes its own latest. The
//! transport-level tests build the transport directly, so a key that parsed
//! but never reached it would pass them; this row loads the file.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::config::Config;
use crate::gateway::Gateway;

const BACKEND: &str = "pinned";
const TOOL: &str = "rows";
/// A revision older than the gateway's latest, so a pin is visible.
const PINNED: &str = "2025-06-18";

/// What the backend saw: `initialize`'s proposed revision, and the
/// `MCP-Protocol-Version` header of each `tools/call`.
#[derive(Default)]
struct Seen {
    proposed: Vec<String>,
    call_headers: Vec<Option<String>>,
}

/// A Streamable HTTP backend that selects whatever revision is proposed.
async fn spawn_backend(seen: Arc<Mutex<Seen>>) -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, axum::Json(request): axum::Json<Value>| {
                let seen = Arc::clone(&seen);
                async move {
                    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
                    let result = match method {
                        "initialize" => {
                            let proposed = request
                                .pointer("/params/protocolVersion")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();
                            seen.lock().expect("lock").proposed.push(proposed.clone());
                            json!({
                                "protocolVersion": proposed,
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": BACKEND, "version": "0"},
                            })
                        }
                        "tools/list" => json!({"tools": [{
                            "name": TOOL, "description": "reads rows",
                            "inputSchema": {"type": "object"},
                        }]}),
                        "tools/call" => {
                            let header = headers
                                .get("mcp-protocol-version")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned);
                            seen.lock().expect("lock").call_headers.push(header);
                            json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
                        }
                        _ => json!({}),
                    };
                    axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    format!("http://{address}/")
}

/// Load `extra` (indented backend keys) into a gateway.yaml, start the real
/// stdio loop on it, call the backend's tool once, and return what it saw.
async fn call_through_config(extra: &str) -> Seen {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let url = spawn_backend(Arc::clone(&seen)).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let store = serde_json::to_string(&dir.path().join("tasks").display().to_string())
        .expect("a JSON string");
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"{url}\"\n    streamable_http: true\n{extra}\
         tasks:\n  store_dir: {store}\n"
    );
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("config loads");
    let gateway = Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());
    let (mut client, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(async move {
        drop(gateway.run_stdio_on(input, output, None).await);
    });
    let mut lines = BufReader::new(reader).lines();
    let frames = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "surf2", "version": "0"}}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "gateway_invoke",
                       "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {}}}}),
    ];
    for (id, frame) in (1_i64..).zip(frames) {
        client
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("stdin");
        loop {
            let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
                .await
                .expect("an answer within the bound")
                .expect("stdout readable")
                .expect("stdout open");
            let answer: Value = serde_json::from_str(&line).expect("one JSON frame per line");
            if answer.get("id").and_then(Value::as_i64) == Some(id) {
                assert!(answer.get("error").is_none(), "premise: {frame} answered {answer}");
                break;
            }
        }
    }
    task.abort();
    let seen = std::mem::take(&mut *seen.lock().expect("lock"));
    seen
}

/// A pinned `protocol_version` in gateway.yaml reaches the HTTP transport:
/// `initialize` proposes it and the `tools/call` carries it. The control, the
/// same file without the key, proposes the gateway's latest instead, so the
/// pin is what made the difference.
#[tokio::test]
async fn a_protocol_version_set_in_gateway_yaml_reaches_the_http_transport() {
    let control = call_through_config("").await;
    let latest = control.proposed.first().cloned().unwrap_or_default();
    assert_ne!(
        latest, PINNED,
        "premise: unset, the gateway proposes its own latest, not {PINNED}: {:?}",
        control.proposed
    );
    let pinned = call_through_config(&format!("    protocol_version: \"{PINNED}\"\n")).await;
    assert_eq!(
        pinned.proposed,
        vec![PINNED.to_string()],
        "the configured revision is what initialize proposes"
    );
    assert_eq!(
        pinned.call_headers,
        vec![Some(PINNED.to_string())],
        "the tools/call carries the configured revision in MCP-Protocol-Version"
    );
}
