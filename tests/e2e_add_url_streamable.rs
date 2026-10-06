// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway add --url` against a streamable-HTTP MCP server, through the
//! built binary: add the server, start the gateway, and call its tool with
//! `gateway_invoke`.
//!
//! The server below speaks streamable HTTP the way the spec allows a server
//! to: JSON-RPC over POST, and 405 on GET because it offers no SSE stream. A
//! backend written by `add --url` must reach it. The CLI's own help example
//! (`add --url https://mcp.sentry.dev/mcp sentry`) is this shape.

#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

const BACKEND: &str = "tidebook";
const TOOL: &str = "tide_table";
const MARKER: &str = "tidebook-answered-over-streamable-http";
const READY_BOUND: Duration = Duration::from_secs(60);

/// Every HTTP wait is bounded, and loopback never goes through an inherited
/// proxy.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .build()
        .expect("an HTTP client")
}

/// POST-only MCP server: GET is answered 405 by the router.
async fn mcp(Json(body): Json<Value>) -> Response {
    let Some(id) = body.get("id").filter(|id| !id.is_null()).cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let result = match body["method"].as_str().unwrap_or_default() {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": BACKEND, "version": "0" }
        }),
        "tools/list" => json!({ "tools": [{
            "name": TOOL,
            "description": "Look up the tide table for a harbour.",
            "inputSchema": { "type": "object", "properties": {} }
        }]}),
        "tools/call" => json!({ "content": [{ "type": "text", "text": MARKER }] }),
        _ => json!({}),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

fn gateway_command(root: &std::path::Path) -> Command {
    let mut command = gateway_bin::command(&root.join("home"), gateway_bin::Inherit::Environment);
    command
        .current_dir(root)
        .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
        .stdin(Stdio::null());
    command
}

async fn post(
    http: &reqwest::Client,
    url: &str,
    sid: Option<&str>,
    body: &Value,
) -> reqwest::Response {
    let mut request = http
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .json(body);
    if let Some(sid) = sid {
        request = request.header("mcp-session-id", sid);
    }
    request.send().await.expect("the gateway answers")
}

/// Poll `/health` until the gateway answers, failing with its log if it exits
/// or misses `READY_BOUND`.
/// Read the port the child bound (`-p 0`) from its log, wait for `/health`
/// on it, and return its base URL.
async fn wait_ready(
    http: &reqwest::Client,
    child: &mut tokio::process::Child,
    log: &std::path::Path,
) -> String {
    let logs = || std::fs::read_to_string(log).unwrap_or_default();
    let deadline = tokio::time::Instant::now() + READY_BOUND;
    loop {
        if let Some(port) = gateway_bin::logged_port(log) {
            let base = format!("http://127.0.0.1:{port}");
            if http
                .get(format!("{base}/health"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return base;
            }
        }
        if let Some(status) = child.try_wait().expect("child status") {
            panic!("serve exited before ready ({status})\n{}", logs());
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "serve not ready\n{}",
            logs()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn add_url_reaches_a_streamable_http_server() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock server binds");
    let server_url = format!("http://{}/mcp", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            axum::Router::new().route("/mcp", axum::routing::post(mcp)),
        )
        .await;
    });

    let tmp = tempfile::tempdir().expect("temp root");
    let root: PathBuf = tmp.path().to_path_buf();
    std::fs::create_dir(root.join("home")).expect("home");

    let added = gateway_command(&root)
        .args(["add", "--url", &server_url, BACKEND])
        .output()
        .expect("add runs");
    assert!(
        added.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(
        String::from_utf8_lossy(&added.stdout).starts_with(&format!("Added '{BACKEND}' (http).")),
        "{}",
        String::from_utf8_lossy(&added.stdout)
    );

    let log = root.join("serve.log");
    let out = std::fs::File::create(&log).expect("serve log");
    let err = out.try_clone().expect("log handle");
    let mut child = tokio::process::Command::from(gateway_command(&root))
        .args(["-c", "gateway.yaml", "-p", "0", "serve"])
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .kill_on_drop(true)
        .spawn()
        .expect("serve spawns");
    let logs = || std::fs::read_to_string(&log).unwrap_or_default();

    let http = http_client();
    let base = wait_ready(&http, &mut child, &log).await;

    let mcp_url = format!("{base}/mcp");
    let init = post(
        &http,
        &mcp_url,
        None,
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": { "name": "add-url-journey", "version": "1" }
        }}),
    )
    .await;
    let sid = init
        .headers()
        .get("mcp-session-id")
        .map(|v| v.to_str().expect("ASCII").to_string());
    post(
        &http,
        &mcp_url,
        sid.as_deref(),
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await;

    let answer: Value = post(
        &http,
        &mcp_url,
        sid.as_deref(),
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": TOOL, "arguments": {} }
        }}),
    )
    .await
    .json()
    .await
    .expect("a JSON answer");
    let text = answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains(MARKER),
        "a server added with `add --url` was not reachable: {answer}\n{}",
        logs()
    );
    server.abort();
}
