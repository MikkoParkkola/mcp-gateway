// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway add --url` must produce a backend that works against both
//! HTTP server shapes the MCP spec allows, driven through the shipped binary.
//!
//! The spec's backwards-compatibility rule: POST `initialize` first (Streamable
//! HTTP) and fall back to the legacy SSE `GET` only when that POST is refused
//! with a 4xx. A streamable-only server answers `GET` with 405, so a config
//! that always opens with `GET` fails on its first call. An explicit flag
//! that the server refuses with such a 4xx gets one try of the other transport.

use stdio_session::gateway_bin;

#[path = "common/mcp_http_servers.rs"]
#[allow(dead_code, reason = "shared fixtures; each binary uses a subset")]
mod mcp_http_servers;
#[path = "common/stdio_session.rs"]
mod stdio_session;

use std::path::Path;

use axum::http::Method;
use mcp_http_servers::{Hits, sse_server, streamable_server};
use serde_json::{Value, json};
use stdio_session::StdioSession;

const BACKEND: &str = "fx";

fn add(home: &Path, url: &str) {
    let output = gateway_bin::command(home, gateway_bin::Inherit::Environment)
        .args(["add", "--url", url, BACKEND, "--config"])
        .arg(home.join("gateway.yaml"))
        .output()
        .expect("run mcp-gateway add");
    assert!(
        output.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Drive one `gateway_invoke` of the fixture's `ping` through `serve --stdio`.
async fn invoke_ping(home: &Path) -> Value {
    let mut session = StdioSession::spawn(home);
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "add-url-autodetect", "version": "0"},
            }}),
        )
        .await;
    let (_, init) = session.read_until_id(1).await;
    assert!(init.is_some(), "the gateway never answered initialize");
    session
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "gateway_invoke",
                "arguments": {"server": BACKEND, "tool": "ping", "arguments": {}},
            }}),
        )
        .await;
    let (lines, reply) = session.read_until_id(2).await;
    session.shutdown().await;
    reply.unwrap_or_else(|| panic!("no reply to the invoke; saw: {lines:?}"))
}

#[tokio::test]
async fn add_url_reaches_a_streamable_only_server() {
    let hits = Hits::default();
    let url = streamable_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    add(home.path(), &url);

    let reply = invoke_ping(home.path()).await;
    assert!(
        reply.to_string().contains("pong-streamable"),
        "a streamable-only server must work after `add --url`; reply: {reply}"
    );
}

#[tokio::test]
async fn add_url_still_reaches_a_legacy_sse_server() {
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    add(home.path(), &url);

    let reply = invoke_ping(home.path()).await;
    assert!(
        reply.to_string().contains("pong-sse"),
        "a legacy SSE server must still work after `add --url`; reply: {reply}"
    );
}

#[tokio::test]
async fn add_url_leaves_the_transport_to_detection() {
    let home = tempfile::tempdir().expect("home");
    add(home.path(), "https://mcp.example.test/mcp");
    let yaml = std::fs::read_to_string(home.path().join("gateway.yaml")).expect("gateway.yaml");
    assert!(
        !yaml.contains("streamable_http"),
        "`add --url` must not pin a transport the server was never asked about:\n{yaml}"
    );
}

fn write_explicit(home: &Path, url: &str, streamable: bool) {
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"{url}\"\n    streamable_http: {streamable}\n"
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(home.join("gateway.yaml"), yaml)
        .expect("write gateway.yaml");
}

/// An explicit `streamable_http: false` that the server accepts is used as
/// written: the gateway opens with the SSE `GET` and never probes with a `POST`.
#[tokio::test]
async fn explicit_streamable_false_is_honoured() {
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    write_explicit(home.path(), &url, false);

    let reply = invoke_ping(home.path()).await;
    assert!(reply.to_string().contains("pong-sse"), "reply: {reply}");
    let posts_to_sse = hits
        .lock()
        .expect("hits")
        .iter()
        .filter(|(method, path)| *method == Method::POST && path == "/sse")
        .count();
    assert_eq!(posts_to_sse, 0, "explicit `false` must not probe with POST");
}

/// The config the old `add --url` wrote: an explicit `false` naming a server
/// that speaks only Streamable HTTP. The refused `GET` costs one request, not
/// the backend.
#[tokio::test]
async fn an_old_add_config_reaches_a_streamable_only_server() {
    let hits = Hits::default();
    let url = streamable_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    write_explicit(home.path(), &url, false);

    let reply = invoke_ping(home.path()).await;
    assert!(
        reply.to_string().contains("pong-streamable"),
        "reply: {reply}"
    );
}

/// The mirror case: an explicit `true` naming a legacy SSE server.
#[tokio::test]
async fn explicit_streamable_true_still_reaches_a_legacy_sse_server() {
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    write_explicit(home.path(), &url, true);

    let reply = invoke_ping(home.path()).await;
    assert!(reply.to_string().contains("pong-sse"), "reply: {reply}");
}
