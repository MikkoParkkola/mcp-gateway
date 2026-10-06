// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A failed `gateway_invoke` reaches the client as `isError: true`, driven
//! through the shipped binary over stdio.
//!
//! MCP reports a tool-execution failure in the result with `isError: true` so
//! the model sees it. The gateway answered such a failure with an outer
//! `isError: false` and the failure only inside the text payload.

#[path = "common/stdio_session.rs"]
mod stdio_session;

use serde_json::{Value, json};
use stdio_session::StdioSession;

const BACKEND: &str = "dead";

#[tokio::test]
async fn a_failed_invoke_is_reported_with_is_error_true() {
    let home = tempfile::tempdir().expect("home");
    // Port 9 (discard) on loopback: nothing listens, so the dispatch fails.
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    streamable_http: true\n"
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(home.path().join("gateway.yaml"), yaml)
        .expect("write gateway.yaml");

    let mut session = StdioSession::spawn(home.path());
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "invoke-failure-is-error", "version": "0"},
            }}),
        )
        .await;
    assert!(
        session.read_until_id(1).await.1.is_some(),
        "no initialize reply"
    );
    session
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "gateway_invoke",
                "arguments": {"server": BACKEND, "tool": "anything", "arguments": {}},
            }}),
        )
        .await;
    let (lines, reply) = session.read_until_id(2).await;
    session.shutdown().await;
    let reply = reply.unwrap_or_else(|| panic!("no reply to the invoke; saw: {lines:?}"));

    let result = reply
        .get("result")
        .unwrap_or_else(|| panic!("tool result expected: {reply}"));
    assert_eq!(
        result.get("isError"),
        Some(&Value::Bool(true)),
        "a failed invoke must say so in the outer result: {reply}"
    );
    let text = result
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        text.contains("\"recovery\""),
        "the structured recovery payload must survive: {text}"
    );
}
