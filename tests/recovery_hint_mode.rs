// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A recovery hint names only meta-tools the caller's mode exposes, through
//! the shipped binary over stdio.
//!
//! Code Mode exposes `gateway_search` and `gateway_execute` and hides the rest,
//! but a "Backend not found" hint told a Code Mode caller to use
//! `gateway_list_tools`, which it cannot see.

#[path = "common/stdio_session.rs"]
mod stdio_session;

use serde_json::{Value, json};
use stdio_session::StdioSession;

/// The text of the failed call's result, recovery hint included.
async fn failed_call(code_mode: bool, call: Value) -> String {
    failed_call_with(&format!("code_mode:\n  enabled: {code_mode}\n"), call).await
}

/// [`failed_call`] on a gateway configured by `settings` (YAML, no `backends`).
async fn failed_call_with(settings: &str, call: Value) -> String {
    let home = tempfile::tempdir().expect("home");
    let yaml = format!("{settings}backends: {{}}\n");
    mcp_gateway::gateway::test_helpers::write_owner_only(home.path().join("gateway.yaml"), yaml)
        .expect("write gateway.yaml");

    let mut session = StdioSession::spawn(home.path());
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "recovery-hint-mode", "version": "0"},
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
        .send(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": call}))
        .await;
    let (lines, reply) = session.read_until_id(2).await;
    session.shutdown().await;
    let reply = reply.unwrap_or_else(|| panic!("no reply; saw: {lines:?}"));
    reply.to_string()
}

#[tokio::test]
async fn code_mode_hints_name_gateway_search() {
    let text = failed_call(
        true,
        json!({"name": "gateway_execute", "arguments": {"tool": "nosuch:anything", "arguments": {}}}),
    )
    .await;
    assert!(
        text.contains("recovery"),
        "a recovery hint is expected: {text}"
    );
    assert!(
        !text.contains("gateway_list_tools"),
        "Code Mode hides gateway_list_tools; the hint must not name it: {text}"
    );
    assert!(
        text.contains("gateway_search"),
        "the hint must name gateway_search: {text}"
    );
}

#[tokio::test]
async fn standard_mode_hints_name_gateway_list_tools() {
    let text = failed_call(
        false,
        json!({"name": "gateway_invoke", "arguments": {"server": "nosuch", "tool": "anything", "arguments": {}}}),
    )
    .await;
    assert!(
        text.contains("recovery"),
        "a recovery hint is expected: {text}"
    );
    assert!(text.contains("gateway_list_tools"), "{text}");
}

#[tokio::test]
async fn a_hidden_discovery_tool_is_not_named() {
    let text = failed_call_with(
        "code_mode:\n  enabled: true\nmeta_mcp:\n  exposed_meta_tools:\n    - gateway_execute\n",
        json!({"name": "gateway_execute", "arguments": {"tool": "nosuch:anything", "arguments": {}}}),
    )
    .await;
    assert!(
        text.contains("recovery"),
        "a recovery hint is expected: {text}"
    );
    assert!(
        !text.contains("gateway_search"),
        "exposed_meta_tools hides gateway_search; the hint must not name it: {text}"
    );
}
