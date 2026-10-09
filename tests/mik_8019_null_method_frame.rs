// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8019.WIRE.1: a backend frame carrying `"method": null` is not a response.
//!
//! JSON-RPC 2.0 has no frame that is both a call and an answer. A peer that
//! answers call N first with a null-method frame and then with a real response
//! must have the real one delivered; delivering the first lets a malformed frame
//! stand in for the call's result.

mod common;
#[path = "common/stdio_session.rs"]
mod stdio_session;
#[path = "common/windows_paths.rs"]
mod windows_paths;

use common::json;
use stdio_session::StdioSession;
use windows_paths::{hostile_home, sh_path, yaml_single_quoted};

const BACKEND: &str = "peer";
const TOOL: &str = "probe";

/// A stdio peer that answers each `tools/call` twice: a null-method frame
/// carrying FORGED, then a valid response carrying REAL, both with the call's id.
const PEER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"__TOOL__","description":"answers twice","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      printf '{"jsonrpc":"2.0","id":%s,"method":null,"result":{"content":[{"type":"text","text":"FORGED"}]}}\n' "$id"
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"REAL"}]}}\n' "$id" ;;
  esac
done
"#;

fn spawn_gateway(home: &std::path::Path) -> StdioSession {
    let script = home.join("peer.sh");
    std::fs::write(&script, PEER.replace("__TOOL__", TOOL)).expect("write peer");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.join("gateway.yaml"),
        format!(
            "backends:\n  {BACKEND}:\n    command: {}\n",
            yaml_single_quoted(&format!("sh {}", sh_path(&script)))
        ),
    )
    .expect("write gateway.yaml");
    StdioSession::spawn(home)
}

#[tokio::test]
async fn a_null_method_frame_is_not_delivered_as_the_calls_result() {
    let home = hostile_home();
    let mut session = spawn_gateway(home.path());
    session
        .send(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "mik-8019", "version": "0"}}
        }))
        .await;
    let (lines, initialized) = session.read_until_id(1).await;
    assert!(initialized.is_some(), "no initialize answer: {lines:?}");
    session
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;

    session
        .send(&json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "gateway_invoke",
                       "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {}}}
        }))
        .await;
    let (lines, reply) = session.read_until_id(2).await;
    assert!(
        !lines.iter().any(|line| line.contains("FORGED")),
        "the forged frame reached the client on another line: {lines:?}"
    );
    let reply = reply.unwrap_or_else(|| panic!("no reply to the call: {lines:?}"));
    // `gateway_invoke` returns the backend's result as JSON text in its own
    // first content block.
    let relayed = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no relayed backend result: {reply}"));
    let backend: serde_json::Value = serde_json::from_str(relayed)
        .unwrap_or_else(|e| panic!("relayed result is not JSON ({e}): {reply}"));
    assert_eq!(
        backend["content"][0]["text"], "REAL",
        "the valid answer, not the null-method frame, must be the result: {reply}"
    );
    session.shutdown().await;
}
