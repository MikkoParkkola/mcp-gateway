// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! F19: two concurrent callers that choose the same `progressToken` for calls
//! to one stdio (`command:`) backend each receive their own progress, never
//! the other's.
//!
//! The suspected defect: the stdio backend transport routes a backend's
//! `notifications/progress` by the token on the wire, so if the caller's token
//! reached the backend unchanged, two callers who both chose `"1"` would be
//! indistinguishable there and one could be handed the other's progress. The
//! gateway is meant to substitute a unique token on send and restore the
//! caller's on delivery (`backend::ops::request_attempted`).
//!
//! The peer holds the first call until the second arrives, then answers both,
//! so the two calls are provably in flight together when the progress is
//! emitted. Each progress carries a value only its own call chose (`mark`), so
//! a swapped delivery is visible even though both carry token `"1"`.

mod common;

use std::time::Duration;

use common::{AppState, Arc, Body, Fixture, Request, ServiceExt, Value, create_router, json};
use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};

const BACKEND: &str = "fixture";
const TOOL: &str = "marks";
/// The token both callers choose.
const SHARED_TOKEN: &str = "1";

/// A stdio MCP peer. It records every `tools/call` it reads, holds the first,
/// and on the second emits one progress per call (value = that call's `mark`,
/// token = whatever token the gateway sent for that call), then answers both.
const PEER: &str = r#"
first_id=""
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"marks","description":"progress by mark","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      printf '%s\n' "$line" >> __LOG__
      token=$(printf '%s' "$line" | sed -n 's/.*"progressToken":\("[^"]*"\).*/\1/p')
      [ -z "$token" ] && token=$(printf '%s' "$line" | sed -n 's/.*"progressToken":\([0-9][0-9]*\).*/\1/p')
      mark=$(printf '%s' "$line" | sed -n 's/.*"mark":\([0-9][0-9]*\).*/\1/p')
      if [ -z "$first_id" ]; then
        first_id=$id; first_token=${token:-null}; first_mark=$mark
      else
        printf '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":%s,"progress":%s,"total":100}}\n' "$first_token" "$first_mark"
        printf '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":%s,"progress":%s,"total":100}}\n' "${token:-null}" "$mark"
        printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"done-%s"}]}}\n' "$first_id" "$first_mark"
        printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"done-%s"}]}}\n' "$id" "$mark"
        first_id=""
      fi ;;
  esac
done
"#;

fn register_command_backend(state: &Arc<AppState>, home: &std::path::Path) -> std::path::PathBuf {
    let log = home.join("calls.log");
    let script = home.join("peer.sh");
    std::fs::write(&script, PEER.replace("__LOG__", &log.display().to_string()))
        .expect("write the peer");
    let config = BackendConfig {
        enabled: true,
        transport: TransportConfig::Stdio {
            command: format!("sh {}", script.display()),
            cwd: None,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    let backend = Backend::new(
        BACKEND,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    assert!(state.backends.register(Arc::new(backend)));
    log
}

/// A modern `gateway_invoke` of the peer's tool, carrying the shared token.
fn call(id: i64, mark: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"mark": mark}},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "progressToken": SHARED_TOKEN,
            },
        },
    })
}

/// POST one call as its own caller and return every JSON frame of its
/// response, whether the gateway answered with a stream or a single body.
async fn post_frames(state: &Arc<AppState>, body: Value) -> Vec<Value> {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router must answer");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    let text = String::from_utf8_lossy(&bytes);
    let data_lines: Vec<Value> = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str(data.trim()).ok())
        .collect();
    if data_lines.is_empty() {
        serde_json::from_str(&text)
            .map(|v| vec![v])
            .unwrap_or_default()
    } else {
        data_lines
    }
}

/// Every `(progressToken, progress)` pair in one caller's response.
fn progress_of(frames: &[Value]) -> Vec<(Value, Value)> {
    frames
        .iter()
        .filter(|f| f.get("method").and_then(Value::as_str) == Some("notifications/progress"))
        .map(|f| {
            (
                f.pointer("/params/progressToken")
                    .cloned()
                    .unwrap_or(Value::Null),
                f.pointer("/params/progress")
                    .cloned()
                    .unwrap_or(Value::Null),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_callers_sharing_a_progress_token_each_receive_only_their_own_progress() {
    let home = tempfile::tempdir().expect("temporary home");
    let (state, _store_dir) = common::state(Fixture::default()).await;
    let log = register_command_backend(&state, home.path());

    let (frames_a, frames_b) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            post_frames(&state, call(1, 11)),
            post_frames(&state, call(2, 22))
        )
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the two calls never completed; the peer answers only once both are in \
             flight, so a backend leg that serialises calls parks here. Peer saw: {:?}",
            std::fs::read_to_string(&log).unwrap_or_default()
        )
    });

    // Control: both calls reached the peer while both were open, so the
    // progress below was emitted with two exchanges outstanding.
    let seen = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        seen.lines().count(),
        2,
        "the peer must see both calls: {seen}"
    );

    assert_eq!(
        progress_of(&frames_a),
        vec![(json!(SHARED_TOKEN), json!(11))],
        "caller A must receive exactly its own progress (11), under its own token: {frames_a:?}"
    );
    assert_eq!(
        progress_of(&frames_b),
        vec![(json!(SHARED_TOKEN), json!(22))],
        "caller B must receive exactly its own progress (22), under its own token: {frames_b:?}"
    );
    // Last, so a failure above says what the caller saw first.
    assert!(
        !seen.contains(&format!("\"progressToken\":\"{SHARED_TOKEN}\"")),
        "the caller's own token reached the backend unchanged: {seen}"
    );
}
