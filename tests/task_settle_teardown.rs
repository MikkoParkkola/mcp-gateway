// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `common::settle_tasks` returns only once each task it was given has its
//! terminal record on disk.
//!
//! A task's last record is written by the task worker after the backend
//! answers, which can be after the test body has finished. If that write lands
//! while the test's store directory is being removed, the removal leaves the
//! directory behind and the shard's leftover check fails the run. The store
//! commits a record before it publishes the status, so a helper that waits for
//! a terminal status through `tasks/get` leaves nothing in flight.
//!
//! The backend here holds its answer until a release file appears, and the
//! release comes only after `settle_tasks` has started. A helper that returned
//! without waiting would find the record on disk still `working`.

mod common;
#[path = "common/windows_paths.rs"]
mod windows_paths;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{AppState, Arc, Body, Fixture, Request, ServiceExt, Value, create_router, json};
use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use windows_paths::{hostile_home, sh_path};

const SERVER: &str = "held";
const TOOL: &str = "wait_for_release";

/// A stdio MCP peer whose one tool answers only after `__RELEASE__` exists.
/// It appends a line to `__SEEN__` when the call arrives, so the test knows the
/// task is parked at the peer before it starts the helper.
const HELD_PEER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"held","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"wait_for_release","description":"answers once released","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      printf 'seen\n' >> __SEEN__
      while [ ! -e __RELEASE__ ]; do sleep 0.05; done
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"released"}]}}\n' "$id" ;;
  esac
done
"#;

/// Register the held peer; returns (the file it marks on a call, its release file).
fn add_held_server(state: &Arc<AppState>, dir: &Path) -> (PathBuf, PathBuf) {
    let seen = dir.join("seen.log");
    let release = dir.join("release");
    let peer = dir.join("held.sh");
    let script = HELD_PEER
        .replace("__SEEN__", &sh_path(&seen))
        .replace("__RELEASE__", &sh_path(&release));
    std::fs::write(&peer, script).expect("the peer script is written");
    let transport = TransportConfig::Stdio {
        command: format!("sh {}", sh_path(&peer)),
        cwd: None,
        protocol_version: None,
    };
    let config = BackendConfig {
        enabled: true,
        transport,
        ..BackendConfig::default()
    };
    let server = Backend::new(
        SERVER,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    assert!(
        state.backends.register(Arc::new(server)),
        "the held peer registers"
    );
    (seen, release)
}

/// Create a task for the held tool and return its id.
async fn create_held_task(state: &Arc<AppState>) -> String {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": SERVER, "tool": TOOL, "arguments": {}},
            "task": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":
                    {"extensions": {"io.modelcontextprotocol/tasks": {}}},
                "io.mcp-gateway/idempotency-key": "settle-row",
            },
        },
    });
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(Body::from(serde_json::to_vec(&body).expect("a JSON body")))
        .expect("a request");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router answers");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the answer reads");
    let text = String::from_utf8_lossy(&bytes);
    // One JSON body, or a stream whose `data:` lines are JSON frames.
    let frames: Vec<Value> = std::iter::once(text.as_ref())
        .chain(text.lines().filter_map(|l| l.strip_prefix("data:")))
        .filter_map(|chunk| serde_json::from_str(chunk.trim()).ok())
        .collect();
    frames
        .iter()
        .find_map(|frame| frame.pointer("/result/taskId").and_then(Value::as_str))
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("the creating answer has no taskId: {text}"))
}

/// The status in the task's record file under the store directory, or a
/// panic naming what the directory holds.
fn status_on_disk(store: &Path, id: &str) -> String {
    let tasks = store.join("tasks");
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&tasks).expect("the store has a tasks directory") {
        let path = entry.expect("a directory entry").path();
        names.push(path.display().to_string());
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if record.pointer("/model/taskId").and_then(Value::as_str) == Some(id) {
            return record
                .pointer("/model/status")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("the record has no model status: {text}"))
                .to_owned();
        }
    }
    panic!("no record for task {id} among {names:?}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_settled_task_has_its_terminal_record_on_disk() {
    let home = hostile_home();
    let (state, store_dir) = common::state(Fixture::default()).await;
    let (seen, release) = add_held_server(&state, home.path());

    let id = create_held_task(&state).await;
    let mut parked = false;
    for _ in 0..400 {
        if seen.exists() {
            parked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(parked, "the task call never reached the held peer");

    // The answer is released only after the helper has started waiting.
    let releaser = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        std::fs::write(&release, b"go").expect("the release file is written");
    });
    common::settle_tasks(&state, &[id.as_str()]).await;

    let status = status_on_disk(store_dir.path(), &id);
    assert!(
        matches!(status.as_str(), "completed" | "failed" | "cancelled"),
        "when settle_tasks returns, the task's record on disk must already be terminal, \
         so no record write is left to race the store directory's removal; it is {status:?}"
    );
    releaser.await.expect("the releaser finishes");
}
