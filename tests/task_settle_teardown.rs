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
//! The backend here holds its answer until a release file appears. The test
//! polls the helper once while the answer is held, requires that poll to be
//! pending, and only then releases the answer. A helper that returned without
//! waiting fails that check.

mod common;
#[path = "common/windows_paths.rs"]
mod windows_paths;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::{Context, Waker};
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

/// Register a held peer named `name`; returns (the file it marks on a call, its
/// release file). Each peer runs alone and has its own files, so two peers'
/// answers are released independently.
fn add_held_server(state: &Arc<AppState>, dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let seen = dir.join(format!("{name}-seen.log"));
    let release = dir.join(format!("{name}-release"));
    let peer = dir.join(format!("{name}.sh"));
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
        name,
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

/// Create a task for the held tool on peer `server` and return its id.
async fn create_held_task(state: &Arc<AppState>, server: &str) -> String {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": server, "tool": TOOL, "arguments": {}},
            "task": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":
                    {"extensions": {"io.modelcontextprotocol/tasks": {}}},
                // One key per peer: a shared key would hand back the first task.
                "io.mcp-gateway/idempotency-key": format!("settle-row-{server}"),
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
        .unwrap_or_else(|| panic!("the creating answer has no taskId: {text}"))
        .to_owned()
}

/// The status in the task's record file, `<store>/tasks/<id>.json`, whose
/// `model` holds the task snapshot with the task itself under `task`.
fn status_on_disk(store: &Path, id: &str) -> String {
    let path = store.join("tasks").join(format!("{id}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the task's record {} reads: {e}", path.display()));
    let record: Value = serde_json::from_str(&text).expect("a task record is JSON");
    assert_eq!(
        record.pointer("/model/task/taskId").and_then(Value::as_str),
        Some(id),
        "the record is this task's: {text}"
    );
    record
        .pointer("/model/task/status")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the record carries no task status: {text}"))
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_settled_task_has_its_terminal_record_on_disk() {
    let home = hostile_home();
    let (state, store_dir) = common::state(Fixture::default()).await;
    let (seen, release) = add_held_server(&state, home.path(), SERVER);

    let id = create_held_task(&state, SERVER).await;
    let mut parked = false;
    for _ in 0..400 {
        if seen.exists() {
            parked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(parked, "the task call never reached the held peer");

    // Poll the helper once while the peer still holds its answer. A helper that
    // waits is pending here; only then is the answer released, and the same wait
    // runs on to the end. A helper that returns at once is ready, which fails
    // here even if the record happens to be terminal already (a task that failed
    // early, say). No clock decides the outcome.
    let ids = [id.as_str()];
    let mut settle = pin!(common::settle_tasks(&state, &ids));
    let mut probe = Context::from_waker(Waker::noop());
    assert!(
        settle.as_mut().poll(&mut probe).is_pending(),
        "settle_tasks returned while the peer still held the task's answer"
    );
    std::fs::write(&release, b"go").expect("the release file is written");
    settle.await;

    let on_disk = status_on_disk(store_dir.path(), &id);
    assert!(
        matches!(on_disk.as_str(), "completed" | "failed" | "cancelled"),
        "settle_tasks came back while the task's last record was not yet written \
         (on disk: {on_disk:?}); a write that late can race the removal of the store dir"
    );
}

fn is_terminal(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "cancelled")
}

/// Two tasks, the first already finished and the second held at its peer. A
/// helper that settles only some of its ids (the first, say) is ready on its
/// first poll and fails the pending check; a helper that waits for every id is
/// pending, so the held answer is released and both records end terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_settle_of_two_tasks_waits_for_the_one_still_held() {
    let home = hostile_home();
    let (state, store_dir) = common::state(Fixture::default()).await;
    let (_, done_release) = add_held_server(&state, home.path(), "done");
    std::fs::write(&done_release, b"go").expect("the first peer is released up front");
    let (held_seen, held_release) = add_held_server(&state, home.path(), SERVER);

    let done = create_held_task(&state, "done").await;
    let held = create_held_task(&state, SERVER).await;
    let mut ready = false;
    for _ in 0..400 {
        let done_path = store_dir.path().join("tasks").join(format!("{done}.json"));
        if held_seen.exists()
            && done_path.exists()
            && is_terminal(&status_on_disk(store_dir.path(), &done))
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        ready,
        "the first task never finished, or the second never reached its peer"
    );

    let ids = [done.as_str(), held.as_str()];
    let mut settle = pin!(common::settle_tasks(&state, &ids));
    let mut probe = Context::from_waker(Waker::noop());
    assert!(
        settle.as_mut().poll(&mut probe).is_pending(),
        "settle_tasks returned while the second peer still held its task's answer"
    );
    std::fs::write(&held_release, b"go").expect("the second release file is written");
    settle.await;

    for id in [&done, &held] {
        let on_disk = status_on_disk(store_dir.path(), id);
        assert!(
            is_terminal(&on_disk),
            "settle_tasks came back while task {id} still read {on_disk:?} on disk"
        );
    }
}
