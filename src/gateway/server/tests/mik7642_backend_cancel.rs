// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7642.PR.B: a client's cancel reaches the backend as the backend's own
//! request id, at most once, and never after the backend answered.
//!
//! Driven through `Gateway::run_stdio_on` over in-memory pipes, against a
//! legacy streamable-HTTP backend (2025-06-18) that records every message it
//! receives, so the rows read what actually reached the backend.

use std::sync::Arc;
use std::time::Duration;

use axum::response::IntoResponse as _;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use crate::config::Config;
use crate::gateway::Gateway;

const BACKEND: &str = "fixture";
/// Answers after [`SLOW_CALL`], so a cancel can land mid-call.
const SLOW: &str = "slow";
/// Answers at once.
const FAST: &str = "fast";
const SLOW_CALL: Duration = Duration::from_secs(4);
const ARRIVAL: Duration = Duration::from_secs(5);

type Stdout = Lines<BufReader<DuplexStream>>;
/// Every message the backend received, in arrival order.
type Seen = Arc<Mutex<Vec<Value>>>;

struct Served {
    stdin: DuplexStream,
    stdout: Stdout,
    seen: Seen,
    task: JoinHandle<crate::Result<()>>,
    _dir: tempfile::TempDir,
}

async fn spawn_backend() -> (String, Seen) {
    let seen = Seen::default();
    let sink = Arc::clone(&seen);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(message): axum::Json<Value>| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().push(message.clone());
                let Some(id) = message.get("id").cloned() else {
                    return axum::http::StatusCode::ACCEPTED.into_response();
                };
                let method = message["method"].as_str().unwrap_or_default();
                let result = match method {
                    "initialize" => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    "tools/list" => json!({"tools": [
                        {"name": SLOW, "description": "answers late", "inputSchema": {"type": "object"}},
                        {"name": FAST, "description": "answers at once", "inputSchema": {"type": "object"}},
                    ]}),
                    "tools/call" => {
                        if message["params"]["name"] == SLOW {
                            tokio::time::sleep(SLOW_CALL).await;
                        }
                        json!({"content": [{"type": "text", "text": "done"}]})
                    }
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    (format!("http://{address}/"), seen)
}

/// A gateway serving stdio against the recording backend, past its handshake.
async fn serve() -> Served {
    let (backend_url, seen) = spawn_backend().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\ntasks:\n  store_dir: {}\n",
        serde_json::to_string(&dir.path().join("tasks").display().to_string())
            .expect("a JSON string")
    );
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("config loads");
    let gateway = Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());
    let (stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut served = Served {
        stdin,
        stdout: BufReader::new(reader).lines(),
        seen,
        task,
        _dir: dir,
    };
    send(&mut served.stdin, &initialize()).await;
    let answered = next_frame(&mut served.stdout).await;
    assert_eq!(
        answered["id"],
        json!(0),
        "the handshake is answered first: {answered}"
    );
    served
}

async fn send(stdin: &mut DuplexStream, line: &str) {
    stdin
        .write_all(format!("{line}\n").as_bytes())
        .await
        .expect("write to the gateway's stdin");
}

async fn next_frame(stdout: &mut Stdout) -> Value {
    let line = timeout(ARRIVAL, stdout.next_line())
        .await
        .expect("a frame arrives within the bound")
        .expect("stdout reads")
        .expect("stdout is open");
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("not one JSON frame ({e}): {line:?}"))
}

/// Read frames until the answer to `id`, or until `window` ends.
async fn answer_within(stdout: &mut Stdout, id: &Value, window: Duration) -> Option<Value> {
    let deadline = Instant::now() + window;
    while let Ok(Ok(Some(line))) = tokio::time::timeout_at(deadline, stdout.next_line()).await {
        let frame: Value = serde_json::from_str(&line).expect("one JSON frame");
        if frame.get("method").is_none() && frame.get("id") == Some(id) {
            return Some(frame);
        }
    }
    None
}

fn initialize() -> String {
    json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mik7642", "version": "0"},
        },
    })
    .to_string()
}

/// A `tools/call` of `tool` on the backend through `gateway_invoke`.
fn call(id: &Value, tool: &str) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": BACKEND, "tool": tool, "arguments": {},
        }},
    })
    .to_string()
}

fn cancel(id: &Value) -> String {
    json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"requestId": id, "reason": "test"}})
    .to_string()
}

/// The backend-side ids of the `tools/call` requests it received for `tool`.
fn backend_call_ids(seen: &Seen, tool: &str) -> Vec<Value> {
    seen.lock()
        .iter()
        .filter(|m| m["method"] == "tools/call" && m["params"]["name"] == tool)
        .map(|m| m["id"].clone())
        .collect()
}

/// The `requestId`s of the cancels the backend received.
fn backend_cancels(seen: &Seen) -> Vec<Value> {
    seen.lock()
        .iter()
        .filter(|m| m["method"] == "notifications/cancelled")
        .map(|m| m["params"]["requestId"].clone())
        .collect()
}

/// Wait until the backend has received a `tools/call` for `tool`.
async fn until_backend_has(seen: &Seen, tool: &str) {
    let deadline = Instant::now() + ARRIVAL;
    while backend_call_ids(seen, tool).is_empty() {
        assert!(
            Instant::now() < deadline,
            "the backend never received {tool}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// C1. A client cancel mid-call reaches the backend exactly once, naming the
/// id the BACKEND received, never the client's id.
#[tokio::test]
async fn a_cancelled_call_cancels_the_backend_call_by_its_own_id() {
    let mut served = serve().await;
    let client_id = json!("client-1");
    send(&mut served.stdin, &call(&client_id, SLOW)).await;
    until_backend_has(&served.seen, SLOW).await;
    send(&mut served.stdin, &cancel(&client_id)).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let backend_ids = backend_call_ids(&served.seen, SLOW);
    let cancels = backend_cancels(&served.seen);
    served.task.abort();
    assert_eq!(
        cancels.len(),
        1,
        "exactly one cancel reaches the backend: {cancels:?}"
    );
    assert_eq!(
        cancels, backend_ids,
        "it names the backend's own request id"
    );
    assert_ne!(cancels[0], client_id, "never the client's id");
}

/// C1b. A cancel for a call the backend already answered sends nothing.
#[tokio::test]
async fn a_cancel_after_the_answer_sends_nothing() {
    let mut served = serve().await;
    let client_id = json!("client-2");
    send(&mut served.stdin, &call(&client_id, FAST)).await;
    assert!(
        answer_within(&mut served.stdout, &client_id, ARRIVAL)
            .await
            .is_some(),
        "precondition: the call was answered"
    );
    send(&mut served.stdin, &cancel(&client_id)).await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let cancels = backend_cancels(&served.seen);
    served.task.abort();
    assert!(
        cancels.is_empty(),
        "a cancel after the answer reached the backend: {cancels:?}"
    );
}
