// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7387.STDIO.2 — an input request cannot overtake the `initialize`
//! response on legacy stdio.
//!
//! Driven in process through `Gateway::run_stdio_on`, the serve loop
//! `run_stdio` runs, over in-memory pipes. The spawned-binary row in
//! `tests/mik_7212_mrtr7_stdio_acs.rs` cannot hold the handshake: `initialize`
//! is answered synchronously and the question needs a backend round trip, so
//! the order holds by timing there whatever the loop does. Two holds make the
//! order depend on the code instead:
//!
//! - the `initialize` response is held before it is queued, so only a loop
//!   that finishes the handshake before reading the next line keeps the
//!   question out of the pipe;
//! - the stdout sink is held with `initialize` already queued while the
//!   question becomes ready, so only a single FIFO writer keeps it behind.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use crate::config::Config;
use crate::gateway::Gateway;

const BACKEND: &str = "fixture";
const ASKING_TOOL: &str = "needs_input";
/// How long each hold lasts. A loop that lets the question through does so
/// within one backend round trip on loopback, far inside this.
const HOLD: Duration = Duration::from_secs(3);
/// Bound on every wait for a frame that must arrive.
const ARRIVAL: Duration = Duration::from_secs(10);

/// Methods the fixture backend has been sent, in arrival order.
type Seen = Arc<Mutex<Vec<String>>>;

fn saw(seen: &Seen, method: &str) -> bool {
    seen.lock()
        .expect("fixture log")
        .iter()
        .any(|m| m == method)
}

/// An HTTP MCP backend whose one tool asks its caller a question.
async fn spawn_backend() -> (String, Seen) {
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let log = Arc::clone(&log);
            async move {
                let method = request.get("method").and_then(Value::as_str).unwrap_or("");
                log.lock().expect("fixture log").push(method.to_owned());
                let result = match method {
                    "initialize" => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    "tools/list" => json!({"tools": [{
                        "name": ASKING_TOOL,
                        "description": "asks before answering",
                        "inputSchema": {"type": "object"},
                    }]}),
                    "tools/call" => json!({
                        "resultType": "input_required",
                        "inputRequests": {"branch": {
                            "method": "elicitation/create",
                            "params": {
                                "mode": "form",
                                "message": "Which branch?",
                                "requestedSchema": {"type": "object", "properties": {}},
                            },
                        }},
                        "requestState": "stdio-order-state",
                    }),
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
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

/// A gateway serving stdio over `input`/`output`, as `run_stdio` would.
async fn serve(
    output: DuplexStream,
    gate: Option<Arc<Semaphore>>,
) -> (DuplexStream, Seen, JoinHandle<()>, tempfile::TempDir) {
    let (backend_url, seen) = spawn_backend().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n"
    );
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("config loads");
    let gateway = Gateway::new(config).await.expect("gateway boots");
    let (client, input) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move {
        drop(gateway.run_stdio_on(input, output, gate).await);
    });
    // The config directory is returned so it outlives the serving task.
    (client, seen, task, dir)
}

async fn send(client: &mut DuplexStream, line: &str) {
    client
        .write_all(format!("{line}\n").as_bytes())
        .await
        .expect("write to the gateway's stdin");
}

fn initialize(id: i64) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            // The legacy client's only place to declare it can be asked.
            "capabilities": {"elicitation": {}},
            "clientInfo": {"name": "stdio-order", "version": "0"},
        },
    })
    .to_string()
}

fn asking_call(id: i64) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": BACKEND, "tool": ASKING_TOOL, "arguments": {},
        }},
    })
    .to_string()
}

fn is_question(frame: &Value) -> bool {
    frame.get("method").and_then(Value::as_str) == Some("elicitation/create")
}

/// Every frame written before `deadline`, stopping early once a question
/// has been read. Each line must parse on its own.
async fn frames_until_question(
    lines: &mut tokio::io::Lines<BufReader<DuplexStream>>,
    deadline: Instant,
) -> Vec<Value> {
    let mut frames = Vec::new();
    while let Ok(Ok(Some(line))) = tokio::time::timeout_at(deadline, lines.next_line()).await {
        let frame: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("a stdout line is not one JSON frame ({e}): {line:?}"));
        let done = is_question(&frame);
        frames.push(frame);
        if done {
            break;
        }
    }
    frames
}

fn position_of_id(frames: &[Value], id: i64) -> Option<usize> {
    frames
        .iter()
        .position(|f| f.get("id").and_then(Value::as_i64) == Some(id) && f.get("method").is_none())
}

/// Hold the `initialize` response before it is queued, with the asking call
/// already on stdin. A loop that reads line 2 before the handshake is queued
/// lets the question reach the client first.
#[tokio::test]
async fn stdio_2_question_waits_for_a_held_initialize_response() {
    let (output, reader) = tokio::io::duplex(1 << 20);
    let gate = Arc::new(Semaphore::new(0));
    let (mut client, seen, task, _config) = serve(output, Some(Arc::clone(&gate))).await;
    let mut lines = BufReader::new(reader).lines();

    // Readiness: the parse error is answered only once startup is over and the
    // loop is reading, so the hold below measures the loop and not the boot.
    send(&mut client, "not json").await;
    let ready = timeout(ARRIVAL, lines.next_line()).await;
    assert!(
        matches!(ready, Ok(Ok(Some(_)))),
        "the serve loop never started reading"
    );

    send(&mut client, &initialize(1)).await;
    send(&mut client, &asking_call(2)).await;

    // Event-driven, not a fixed sleep: once the backend is asked, a loop that
    // read past the held handshake has a question on its way, so the hold is
    // extended until it is written rather than cut short on a slow runner.
    let asked = timeout(HOLD, async {
        while !saw(&seen, "tools/call") {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();
    let window = if asked {
        ARRIVAL
    } else {
        Duration::from_millis(200)
    };
    let held = frames_until_question(&mut lines, Instant::now() + window).await;
    assert!(
        !held.iter().any(is_question),
        "STDIO.2: the input request was written while the initialize response \
         was still held: {held:?}"
    );

    gate.add_permits(1);
    let mut frames = held;
    frames.extend(frames_until_question(&mut lines, Instant::now() + ARRIVAL).await);
    let handshake =
        position_of_id(&frames, 1).expect("STDIO.2: no initialize response after the release");
    let question = frames.iter().position(is_question).unwrap_or_else(|| {
        panic!("control: no input request was ever written, so the order is untested: {frames:?}")
    });
    assert!(
        saw(&seen, "tools/call"),
        "control: the backend was never asked"
    );
    assert!(
        handshake < question,
        "STDIO.2: the input request overtook the initialize response: {frames:?}"
    );
    task.abort();
}

/// Hold the stdout sink on a frame queued before `initialize`, and keep it
/// held until the question is ready. Only a single FIFO writer then emits
/// `initialize` ahead of the question.
#[tokio::test]
async fn stdio_2_held_writer_emits_initialize_before_a_ready_question() {
    // A pipe too small for one frame: the writer blocks inside the first
    // write until this test starts reading.
    let (output, reader) = tokio::io::duplex(8);
    let (mut client, seen, task, _config) = serve(output, None).await;

    send(&mut client, "not json").await;
    send(&mut client, &initialize(1)).await;
    send(&mut client, &asking_call(2)).await;

    // Control: the question exists only once the backend has been asked.
    let asked = timeout(ARRIVAL, async {
        while !saw(&seen, "tools/call") {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        asked.is_ok(),
        "control: the backend was never asked while stdout was held"
    );
    // The bridge queues its request microseconds after the backend answers.
    tokio::time::sleep(HOLD).await;

    let mut lines = BufReader::new(reader).lines();
    let frames = frames_until_question(&mut lines, Instant::now() + ARRIVAL).await;
    assert_eq!(
        frames
            .first()
            .and_then(|f| f.pointer("/error/code"))
            .and_then(Value::as_i64),
        Some(-32700),
        "control: the held frame was not the parse error, so nothing was held: {frames:?}"
    );
    let handshake = position_of_id(&frames, 1).unwrap_or_else(|| {
        panic!("STDIO.2: the input request was emitted with no initialize response before it: {frames:?}")
    });
    let question = frames
        .iter()
        .position(is_question)
        .unwrap_or_else(|| panic!("control: no input request was written: {frames:?}"));
    assert!(
        handshake < question,
        "STDIO.2: the input request overtook the queued initialize response: {frames:?}"
    );
    task.abort();
}
