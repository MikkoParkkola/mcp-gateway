// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.LIFE.1 — a held legacy stdio RPC can be cancelled and joined.
//!
//! Test plan: `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md` (I3);
//! design D5 in `docs/design/2026-09-30-sub4-stdio-owner.md`. Driven through
//! `Gateway::run_stdio_on` over in-memory pipes. The loop's `pending` map and
//! `JoinSet` are not visible from here, so "nothing left pending" is observed
//! through behaviour that differs only when an entry or a task survives: a
//! late answer resolves nothing, no frame appears for the cancelled id, and
//! EOF returns promptly.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use crate::config::Config;
use crate::gateway::Gateway;

const BACKEND: &str = "fixture";
/// Answers its first round with one `elicitation/create`, and a round that
/// carries the answer with a result.
const ASKING: &str = "needs_input";
/// Answers after [`SLOW_CALL`], so a cancel can land mid-call.
const SLOW: &str = "slow";
const SLOW_CALL: Duration = Duration::from_secs(3);
/// Bound on every wait for a frame, and the window a frame must not appear in.
const ARRIVAL: Duration = Duration::from_secs(5);
/// The legacy idempotency key field (`protocol::mrtr::IDEMPOTENCY_KEY_META`).
const KEY_META: &str = crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

type Stdout = Lines<BufReader<DuplexStream>>;

struct Served {
    stdin: DuplexStream,
    stdout: Stdout,
    /// `tools/call` rounds the backend has received.
    rounds: Arc<AtomicUsize>,
    task: JoinHandle<crate::Result<()>>,
    _dir: tempfile::TempDir,
}

async fn spawn_backend() -> (String, Arc<AtomicUsize>) {
    let rounds = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&rounds);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let counted = Arc::clone(&counted);
            async move {
                let method = request.get("method").and_then(Value::as_str).unwrap_or("");
                let result = match method {
                    "initialize" => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    "tools/list" => json!({"tools": [
                        {"name": ASKING, "description": "asks first", "inputSchema": {"type": "object"}},
                        {"name": SLOW, "description": "answers late", "inputSchema": {"type": "object"}},
                    ]}),
                    "tools/call" => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let params = request.get("params").cloned().unwrap_or_default();
                        if params["name"] == SLOW {
                            tokio::time::sleep(SLOW_CALL).await;
                            json!({"content": [{"type": "text", "text": "slow done"}]})
                        } else if params.get("inputResponses").is_some() {
                            json!({"content": [{"type": "text", "text": "answered"}]})
                        } else {
                            json!({
                                "resultType": "input_required",
                                "inputRequests": {"branch": {
                                    "method": "elicitation/create",
                                    "params": {
                                        "mode": "form",
                                        "message": "Which branch?",
                                        "requestedSchema": {"type": "object", "properties": {}},
                                    },
                                }},
                                "requestState": "life1-state",
                            })
                        }
                    }
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
    (format!("http://{address}/"), rounds)
}

/// A gateway serving stdio, writing to a pipe of `output_capacity` bytes, and
/// already past its handshake.
async fn serve(output_capacity: usize) -> Served {
    let (backend_url, rounds) = spawn_backend().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    // The task store under the test's own directory, never the default under $HOME.
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
    let (output, reader) = tokio::io::duplex(output_capacity);
    let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut served = Served {
        stdin,
        stdout: BufReader::new(reader).lines(),
        rounds,
        task,
        _dir: dir,
    };
    send(&mut served.stdin, &initialize(&json!(0))).await;
    let answered = next_frame(&mut served.stdout).await;
    assert_eq!(
        answered["id"],
        json!(0),
        "the handshake is answered first: {answered}"
    );
    served
}

/// Require that `run_stdio_on` returned `Ok`: a panic or an error is not a
/// clean shutdown. The wait itself stays at each call site, where its window
/// is a named constant the timing guard can read.
fn returned_ok(joined: Result<crate::Result<()>, tokio::task::JoinError>) {
    joined
        .expect("the serve task does not panic")
        .expect("run_stdio_on returns Ok");
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

/// Every frame written within `window`, or until stdout ends.
async fn frames_within(stdout: &mut Stdout, window: Duration) -> Vec<Value> {
    let deadline = Instant::now() + window;
    let mut frames = Vec::new();
    while let Ok(Ok(Some(line))) = tokio::time::timeout_at(deadline, stdout.next_line()).await {
        frames.push(serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}")));
    }
    frames
}

/// A response (not a request) whose id is `id`.
fn answers(frames: &[Value], id: &Value) -> Vec<Value> {
    frames
        .iter()
        .filter(|f| f.get("method").is_none() && f.get("id") == Some(id))
        .cloned()
        .collect()
}

fn initialize(id: &Value) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"elicitation": {}},
            "clientInfo": {"name": "life1", "version": "0"},
        },
    })
    .to_string()
}

/// A legacy `tools/call` of `tool` through `gateway_invoke`, keyed when `key` is set.
fn call(id: &Value, tool: &str, key: Option<&str>) -> Value {
    let mut request = json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": BACKEND, "tool": tool, "arguments": {},
        }},
    });
    if let Some(key) = key {
        request["params"]["_meta"] = json!({(KEY_META): key});
    }
    request
}

fn cancel(id: &Value) -> String {
    json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"requestId": id, "reason": "test"}})
    .to_string()
}

/// Send `request` and read until its outbound `elicitation/create`; the id of
/// that prompt is returned, and the call is then held at the input bridge.
async fn hold(served: &mut Served, request: &Value) -> Value {
    send(&mut served.stdin, &request.to_string()).await;
    loop {
        let frame = next_frame(&mut served.stdout).await;
        if frame.get("method").and_then(Value::as_str) == Some("elicitation/create") {
            return frame["id"].clone();
        }
    }
}

/// The client's answer to prompt `prompt`.
fn answer(prompt: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": prompt, "result": {"action": "accept", "content": {}}})
        .to_string()
}

/// L1. Cancelling a held call releases its prompt: the client's late answer
/// resolves nothing, so the bridge never re-invokes the backend, and the
/// cancelled id is never answered.
#[tokio::test]
async fn cancel_releases_the_held_exchange() {
    let mut served = serve(1 << 20).await;
    let held = json!("held-1");
    let prompt = hold(&mut served, &call(&held, ASKING, None)).await;
    send(&mut served.stdin, &cancel(&held)).await;
    send(&mut served.stdin, &answer(&prompt)).await;
    let frames = frames_within(&mut served.stdout, ARRIVAL).await;
    assert_eq!(
        served.rounds.load(Ordering::SeqCst),
        1,
        "a late answer must not resume a cancelled call: {frames:?}"
    );
    assert!(answers(&frames, &held).is_empty(), "{frames:?}");
    served.task.abort();
}

/// L2. A cancelled call is joined, so EOF returns promptly and the call is
/// never answered, not even by the close that fails outstanding prompts.
#[tokio::test]
async fn a_cancelled_call_is_joined_before_eof_returns() {
    let mut served = serve(1 << 20).await;
    let held = json!("held-1");
    hold(&mut served, &call(&held, ASKING, None)).await;
    send(&mut served.stdin, &cancel(&held)).await;
    // Let the loop read the cancel before stdin closes.
    let before = frames_within(&mut served.stdout, Duration::from_millis(500)).await;
    drop(served.stdin);
    returned_ok(
        timeout(ARRIVAL, &mut served.task)
            .await
            .unwrap_or_else(|_| panic!("run_stdio_on must return within {ARRIVAL:?} of EOF")),
    );
    let after = frames_within(&mut served.stdout, Duration::from_millis(500)).await;
    let frames = [before, after].concat();
    assert!(answers(&frames, &held).is_empty(), "{frames:?}");
}

/// L3. A cancel naming an id that was never sent is ignored.
#[tokio::test]
async fn an_unknown_cancel_is_ignored() {
    let mut served = serve(1 << 20).await;
    send(&mut served.stdin, &cancel(&json!("never-sent"))).await;
    let list = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_list_servers", "arguments": {}}});
    send(&mut served.stdin, &list.to_string()).await;
    let frames = frames_within(&mut served.stdout, ARRIVAL).await;
    assert_eq!(answers(&frames, &json!(7)).len(), 1, "{frames:?}");
    assert!(
        answers(&frames, &json!("never-sent")).is_empty(),
        "{frames:?}"
    );
    served.task.abort();
}

/// L4. `initialize` cannot be cancelled (MCP 2025-06-18, cancellation rule 2).
#[tokio::test]
async fn initialize_is_not_cancelled() {
    let mut served = serve(1 << 20).await;
    let id = json!("init-2");
    let both = format!("{}\n{}", initialize(&id), cancel(&id));
    send(&mut served.stdin, &both).await;
    let frames = frames_within(&mut served.stdout, ARRIVAL).await;
    assert_eq!(answers(&frames, &id).len(), 1, "{frames:?}");
    served.task.abort();
}

/// L5. Cancelling a finished call changes nothing (rule 4), and the id is free
/// again: a later call reusing it can itself be cancelled, and one after that
/// is answered.
#[tokio::test]
async fn cancelling_a_finished_call_changes_nothing() {
    let mut served = serve(1 << 20).await;
    let list = |id: i64| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "gateway_list_servers", "arguments": {}}})
        .to_string()
    };
    send(&mut served.stdin, &list(5)).await;
    let first = next_frame(&mut served.stdout).await;
    assert_eq!(first["id"], json!(5), "{first}");
    send(&mut served.stdin, &cancel(&json!(5))).await;
    send(&mut served.stdin, &list(6)).await;
    let second = next_frame(&mut served.stdout).await;
    assert_eq!(second["id"], json!(6), "{second}");
    // The first call has long finished; give the loop a beat to reap it, so
    // the reuse below is a new mapping and not an in-flight duplicate.
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The finished id, reused for a call that is still running when cancelled.
    send(&mut served.stdin, &call(&json!(5), SLOW, None).to_string()).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    send(&mut served.stdin, &cancel(&json!(5))).await;
    let frames = frames_within(&mut served.stdout, SLOW_CALL + ARRIVAL).await;
    assert!(
        answers(&frames, &json!(5)).is_empty(),
        "the reused id's call was cancelled, and the finished one was not answered twice: {frames:?}"
    );
    assert!(answers(&frames, &json!(6)).is_empty(), "{frames:?}");
    // Both cancels for 5 were settled by a reap, so the id is answered again;
    // a map entry outliving its task would leave 5 silenced for good.
    send(&mut served.stdin, &list(5)).await;
    let third = next_frame(&mut served.stdout).await;
    assert_eq!(third["id"], json!(5), "{third}");
    served.task.abort();
}

/// Re-issue `request`'s key under fresh ids until the answer is no longer the
/// in-flight refusal: the aborted task settles its lease asynchronously.
async fn settled_reissue(served: &mut Served, tool: &str, key: &str) -> Value {
    let deadline = Instant::now() + ARRIVAL;
    for attempt in 0.. {
        let id = json!(format!("again-{attempt}"));
        send(&mut served.stdin, &call(&id, tool, Some(key)).to_string()).await;
        let answer = loop {
            let frame = next_frame(&mut served.stdout).await;
            if frame.get("method").is_none() && frame["id"] == id {
                break frame;
            }
        };
        if !answer
            .to_string()
            .contains("Execution is already in progress")
            || Instant::now() >= deadline
        {
            return answer;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    unreachable!("the loop returns")
}

/// L6. A cancelled keyed call held at the bridge settles as outcome-unknown:
/// its key is refused, never re-executed (settlement matrix, "held" row).
#[tokio::test]
async fn a_cancelled_keyed_call_is_not_re_executed() {
    let mut served = serve(1 << 20).await;
    let held = json!("held-1");
    hold(&mut served, &call(&held, ASKING, Some("life1-held"))).await;
    send(&mut served.stdin, &cancel(&held)).await;
    let answer = settled_reissue(&mut served, ASKING, "life1-held").await;
    assert!(
        answer
            .to_string()
            .contains("Secured execution result is unavailable"),
        "{answer}"
    );
    assert_eq!(served.rounds.load(Ordering::SeqCst), 1, "{answer}");
    served.task.abort();
}

/// L7. A batched call cannot be held: it is refused without a prompt.
#[tokio::test]
async fn a_batched_call_cannot_hold() {
    let mut served = serve(1 << 20).await;
    let batch = json!([call(&json!("b1"), ASKING, None)]);
    send(&mut served.stdin, &batch.to_string()).await;
    let frames = frames_within(&mut served.stdout, ARRIVAL).await;
    assert!(
        !frames
            .iter()
            .any(|f| f.get("method").and_then(Value::as_str) == Some("elicitation/create")),
        "{frames:?}"
    );
    let items: Vec<&Value> = frames
        .iter()
        .filter_map(Value::as_array)
        .flatten()
        .collect();
    assert!(
        items.iter().any(|item| item["id"] == json!("b1")),
        "the batch item is answered: {frames:?}"
    );
    served.task.abort();
}

/// L8. EOF is bounded when the client stops reading: the drain and the writer
/// join share one `STDIO_DRAIN_TIMEOUT` deadline (design D5 rev 4.1).
#[tokio::test]
async fn eof_is_bounded_when_the_client_stops_reading() {
    // 64 bytes: the held call's `elicitation/create` frame is larger, so the
    // writer blocks on it once stdout is no longer read.
    let mut served = serve(64).await;
    send(
        &mut served.stdin,
        &call(&json!("held-8"), ASKING, None).to_string(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(served.stdin);
    returned_ok(
        timeout(
            super::super::STDIO_DRAIN_TIMEOUT + Duration::from_secs(10),
            &mut served.task,
        )
        .await
        .expect("run_stdio_on must return within the drain bound of EOF"),
    );
    // Kept open until here: a dropped reader would unblock the writer.
    drop(served.stdout);
}

/// L9. A keyed call cancelled while its backend call is in flight settles as
/// outcome-unknown: refused on re-issue, never dispatched twice.
#[tokio::test]
async fn a_cancel_during_the_backend_call_settles_unknown() {
    let mut served = serve(1 << 20).await;
    let slow = json!("slow-1");
    send(
        &mut served.stdin,
        &call(&slow, SLOW, Some("life1-slow")).to_string(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    send(&mut served.stdin, &cancel(&slow)).await;
    let answer = settled_reissue(&mut served, SLOW, "life1-slow").await;
    assert!(
        answer
            .to_string()
            .contains("Secured execution result is unavailable"),
        "{answer}"
    );
    assert_eq!(served.rounds.load(Ordering::SeqCst), 1, "{answer}");
    served.task.abort();
}
