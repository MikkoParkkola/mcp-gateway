// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MRTR.7a acceptance rows that need a real stdio serve loop.
//!
//! The sibling file `mik_7212_mrtr7_bridge_acs.rs` drives the input bridge
//! through trait fakes, which is the right shape for the rows about what the
//! bridge *says* — a round's methods, its retry body, its refusals. It cannot
//! reach the three rows here, because each of them is a property of the
//! **serve loop** rather than of the bridge: that the single sequential stdio
//! reader keeps reading while a question is outstanding, that an outstanding
//! question cannot be written into the middle of the `initialize` handshake,
//! and that two concurrent outbound requests reach the pipe as whole frames.
//! A fake client answers instantly, in the caller's own task, over no pipe at
//! all — so it satisfies all three by construction and can never fail them.
//!
//! Everything here therefore spawns the shipped binary over stdio, speaks
//! line-delimited JSON-RPC to it, and reads its stdout under a bounded window.
//! Every read is bounded and the child is killed on every exit path, including
//! a panicking assertion, so a missing reply fails an assertion rather than
//! hanging the suite.

use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

/// The revision this suite's client speaks. Matches the fixture backend's.
const CLIENT_PROTOCOL_VERSION: &str = "2025-06-18";
/// Config name for the backend the child dials.
const BACKEND: &str = "fixture";
/// The fixture tool whose result asks a question instead of answering one.
const ASKING_TOOL: &str = "needs_input";
/// Bound on one read. Generous enough for a cold child, far below the shipped
/// bridge's 30s/120s bounds, which nothing here should ever wait on.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on draining everything the child has to say. A row that expects a
/// frame and gets none spends this once and then asserts.
const COLLECT_WINDOW: Duration = Duration::from_secs(5);

/// Every JSON-RPC request the fixture backend was handed, in arrival order.
type Received = Arc<Mutex<Vec<Value>>>;

fn saw_method(received: &Received, method: &str) -> bool {
    received
        .lock()
        .expect("fixture sink poisoned")
        .iter()
        .any(|request| request.get("method").and_then(Value::as_str) == Some(method))
}

/// A question body large enough that one frame cannot be written atomically.
///
/// Row 324 asserts that concurrent outbound frames are not interleaved, and on
/// a pipe a single `write_all` below `PIPE_BUF` is atomic already — at the
/// fixture's original ~100 bytes the assertion could not fire whatever the
/// writer did, so an unlocked writer passed the row written to catch it. The
/// size is the test: a frame past the buffer takes several writes, and two
/// unserialized writers then produce a line that does not parse.
const QUESTION_BYTES: usize = 96 * 1024;

/// The backend's delay before answering `initialize`.
///
/// Row 323 needs the client-visible handshake to still be outstanding when the
/// pipelined `tools/call` is processed. Without a delay the gateway answers
/// `initialize` in microseconds while the bridged question needs a backend
/// round-trip, so the ordering the row asserts holds by timing rather than by
/// design and the row passes against the interleaving it exists to catch.
const BACKEND_INITIALIZE_DELAY: std::time::Duration = std::time::Duration::from_millis(300);

/// An HTTP MCP backend that answers `initialize` and `tools/list`, and whose
/// one tool returns the MRTR interim shape carrying an `elicitation/create`
/// the gateway is meant to relay to its own client.
async fn spawn_fixture_backend() -> (String, Received) {
    let sink: Received = Arc::new(Mutex::new(Vec::new()));
    let app_sink = Arc::clone(&sink);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let sink = Arc::clone(&app_sink);
            async move {
                if request.get("method").and_then(Value::as_str) == Some("initialize") {
                    tokio::time::sleep(BACKEND_INITIALIZE_DELAY).await;
                }
                axum::Json(fixture_answer(&request, &sink))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture backend address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}/"), sink)
}

fn fixture_answer(request: &Value, sink: &Received) -> Value {
    sink.lock()
        .expect("fixture sink poisoned")
        .push(request.clone());
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": CLIENT_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": BACKEND, "version": "0"},
        }),
        Some("tools/list") => json!({
            "tools": [{
                "name": ASKING_TOOL,
                "description": "asks its caller a question before answering",
                "inputSchema": {"type": "object"},
            }],
        }),
        Some("tools/call") => {
            // A retry carrying answers completes; a first call asks. The two
            // must be distinguishable in the child's output, or a row could
            // pass on the interim result it was supposed to have relayed.
            let answered = request
                .pointer("/params/arguments/inputResponses")
                .is_some()
                || request.pointer("/params/inputResponses").is_some();
            if answered {
                json!({"content": [{"type": "text", "text": "answered"}]})
            } else {
                json!({
                    "resultType": "input_required",
                    "inputRequests": {
                        "branch": {
                            "method": "elicitation/create",
                            "params": {
                                "mode": "form",
                                "message": "Which branch? ".to_string()
                                    + &"x".repeat(QUESTION_BYTES),
                                "requestedSchema": {"type": "object", "properties": {}},
                            },
                        },
                    },
                    "requestState": "mrtr7-stdio-state",
                })
            }
        }
        _ => json!({}),
    };
    json!({"jsonrpc": "2.0", "id": request.get("id").cloned(), "result": result})
}

/// Write the config the child will actually read.
///
/// `Config::FALLBACK_PATHS` checks `gateway.yaml` relative to the working
/// directory before `~/.config/mcp-gateway/gateway.yaml`, and the session below
/// sets the child's working directory to this same temporary home — so a file
/// dropped here is found without depending on `HOME` layout at all.
fn write_config(home: &Path, backend_url: &str) {
    std::fs::write(
        home.join("gateway.yaml"),
        format!(
            "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n"
        ),
    )
    .expect("write gateway.yaml");
}

/// The shipped binary, spawned the way a stdio client spawns it.
struct StdioSession {
    child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
}

impl StdioSession {
    fn spawn(home: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
        command
            .arg("serve")
            .arg("--stdio")
            .current_dir(home)
            .env("HOME", home);
        // The developer's own environment must not decide what this child
        // connects to.
        for (name, _) in std::env::vars() {
            if name.starts_with("MCP_GATEWAY_") {
                command.env_remove(name);
            }
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Inherited rather than piped: an undrained stderr pipe deadlocks
            // the child once its logs fill the buffer.
            .stderr(Stdio::inherit())
            // The kill that survives a panicking assertion. `shutdown` is the
            // orderly path; this is the one that runs when a row fails.
            .kill_on_drop(true)
            .spawn()
            .expect("spawn gateway over stdio");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout")).lines();
        Self {
            child,
            stdin,
            stdout,
        }
    }

    async fn send(&mut self, message: &Value) {
        self.stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("write to child stdin");
        self.stdin.flush().await.expect("flush child stdin");
    }

    /// Read lines until one carries `id`, or the bound expires.
    ///
    /// Returns every line consumed on the way, so a caller can still assert on
    /// what the child wrote before the reply it was waiting for.
    async fn read_until_id(&mut self, id: i64) -> (Vec<String>, Option<Value>) {
        let mut seen = Vec::new();
        loop {
            let line = match timeout(READ_TIMEOUT, self.stdout.next_line()).await {
                Ok(Ok(Some(line))) => line,
                _ => return (seen, None),
            };
            let matched = serde_json::from_str::<Value>(&line)
                .ok()
                .filter(|value| value.get("id").and_then(Value::as_i64) == Some(id));
            seen.push(line);
            if let Some(value) = matched {
                return (seen, Some(value));
            }
        }
    }

    /// Drain stdout for a fixed window and return the raw lines.
    ///
    /// The whole drain is under one timeout rather than each read, so a chatty
    /// child cannot keep this alive indefinitely: the window expires, the
    /// caller gets what arrived, and the row asserts on it.
    async fn collect_lines(&mut self, window: Duration) -> Vec<String> {
        let mut lines = Vec::new();
        let _ = timeout(window, async {
            while let Ok(Some(line)) = self.stdout.next_line().await {
                lines.push(line);
            }
        })
        .await;
        lines
    }

    async fn shutdown(mut self) {
        drop(self.stdin);
        let _ = self.child.kill().await;
    }
}

fn initialize_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": CLIENT_PROTOCOL_VERSION,
            // Declared per request, under the `_meta` key MRTR.9 reads. Sent on
            // the handshake as well so a client that reads either place is
            // covered.
            "capabilities": {"elicitation": {}},
            "clientInfo": {"name": "mrtr7-stdio-acs", "version": "0"},
        },
    })
}

/// A `tools/call` that reaches the fixture's asking tool through the meta tool.
///
/// Backend tools are not on `tools/call` by their own name unless an operator
/// pins them, so the invoke meta tool is the route a real client takes.
fn asking_call(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {
                "server": BACKEND,
                "tool": ASKING_TOOL,
                "arguments": {},
            },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": CLIENT_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
            },
        },
    })
}

/// Parse what parses; used by rows that are not about frame integrity.
fn frames_lenient(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// Index of the first line that is a server-to-client request for `method`.
///
/// Matched on the method rather than on an id: the gateway mints its own
/// string ids for outbound requests, so an i64 id match could never see one.
fn position_of_outbound(frames: &[Value], method: &str) -> Option<usize> {
    frames
        .iter()
        .position(|frame| frame.get("method").and_then(Value::as_str) == Some(method))
}

/// Row 312 — a stdio client is asked, and answers, while the serve loop keeps
/// reading.
///
/// The reply to a question can only arrive on the same pipe the request went
/// out on, and `src/server/*` runs a single sequential stdio reader: a bridge
/// that blocks inside dispatch deadlocks the only task that could deliver it.
/// The row therefore has to be driven through a spawned child rather than a
/// fake, and the assertion has to be on the **answer**, not on completion —
/// a test asserting only that the call returned passes against a gateway that
/// never asked anything at all, which is exactly today's behaviour.
#[tokio::test]
async fn ac_mrtr_7a_stdio_client_answers_while_serve_loop_reads() {
    let home = tempfile::tempdir().expect("temporary home");
    let (backend_url, received) = spawn_fixture_backend().await;
    write_config(home.path(), &backend_url);
    let mut session = StdioSession::spawn(home.path());

    session.send(&initialize_request(1)).await;
    let (_, initialized) = session.read_until_id(1).await;
    assert!(initialized.is_some(), "the child never answered initialize");

    session.send(&asking_call(2)).await;
    let lines = session.collect_lines(COLLECT_WINDOW).await;
    let frames = frames_lenient(&lines);

    // Control: without this, every assertion below measures the fixture rather
    // than the gateway, because an unreached backend also produces no question.
    assert!(
        saw_method(&received, "initialize"),
        "the fixture backend was never reached, so nothing could have asked: {lines:?}"
    );
    assert!(
        position_of_outbound(&frames, "elicitation/create").is_some(),
        "row 312: the interim result was never relayed as an outbound \
         elicitation/create; the client cannot answer a question it was not \
         asked. Frames: {lines:?}"
    );

    // Reached only once the question is relayed: answer it, and require the
    // final result to be the fixture's answered-branch text, so the row cannot
    // be satisfied by the interim result being handed back to the caller.
    let question = frames
        .iter()
        .find(|frame| frame.get("method").and_then(Value::as_str) == Some("elicitation/create"))
        .expect("checked above");
    session
        .send(&json!({
            "jsonrpc": "2.0",
            "id": question.get("id").cloned(),
            "result": {"action": "accept", "content": {"branch": "main"}},
        }))
        .await;
    let (tail, answer) = session.read_until_id(2).await;
    let answer = answer.expect("row 312: no result for the bridged call after the answer");
    assert_eq!(
        answer
            .pointer("/result/content/0/text")
            .and_then(Value::as_str),
        Some("answered"),
        "row 312: the answered retry never reached the backend: {tail:?}"
    );

    session.shutdown().await;
}

/// Row 323 — a client asked before its `initialize` response has been written
/// receives the bridged request only after initialization.
///
/// Concurrent dispatch is what the design's §2 adds, and the ordering it can
/// break is invisible to a row that starts from an already-initialized
/// session: the two requests are sent back to back without waiting, so the
/// question is outstanding while the handshake is still being written. A
/// weaker version — initialize, wait, then call — proves nothing, because the
/// interleaving it is meant to rule out cannot occur in it.
#[tokio::test]
async fn ac_mrtr_7a_bridged_request_follows_the_initialize_response() {
    let home = tempfile::tempdir().expect("temporary home");
    let (backend_url, received) = spawn_fixture_backend().await;
    write_config(home.path(), &backend_url);
    let mut session = StdioSession::spawn(home.path());

    session.send(&initialize_request(1)).await;
    session.send(&asking_call(2)).await;

    let lines = session.collect_lines(COLLECT_WINDOW).await;
    let frames = frames_lenient(&lines);

    assert!(
        saw_method(&received, "initialize"),
        "the fixture backend was never reached, so nothing could have asked: {lines:?}"
    );
    let handshake = frames
        .iter()
        .position(|frame| frame.get("id").and_then(Value::as_i64) == Some(1))
        .expect("row 323: the child never wrote an initialize response");
    let question = position_of_outbound(&frames, "elicitation/create");
    assert!(
        question.is_some(),
        "row 323: no bridged request was written at all, so its ordering \
         against initialize is untested. Frames: {lines:?}"
    );
    assert!(
        question.expect("checked above") > handshake,
        "row 323: the bridged request was written before the initialize \
         response, interleaving with the handshake. Frames: {lines:?}"
    );

    session.shutdown().await;
}

/// Row 324 — two bridged requests dispatched concurrently produce two whole,
/// non-interleaved frames.
///
/// The serialized-writer requirement is unobservable without concurrent
/// outbound traffic: a shared unlocked writer passes every sequential row and
/// tears only when two tasks write at once. Both calls go out before either
/// result is read, so both questions are outstanding together.
///
/// The count is asserted before the framing, deliberately. "Every line parses
/// as whole JSON" is vacuously true of the empty output today, so a test
/// leading with it would report a passing framing check on a gateway that
/// wrote nothing — the count is what makes the row load-bearing, and the
/// parse is what the row actually specifies once frames exist.
#[tokio::test]
async fn ac_mrtr_7a_concurrent_bridged_requests_write_whole_frames() {
    let home = tempfile::tempdir().expect("temporary home");
    let (backend_url, received) = spawn_fixture_backend().await;
    write_config(home.path(), &backend_url);
    let mut session = StdioSession::spawn(home.path());

    session.send(&initialize_request(1)).await;
    let (_, initialized) = session.read_until_id(1).await;
    assert!(initialized.is_some(), "the child never answered initialize");

    session.send(&asking_call(2)).await;
    session.send(&asking_call(3)).await;
    let lines = session.collect_lines(COLLECT_WINDOW).await;

    assert!(
        saw_method(&received, "initialize"),
        "the fixture backend was never reached, so nothing could have asked: {lines:?}"
    );
    let questions = frames_lenient(&lines)
        .iter()
        .filter(|frame| frame.get("method").and_then(Value::as_str) == Some("elicitation/create"))
        .count();
    assert_eq!(
        questions, 2,
        "row 324: two concurrent bridged calls must produce two outbound \
         elicitation/create requests; without both there is no concurrent \
         outbound traffic to serialize. Frames: {lines:?}"
    );
    for line in &lines {
        assert!(
            serde_json::from_str::<Value>(line).is_ok(),
            "row 324: a torn frame is a line that does not parse as whole \
             JSON: {line:?}"
        );
    }

    session.shutdown().await;
}
