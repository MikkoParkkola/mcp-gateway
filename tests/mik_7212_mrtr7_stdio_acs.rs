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
//!
//! Two limits, stated rather than discovered later.
//!
//! The stagings that rows 323 and 324 depend on — a backend slow enough to put
//! a question beside the `initialize` response, and a frame large enough that
//! an unlocked writer can be caught interleaving — cannot be shown to work
//! while `InputBridge::run` has no production caller. The bridge itself is
//! implemented and its rounds are driven green through trait fakes in the
//! sibling file, but nothing on a transport calls it, so no bridged request is
//! written to the pipe at all and the ordering and the framing are both
//! unobservable. Each staging removes a known reason its row could not fail;
//! neither is yet evidence that the row now can. Re-check both against the
//! first wired bridge.
//!
//! Row 308 wants a legacy client **on an SSE session** to receive its
//! `elicitation/create` on its own connection. No row covers that: this file
//! drives stdio, the sibling file drives trait fakes against the live
//! `InputBridge::run`, and the projection test in `mik_7212_acs.rs` calls
//! `Bridge::to_legacy_client`, all in process. The SSE
//! half of row 308 is uncovered, and closing it needs a row of its own here
//! rather than a wider assertion on an existing one.

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
/// Row 324 asserts that concurrent outbound frames are not interleaved, and a
/// frame small enough to clear the pipe in one go never gives an unlocked
/// writer the chance to interleave: at the fixture's original ~100 bytes the
/// assertion could not fire whatever the writer did, so an unlocked writer
/// passed the row written to catch it. The size is the test. It is chosen
/// against the pipe's **capacity** (64 KiB on this platform) rather than
/// against `PIPE_BUF`, which `getconf` reports as 512 and which bounds only
/// the guaranteed-atomic write: past the capacity a write blocks partway and
/// must be resumed, and two unserialized writers resuming into one pipe
/// produce a line that does not parse.
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
    /// Taken by [`Self::close_stdin`]: EOF is the stimulus of the drain row,
    /// and the session has to outlive it to read what the drain writes.
    stdin: Option<ChildStdin>,
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
            stdin: Some(stdin),
            stdout,
        }
    }

    async fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("child stdin still open");
        stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("write to child stdin");
        stdin.flush().await.expect("flush child stdin");
    }

    /// Send EOF and keep the session: the child's reader loop leaves its
    /// `while let Ok(Some(line))` and enters the drain.
    fn close_stdin(&mut self) {
        drop(self.stdin.take());
    }

    /// Read lines until one carries `id`, or the bound expires.
    ///
    /// Returns every line consumed on the way, so a caller can still assert on
    /// what the child wrote before the reply it was waiting for.
    async fn read_until_id(&mut self, id: i64) -> (Vec<String>, Option<Value>) {
        let mut seen = Vec::new();
        loop {
            let Ok(Ok(Some(line))) = timeout(READ_TIMEOUT, self.stdout.next_line()).await else {
                return (seen, None);
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

    /// Collect until `enough` holds, then keep reading for `settle`.
    ///
    /// A fixed window asserts a timing coincidence: every admitted request has
    /// to have written its question before the window closes, which a loaded CI
    /// runner does not guarantee. Waiting for the count removes that race
    /// without weakening the row -- `budget` still bounds a parked reader into a
    /// failure, and `settle` still lets an over-admitted extra arrive and redden
    /// the assertion.
    async fn collect_lines_until(
        &mut self,
        budget: Duration,
        settle: Duration,
        enough: impl Fn(&[String]) -> bool,
    ) -> Vec<String> {
        let mut lines = Vec::new();
        let ended = timeout(budget, async {
            while let Ok(Some(line)) = self.stdout.next_line().await {
                lines.push(line);
                if enough(&lines) {
                    break;
                }
            }
        })
        .await;
        // Which of the three ways collection ended is what separates a budget cut
        // too fine from a question that never arrived, and the count alone does
        // not say which. Printed rather than returned: cargo surfaces it for the
        // run that failed and swallows it for the runs that did not.
        eprintln!(
            "collect_lines_until: {} after {} lines",
            match ended {
                Err(_) => "the budget expired",
                Ok(()) if enough(&lines) => "the expected count arrived",
                Ok(()) => "stdout ended",
            },
            lines.len()
        );
        let _ = timeout(settle, async {
            while let Ok(Some(line)) = self.stdout.next_line().await {
                lines.push(line);
            }
        })
        .await;
        lines
    }

    async fn shutdown(mut self) {
        drop(self.stdin.take());
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
            // The only place a legacy-shaped client can declare
            // `elicitation`: MRTR.9 reads per-request `_meta` for a modern
            // call, and a legacy call has none. See [`asking_call`] for why
            // these rows must be legacy-shaped.
            "capabilities": {"elicitation": {}},
            "clientInfo": {"name": "mrtr7-stdio-acs", "version": "0"},
        },
    })
}

/// A `tools/call` that reaches the fixture's asking tool through the meta tool.
///
/// Backend tools are not on `tools/call` by their own name unless an operator
/// pins them, so the invoke meta tool is the route a real client takes.
///
/// Deliberately carries no `params._meta`. The rows here assert an outbound
/// `elicitation/create` frame on the client's own channel, and that frame is
/// written only by the in-band bridge, which serves the legacy request shape;
/// a `_meta` carrying the modern fields classifies the call Modern and takes
/// the continuation route instead, which answers with an envelope and asks
/// nobody. The elicitation capability therefore has to come from the
/// `initialize` handshake -- see [`initialize_request`].
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
    // `gateway_invoke` hands the backend's own result back inside an envelope
    // that also carries the trace id, so the answered-branch text is one parse
    // further down. Asserted through the envelope rather than on a substring:
    // the interim result's text would match a `contains`, which is the exact
    // outcome this row exists to rule out.
    let envelope = answer
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or_else(|| panic!("row 312: no invoke envelope in the result: {tail:?}"));
    assert_eq!(
        envelope.pointer("/content/0/text").and_then(Value::as_str),
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

/// Design §6 — a request the loop accepted still gets its response when stdin
/// closes under it.
///
/// EOF drains, it does not abort. The row stages the hardest case the drain
/// has: a dispatch that is not merely slow but *waiting on the client*, its
/// question already written to the pipe that then closes. Nothing can answer
/// it, so `channel.close()` has to fail the prompt and the dispatch has to
/// carry a response back out — and the writer has to still be there to write
/// it, which is why `run_stdio` joins the writer task only after the drain.
///
/// Asserted on arrival and on being a response, not on a particular error: the
/// pin is that the caller is not left without an answer, and whether the
/// refusal reads as an error object or an error result is the bridge's to
/// decide. A row asserting the text would fail the next time that wording
/// improves, for no defect.
///
/// The failure this catches is silence: abort the `JoinSet` at EOF, or drop the
/// writer before the drain, and the id-2 frame never arrives.
#[tokio::test]
async fn ac_mrtr_7a_request_in_flight_when_stdin_closes_still_gets_its_response() {
    let home = tempfile::tempdir().expect("temporary home");
    let (backend_url, received) = spawn_fixture_backend().await;
    write_config(home.path(), &backend_url);
    let mut session = StdioSession::spawn(home.path());

    session.send(&initialize_request(1)).await;
    let (_, initialized) = session.read_until_id(1).await;
    assert!(initialized.is_some(), "the child never answered initialize");

    session.send(&asking_call(2)).await;
    let staged = session.collect_lines(COLLECT_WINDOW).await;

    // Control: with no question outstanding there is no in-flight dispatch for
    // EOF to interrupt, and the row would pass against a gateway that had
    // already answered id 2 before stdin ever closed.
    assert!(
        saw_method(&received, "initialize"),
        "the fixture backend was never reached: {staged:?}"
    );
    assert!(
        position_of_outbound(&frames_lenient(&staged), "elicitation/create").is_some(),
        "nothing was in flight: the call never reached the bridge, so this row \
         would not be measuring the drain. Frames: {staged:?}"
    );
    assert!(
        !frames_lenient(&staged)
            .iter()
            .any(|frame| frame.get("id").and_then(Value::as_i64) == Some(2)),
        "id 2 was answered before stdin closed, so the drain is untested: {staged:?}"
    );

    session.close_stdin();

    let (tail, answer) = session.read_until_id(2).await;
    let answer = answer.unwrap_or_else(|| {
        panic!("the in-flight call got no response across EOF; the drain dropped it: {tail:?}")
    });
    assert!(
        answer.get("result").is_some() || answer.get("error").is_some(),
        "the frame for id 2 is neither a result nor an error: {answer}"
    );

    session.shutdown().await;
}

/// The reply a client sends to one `elicitation/create`.
///
/// `action` is mandatory for elicitation: `InputBridge::project`
/// (`src/gateway/input_bridge.rs:647`) treats a reply without it as malformed
/// rather than filing it, so a row that answers with a bare object would leave
/// the dispatch to fail instead of complete.
fn elicitation_answer(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        // Echoed verbatim: the bridge mints its own ids and they are strings,
        // not the numbers a client uses for its own calls.
        "id": id.clone(),
        "result": {"action": "accept", "content": {}},
    })
}

/// The burst bound. `StdioSession::send` has no timeout of its own, so a
/// gateway that stops reading fills the stdin pipe and parks the test forever;
/// under this bound it fails the row instead of hanging CI.
const BURST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a saturation row waits for the questions it expects.
///
/// Thirty seconds was once read as too tight: four CI runs failed with 57, 58,
/// 59 and 63 of the expected 64 questions, a spread just under the cap. Raising
/// this to 180s tested that reading and refuted it. The row then ran for its
/// full budget -- 187.60s wall clock for the binary -- and still collected 58,
/// while the sibling inflight row collected 60. Six times the budget moved the
/// count by nothing, so the missing questions are not late, they do not arrive.
///
/// The value is back at its original 30s because the extra 150s buys no
/// evidence and costs every green run. What separates a parked reader from a
/// child that stopped emitting is the end-cause line `collect_lines_until`
/// prints on failure, not a larger number here.
const COLLECT_BUDGET: Duration = Duration::from_secs(30);

/// Kept reading after the expected count arrives, so one question too many is
/// still observed rather than cut off by an early return.
const SETTLE_WINDOW: Duration = Duration::from_secs(2);

/// `MAX_CONCURRENT_STDIO_DISPATCHES` (`src/gateway/server/mod.rs:83`). Not
/// importable from an integration test, so it is repeated here and the row
/// fails loudly if it ever moves.
const ADMISSION_CAP: i64 = 64;

/// The first id of a burst. `1` is the `initialize` handshake.
const FIRST_CALL_ID: i64 = 2;

/// Every outbound `elicitation/create` in `frames`.
fn prompts_in(frames: &[Value]) -> Vec<&Value> {
    frames
        .iter()
        .filter(|frame| frame.get("method").and_then(Value::as_str) == Some("elicitation/create"))
        .collect()
}

/// Every id carrying a `-32000 server busy` refusal.
fn refused_ids(frames: &[Value]) -> Vec<i64> {
    frames
        .iter()
        .filter(|frame| frame.pointer("/error/code").and_then(Value::as_i64) == Some(-32000))
        .filter_map(|frame| frame.get("id").and_then(Value::as_i64))
        .collect()
}

/// MIK-7212.MRTR.7a — the single stdin reader keeps reading past the admission
/// cap, so a client that pipelines more bridged calls than may run at once is
/// still served.
///
/// This is the regression pin for `d0c68e15`, where the read loop awaited an
/// admission permit inline: the 65th pipelined call parked the only reader, and
/// the answers that would have released the 64 running dispatches could only
/// arrive through that parked reader. Until now the defect was pinned only by a
/// unit row on the non-async helper, which cannot see the loop it was a defect
/// in.
///
/// The load-bearing assertion is the last one. Counting 64 prompts and no
/// refusal says only that the gateway did not refuse the 65th; a gateway that
/// read the 65th line and dropped it on the floor passes that much. Requiring
/// the 65th prompt to appear once admission frees is what separates accepted
/// and parked from silently discarded.
#[tokio::test]
async fn ac_mrtr_7a_the_reader_keeps_reading_past_the_admission_cap() {
    let home = tempfile::tempdir().expect("temporary home");
    let (backend_url, received) = spawn_fixture_backend().await;
    write_config(home.path(), &backend_url);
    let mut session = StdioSession::spawn(home.path());

    // Synchronised deliberately: a burst sent before the handshake is answered
    // races initialization, and the errors that produces have nothing to do
    // with the cap this row is about.
    session.send(&initialize_request(1)).await;
    let (_, initialized) = session.read_until_id(1).await;
    assert!(initialized.is_some(), "the child never answered initialize");

    let last_call_id = FIRST_CALL_ID + ADMISSION_CAP;
    timeout(BURST_TIMEOUT, async {
        for id in FIRST_CALL_ID..=last_call_id {
            session.send(&asking_call(id)).await;
        }
    })
    .await
    .expect("the child stopped reading stdin mid-burst: the reader parked");

    let wanted = usize::try_from(ADMISSION_CAP).expect("the admission cap is not negative");
    let lines = session
        .collect_lines_until(COLLECT_BUDGET, SETTLE_WINDOW, |seen| {
            prompts_in(&frames_lenient(seen)).len() >= wanted
        })
        .await;
    let frames = frames_lenient(&lines);
    assert!(
        saw_method(&received, "initialize"),
        "the fixture backend was never reached, so nothing could have asked"
    );

    let prompts = prompts_in(&frames);
    assert_eq!(
        prompts.len(),
        usize::try_from(ADMISSION_CAP).expect("the admission cap is not negative"),
        "admission bounds what may run at 64, so 65 unanswered bridged calls \
         must produce exactly 64 outstanding questions; {} arrived",
        prompts.len()
    );
    assert!(
        refused_ids(&frames).is_empty(),
        "65 calls is one past admission but far short of the inflight cap, so \
         none of them may be refused; refused: {:?}",
        refused_ids(&frames)
    );

    // Answer a question the test has actually received. A predetermined id
    // assumes dispatches start in stdin order, which 9b0caa1e withdrew, and
    // would hang whenever the chosen call is the one still parked.
    let answered = prompts[0]
        .get("id")
        .cloned()
        .expect("an elicitation/create the gateway wrote carries an id");
    session.send(&elicitation_answer(&answered)).await;

    let after = frames_lenient(&session.collect_lines(COLLECT_WINDOW).await);
    assert!(
        after.iter().any(|frame| {
            frame.get("method").is_none()
                && frame.get("result").is_some()
                && matches!(frame.get("id").and_then(Value::as_i64),
                    Some(id) if (FIRST_CALL_ID..=last_call_id).contains(&id))
        }),
        "the answered call never completed, so the reader never consumed the \
         answer: {after:?}"
    );
    assert!(
        !prompts_in(&after).is_empty(),
        "the 65th call was accepted but never asked its question once \
         admission freed, so it was read and dropped rather than parked: \
         {after:?}"
    );

    session.shutdown().await;
}

/// `MAX_INFLIGHT_STDIO_REQUESTS` = `STDOUT_QUEUE_DEPTH`
/// (`src/gateway/server/mod.rs:76,89`). Repeated here for the same reason as
/// [`ADMISSION_CAP`].
const INFLIGHT_CAP: i64 = 1024;

/// MIK-7212.MRTR.7b — past the inflight cap the excess is refused, not queued
/// behind the reader.
///
/// The read loop consults `inflight` through a deliberately non-async
/// `try_acquire_owned` and answers `-32000 server busy` with `try_send`, so
/// saturation costs the client a refusal and never costs it the reader. Nothing
/// in this row is answered, so no permit is released mid-burst and the ids the
/// loop accepts are the ids it read first.
///
/// The boundary is asserted as a window rather than a point, and that is not
/// slack for its own sake: `initialize`'s own dispatch takes an inflight permit
/// and releases it at `drop(slot)`, which is not ordered against the response
/// this row waits for, so the cap is observable to within one slot. The window
/// still fails any regressed cap — halve the constant and the first group draws
/// refusals — which "at least one refusal somewhere in 1025 calls" would not.
#[tokio::test]
async fn ac_mrtr_7b_the_excess_past_the_inflight_cap_is_refused_not_queued() {
    let home = tempfile::tempdir().expect("temporary home");
    let (backend_url, received) = spawn_fixture_backend().await;
    write_config(home.path(), &backend_url);
    let mut session = StdioSession::spawn(home.path());

    session.send(&initialize_request(1)).await;
    let (_, initialized) = session.read_until_id(1).await;
    assert!(initialized.is_some(), "the child never answered initialize");

    // One short of the cap, so the handshake's own permit cannot push this
    // group over it whether or not it has been released yet.
    let last_below_cap = FIRST_CALL_ID + INFLIGHT_CAP - 2;
    let last_over_cap = last_below_cap + 3;
    timeout(BURST_TIMEOUT, async {
        for id in FIRST_CALL_ID..=last_over_cap {
            session.send(&asking_call(id)).await;
        }
    })
    .await
    .expect("the child stopped reading stdin mid-burst: the reader parked");

    let wanted = usize::try_from(ADMISSION_CAP).expect("the admission cap is not negative");
    let lines = session
        .collect_lines_until(COLLECT_BUDGET, SETTLE_WINDOW, |seen| {
            prompts_in(&frames_lenient(seen)).len() >= wanted
        })
        .await;
    let frames = frames_lenient(&lines);
    assert!(
        saw_method(&received, "initialize"),
        "the fixture backend was never reached, so nothing could have asked"
    );

    let refused = refused_ids(&frames);
    let below: Vec<i64> = refused
        .iter()
        .copied()
        .filter(|id| *id <= last_below_cap)
        .collect();
    assert!(
        below.is_empty(),
        "ids up to {last_below_cap} are within the inflight cap and must all be \
         accepted; {} of them were refused, so the cap has regressed below \
         1024. First: {:?}",
        below.len(),
        &below[..below.len().min(5)]
    );
    assert!(
        !refused.is_empty(),
        "{} calls is past the inflight cap, so the excess must be refused with \
         -32000 rather than queued; nothing was refused at all",
        last_over_cap - FIRST_CALL_ID + 1
    );

    // The refusal is not the whole invariant: a gateway that refuses everything
    // once saturated would satisfy the assertions above. Work accepted before
    // the cap must still complete when its answer arrives.
    let prompts = prompts_in(&frames);
    assert_eq!(
        prompts.len(),
        usize::try_from(ADMISSION_CAP).expect("the admission cap is not negative"),
        "saturating inflight must not change what admission lets run: {} \
         questions are outstanding, not {ADMISSION_CAP}",
        prompts.len()
    );
    let answered = prompts[0]
        .get("id")
        .cloned()
        .expect("an elicitation/create the gateway wrote carries an id");
    session.send(&elicitation_answer(&answered)).await;

    let after = frames_lenient(&session.collect_lines(COLLECT_WINDOW).await);
    assert!(
        after.iter().any(|frame| {
            frame.get("method").is_none()
                && frame.get("result").is_some()
                && matches!(frame.get("id").and_then(Value::as_i64),
                    Some(id) if (FIRST_CALL_ID..=last_below_cap).contains(&id))
        }),
        "a call accepted before the cap never completed after its answer was \
         sent, so saturation cost the client its reader: {after:?}"
    );

    session.shutdown().await;
}
