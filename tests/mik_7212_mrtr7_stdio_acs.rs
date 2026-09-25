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

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::timeout;

#[path = "common/stdio_session.rs"]
mod stdio_session;
use stdio_session::StdioSession;

/// The revision this suite's client speaks. Matches the fixture backend's.
const CLIENT_PROTOCOL_VERSION: &str = "2025-06-18";
/// Config name for the backend the child dials.
const BACKEND: &str = "fixture";
/// The fixture tool whose result asks a question instead of answering one.
const ASKING_TOOL: &str = "needs_input";
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
/// The error budget is put out of reach. None of these rows answers every
/// question, so on a loaded machine some bridged prompts reach the bridge's
/// 30s `per_prompt` and end `-32003`. Those endings are charged to the
/// capability's error budget, whose kill switch then disables the fixture tool,
/// and every later call is refused `-32000 … temporarily disabled` rather than
/// admitted: a cascade the rows then misread as a regressed cap. The budget is
/// not what these rows are about, so it is configured never to evaluate —
/// `min_samples` equal to the largest window, which no row comes near.
///
/// `Config::FALLBACK_PATHS` checks `gateway.yaml` relative to the working
/// directory before `~/.config/mcp-gateway/gateway.yaml`, and the session below
/// sets the child's working directory to this same temporary home — so a file
/// dropped here is found without depending on `HOME` layout at all.
fn write_config(home: &Path, backend_url: &str) {
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.join("gateway.yaml"),
        format!(
            "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n\
             error_budget:\n  window_size: 100000\n  min_samples: 100000\n  capability:\n    \
             window_size: 100000\n    min_samples: 100000\n"
        ),
    )
    .expect("write gateway.yaml");
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

/// What the collected stream actually contained, for a shortfall's failure text.
///
/// [`frames_lenient`] drops an unparsable line with `.ok()`, so a mangled line
/// does not fail a row, it just lowers the count -- indistinguishable from a
/// question that was never asked. The saturation rows fail with a count a few
/// short of the cap and no way to tell those apart, so they report the census
/// alongside the count: a line the parser refused is a different defect from a
/// call that answered instead of asking, and both are different from a call
/// that produced nothing at all.
fn census_of(lines: &[String]) -> String {
    let mut unparsable: Vec<&str> = Vec::new();
    let mut methods: BTreeMap<String, usize> = BTreeMap::new();
    let mut results = 0usize;
    // A minted continuation is a `result` frame too, distinguished only by the
    // `requestState` the gateway writes into it (`meta_mcp/invoke.rs`). Counting
    // both as "results" collapses a fabricated plain answer and a re-emitted
    // question into one number, which is the discrimination this census exists
    // to make.
    let mut continuations = 0usize;
    // The bodies of the plain results, not just how many. Three hypotheses about
    // what fabricates them have now been eliminated by counting alone, and the
    // frame itself is the only authority left: it names the shape directly
    // instead of inviting a fourth guess.
    let mut plain_samples: Vec<String> = Vec::new();
    // MCP carries a tool-level failure INSIDE a successful response, as
    // `isError: true` beside the text (`meta_mcp/invoke.rs`). A census that
    // buckets by frame shape alone therefore files every refusal the gateway
    // answered correctly under `results`, which is the bucket that means "a
    // call answered instead of asking". Nine circuit-breaker trips were read
    // as nine fabricated successes that way. Histogrammed by message because
    // the shape is shared by every tool-level refusal and only the text names
    // which one happened.
    let mut refusals: BTreeMap<String, usize> = BTreeMap::new();
    let mut errors: BTreeMap<i64, usize> = BTreeMap::new();
    // `-32003` carries at least four distinct meanings in this codebase
    // (budget exhaustion, a missing client capability, forbidden, and service
    // unavailable), so the code alone does not name the defect. The child's
    // stderr is not captured under `cargo test`, so the text has to come back
    // through the frame or not at all.
    let mut messages: BTreeMap<String, usize> = BTreeMap::new();
    for line in lines {
        match serde_json::from_str::<Value>(line) {
            Err(_) => unparsable.push(line.as_str()),
            Ok(frame) => {
                if let Some(method) = frame.get("method").and_then(Value::as_str) {
                    *methods.entry(method.to_owned()).or_default() += 1;
                } else if let Some(code) = frame.pointer("/error/code").and_then(Value::as_i64) {
                    *errors.entry(code).or_default() += 1;
                    if let Some(message) = frame.pointer("/error/message").and_then(Value::as_str) {
                        *messages.entry(message.to_owned()).or_default() += 1;
                    }
                } else if let Some(result) = frame.get("result") {
                    if result.get("requestState").is_some() {
                        continuations += 1;
                    } else if let Some(text) = tool_refusal_text(result) {
                        *refusals.entry(text).or_default() += 1;
                    } else {
                        results += 1;
                        if plain_samples.len() < 3 {
                            let body: String = result.to_string().chars().take(240).collect();
                            plain_samples.push(format!("\n      {body:?}"));
                        }
                    }
                }
            }
        }
    }
    let samples: Vec<String> = unparsable
        .iter()
        .take(3)
        .map(|line| {
            let head: String = line.chars().take(160).collect();
            format!("\n      {head:?}")
        })
        .collect();
    format!(
        "census of {} collected lines: {} unparsable, methods {:?}, {} plain results, \
         {} continuation results, tool-level refusals {:?}, errors {:?}, \
         error messages {:?}{}{}{}",
        lines.len(),
        unparsable.len(),
        methods,
        results,
        continuations,
        refusals,
        errors,
        messages,
        samples.concat(),
        if plain_samples.is_empty() {
            ""
        } else {
            "\n    plain result samples:"
        },
        plain_samples.concat(),
    )
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
/// A 180s budget once still collected 58 of 64, so a larger number buys no
/// evidence; `collect_lines_until`'s end-cause line is what diagnoses a miss.
///
/// Nor is it an idle deadline (MIK-7553): it must stay within the bridge's own
/// 30s `per_prompt` (`BridgeBounds::DEFAULT`). Past that the gateway ends
/// unanswered dispatches itself, whose frames keep an idle wait alive, whose
/// freed permits admit a 65th question on a correct gateway, and which un-park
/// a reader that awaits admission inline -- the defect row 7a pins.
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

/// The stdio reader's own refusal, `stdio_busy_response` in
/// `src/gateway/server/mod.rs`.
const SERVER_BUSY: &str = "server busy: too many stdio requests in flight";

/// Every id carrying a `-32000 server busy` refusal.
///
/// Matched on the message as well as the code. `-32000` is also what a
/// disabled capability, a backend error and other gateway refusals answer
/// with, and counting those as busy refusals once read a kill-switch cascade
/// as "the inflight cap regressed below 1024".
fn refused_ids(frames: &[Value]) -> Vec<i64> {
    frames
        .iter()
        .filter(|frame| frame.pointer("/error/code").and_then(Value::as_i64) == Some(-32000))
        .filter(|frame| {
            frame
                .pointer("/error/message")
                .and_then(Value::as_str)
                .is_some_and(|message| message.starts_with(SERVER_BUSY))
        })
        .filter_map(|frame| frame.get("id").and_then(Value::as_i64))
        .collect()
}

/// Every id whose answer was a tool-level refusal rather than a question.
///
/// A dispatch the gateway declined once it was already admitted -- a tripped
/// circuit breaker is the one observed in CI -- answers the MCP way, as a
/// `result` carrying `isError: true`, not as a JSON-RPC error. It is a terminal
/// answer to an admitted call, so it belongs with the questions when counting
/// what admission let run, and nowhere near the plain-result count.
fn tool_refused_ids(frames: &[Value]) -> Vec<i64> {
    frames
        .iter()
        .filter(|frame| frame.get("result").and_then(tool_refusal_text).is_some())
        .filter_map(|frame| frame.get("id").and_then(Value::as_i64))
        .collect()
}

/// The message of a tool-level refusal carried in a successful `result`, or
/// `None` when the result is an ordinary answer.
///
/// The flag is not always where a reader reaches for it first. A backend's own
/// result carries `isError: true` beside its content, but the meta surface
/// wraps that result once more before it reaches the wire: `result.content[0]
/// .text` is then the backend's JSON *as a string*, and the flag sits one
/// level below `/result/isError`. Reading only the outer pointer files every
/// wrapped refusal as a plain success -- the exact miscount that made a
/// tripped circuit breaker look like fabricated work.
fn tool_refusal_text(result: &Value) -> Option<String> {
    let text = result.pointer("/content/0/text").and_then(Value::as_str);
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Some(text.unwrap_or("<no text>").to_owned());
    }
    let inner: Value = serde_json::from_str(text?).ok()?;
    // The full MCP refusal shape, not the flag alone: an ordinary answer whose
    // text happens to be JSON carrying `isError` would otherwise be re-filed as
    // a refusal and could hide one missing outcome in the admission sum.
    if inner.get("isError").and_then(Value::as_bool) != Some(true)
        || !inner.get("content").is_some_and(Value::is_array)
    {
        return None;
    }
    Some(
        inner
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or("<no text>")
            .to_owned(),
    )
}

/// The frame shape that made a tripped circuit breaker read as fabricated work.
///
/// A contended runner trips the fixture backend's breaker; a fast machine never
/// does, so no number of local reruns exercises this path and only CI ever sees
/// it. Pinning the body here is what keeps the reader honest between those
/// runs: without it the nesting can regress silently and the two rows above go
/// red again on a loaded machine, months later, for a reason already diagnosed.
#[test]
fn a_wrapped_tool_refusal_reads_as_a_refusal() {
    const TRIPPED: &str = "Circuit breaker open for backend 'fixture'";
    let inner = serde_json::json!({
        "content": [{ "text": TRIPPED, "type": "text" }],
        "isError": true,
    });
    let wrapped = serde_json::json!({
        "id": 7,
        "result": {
            "content": [{
                "text": serde_json::to_string_pretty(&inner).expect("the fixture body serialises"),
            }],
        },
    });

    assert_eq!(
        tool_refusal_text(&wrapped["result"]).as_deref(),
        Some(TRIPPED),
        "the meta surface wraps the backend result, so the flag sits one level \
         below /result/isError; reading only the outer pointer files this \
         refusal as a plain success"
    );
    assert_eq!(tool_refused_ids(std::slice::from_ref(&wrapped)), vec![7]);

    // An unwrapped refusal is the same answer one layer up, and must still read.
    assert_eq!(tool_refusal_text(&inner).as_deref(), Some(TRIPPED));

    // An ordinary answer is not a refusal, whether or not its text is JSON.
    assert_eq!(
        tool_refusal_text(&serde_json::json!({ "content": [{ "text": "ok" }] })),
        None
    );
    assert_eq!(
        tool_refusal_text(&serde_json::json!({
            "content": [{ "text": serde_json::json!({ "content": [] }).to_string() }],
        })),
        None
    );

    // The flag alone is not the refusal shape: a plain answer whose text is
    // JSON carrying `isError` is still an answer, and counting it as a refusal
    // would let one missing outcome pass the admission sum.
    assert_eq!(
        tool_refusal_text(&serde_json::json!({
            "content": [{ "text": serde_json::json!({ "isError": true }).to_string() }],
        })),
        None
    );
}

/// Busy refusals match the calls past the inflight cap one for one, to within
/// the handshake's own permit (see row 7b's doc): a count outside that window
/// is a refusal the cap did not cause, or excess the cap let through.
fn assert_busy_matches_excess(refused: usize, over_cap: i64, lines: &[String]) {
    let over_cap = usize::try_from(over_cap).expect("the over-cap group is positive");
    eprintln!("7b server-busy refusals: {refused} of {over_cap} over the cap");
    assert!(
        (over_cap - 1..=over_cap).contains(&refused),
        "{refused} of the {over_cap} calls past the cap were refused busy. {}",
        census_of(lines)
    );
}

/// The two bounds that keep row 7a's teeth once a decline can buy an extra
/// question: admission may never let more than `ADMISSION_CAP` questions stand
/// at once, and at least that many calls must reach a terminal outcome.
/// Returns the questions, so the row can answer one it actually received.
fn assert_admission_bounded<'a>(frames: &'a [Value], lines: &[String]) -> Vec<&'a Value> {
    let prompts = prompts_in(frames);
    // Asking is only one terminal outcome of an admitted call. A dispatch the
    // gateway declines after admission -- in CI, the fixture backend's rate
    // limiter refusing part of the burst, which a fast local run never reaches -- consumed a
    // slot and answered, so it counts toward what admission let run. The row
    // still discriminates: a gateway that dropped an admitted call silently
    // produces neither a question nor a refusal and the sum falls short.
    let declined = tool_refused_ids(frames);
    // Admission bounds CONCURRENCY, not the lifetime count of terminal
    // outcomes, so the sum is not an equality under contention: a dispatch the
    // gateway declines after admission -- in CI, the fixture backend's rate
    // limiter refusing part of the burst, which a fast local run never reaches -- releases its
    // permit, and the call behind it is admitted and asks. One decline can
    // therefore buy one extra question, and the sum runs past the cap without
    // anything being wrong. Two bounds keep the row's teeth where the equality
    // only looked like it did:
    //   * no more than ADMISSION_CAP questions may be outstanding at once, or
    //     admission is not bounding anything;
    //   * at least ADMISSION_CAP calls must have reached a terminal outcome, or an
    //     admitted call was dropped on the floor -- neither asked nor refused.
    let cap = usize::try_from(ADMISSION_CAP).expect("the admission cap is not negative");
    assert!(
        prompts.len() <= cap,
        "admission must bound what may run at once; {} questions are outstanding against a cap of {cap}. {}",
        prompts.len(),
        census_of(lines)
    );
    assert!(
        prompts.len() + declined.len() >= cap,
        "the reader must keep reading past the cap; {} questions plus {} declined after admission is short of \
         {cap}, so an admitted call produced no answer at all. {}",
        prompts.len(),
        declined.len(),
        census_of(lines)
    );
    assert!(
        refused_ids(frames).is_empty(),
        "65 calls is one past admission but far short of the inflight cap, so \
         none of them may be refused; refused: {:?}",
        refused_ids(frames)
    );
    prompts
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
/// read the 65th line and dropped it on the floor passes that much. What
/// separates accepted-and-parked from silently discarded is a frame carrying
/// the 65th call's own id once admission frees -- any terminal outcome, since
/// an admitted call that the gateway then declines still answers under its id,
/// while a dropped one answers nothing.
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
            prompts_in(seen).len() + tool_refused_ids(seen).len() >= wanted
        })
        .await;
    let frames = frames_lenient(&lines);
    assert!(
        saw_method(&received, "initialize"),
        "the fixture backend was never reached, so nothing could have asked"
    );

    let prompts = assert_admission_bounded(&frames, &lines);

    // Answer a question the test has actually received. A predetermined id
    // assumes dispatches start in stdin order, which 9b0caa1e withdrew, and
    // would hang whenever the chosen call is the one still parked.
    let answered = prompts
        .first()
        .expect("the count above admits a run of pure refusals; one question must remain to answer")
        .get("id")
        .cloned()
        .expect("an elicitation/create the gateway wrote carries an id");
    session.send(&elicitation_answer(&answered)).await;

    // A fixed window assumes the parked call's question lands inside it. Under
    // CI load the answer above arrives first and the window can close before
    // the parked dispatch is scheduled, which reddens the row for a delay
    // rather than for the drop it exists to catch. Collect until the question
    // arrives instead: a call read and dropped never produces one, so the
    // budget expires and both assertions below still fail.
    let after_lines = session
        .collect_lines_until(COLLECT_BUDGET, SETTLE_WINDOW, |seen| {
            !prompts_in(seen).is_empty()
        })
        .await;
    let after = frames_lenient(&after_lines);

    // Every one of the 64 admitted calls already asked in the first window, so
    // a question arriving after the answer can only be the 65th's. Answering
    // it is what makes this row cheap: the 65th's own terminal frame is
    // otherwise its own `per_prompt` timeout (30s, `gateway/input_bridge.rs`),
    // which a 30s collection window is racing rather than waiting for. Nothing
    // here is asserted -- a run where the question never came has the defect
    // this row exists to catch, and the assertion below reports it with a
    // census instead of unwrapping into a bare panic.
    if let Some(question) = prompts_in(&after)
        .first()
        .and_then(|frame| frame.get("id"))
        .cloned()
    {
        session.send(&elicitation_answer(&question)).await;
    }
    // Same filters as `terminal_for_last` below, deliberately. A predicate that
    // stops on any frame carrying the id would let a late busy refusal close the
    // window on a frame the assertion then rejects, reddening the row for a
    // refusal rather than for the drop it exists to catch.
    let settled_lines = session
        .collect_lines_until(COLLECT_BUDGET, SETTLE_WINDOW, |seen| {
            seen.iter()
                .filter(|frame| frame.get("method").is_none())
                .filter(|frame| {
                    frame.pointer("/error/code").and_then(Value::as_i64) != Some(-32000)
                })
                .any(|frame| frame.get("id").and_then(Value::as_i64) == Some(last_call_id))
        })
        .await;
    let settled = frames_lenient(&settled_lines);
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
    // The 65th call's OWN id, not "some question appeared". An
    // `elicitation/create` carries the gateway's `elic-<uuid>` id and
    // attributes to no call, so a question from any of the 64 already-admitted
    // calls satisfied the earlier form of this assertion while the 65th sat
    // dropped -- and, inversely, a backend that stopped serving before
    // admission freed reddened the row for the backend's state rather than for
    // the drop. A frame naming `last_call_id` discriminates both ways: every
    // terminal outcome answers under the call's own id, and a call read and
    // dropped produces no frame with that id at all.
    let terminal_for_last = frames
        .iter()
        .chain(after.iter())
        .chain(settled.iter())
        .filter(|frame| frame.get("method").is_none())
        .filter(|frame| frame.pointer("/error/code").and_then(Value::as_i64) != Some(-32000))
        .any(|frame| frame.get("id").and_then(Value::as_i64) == Some(last_call_id));
    assert!(
        terminal_for_last,
        "call {last_call_id} is one past admission and was accepted without a \
         busy refusal, so it must be parked and answered once admission frees. \
         No frame carries its id, so it was read and dropped. Before the \
         answer: {}. After: {}. Once settled: {}",
        census_of(&lines),
        census_of(&after_lines),
        census_of(&settled_lines)
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
            prompts_in(seen).len() >= wanted
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
    assert_busy_matches_excess(refused.len(), last_over_cap - last_below_cap, &lines);

    // The refusal is not the whole invariant: a gateway that refuses everything
    // once saturated would satisfy the assertions above. Work accepted before
    // the cap must still complete when its answer arrives.
    let prompts = prompts_in(&frames);
    // Every admitted call must reach a terminal outcome, and asking is only one
    // of them: a dispatch the gateway declines after admission -- in CI, the
    // fixture backend's rate limiter refusing part of the burst, which a fast
    // local run never reaches -- answers with `isError: true` inside a result. That
    // consumed an admission slot and produced an answer, so it counts toward
    // what admission let run. Counting questions alone read those refusals as
    // missing work and failed the row for a defect that was not there.
    let declined = tool_refused_ids(&frames);
    // Admission bounds CONCURRENCY, not the lifetime count of terminal
    // outcomes, so the sum is not an equality under contention: a dispatch the
    // gateway declines after admission -- in CI, the fixture backend's rate
    // limiter refusing part of the burst, which a fast local run never reaches -- releases its
    // permit, and the call behind it is admitted and asks. One decline can
    // therefore buy one extra question, and the sum runs past the cap without
    // anything being wrong. Two bounds keep the row's teeth where the equality
    // only looked like it did:
    //   * no more than ADMISSION_CAP questions may be outstanding at once, or
    //     admission is not bounding anything;
    //   * at least ADMISSION_CAP calls must have reached a terminal outcome, or an
    //     admitted call was dropped on the floor -- neither asked nor refused.
    let cap = usize::try_from(ADMISSION_CAP).expect("the admission cap is not negative");
    assert!(
        prompts.len() <= cap,
        "saturating inflight must not raise what admission lets run at once; {} questions are outstanding against a cap of {cap}. {}",
        prompts.len(),
        census_of(&lines)
    );
    assert!(
        prompts.len() + declined.len() >= cap,
        "saturating inflight must not cost an admitted call its answer; {} questions plus {} declined after admission is short of \
         {cap}, so an admitted call produced no answer at all. {}",
        prompts.len(),
        declined.len(),
        census_of(&lines)
    );
    let answered = prompts
        .first()
        .expect("the count above admits a run of pure refusals; one question must remain to answer")
        .get("id")
        .cloned()
        .expect("an elicitation/create the gateway wrote carries an id");
    session.send(&elicitation_answer(&answered)).await;

    // A fixed window assumes the answered call's terminal frame lands inside
    // it. Under load the reader can settle it before this window even opens
    // -- it is already sitting in `frames` from the first collection -- or
    // after a fixed window has closed, which reddens the row for a scheduling
    // delay rather than for the drop it exists to catch. Collect until the
    // terminal frame arrives instead, same as `ac_mrtr_7a_the_reader_keeps_\
    // reading_past_the_admission_cap`'s equivalent wait, and check both
    // collections: a terminal frame already present in `frames` when this
    // wait starts never gets re-emitted, so `after` alone can be empty on a
    // perfectly correct run.
    let after_lines = session
        .collect_lines_until(COLLECT_BUDGET, SETTLE_WINDOW, |seen| {
            seen.iter().any(|frame| {
                frame.get("method").is_none()
                    && frame.get("result").is_some()
                    && matches!(frame.get("id").and_then(Value::as_i64),
                        Some(id) if (FIRST_CALL_ID..=last_below_cap).contains(&id))
            })
        })
        .await;
    let after = frames_lenient(&after_lines);
    assert!(
        frames.iter().chain(after.iter()).any(|frame| {
            frame.get("method").is_none()
                && frame.get("result").is_some()
                && matches!(frame.get("id").and_then(Value::as_i64),
                    Some(id) if (FIRST_CALL_ID..=last_below_cap).contains(&id))
        }),
        // This row went red once and green on the next run with the same code,
        // so the message has to separate a stale answer from a dropped call.
        // The id answered is an `elic-<uuid>` while the assertion matches
        // numeric call ids, so a raw dump never says whether the call that was
        // answered is among the errors; and `meta_mcp/invoke.rs` collapses every
        // bridge error into one -32003, so the census histogram is the only
        // thing that tells the bounds apart.
        "a call accepted before the cap never completed after its answer was \
         sent, so saturation cost the client its reader. Answered {answered}. {}",
        census_of(&after_lines)
    );

    session.shutdown().await;
}
