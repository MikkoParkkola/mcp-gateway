// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7479 (MRTR.7 row 7b): does every stdio call reach exactly one terminal
//! frame?
//!
//! The ticket read "40 of 1026 calls produce no response" off a census that
//! subtracted 986 responses from 1026 calls and left out the 60 asks. The row
//! in `mik_7212_mrtr7_stdio_acs.rs` asserts admission bounds, not ids, so it
//! cannot settle that. This suite keeps a ledger keyed by call id instead.
//!
//! A frame is **terminal** for id X when it is a JSON-RPC response: `id == X`,
//! it carries `result` or `error`, and it has no `method`. A continuation, an
//! expired ask's `-32003`, a `-32000` busy refusal and an `isError` tool result
//! are all terminal. An `elicitation/create` ask never is. The first response
//! for X is its terminal; any later one is a **duplicate**, a protocol
//! violation of its own, never a second terminal.
//!
//! Deadlines are sized for a burst in which every accepted call asks
//! (`ceil(n/64)` waves of one ask timeout). How much of a burst the rate
//! limiter refuses at once depends on the host: a fast one finishes in about
//! one ask timeout, a CI runner drains the full burst in about eight minutes.
//! So the full burst runs in `mrtr7b-full-burst.yml` (nightly, dispatch, and
//! a PR labelled `mrtr7b-full-burst`) and the per-PR job skips it. Locally:
//! `cargo test --test mik_7479_mrtr7b_ledger -- --skip mik_7479_full_burst`.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::time::timeout;

#[path = "common/stdio_session.rs"]
mod stdio_session;
use stdio_session::{EOF_LINE, StdioSession};

const CLIENT_PROTOCOL_VERSION: &str = "2025-06-18";
const BACKEND: &str = "fixture";
const ASKING_TOOL: &str = "needs_input";
/// As the 7b row: large enough that frames fill the stdout queue under a
/// burst, which is the condition hypothesis H1 (a dropped refusal) needs.
const QUESTION_BYTES: usize = 96 * 1024;
/// `MAX_CONCURRENT_STDIO_DISPATCHES` (`gateway/server/mod.rs`); not importable here.
const ADMISSION_CAP: i64 = 64;
/// `MAX_INFLIGHT_STDIO_REQUESTS` (`gateway/server/mod.rs`).
const INFLIGHT_CAP: i64 = 1024;
/// `BridgeBounds::DEFAULT.per_prompt` (`gateway/input_bridge.rs`): how long an
/// unanswered ask holds its admission permit before ending in `-32003`.
const PER_PROMPT: Duration = Duration::from_secs(30);
/// `1` is the `initialize` handshake.
const FIRST_CALL_ID: i64 = 2;
/// `StdioSession::send` has no bound of its own; a parked reader fails here.
const BURST_TIMEOUT: Duration = Duration::from_secs(60);

/// The cause phrases the burst assertions count, each from the gateway's own
/// text: `meta_mcp/invoke.rs` (capability auto-disable, bridged ask failure),
/// `backend/ops.rs` via the tool envelope (open breaker), and
/// `gateway/server/mod.rs` (stdio admission refusal). Pinned against real
/// envelopes by `kind_names_each_cause_the_burst_counts`.
const CAPABILITY_DISABLED: &str = "temporarily disabled due to a high error rate";
const ASK_EXPIRED: &str = "asked for input and the bridged exchange could not be completed";
const BREAKER_OPEN: &str = "Circuit breaker open";
const SERVER_BUSY: &str = "server busy: too many stdio requests in flight";

// ---------------------------------------------------------------- the ledger

/// What became of every call id in a burst.
#[derive(Debug, Default)]
struct Ledger {
    /// Ids with no response at all: the ticket's "no response".
    unaccounted: Vec<i64>,
    /// Ids answered more than once.
    duplicates: Vec<i64>,
    /// How each terminal frame ended, for the failure text.
    kinds: BTreeMap<String, usize>,
}

/// The call id a frame terminates, if it is a response to a numeric id.
fn terminal_id(frame: &Value) -> Option<i64> {
    if frame.get("method").is_some() {
        return None;
    }
    if frame.get("result").is_none() && frame.get("error").is_none() {
        return None;
    }
    frame.get("id").and_then(Value::as_i64)
}

/// A terminal frame's outcome, as a histogram key: its shape plus the text
/// that names the cause, whitespace collapsed.
///
/// The code alone is ambiguous (-32000 and -32003 each carry several meanings
/// here), and a tool-level refusal can arrive as text nested inside a result,
/// so assertions match a cause phrase anywhere in the key ([`Run::kind`]).
fn kind_of(frame: &Value) -> String {
    let (shape, text) = if let Some(code) = frame.pointer("/error/code").and_then(Value::as_i64) {
        (
            format!("error {code}"),
            frame.pointer("/error/message").cloned(),
        )
    } else {
        let result = frame.get("result").unwrap_or(&Value::Null);
        let shape = if result.get("requestState").is_some() {
            "continuation"
        } else if result.get("isError").and_then(Value::as_bool) == Some(true) {
            "isError"
        } else {
            "result"
        };
        (shape.to_owned(), result.pointer("/content/0/text").cloned())
    };
    let text = text.as_ref().and_then(Value::as_str).unwrap_or("");
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    format!("{shape}: {}", flat.chars().take(240).collect::<String>())
}

impl Ledger {
    fn from_frames(ids: RangeInclusive<i64>, frames: &[Value]) -> Self {
        let mut seen = BTreeSet::new();
        let mut ledger = Self::default();
        for frame in frames {
            let Some(id) = terminal_id(frame).filter(|id| ids.contains(id)) else {
                continue;
            };
            if seen.insert(id) {
                *ledger.kinds.entry(kind_of(frame)).or_default() += 1;
            } else {
                ledger.duplicates.push(id);
            }
        }
        ledger.unaccounted = ids.filter(|id| !seen.contains(id)).collect();
        ledger
    }

    fn terminals(&self) -> usize {
        self.kinds.values().sum()
    }

    fn is_clean(&self) -> bool {
        self.unaccounted.is_empty() && self.duplicates.is_empty()
    }
}

fn response(id: i64, body: &Value) -> Value {
    let mut frame = json!({"jsonrpc": "2.0", "id": id});
    frame
        .as_object_mut()
        .expect("a frame is an object")
        .extend(body.as_object().expect("a body is an object").clone());
    frame
}

fn ask(id: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "elicitation/create", "params": {}})
}

/// One of every terminal shape the ledger must accept, for ids 2..=11.
fn every_terminal_shape() -> Vec<Value> {
    let bodies = [
        json!({"result": {"content": []}}),
        json!({"result": {"requestState": "s", "inputRequests": {}}}),
        json!({"error": {"code": -32003, "message": "ask expired"}}),
        json!({"error": {"code": -32000, "message": "busy"}}),
        json!({"result": {"isError": true, "content": []}}),
    ];
    let mut frames = vec![ask(&json!("elic-a")), ask(&json!(3))];
    frames.extend((2..=11).map(|id| {
        let index = usize::try_from(id).expect("small id") % bodies.len();
        response(id, &bodies[index])
    }));
    frames
}

/// The design's mutation ("the fixture drops one line -> the ledger names that
/// id"), made deterministic.
#[test]
fn ledger_names_the_id_whose_terminal_frame_was_dropped() {
    let frames = every_terminal_shape();
    let whole = Ledger::from_frames(2..=11, &frames);
    assert!(whole.is_clean(), "every id was answered once: {whole:?}");
    assert_eq!(whole.kinds.len(), 5, "all five shapes count: {whole:?}");

    let dropped: Vec<Value> = frames
        .into_iter()
        .filter(|frame| terminal_id(frame) != Some(7))
        .collect();
    let ledger = Ledger::from_frames(2..=11, &dropped);
    assert_eq!(ledger.unaccounted, vec![7]);
    assert!(ledger.duplicates.is_empty(), "{ledger:?}");
}

#[test]
fn ledger_counts_a_second_response_as_duplicate_not_terminal() {
    let mut frames = every_terminal_shape();
    frames.push(response(4, &json!({"result": {"content": []}})));
    let ledger = Ledger::from_frames(2..=11, &frames);
    assert_eq!(ledger.duplicates, vec![4]);
    assert!(ledger.unaccounted.is_empty(), "{ledger:?}");
    assert_eq!(
        ledger.terminals(),
        10,
        "a duplicate is not a second terminal"
    );
}

#[test]
fn ledger_never_counts_an_ask_as_terminal() {
    // An ask carrying a call's own numeric id is still a request, not an answer.
    let frames: Vec<Value> = (2..=4)
        .map(|id| ask(&json!(id)))
        .chain([ask(&json!("elic-x"))])
        .collect();
    let ledger = Ledger::from_frames(2..=4, &frames);
    assert_eq!(ledger.unaccounted, vec![2, 3, 4]);
    assert_eq!(ledger.terminals(), 0);
}

/// The burst assertions count causes by phrase; this pins each phrase against
/// the envelope shape the gateway actually writes, so an envelope change fails
/// here in milliseconds instead of silently zeroing a burst assertion.
#[test]
fn kind_names_each_cause_the_burst_counts() {
    let error = |code: i64, message: &str| json!({"error": {"code": code, "message": message}});
    let frames = [
        response(
            2,
            &error(
                -32000,
                "JSON-RPC error -32000: Capability 'needs_input' on server \
            'fixture' is temporarily disabled due to a high error rate. It will auto-recover",
            ),
        ),
        response(
            3,
            &error(
                -32003,
                "JSON-RPC error -32003: Tool 'needs_input' on server \
            'fixture' asked for input and the bridged exchange could not be completed",
            ),
        ),
        response(
            4,
            &error(
                -32000,
                "server busy: too many stdio requests in flight, retry this request",
            ),
        ),
        // As observed on the wire: the refusal envelope nested as text in a result.
        response(
            5,
            &json!({"result": {"content": [{"type": "text",
            "text": "{\n  \"content\": [\n    {\n      \"text\": \"Circuit breaker open for backend 'fixture'\""}]}}),
        ),
        response(6, &error(-32003, "Forbidden: something else")),
    ];
    let run = Run {
        ledger: Ledger::from_frames(2..=6, &frames),
        asks: 1,
        unparsable: 0,
        ended: "fixture",
        elapsed: Duration::ZERO,
        stderr: Vec::new(),
    };
    assert_eq!(
        run.kind(&[CAPABILITY_DISABLED]),
        1,
        "{:?}",
        run.ledger.kinds
    );
    assert_eq!(
        run.kind(&["error -32003", ASK_EXPIRED]),
        1,
        "{:?}",
        run.ledger.kinds
    );
    assert_eq!(run.kind(&["error -32003"]), 2, "{:?}", run.ledger.kinds);
    assert_eq!(
        run.kind(&["error -32000", SERVER_BUSY]),
        1,
        "{:?}",
        run.ledger.kinds
    );
    assert_eq!(run.kind(&[BREAKER_OPEN]), 1, "{:?}", run.ledger.kinds);
}

/// The phrases are the gateway's own text, not the test's: each one must
/// appear in the source that writes it (Rust string continuations joined), so
/// a rewording there fails here instead of silently zeroing a burst assertion.
#[test]
fn cause_phrases_are_the_gateways_own_text() {
    fn joined(source: &str) -> String {
        source
            .split("\\\n")
            .enumerate()
            .map(|(i, piece)| if i == 0 { piece } else { piece.trim_start() })
            .collect()
    }
    let invoke = joined(include_str!("../src/gateway/meta_mcp/invoke.rs"));
    let error = joined(include_str!("../src/error.rs"));
    let server = joined(include_str!("../src/gateway/server/mod.rs"));
    for (phrase, source, file) in [
        (CAPABILITY_DISABLED, &invoke, "meta_mcp/invoke.rs"),
        (ASK_EXPIRED, &invoke, "meta_mcp/invoke.rs"),
        (BREAKER_OPEN, &error, "error.rs"),
        (SERVER_BUSY, &server, "gateway/server/mod.rs"),
    ] {
        assert!(
            source.contains(phrase),
            "{file} no longer writes {phrase:?}"
        );
    }
}

// ------------------------------------------------ the fixture (as the 7b row)

/// An HTTP MCP backend whose one tool asks: a first call gets the MRTR interim
/// carrying an `elicitation/create`, a retry carrying answers completes. Copied
/// from `mik_7212_mrtr7_stdio_acs.rs`, as `r5_stdio_modern_continuation.rs` does.
async fn spawn_fixture_backend() -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(|axum::Json(request): axum::Json<Value>| async move {
            axum::Json(fixture_answer(&request))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture backend address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/")
}

fn fixture_answer(request: &Value) -> Value {
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

fn write_config(home: &Path, backend_url: &str) {
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.join("gateway.yaml"),
        format!(
            "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n"
        ),
    )
    .expect("write gateway.yaml");
}

/// Legacy-shaped on purpose: elicitation is declared at the handshake and the
/// calls carry no `_meta`, so each goes through the in-band bridge and an
/// unanswered ask ends in `-32003` (`meta_mcp/invoke.rs`), not a continuation.
fn initialize_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": CLIENT_PROTOCOL_VERSION,
            "capabilities": {"elicitation": {}},
            "clientInfo": {"name": "mik-7479-ledger", "version": "0"},
        },
    })
}

fn asking_call(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": ASKING_TOOL, "arguments": {}},
        },
    })
}

fn elicitation_answer(id: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id.clone(), "result": {"action": "accept", "content": {}}})
}

// ------------------------------------------------------------- the real child

/// Whether the client answers the gateway's asks.
#[derive(Clone, Copy)]
enum Client {
    /// Answers each `elicitation/create` on arrival: the fast positive control.
    Draining,
    /// The 7b row's client, which never answers: every accepted call holds an
    /// admission permit until its ask expires.
    Silent,
}

/// Enough to drain `accepted` calls behind a silent client: `ceil(n/64)` waves
/// of one ask timeout each, plus slack. Derived, so it moves with the constants.
fn drain_deadline(accepted: i64) -> Duration {
    let waves =
        u32::try_from((accepted + ADMISSION_CAP - 1) / ADMISSION_CAP).expect("a small wave count");
    PER_PROMPT * waves + Duration::from_secs(30)
}

/// The whole post-collection settle, however chatty the child.
const SETTLE_CAP: Duration = Duration::from_secs(10);

/// Collection also ends when the ledger has not moved for this long, but only
/// once it has moved at all: the first `-32003` wave lands a full ask timeout
/// in, and an idle stop armed from the start could fire before it.
const IDLE_STOP: Duration = Duration::from_secs(PER_PROMPT.as_secs() * 2);

struct Run {
    ledger: Ledger,
    asks: usize,
    unparsable: usize,
    ended: &'static str,
    elapsed: Duration,
    stderr: Vec<String>,
}

impl Run {
    fn stderr_count(&self, needle: &str) -> usize {
        self.stderr
            .iter()
            .filter(|line| line.contains(needle))
            .count()
    }

    /// The child's WARN/ERROR lines, histogrammed by their text past the
    /// timestamp, so a red run names what the gateway itself saw fail.
    fn warn_histogram(&self) -> BTreeMap<String, usize> {
        let mut seen = BTreeMap::new();
        for line in &self.stderr {
            let Some(at) = line.find("WARN").or_else(|| line.find("ERROR")) else {
                continue;
            };
            // Colour codes stripped: the child may colour its log even into a pipe.
            let mut text = String::new();
            let mut in_escape = false;
            for c in line[at..].chars() {
                match (in_escape, c) {
                    (false, '\u{1b}') => in_escape = true,
                    (true, 'm') => in_escape = false,
                    (false, c) => text.push(c),
                    (true, _) => {}
                }
            }
            // Per-request ids would make every line its own bucket.
            let text: String = text
                .split(" request_id")
                .next()
                .unwrap_or("")
                .chars()
                .take(120)
                .collect();
            *seen.entry(text).or_default() += 1;
        }
        seen
    }

    /// Terminals whose kind contains every one of `needles`.
    fn kind(&self, needles: &[&str]) -> usize {
        self.ledger
            .kinds
            .iter()
            .filter(|(kind, _)| needles.iter().all(|needle| kind.contains(needle)))
            .map(|(_, count)| count)
            .sum()
    }

    /// Everything a red run needs to say which hypothesis it is: H1 is ids
    /// past the inflight cap plus the "could not be queued" WARN, H2 scattered
    /// ids with no WARN, H3 an early stdout EOF.
    fn report(&self) -> String {
        let unaccounted = &self.ledger.unaccounted;
        format!(
            "collection {} after {:?}; {} unaccounted (first {:?}); duplicates {:?}; \
             terminals {:?}; {} asks; {} unparsable lines; stderr: {} 'could not be queued', \
             {} 'refusing a request', {} 'stdout is gone', EOF line captured: {}; warnings {:#?}",
            self.ended,
            self.elapsed,
            unaccounted.len(),
            &unaccounted[..unaccounted.len().min(20)],
            self.ledger.duplicates,
            self.ledger.kinds,
            self.asks,
            self.unparsable,
            self.stderr_count("could not be queued"),
            self.stderr_count("refusing a request"),
            self.stderr_count("stdout is gone"),
            self.stderr_count(EOF_LINE) > 0,
            self.warn_histogram(),
        )
    }
}

/// Send calls `FIRST_CALL_ID..=last_id` in one burst, then read until every
/// id has a response, the deadline passes, or the ledger goes idle.
async fn run_burst(last_id: i64, client: Client, deadline: Duration) -> Run {
    let home = tempfile::tempdir().expect("temporary home");
    let backend_url = spawn_fixture_backend().await;
    write_config(home.path(), &backend_url);
    let (mut session, captured) = StdioSession::spawn_capturing_stderr(home.path());

    session.send(&initialize_request(1)).await;
    let (_, initialized) = session.read_until_id(1).await;
    assert!(initialized.is_some(), "the child never answered initialize");

    let ids = FIRST_CALL_ID..=last_id;
    timeout(BURST_TIMEOUT, async {
        for id in ids.clone() {
            session.send(&asking_call(id)).await;
        }
    })
    .await
    .expect("the child stopped reading stdin mid-burst: the reader parked");

    // Only responses are kept: each ask carries a 96 KiB question, and a full
    // burst of them would hold ~100 MB for no evidence.
    let mut responses = Vec::new();
    let mut terminated = BTreeSet::new();
    let (mut asks, mut unparsable) = (0, 0);
    let started = Instant::now();
    let mut last_change: Option<Instant> = None;
    let ended = loop {
        if terminated.len() == ids.clone().count() {
            break "every id was accounted for";
        }
        let Some(left) = deadline.checked_sub(started.elapsed()) else {
            break "the deadline passed";
        };
        if last_change.is_some_and(|at| at.elapsed() >= IDLE_STOP) {
            break "the ledger went idle";
        }
        let line = match session.next_line(left.min(Duration::from_secs(1))).await {
            Err(_) => continue,
            Ok(None) => break "stdout ended",
            Ok(Some(line)) => line,
        };
        let Ok(frame) = serde_json::from_str::<Value>(&line) else {
            unparsable += 1;
            continue;
        };
        if frame.get("method").and_then(Value::as_str) == Some("elicitation/create") {
            asks += 1;
            if let (Client::Draining, Some(id)) = (client, frame.get("id")) {
                session.send(&elicitation_answer(id)).await;
            }
        } else if let Some(id) = terminal_id(&frame) {
            if ids.contains(&id) {
                // Any response keeps the run alive, not only a first one:
                // a burst of refusals is progress even when it answers ids
                // already seen.
                terminated.insert(id);
                last_change = Some(Instant::now());
            }
            responses.push(frame);
        }
    };
    let elapsed = started.elapsed();
    // A duplicate can only follow its terminal; a short settle gives it the
    // chance to arrive rather than ending the run on the frame before it.
    // Bounded as a whole as well as per line: a child that keeps writing
    // would otherwise keep this loop alive forever.
    let _ = timeout(SETTLE_CAP, async {
        while let Ok(Some(line)) = session.next_line(Duration::from_secs(2)).await {
            if let Ok(frame) = serde_json::from_str::<Value>(&line)
                && terminal_id(&frame).is_some()
            {
                responses.push(frame);
            }
        }
    })
    .await;

    let stderr = session.finish_capturing(captured).await;
    Run {
        ledger: Ledger::from_frames(ids, &responses),
        asks,
        unparsable,
        ended,
        elapsed,
        stderr,
    }
}

/// The capture is only evidence if it demonstrably works: the child's fixed
/// EOF line must be in it, or "no WARN" would mean nothing.
fn assert_capture_worked(run: &Run) {
    assert!(
        run.stderr_count(EOF_LINE) > 0,
        "the child's stderr capture is broken: '{EOF_LINE}' is missing from {} captured lines",
        run.stderr.len()
    );
}

/// What a correct gateway does with a burst from a client that never answers:
/// every call that asked ends in the expired-ask `-32003`, and the rest are
/// refused fast by admission or the per-backend rate limiter. What it must not
/// do is let one client's silence disable the capability, or open the breaker,
/// for every caller.
///
/// Expired asks are not backend failures (the bridge's timeout returns outside
/// `accounted_dispatch`, `meta_mcp/invoke.rs`), and a rate-limit refusal is not
/// one either. Before F23 the limiter's instant refusals were sampled as
/// failures ahead of the slow asking dispatches, surfaced as "Circuit breaker
/// open", and auto-disabled the capability.
fn assert_drained_behind_unanswered_asks(run: &Run) {
    let disabled = run.kind(&[CAPABILITY_DISABLED]);
    let breaker = run.kind(&[BREAKER_OPEN]);
    assert_eq!(
        (disabled, breaker),
        (0, 0),
        "one client's unanswered asks cost every caller the capability \
         (disabled, breaker-open terminals): {}",
        run.report()
    );
    assert!(
        run.asks > 0,
        "no call asked, so nothing drained: {}",
        run.report()
    );
    // Both counts, because -32003 has other meanings: an unrelated -32003
    // must not stand in for an ask that never expired.
    assert_eq!(
        (
            run.kind(&["error -32003", ASK_EXPIRED]),
            run.kind(&["error -32003"])
        ),
        (run.asks, run.asks),
        "every call that asked must end in its expired ask, once, and nothing \
         else may end -32003: {}",
        run.report()
    );
}

/// Burst size for the per-PR rows: three admission waves and a partial fourth,
/// all inside the inflight cap.
const PER_PR_LAST_ID: i64 = FIRST_CALL_ID + 3 * ADMISSION_CAP + 1;

/// Positive control: with every ask answered, the ledger sees every call end.
#[tokio::test]
async fn ac_mrtr_7b_draining_client_accounts_for_every_call() {
    let run = run_burst(PER_PR_LAST_ID, Client::Draining, Duration::from_secs(60)).await;
    assert!(run.ledger.is_clean(), "{}", run.report());
    assert!(
        run.asks > 0,
        "nothing asked, so nothing was drained: {}",
        run.report()
    );
    assert_capture_worked(&run);
}

/// MIK-7479.STDIO.1, per PR: a client that never answers still gets exactly one
/// terminal frame for each of 194 calls.
#[tokio::test]
async fn ac_mrtr_7b_every_call_reaches_one_terminal_frame() {
    let calls = PER_PR_LAST_ID - FIRST_CALL_ID + 1;
    let run = run_burst(PER_PR_LAST_ID, Client::Silent, drain_deadline(calls)).await;
    assert!(
        run.ledger.is_clean(),
        "a call never reached exactly one terminal frame: {}",
        run.report()
    );
    assert_drained_behind_unanswered_asks(&run);
    assert_capture_worked(&run);
}

/// The ticket's exact scenario: 1026 calls, the excess past the inflight cap
/// refused `-32000`, the rest asking or refused by the rate limiter.
#[tokio::test]
async fn mik_7479_full_burst_every_call_reaches_one_terminal_frame() {
    let last_id = FIRST_CALL_ID + INFLIGHT_CAP + 1;
    let run = run_burst(last_id, Client::Silent, drain_deadline(INFLIGHT_CAP)).await;
    eprintln!("mik_7479 ledger: {}", run.report());
    assert!(
        run.ledger.is_clean(),
        "a call never reached exactly one terminal frame: {}",
        run.report()
    );
    assert_drained_behind_unanswered_asks(&run);
    assert!(
        run.stderr_count("refusing a request") >= run.kind(&["error -32000", SERVER_BUSY]),
        "each busy refusal logs one WARN, so fewer WARNs than refusals means a broken capture: {}",
        run.report()
    );
    assert_capture_worked(&run);
}
