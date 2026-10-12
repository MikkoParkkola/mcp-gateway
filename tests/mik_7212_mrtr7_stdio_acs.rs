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
//! an unlocked writer can be caught interleaving — need a bridged request to
//! reach the pipe. `InputBridge::run` has a production caller
//! (`run_input_bridge` in `src/gateway/meta_mcp/invoke.rs`), so the staging
//! is no longer blocked on a missing caller. Each staging removes a known
//! reason its row could not fail; neither is yet evidence that the row now
//! can. Re-check both against a bridged call.
//!
//! Row 308 wants a legacy client **on an SSE session** to receive its
//! `elicitation/create` on its own connection. No row covers that: this file
//! drives stdio, the sibling file drives trait fakes against the live
//! `InputBridge::run`, and the projection test in `mik_7212_acs.rs` calls
//! `Bridge::to_legacy_client`, all in process. The SSE
//! half of row 308 is uncovered, and closing it needs a row of its own here
//! rather than a wider assertion on an existing one.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::timeout;

#[path = "common/stdio_session.rs"]
mod stdio_session;
use stdio_session::StdioSession;

#[path = "common/mrtr7_fixture.rs"]
mod mrtr7_fixture;
use mrtr7_fixture::*;

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
    let lines = session
        .collect_lines_until(COLLECT_BUDGET, SETTLE_WINDOW, |f| {
            position_of_outbound(f, "elicitation/create").is_some()
        })
        .await;
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

/// MIK-1991 — a legacy stdio client whose `initialize` handshake does not
/// declare `elicitation` is never sent an `elicitation/create`.
///
/// The positive row above proves the handshake's declaration reaches the
/// bridge (replace `client.handshake_capabilities` with `Declared::NONE` and it
/// goes red). This is its complement: the same wiring must also keep a
/// capability out when the handshake omitted it, so the declaration is read
/// from the handshake and is not a constant that always says yes.
#[tokio::test]
async fn mik_1991_a_handshake_without_elicitation_keeps_the_question_out() {
    let home = tempfile::tempdir().expect("temporary home");
    let (backend_url, received) = spawn_fixture_backend().await;
    write_config(home.path(), &backend_url);
    let mut session = StdioSession::spawn(home.path());

    let mut handshake = initialize_request(1);
    handshake["params"]["capabilities"] = json!({});
    session.send(&handshake).await;
    let (_, initialized) = session.read_until_id(1).await;
    assert!(initialized.is_some(), "the child never answered initialize");

    session.send(&asking_call(2)).await;
    // Ends on the call's answer; the settle after it is where a prompt that
    // must not be sent would show.
    let lines = session
        .collect_lines_until(COLLECT_BUDGET, SETTLE_WINDOW, |f| {
            f.iter()
                .any(|frame| frame.get("id").and_then(Value::as_i64) == Some(2))
        })
        .await;
    let frames = frames_lenient(&lines);

    // Control: the call itself reached the backend, so "no question" is the
    // bridge's refusal and not a dropped `tools/call`.
    assert!(
        saw_method(&received, "tools/call"),
        "the call never reached the fixture backend: {lines:?}"
    );
    assert!(
        prompts_in(&frames).is_empty(),
        "a client that declared no elicitation was sent one: {lines:?}"
    );
    let answer = frames
        .iter()
        .find(|frame| frame.get("id").and_then(Value::as_i64) == Some(2))
        .unwrap_or_else(|| panic!("the undeclared call got no answer: {lines:?}"));
    assert!(
        !answer.to_string().contains("answered"),
        "the call completed as if the question had been answered: {answer}"
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

    let lines = session
        .collect_lines_until(COLLECT_BUDGET, SETTLE_WINDOW, |f| {
            position_of_outbound(f, "elicitation/create").is_some()
        })
        .await;
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
///
/// MIK-7387.STDIO.3 adds correlation: each call is tagged, the replies race in
/// reverse order, and each call must get back the answer to its own question.
#[tokio::test]
async fn ac_mrtr_7a_concurrent_bridged_requests_write_whole_frames() {
    let home = tempfile::tempdir().expect("temporary home");
    let (backend_url, received) = spawn_fixture_backend().await;
    write_config(home.path(), &backend_url);
    let mut session = StdioSession::spawn(home.path());

    session.send(&initialize_request(1)).await;
    let (_, initialized) = session.read_until_id(1).await;
    assert!(initialized.is_some(), "the child never answered initialize");

    session.send(&tagged_call(2)).await;
    session.send(&tagged_call(3)).await;
    let lines = session
        .collect_lines_until(COLLECT_BUDGET, SETTLE_WINDOW, |frames| {
            frames
                .iter()
                .filter(|frame| {
                    frame.get("method").and_then(Value::as_str) == Some("elicitation/create")
                })
                .count()
                >= 2
        })
        .await;

    assert!(
        saw_method(&received, "initialize"),
        "the fixture backend was never reached, so nothing could have asked: {}",
        census_of(&lines)
    );
    // Every emitted line is parsed on its own: a torn or merged frame fails
    // here rather than being skipped.
    let frames: Vec<Value> = lines
        .iter()
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap_or_else(|e| {
                let head: String = line.chars().take(160).collect();
                panic!("row 324: a line is not one whole JSON frame ({e}): {head:?}")
            })
        })
        .collect();
    // Which exchange each question belongs to, read off the call tag the
    // fixture wrote into it.
    let questions: BTreeMap<String, Value> = frames
        .iter()
        .filter(|frame| frame.get("method").and_then(Value::as_str) == Some("elicitation/create"))
        .map(|frame| {
            let message = frame
                .pointer("/params/message")
                .and_then(Value::as_str)
                .unwrap_or("");
            let tag = message
                .split_once('[')
                .and_then(|(_, rest)| rest.split_once(']'))
                .map_or("", |(tag, _)| tag);
            (
                tag.to_owned(),
                frame.get("id").cloned().unwrap_or(Value::Null),
            )
        })
        .collect();
    // Counted before the map is built from them: a duplicate question for one
    // call would otherwise collapse into its tag's single entry.
    assert_eq!(
        frames
            .iter()
            .filter(
                |frame| frame.get("method").and_then(Value::as_str) == Some("elicitation/create")
            )
            .count(),
        2,
        "row 324: exactly one outbound request per concurrent call. {}",
        census_of(&lines)
    );
    assert_eq!(
        questions.keys().map(String::as_str).collect::<Vec<_>>(),
        ["call-2", "call-3"],
        "row 324: two concurrent bridged calls must each produce their own \
         elicitation/create. {}",
        census_of(&lines)
    );
    assert_ne!(
        questions["call-2"], questions["call-3"],
        "row 324: two outstanding requests share one id, so their replies cannot be told apart"
    );

    // Answered in reverse order, back to back, with nothing read between:
    // both replies race into the loop while both exchanges are waiting.
    for tag in ["call-3", "call-2"] {
        session
            .send(&json!({
                "jsonrpc": "2.0",
                "id": questions[tag].clone(),
                "result": {"action": "accept", "content": {"tag": tag}},
            }))
            .await;
    }
    let tail = session
        .collect_lines_until(COLLECT_BUDGET, Duration::ZERO, |frames| {
            [2_i64, 3].iter().all(|id| {
                frames
                    .iter()
                    .any(|frame| frame.get("id").and_then(Value::as_i64) == Some(*id))
            })
        })
        .await;
    for id in [2_i64, 3] {
        assert_own_answer(&tail, id);
    }

    session.shutdown().await;
}

/// Row 324's correlation check: call `id`'s final result echoes its own tag
/// twice, once from its arguments and once from the answer it was given.
fn assert_own_answer(tail: &[String], id: i64) {
    let answer = tail
        .iter()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|e| panic!("row 324: a reply line is not whole JSON ({e})"))
        })
        .find(|frame| frame.get("id").and_then(Value::as_i64) == Some(id))
        .unwrap_or_else(|| panic!("row 324: no final result for call {id}: {tail:?}"));
    let envelope = answer
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or_else(|| panic!("row 324: no invoke envelope for call {id}: {answer}"));
    let expected = format!("answered:call-{id}:call-{id}");
    assert_eq!(
        envelope.pointer("/content/0/text").and_then(Value::as_str),
        Some(expected.as_str()),
        "row 324: call {id} did not receive the answer to its own request: {answer}"
    );
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
    let staged = session
        .collect_lines_until(COLLECT_BUDGET, SETTLE_WINDOW, |f| {
            position_of_outbound(f, "elicitation/create").is_some()
        })
        .await;

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
/// `src/gateway/server/stdio_refusal.rs`.
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

#[path = "mik_7212_mrtr7_stdio_acs/admission.rs"]
mod admission;
