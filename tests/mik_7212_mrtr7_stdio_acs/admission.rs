// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Admission cap and in-flight cap: the serve loop keeps reading and refuses the excess instead of queueing it.

use super::*;

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
    let over_cap = usize::try_from(over_cap)
        .ok()
        .filter(|n| *n >= 1)
        .expect("the over-cap group is positive");
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
            prompts_in(seen).len() + tool_refused_ids(seen).len() >= wanted
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
