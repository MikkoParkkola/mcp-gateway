// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 Busy parity rows B1-B4: a transient custody Busy at the
//! mint-free view read gives the same wire answer and the same audit
//! records on a live call and on a stored task read by the same caller
//! in the same state, and a signed live call it refuses gives its nonce
//! back. Driven through `/mcp` as the sole operator.

use serde_json::{Value, json};

use super::busy_nonce::{refused_as_replay, signed_fixture, signed_invoke, signed_task_invoke};
use super::{
    BACKEND, Fx, MARKER, PLAIN, TOOL, fixture, modern_meta, register_plain, send, task_get,
};

/// A finished task of the operator's `read`, its output served once.
/// Replicated from the lease rows' helper rather than widening its
/// visibility.
async fn finished_task(fx: &Fx, key: &str) -> String {
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let made = send(
        fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
            "task": {}, "_meta": meta}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = task_get(fx, &id).await;
        if got.to_string().contains(MARKER) {
            return id;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: served once: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// The `idp_refuse` records this fixture's transparency log holds.
fn refusals(fx: &Fx) -> usize {
    refusal_reasons(fx).len()
}

/// The reasons of those records, in order.
fn refusal_reasons(fx: &Fx) -> Vec<String> {
    std::fs::read_to_string(&fx.audit_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["action"] == "idp_refuse")
        .map(|entry| entry["reason"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// A live keyed `gateway_invoke` of the operator's `read`.
async fn live_invoke(fx: &Fx, key: &str) -> Value {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    send(
        fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
            "_meta": meta}),
    )
    .await
}

/// A live call of `read` by its surfaced name.
async fn surfaced_call(fx: &Fx) -> Value {
    send(
        fx,
        "tools/call",
        TOOL,
        json!({"name": TOOL, "arguments": {"folder": "inbox"}, "_meta": modern_meta()}),
    )
    .await
}

fn assert_retryable(reply: &Value, row: &str) {
    assert_eq!(
        reply.pointer("/error/code"),
        Some(&json!(-32603)),
        "{row}: {reply}"
    );
    assert_eq!(
        reply.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "{row}: retryable: {reply}"
    );
    assert!(
        reply.pointer("/error/data/retry_after_ms").is_none(),
        "{row}: no lease runs on this path: {reply}"
    );
    assert!(
        !reply.to_string().contains(MARKER),
        "{row}: output: {reply}"
    );
}

/// B1 twin: with custody busy, the live call and the stored read by the
/// same caller answer the same retryable error and write one `idp_refuse`
/// each; after recovery the stored read serves (U1 kept).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b1_a_busy_custody_answers_the_same_live_and_stored() {
    let fx = fixture().await;
    let id = finished_task(&fx, "s1-b1").await;
    fx.gateway.fail_custody_for_test(true);
    let before_live = refusals(&fx);
    let live = live_invoke(&fx, "s1-b1-live").await;
    assert_retryable(&live, "B1 live");
    assert_eq!(
        refusals(&fx) - before_live,
        1,
        "B1: the live call writes one idp_refuse"
    );
    assert!(
        refusal_reasons(&fx)
            .last()
            .is_some_and(|reason| reason.contains("transient")),
        "B1: the live record's reason names the transience: {:?}",
        refusal_reasons(&fx)
    );
    let before_stored = refusals(&fx);
    let stored = task_get(&fx, &id).await;
    assert_retryable(&stored, "B1 stored");
    assert_eq!(
        refusals(&fx) - before_stored,
        1,
        "B1: the stored read writes one idp_refuse"
    );
    assert!(
        refusal_reasons(&fx)
            .last()
            .is_some_and(|reason| reason.contains("transient")),
        "B1: the stored record's reason names the transience: {:?}",
        refusal_reasons(&fx)
    );
    assert_eq!(
        live.get("error"),
        stored.get("error"),
        "B1: the two error objects are equal, id excluded: live {live} stored {stored}"
    );
    assert_eq!(
        live["error"].to_string(),
        stored["error"].to_string(),
        "B1: the two error objects are byte-equal, id excluded"
    );
    fx.gateway.fail_custody_for_test(false);
    let read = task_get(&fx, &id).await;
    assert!(
        read.to_string().contains(MARKER),
        "B1: served after recovery: {read}"
    );
}

/// B2: a live call in the Busy state reads custody exactly once: the
/// verdict's view read, carried to the dispatch and consumed there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2_a_busy_live_call_reads_custody_once() {
    let fx = fixture().await;
    fx.gateway.fail_custody_for_test(true);
    let before = fx.gateway.resolves();
    let live = live_invoke(&fx, "s1-b2-live").await;
    assert_retryable(&live, "B2");
    assert_eq!(
        fx.gateway.resolves() - before,
        1,
        "B2: no second custody read after the view read"
    );
}

/// B3: a Busy surfaced-name call leaves no `NoView` marker: after custody
/// recovers, the very next live call serves instead of answering absent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b3_a_busy_surfaced_call_leaves_no_no_view_marker() {
    let fx = fixture().await;
    fx.gateway.fail_custody_for_test(true);
    let busy = surfaced_call(&fx).await;
    assert_retryable(&busy, "B3 busy");
    fx.gateway.fail_custody_for_test(false);
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let next = surfaced_call(&fx).await;
    assert_ne!(
        next.pointer("/error/code"),
        Some(&json!(-32601)),
        "B3: the next call is not answered as absent: {next}"
    );
    assert!(
        next.to_string().contains(MARKER),
        "B3: the next call serves after recovery: {next}"
    );
}

/// B4: a signed live call refused by a busy custody reaches no backend,
/// so it gives its nonce back: the same signed request re-sent after
/// custody recovers is served, not refused as a replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b4_a_busy_signed_call_gives_its_nonce_back() {
    let fx = signed_fixture().await;
    fx.gateway.fail_custody_for_test(true);
    let busy = signed_invoke(&fx, "b4-n1").await;
    assert_retryable(&busy, "B4 busy");
    fx.gateway.fail_custody_for_test(false);
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let resent = signed_invoke(&fx, "b4-n1").await;
    assert!(
        !refused_as_replay(&resent),
        "B4: the nonce was kept spent after a busy refusal: {resent}"
    );
    assert!(
        resent.to_string().contains(MARKER),
        "B4: the re-sent call is served after recovery: {resent}"
    );
}

/// B (seat finding 1): a kill-switched (policy-refused) target under a
/// busy custody: the stored read still answers the policy refusal, with
/// no custody read and no `idp_refuse` for the busy account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_a_policy_refused_stored_read_reads_no_custody_and_writes_no_refusal() {
    let fx = fixture().await;
    let id = finished_task(&fx, "s1-b-kill").await;
    fx.state.meta_mcp.kill_switch().kill(BACKEND);
    let control = task_get(&fx, &id).await;
    assert!(
        control.get("error").is_some() && !control.to_string().contains(MARKER),
        "B premise: the kill-switched read is refused: {control}"
    );
    fx.gateway.fail_custody_for_test(true);
    let reads = fx.gateway.resolves();
    let before = refusals(&fx);
    let read = task_get(&fx, &id).await;
    assert_eq!(
        read.get("error"),
        control.get("error"),
        "B: still the policy refusal under busy custody: {read}"
    );
    assert_eq!(
        fx.gateway.resolves() - reads,
        0,
        "B: the pre-pass read custody for a policy-refused target"
    );
    assert_eq!(
        refusals(&fx) - before,
        0,
        "B: the pre-pass wrote an idp_refuse for a policy-refused target"
    );
}

/// The committed tasks this fixture's store holds.
fn committed_tasks(fx: &Fx) -> usize {
    fx.state
        .task_executor
        .service
        .store
        .committed_count_for_test()
}

/// Poll `id`'s stored read until it serves the marker.
async fn served(fx: &Fx, id: &str) {
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = task_get(fx, id).await;
        if got.to_string().contains(MARKER) {
            return;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task completes with its output: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// A task-augmented keyed `gateway_invoke` under a fresh idempotency key.
async fn tasked_invoke(fx: &Fx, key: &str) -> Value {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    send(
        fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
            "task": {}, "_meta": meta}),
    )
    .await
}

/// G1a: the view read succeeds, the acting resolution meets a busy
/// custody at the mint. The verdict's error is carried to the dispatch:
/// two custody reads for the call (view + mint), one `idp_refuse`, and
/// the shared retryable answer (MIK-8428 Case B, fixed by #3892).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g1a_a_mint_time_busy_resolves_once_per_call() {
    let fx = fixture().await;
    // One further read allowed (the view); the mint's read fails busy.
    fx.gateway.fail_custody_after_for_test(1);
    let reads = fx.gateway.resolves();
    let before = refusals(&fx);
    let live = live_invoke(&fx, "s1-g1a-live").await;
    assert!(
        live.get("error").is_some() && !live.to_string().contains(MARKER),
        "G1a premise: the call is refused at its resolution: {live}"
    );
    assert_eq!(
        live.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "G1a: a mint-time busy answers the shared transient (MIK-8428 Case B, fixed by #3892): {live}"
    );
    assert_eq!(
        fx.gateway.resolves() - reads,
        2,
        "G1a: view + mint, never a second resolution"
    );
    assert_eq!(
        refusals(&fx) - before,
        1,
        "G1a: one resolution wrote one idp_refuse"
    );
}

/// G2a + G2b: a task-augmented call whose intake met a busy custody is
/// answered at intake — no task is created — and re-sent after recovery
/// under the same key it is served, not replayed as a stale failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g2_a_tasked_call_meeting_busy_at_intake_creates_no_task() {
    let fx = fixture().await;
    fx.gateway.fail_custody_for_test(true);
    let reads = fx.gateway.resolves();
    let before = refusals(&fx);
    let held = committed_tasks(&fx);
    let busy = tasked_invoke(&fx, "s1-g2").await;
    assert_retryable(&busy, "G2a");
    assert!(
        busy.pointer("/result/taskId").is_none(),
        "G2a: no task was handed back: {busy}"
    );
    assert_eq!(
        committed_tasks(&fx),
        held,
        "G2a: the task store holds no task for the key"
    );
    assert_eq!(refusals(&fx) - before, 1, "G2a: one idp_refuse");
    assert_eq!(
        fx.gateway.resolves() - reads,
        1,
        "G2a: one custody read, at intake"
    );
    fx.gateway.fail_custody_for_test(false);
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let resent = tasked_invoke(&fx, "s1-g2").await;
    let id = resent
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("G2b: the re-sent call makes its task: {resent}"))
        .to_owned();
    served(&fx, &id).await;
}

/// G2m (#3892, gpt F1): a task call whose view reads fine and whose mint at
/// the route stage meets a busy custody is answered at intake as a view Busy
/// is: the shared retryable error, no task, no held key, two custody reads
/// (view + mint) and one transient `idp_refuse`; the same keyed call after
/// recovery makes its task and is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g2_a_tasked_call_meeting_a_mint_busy_creates_no_task() {
    let fx = fixture().await;
    // One further read allowed (the view); the mint's read fails busy.
    fx.gateway.fail_custody_after_for_test(1);
    let reads = fx.gateway.resolves();
    let before = refusals(&fx);
    let held = committed_tasks(&fx);
    let busy = tasked_invoke(&fx, "s1-g2-mint").await;
    assert_retryable(&busy, "G2m");
    assert!(
        busy.pointer("/result/taskId").is_none(),
        "G2m: no task was handed back: {busy}"
    );
    assert_eq!(
        committed_tasks(&fx),
        held,
        "G2m: the task store holds no task for the key"
    );
    assert_eq!(refusals(&fx) - before, 1, "G2m: one idp_refuse");
    assert_eq!(
        fx.gateway.resolves() - reads,
        2,
        "G2m: view + mint, nothing after intake"
    );
    fx.gateway.fail_custody_for_test(false);
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let resent = tasked_invoke(&fx, "s1-g2-mint").await;
    let id = resent
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("G2m: the re-sent call makes its task: {resent}"))
        .to_owned();
    served(&fx, &id).await;
}

/// G2c: as G2, signed: after recovery the same signed request (same
/// nonce, same key) is served, not refused as a replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g2c_a_signed_tasked_call_meeting_busy_gives_its_nonce_back() {
    let fx = signed_fixture().await;
    fx.gateway.fail_custody_for_test(true);
    let busy = signed_task_invoke(&fx, "g2c-n1", "s1-g2c").await;
    assert_retryable(&busy, "G2c busy");
    assert!(
        busy.pointer("/result/taskId").is_none(),
        "G2c: no task was handed back: {busy}"
    );
    fx.gateway.fail_custody_for_test(false);
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let resent = signed_task_invoke(&fx, "g2c-n1", "s1-g2c").await;
    assert!(
        !refused_as_replay(&resent),
        "G2c: the nonce was kept spent after an intake busy refusal: {resent}"
    );
    let id = resent
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("G2c: the re-sent call makes its task: {resent}"))
        .to_owned();
    served(&fx, &id).await;
}

/// A `gateway_invoke` of the plain backend's `echo`.
async fn plain_invoke(fx: &Fx, key: &str) -> Value {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    send(
        fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": PLAIN, "tool": "echo", "arguments": {}},
            "_meta": meta}),
    )
    .await
}

/// M2: after a busy surfaced call and recovery, with no listing in
/// between (so no re-check runs), the invoke predictions reader — which
/// trusts the marker through `shows_name` — still names the tool. This pins
/// the LIVE Busy arm recording no `NoView` marker. It does not cover the
/// listing path: a `tools/list` during Busy still records `NoView` by design
/// (fail-closed), a stated residual (MIK-8392 PR body).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m2_after_a_busy_call_a_reader_without_a_recheck_still_sees_the_tool() {
    let fx = fixture().await;
    register_plain(&fx);
    let tracker = std::sync::Arc::new(crate::transition::TransitionTracker::new());
    for _ in 0..8 {
        tracker.record_transition("teacher", &format!("{PLAIN}:echo"));
        tracker.record_transition("teacher", &format!("{BACKEND}:{TOOL}"));
    }
    fx.state
        .meta_mcp
        .set_transition_tracker(std::sync::Arc::clone(&tracker));
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let warm = live_invoke(&fx, "s1-m2-warm").await;
    assert!(
        warm.to_string().contains(MARKER),
        "M2 premise: the warm call served: {warm}"
    );
    let predicted = format!("{BACKEND}:{TOOL}");
    let control = plain_invoke(&fx, "s1-m2-control").await;
    assert!(
        control.to_string().contains(&predicted),
        "M2 premise: the predictions reader names the tool: {control}"
    );
    fx.gateway.fail_custody_for_test(true);
    let busy = surfaced_call(&fx).await;
    assert_retryable(&busy, "M2 busy");
    fx.gateway.fail_custody_for_test(false);
    let after = plain_invoke(&fx, "s1-m2-after").await;
    assert!(
        after.to_string().contains(&predicted),
        "M2: the tool is stale-hidden from a reader with no re-check: {after}"
    );
}

/// Item 3, descriptor clause: a descriptor-blocked target under a busy
/// custody: the stored read still answers the descriptor refusal, with
/// no custody read and no `idp_refuse` for the busy account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_blocked_stored_read_reads_no_custody_and_writes_no_refusal() {
    let fx = fixture().await;
    let id = finished_task(&fx, "s1-a-desc").await;
    fx.gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .block_tool_for_test(TOOL);
    let control = task_get(&fx, &id).await;
    assert!(
        control.get("error").is_some() && !control.to_string().contains(MARKER),
        "descriptor premise: the blocked read is refused: {control}"
    );
    fx.gateway.fail_custody_for_test(true);
    let reads = fx.gateway.resolves();
    let before = refusals(&fx);
    let read = task_get(&fx, &id).await;
    assert_eq!(
        read.get("error"),
        control.get("error"),
        "descriptor: still the descriptor refusal under busy custody: {read}"
    );
    assert_eq!(
        fx.gateway.resolves() - reads,
        0,
        "descriptor: the pre-pass read custody for a blocked target"
    );
    assert_eq!(
        refusals(&fx) - before,
        0,
        "descriptor: the pre-pass wrote an idp_refuse for a blocked target"
    );
}

/// Item 2 (seat finding 1), the surfaced twin of G1a: the view read
/// succeeds, the mint meets a busy custody, and the route's second
/// verdict is a memo hit on the carried error — two custody reads and
/// one `idp_refuse` for the whole surfaced-name call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f2_a_mint_time_busy_surfaced_call_resolves_once() {
    let fx = fixture().await;
    fx.gateway.fail_custody_after_for_test(1);
    let reads = fx.gateway.resolves();
    let before = refusals(&fx);
    let live = surfaced_call(&fx).await;
    assert!(
        live.get("error").is_some() && !live.to_string().contains(MARKER),
        "F2 premise: the surfaced call is refused at its resolution: {live}"
    );
    assert_eq!(
        live.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "F2: a mint-time busy answers the shared transient (MIK-8428 Case B, fixed by #3892): {live}"
    );
    assert_eq!(
        fx.gateway.resolves() - reads,
        2,
        "F2: view + mint, the second verdict read no custody again"
    );
    assert_eq!(
        refusals(&fx) - before,
        1,
        "F2: one resolution wrote one idp_refuse"
    );
}

/// A task-augmented, keyed single-tool `gateway_execute` of `read` (code
/// mode's single-tool shape: a `tool`, no `chain`).
async fn tasked_execute_single(fx: &Fx, key: &str) -> Value {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    send(
        fx,
        "tools/call",
        "gateway_execute",
        json!({"name": "gateway_execute",
            "arguments": {"tool": format!("{BACKEND}:{TOOL}"), "arguments": {"folder": "inbox"}},
            "task": {}, "_meta": meta}),
    )
    .await
}

/// A single-tool `gateway_execute` task call whose verdict met a busy
/// custody is answered at intake like any other shape: no task, no held
/// key — the same keyed call serves once custody recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g2_a_single_tool_execute_tasked_call_meeting_busy_creates_no_task() {
    let fx = fixture().await;
    fx.gateway.fail_custody_for_test(true);
    let reads = fx.gateway.resolves();
    let before = refusals(&fx);
    let held = committed_tasks(&fx);
    let busy = tasked_execute_single(&fx, "s1-g2-exec").await;
    assert_retryable(&busy, "G2 execute");
    assert!(
        busy.pointer("/result/taskId").is_none(),
        "G2 execute: no task was handed back: {busy}"
    );
    assert_eq!(
        committed_tasks(&fx),
        held,
        "G2 execute: the task store holds no task for the key"
    );
    assert_eq!(refusals(&fx) - before, 1, "G2 execute: one idp_refuse");
    assert_eq!(
        fx.gateway.resolves() - reads,
        1,
        "G2 execute: one custody read, at intake"
    );
    fx.gateway.fail_custody_for_test(false);
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let resent = tasked_execute_single(&fx, "s1-g2-exec").await;
    let id = resent
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("G2 execute: the re-sent call makes its task: {resent}"))
        .to_owned();
    served(&fx, &id).await;
}

#[path = "busy_intake_policy_tests.rs"]
mod intake_policy;

#[path = "busy_resume_tests.rs"]
mod resume;
