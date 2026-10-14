// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 Busy parity rows B1-B4: a transient custody Busy at the
//! mint-free view read gives the same wire answer and the same audit
//! records on a live call and on a stored task read by the same caller
//! in the same state, and a signed live call it refuses gives its nonce
//! back. Driven through `/mcp` as the sole operator.

use serde_json::{Value, json};

use super::busy_nonce::{refused_as_replay, signed_fixture, signed_invoke};
use super::{BACKEND, Fx, MARKER, TOOL, fixture, modern_meta, send, task_get};

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
    std::fs::read_to_string(&fx.audit_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["action"] == "idp_refuse")
        .count()
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
    let before_stored = refusals(&fx);
    let stored = task_get(&fx, &id).await;
    assert_retryable(&stored, "B1 stored");
    assert_eq!(
        refusals(&fx) - before_stored,
        1,
        "B1: the stored read writes one idp_refuse"
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
