// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A refused nonce on `/mcp` under each audit configuration: counted once
//! like any refused call; with a failing log, answered 503 when the log
//! fails closed and as before when it is best-effort; with no log, answered
//! as before. Its delivery record joins its invocation record, and a nonce
//! refused once stays refused.

use super::counting::{attach, meta_invoke, totals};
use super::signing_records::signed;
use super::*;
use crate::security::metrics_scrape::{ONE_DENIAL, meta_denials, scrape_if_enabled};

/// `[calls, blocks, errors, firewall refusals, cache hits]` after one
/// delivered call and one refused replay.
const ONE_SERVED_ONE_REFUSED: [u64; 5] = [2, 1, 0, 0, 0];

/// A hardened, signing gateway whose log is `log`, failing closed when
/// `fail_closed`.
async fn signing_gateway(log: Log, fail_closed: bool) -> Fixture {
    let setup = Setup {
        extras: &[Extra::Signing, Extra::Hardened],
        log,
        fail_closed,
        ..Setup::default()
    };
    fixture(setup).await
}

/// One `/mcp` `gateway_invoke` of alpha's `t` signed with `nonce`.
async fn send_signed(fx: &Fixture, id: u64, nonce: &str) -> (StatusCode, Value) {
    let invoke = meta_invoke("alpha", "t", &json!({}));
    let request = signed(&invoke, id, &json!(nonce));
    post_to(fx, "/mcp", &request, &Caller::ModernOidc).await
}

/// The replay's answer as it has always been: 400, -32001.
fn assert_replay_answer(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32001, "{body}");
    assert_eq!(body["error"]["message"], "Nonce replay detected", "{body}");
}

/// T1 counts: the delivered call and the refused replay each move the
/// counters once; the replay as a block, and once in D4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t1_counts_a_refused_replay_once_as_a_block() {
    let fx = signing_gateway(Log::On, false).await;
    let store = attach(&fx);
    let (_, first) = send_signed(&fx, 1, "count-nonce").await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    let ((status, second), text) = scrape_if_enabled(send_signed(&fx, 2, "count-nonce"));
    assert_replay_answer(status, &second);
    let d4 = meta_denials(text.as_deref(), "gateway_refusal");
    assert_eq!((totals(&store), d4), (ONE_SERVED_ONE_REFUSED, ONE_DENIAL));
}

/// F1: the log fails closed and its append fails: the refused replay is
/// answered 503 with the log's unavailability code, never as an unrecorded
/// refusal; it is still counted once.
#[tokio::test]
async fn f1_a_failed_refusal_write_answers_503_when_the_log_fails_closed() {
    let fx = signing_gateway(Log::On, true).await;
    let store = attach(&fx);
    let (_, first) = send_signed(&fx, 1, "closed-nonce").await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    fx.log.set_append_failure_for_test(true);
    let (status, second) = send_signed(&fx, 2, "closed-nonce").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{second}");
    assert_eq!(second["error"]["code"], -32005, "{second}");
    assert_eq!(totals(&store), ONE_SERVED_ONE_REFUSED);
}

/// F1n: F1 for a request with no id at all, refused at the early nonce site.
/// A signing refusal fails closed whatever its id: 503 and the log's
/// unavailability code, still with no id, never the nonce refusal it could
/// not record.
#[tokio::test]
async fn f1n_an_id_less_unrecordable_signing_refusal_answers_503() {
    let fx = signing_gateway(Log::On, true).await;
    fx.log.set_append_failure_for_test(true);
    let invoke = meta_invoke("alpha", "t", &json!({}));
    let mut no_id: Value =
        serde_json::from_str(&signed(&invoke, 3, &json!(7))).expect("the request parses");
    if let Some(call) = no_id.as_object_mut() {
        call.remove("id");
    }
    let (status, body) = post_to(&fx, "/mcp", &no_id.to_string(), &Caller::ModernOidc).await;
    assert_eq!(
        (status, body["error"]["code"].as_i64(), body["id"].is_null()),
        (StatusCode::SERVICE_UNAVAILABLE, Some(-32005), true),
        "{body}"
    );
}

/// B1: the log is best-effort and its append fails: the refused replay is
/// answered as before and counted once, on the counters and in D4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b1_a_failed_refusal_write_keeps_the_answer_when_best_effort() {
    let fx = signing_gateway(Log::On, false).await;
    let store = attach(&fx);
    let (_, first) = send_signed(&fx, 1, "effort-nonce").await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    fx.log.set_append_failure_for_test(true);
    let ((status, second), text) = scrape_if_enabled(send_signed(&fx, 2, "effort-nonce"));
    assert_replay_answer(status, &second);
    let d4 = meta_denials(text.as_deref(), "gateway_refusal");
    assert_eq!((totals(&store), d4), (ONE_SERVED_ONE_REFUSED, ONE_DENIAL));
}

/// L1: no transparency log at all: answered as before, counted once, on the
/// counters and in D4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l1_with_no_log_a_refused_replay_is_answered_and_counted() {
    let fx = signing_gateway(Log::Off, false).await;
    let store = attach(&fx);
    let (_, first) = send_signed(&fx, 1, "nolog-nonce").await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    let ((status, second), text) = scrape_if_enabled(send_signed(&fx, 2, "nolog-nonce"));
    assert_replay_answer(status, &second);
    let d4 = meta_denials(text.as_deref(), "gateway_refusal");
    assert_eq!((totals(&store), d4), (ONE_SERVED_ONE_REFUSED, ONE_DENIAL));
}

/// N1: recording a refusal gives nothing back: the same nonce a third time
/// is refused again, and each refusal has its own record and trace.
#[tokio::test]
async fn n1_a_recorded_replay_never_frees_its_nonce() {
    let fx = signing_gateway(Log::On, false).await;
    let (_, first) = send_signed(&fx, 1, "held-nonce").await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    for id in [2, 3] {
        let (status, body) = send_signed(&fx, id, "held-nonce").await;
        assert_replay_answer(status, &body);
    }
    let all = invocations(&fx);
    assert_eq!(all.len(), 3, "the delivery and two refusals: {all:?}");
    let (second, third) = (&all[1]["trace_id"], &all[2]["trace_id"]);
    assert!(second.is_string() && second != third, "{all:?}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "only the first was sent"
    );
}

/// W1: the refused replay's delivery record carries the trace of its
/// invocation record, so the receipt joins them.
#[tokio::test]
async fn w1_a_refused_replay_delivery_joins_its_record() {
    let fx = signing_gateway(Log::On, false).await;
    let (_, first) = send_signed(&fx, 1, "joined-nonce").await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    let (status, second) = send_signed(&fx, 2, "joined-nonce").await;
    assert_replay_answer(status, &second);
    let all = invocations(&fx);
    let refusal = all.last().expect("the refusal's record");
    let delivered: Vec<Value> = std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect();
    let last = delivered.last().expect("the refusal's delivery record");
    assert_eq!(last["trace_id"], refusal["trace_id"], "{last} / {refusal}");
}
