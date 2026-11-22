// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the skipped-claim absorb behind `Refusing::read_task`: a stored
//! read that skipped its claim (custody busy on a slow runner) is read again,
//! a bounded number of times, and nothing else ever is. T5-T7 drive the
//! absorb with scripted answers on paused time; T1 and T4 run end to end.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{
    REFUSAL, SKIPS_ABSORBED, absorb_skips, assert_refusal, assert_retryable, refusing, skipped,
};

/// What a stored read answers when it skipped its claim.
fn skip_answer() -> Value {
    let data = json!({"retryable": true});
    json!({"error": {"code": -32603, "data": data, "message": "temporarily unavailable, retry"}})
}

/// The lender's refusal, as the live routes give it.
fn refusal_answer() -> Value {
    let data = json!({"gateway_http_status": 403});
    json!({"error": {"code": -32001, "data": data, "message": format!("refused: {REFUSAL}")}})
}

/// `answers` handed to the absorb one per attempt; the lender's refusal count
/// moves during attempt `i` when `moved[i]` is true. Returns the absorb's
/// answer and how many attempts it made.
async fn scripted(answers: Vec<Value>, moved: Vec<bool>) -> (Value, usize) {
    let next = AtomicUsize::new(0);
    let refusals = AtomicUsize::new(0);
    let attempt = || {
        let i = next.fetch_add(1, Ordering::SeqCst);
        if moved.get(i).copied().unwrap_or(false) {
            refusals.fetch_add(1, Ordering::SeqCst);
        }
        let answer = answers.get(i).cloned();
        async move { answer.expect("an answer is scripted for every attempt") }
    };
    absorb_skips(attempt, || refusals.load(Ordering::SeqCst), || 0).await
}

/// T5: two skipped answers, then the refusal: returned after 3 attempts.
#[tokio::test(start_paused = true)]
async fn two_skipped_answers_then_a_refusal_take_three_attempts() {
    let answers = vec![skip_answer(), skip_answer(), refusal_answer()];
    let (answer, attempts) = scripted(answers, Vec::new()).await;
    assert_eq!((answer, attempts), (refusal_answer(), 3));
}

/// T6: three skipped answers, the most absorbed, then the refusal: returned
/// after 4 attempts, the bound.
#[tokio::test(start_paused = true)]
async fn three_skipped_answers_then_a_refusal_take_four_attempts() {
    assert_eq!(SKIPS_ABSORBED, 3, "premise");
    let mut answers = vec![skip_answer(); 3];
    answers.push(refusal_answer());
    let (answer, attempts) = scripted(answers, Vec::new()).await;
    assert_eq!((answer, attempts), (refusal_answer(), 4));
}

/// T7: every answer a row judges, and each near miss of the skipped shape,
/// is returned after exactly one attempt.
#[tokio::test(start_paused = true)]
async fn every_other_answer_is_returned_at_its_first_attempt() {
    let lease =
        json!({"error": {"code": -32603, "data": {"retryable": true, "retry_after_ms": 60_000}}});
    let near_misses = [
        json!({"error": {"code": -32603, "data": {}}}),
        json!({"error": {"code": -32603, "data": {"retryable": false}}}),
        json!({"error": {"code": -32000, "data": {"retryable": true}}}),
        json!({"error": {"code": -32603, "data": {"retryable": true}, "message": REFUSAL}}),
    ];
    let mut answers = vec![
        refusal_answer(),
        lease,
        json!({"result": {"status": "completed"}}),
        json!({"error": {"code": -32602, "message": "invalid params"}}),
    ];
    answers.extend(near_misses);
    for answer in answers {
        assert!(
            !skipped(&answer),
            "premise: {answer} is not the skipped shape"
        );
        let (got, attempts) = scripted(vec![answer.clone()], Vec::new()).await;
        assert_eq!((got, attempts), (answer, 1));
    }
}

/// T7b: a skipped answer from an attempt whose fill the lender refused is the
/// regression R1 exists for, and is returned at once, never read again.
/// Red against an absorb that ignores the refusal count.
#[tokio::test(start_paused = true)]
async fn a_skipped_answer_with_a_refused_fill_is_returned_at_once() {
    let (answer, attempts) = scripted(vec![skip_answer()], vec![true]).await;
    assert_eq!((answer, attempts), (skip_answer(), 1));
}

/// T1: the settled read's account outcome is left unfilled for exactly one
/// attempt (the seam is set, and the fixture clears it after the first
/// skipped answer). R1's guarantees then hold end to end: the read answers
/// the lender's refusal and its own fill reached the lender. Red with
/// `read_task` reading once: the skipped answer reaches R1's assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_settled_read_that_skipped_its_claim_once_is_read_again() {
    let gw = refusing().await;
    let id = gw.create_task().await;
    gw.await_refusals(2).await;
    let unfilled_before = gw.backend.unfilled_outcome_reads.load(Ordering::SeqCst);
    gw.backend
        .skip_account_prepass
        .store(true, Ordering::SeqCst);
    gw.clear_skip_after_one.store(true, Ordering::SeqCst);
    let settled = gw.settled_read(&id).await;
    assert!(
        !gw.clear_skip_after_one.load(Ordering::SeqCst),
        "premise: one attempt answered the skipped claim"
    );
    // Which judgement answered the skipped shape (an unfilled outcome bumps
    // this count; a busy custody answers the same shape without it) is for
    // the log only: the row is about the read again, not the cause.
    eprintln!(
        "T1 unfilled outcome reads: {unfilled_before} -> {}",
        gw.backend.unfilled_outcome_reads.load(Ordering::SeqCst)
    );
    assert_refusal(&settled.answer, "T1");
    assert_eq!(
        settled.refusals_after,
        settled.refusals_before + 1,
        "T1: the read's own fill reached the lender: {}",
        settled.answer
    );
}

/// T4: an account that never confirms live (the seam stays set) fails the
/// read loudly at the bound, after about 60 ms of waits. The row's limit is
/// the 120 s hang guard (the flaky-under-load family: shorter real-time waits
/// failed under a loaded runner); real sockets keep it off a paused clock.
/// An absorb with no bound never returns at all, so only the bound ends it.
/// Red against an absorb with no bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_that_never_claims_fails_loudly_at_the_bound() {
    let gw = Arc::new(refusing().await);
    let id = gw.create_task().await;
    gw.await_refusals(2).await;
    gw.backend
        .skip_account_prepass
        .store(true, Ordering::SeqCst);
    let read = {
        let gw = Arc::clone(&gw);
        tokio::spawn(async move { gw.settled_read(&id).await })
    };
    let ended = tokio::time::timeout(Duration::from_secs(120), read).await;
    let joined = ended.expect("the read ends at its bound");
    let Err(failure) = joined else {
        panic!("the read answered instead of failing at the bound");
    };
    assert!(failure.is_panic(), "{failure}");
    let payload = failure.into_panic();
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        message.contains("4 skipped-claim answers in a row"),
        "the failure names the count: {message}"
    );
}

/// An answer helper a row judges with: it panics on an answer it rejects.
type AnswerCheck = fn(&Value, &str);

/// T8 (a): the answer helpers the rows judge with both reject the skipped
/// shape, so a row can never pass on an answer the absorb would hide.
#[test]
fn the_answer_helpers_reject_the_skipped_shape() {
    assert!(skipped(&skip_answer()), "premise: the skipped shape");
    let helpers: [(&str, AnswerCheck); 2] = [
        ("assert_refusal", assert_refusal),
        ("assert_retryable", assert_retryable),
    ];
    for (name, helper) in helpers {
        let caught = std::panic::catch_unwind(|| helper(&skip_answer(), "T8"));
        assert!(caught.is_err(), "{name} accepted the skipped-claim answer");
    }
}

/// T8 (b): the rows' file judges an error code in exactly three places: the
/// two helpers T8 (a) covers, by `["error"]["code"]`, and `skipped`, by
/// `.pointer("/error/code")`. A new row that judges a code itself raises a
/// count: route it through a listed helper, or add its helper to T8 (a).
/// Limit: a new helper spelled some third way escapes this pin.
#[test]
fn every_error_code_check_goes_through_a_listed_helper() {
    let source = include_str!("task_read.rs");
    let indexed = source.matches(r#"["error"]["code"]"#).count();
    let pointed = source.matches(r#""/error/code""#).count();
    assert_eq!(
        (indexed, pointed),
        (2, 1),
        "an error code judged outside assert_refusal, assert_retryable and skipped"
    );
}
