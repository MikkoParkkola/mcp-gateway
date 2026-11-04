// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A destructive task call refused because the gateway cannot name its
//! caller is a decision about that caller, so its delivery record says
//! `refused`. The other confirmation answers keep
//! the records they had.
//!
//! Only HTTP reaches this answer. A stdio caller always carries its session
//! nonce, which gives it both a principal (`PrincipalSource::Stdio`) and a
//! quota key (`QuotaSource::Stdio`), so the gate can always name it.
use super::*;
use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};

/// POST `body` with no credential at all, returning the body.
async fn anonymous_post(state: &Arc<AppState>, body: &Value) -> Value {
    let response = create_router(Arc::clone(state))
        .oneshot(http_request(None, body))
        .await
        .expect("the router must answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must read");
    serde_json::from_slice(&bytes).expect("the body is JSON")
}

/// The one delivery record `log` gained since it held `before` rows.
async fn the_new_row(log: &crate::security::TransparencyLogger, before: usize) -> Value {
    let rows = delivery_rows(log).await;
    std::assert_eq!(
        rows.len(),
        before + 1,
        "one call, one delivery record: {rows:?}"
    );
    rows.last().cloned().expect("a delivery record")
}

/// UNBIND.1/2: the unbindable answer is recorded as refused, and nothing
/// reaches the backend.
#[tokio::test]
async fn an_unbindable_destructive_call_is_recorded_as_refused() {
    let (_dir, log) = temp_log(None);
    let (mock, _gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = anonymous_fixture(&mock, Arc::clone(&log)).await;
    let before = delivery_rows(&log).await.len();
    let answer = anonymous_post(&state, &request("unbindable")).await;
    std::assert_eq!(
        answer.pointer("/error/code"),
        Some(&json!(-32003)),
        "premise: the gate answers unbindable_caller: {answer}"
    );
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("cannot name")),
        "premise: the unbindable_caller wording: {answer}"
    );
    std::assert_eq!(mock.calls(), 0, "premise: nothing dispatched");
    let row = the_new_row(&log, before).await;
    std::assert_eq!(row["response_effect"], "refused", "{row}");
}

/// UNBIND.2 control: a caller the gate can name is asked, and the question is
/// not a refusal.
#[tokio::test]
async fn a_named_callers_confirmation_question_is_not_recorded_as_refused() {
    let (_dir, log) = temp_log(None);
    let (mock, _gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = fixture_with(&mock, crate::config::Config::default(), |meta| {
        meta.enable_transparency_log(Arc::clone(&log));
    })
    .await;
    let before = delivery_rows(&log).await.len();
    let challenge = post(&state, "key-a", request("named")).await;
    std::assert_eq!(
        challenge.pointer("/result/resultType"),
        Some(&json!("input_required")),
        "premise: a named caller is asked: {challenge}"
    );
    let row = the_new_row(&log, before).await;
    std::assert_ne!(row["response_effect"], "refused", "{row}");
}

/// UNBIND.2 control: `no_grant` (answers with no confirmation grant) is a
/// client-protocol rejection, classed not-a-decision, and keeps its record.
#[tokio::test]
async fn a_no_grant_answer_is_not_recorded_as_refused() {
    let (_dir, log) = temp_log(None);
    let (mock, _gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = fixture_with(&mock, crate::config::Config::default(), |meta| {
        meta.enable_transparency_log(Arc::clone(&log));
    })
    .await;
    let original = request("no-grant");
    let challenge = post(&state, "key-a", original.clone()).await;
    let mut answers_only = retry(&original, &challenge, "accept");
    answers_only["params"]
        .as_object_mut()
        .expect("params")
        .remove("requestState");
    let before = delivery_rows(&log).await.len();
    let answer = post(&state, "key-a", answers_only).await;
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("no confirmation grant")),
        "premise: the no_grant answer: {answer}"
    );
    let row = the_new_row(&log, before).await;
    std::assert_ne!(row["response_effect"], "refused", "{row}");
}
