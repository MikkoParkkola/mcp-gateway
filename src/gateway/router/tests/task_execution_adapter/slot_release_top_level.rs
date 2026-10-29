// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8297: the 4.0 contract for a dropped top-level question on `/mcp` (operator ruling 2026-10-21): a same-key retry is refused 409, a fresh key recovers.
use super::super::*;
use super::input_round::*;
use super::slot_release_tasks::settles_at;
use super::support::*;

/// A keyed top-level `gateway_invoke` call answered over SSE and dropped unread, with its retry body.
async fn dropped_top_level_question(
    key: &str,
) -> (
    Arc<MockBackend>,
    Arc<AppState>,
    crate::gateway::router::tests::FixtureDir,
    Value,
) {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, dir) = state_with(&mock).await;
    let body = keyed(
        declaring_elicitation(modern(
            1,
            "tools/call",
            json!({ "name": "gateway_invoke", "arguments": { "server": BACKEND, "tool": TOOL, "arguments": {} } }),
            true,
        )),
        key,
    );
    let mut request = http_request(Some("key-a"), &body);
    request.headers_mut().insert(
        axum::http::header::ACCEPT,
        axum::http::HeaderValue::from_static("application/json, text/event-stream"),
    );
    let response = create_router(Arc::clone(&state))
        .oneshot(request)
        .await
        .expect("the router must answer");
    std::assert_eq!(response.status(), StatusCode::OK);
    std::assert_eq!(
        mock.calls(),
        1,
        "precondition: the backend received the call"
    );
    std::assert_eq!(
        settles_at(&state, 1).await,
        1,
        "precondition: the question was minted and holds its slot"
    );
    // The client goes away: the SSE body is never read.
    drop(response);
    settle_quiet().await;
    (mock, state, dir, body)
}

/// MIK-8297.FREEZE.2 (the 4.0 contract, operator ruling 2026-10-21): a top-level question (`gateway_invoke`) whose answer is dropped is not retained, so a same-key retry is refused 409 "Secured execution result is unavailable" and the backend is not called again; a question nested in a playbook output is replayed instead (C1 above). Goes red if admission ever retains a top-level question (MIK-8622 changes this in 4.1.0).
#[tokio::test]
async fn c1_mcp_a_dropped_top_level_question_is_not_replayed_under_its_key() {
    let (mock, state, _dir, body) = dropped_top_level_question("c1-mcp-dropped-top-level").await;
    let replay = post(&state, "key-a", body).await;
    std::assert_eq!(
        replay["error"]["code"],
        json!(409),
        "a same-key retry of a dropped top-level question is refused: {replay}"
    );
    std::assert!(
        replay.to_string().contains("unavailable"),
        "the refusal is Unavailable: {replay}"
    );
    std::assert_eq!(
        mock.calls(),
        1,
        "the retry did not reach the backend: {replay}"
    );
    std::assert_eq!(
        settles_at(&state, 0).await,
        0,
        "the dropped question's slot is released, not held by the store"
    );
    // A fresh key recovers: it is not refused, and the backend runs again (the mock's second answer is `done()`).
    let fresh_body = keyed(
        declaring_elicitation(modern(
            2,
            "tools/call",
            json!({ "name": "gateway_invoke", "arguments": { "server": BACKEND, "tool": TOOL, "arguments": {} } }),
            true,
        )),
        "c1-mcp-fresh-key",
    );
    let fresh = post(&state, "key-a", fresh_body).await;
    std::assert!(
        fresh.get("error").is_none(),
        "a fresh key is not refused: {fresh}"
    );
    std::assert_eq!(
        mock.calls(),
        2,
        "the fresh key ran the backend call again: {fresh}"
    );
}
