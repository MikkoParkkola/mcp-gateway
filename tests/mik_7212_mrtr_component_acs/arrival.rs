// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fixture controls, MRTR.1 and MRTR.2: what reaches the backend and the client.

use super::*;

/// GIVEN the fixture backend, WHEN a fresh call is made, THEN it arrives.
///
/// Not an acceptance criterion — the control that makes MRTR.1 and MRTR.2
/// readable. If this fails, every "the backend received nothing" assertion in
/// this file is measuring the fixture rather than the gateway.
#[tokio::test]
async fn fixture_control_a_fresh_call_reaches_the_backend() {
    let (state, _store_dir) = app_state().await;
    let (url, received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);

    let (_status, response) = post(&state, &fresh_body(1, TOOL, &arguments())).await;

    let calls = received.lock().expect("recorder").clone();
    assert_eq!(
        calls.len(),
        1,
        "a fresh call must reach the fixture backend, it recorded {calls:?}; the gateway answered {response}"
    );
}

/// GIVEN a handle this gateway minted, WHEN it is presented on the retry
/// route, THEN the retry reaches the backend.
///
/// Not an acceptance criterion — the control that makes every "the backend
/// received nothing" assertion in this file mean something. The control above
/// drives `gateway_invoke`, a different route: a retry route that cannot
/// dispatch *at all* satisfies each of those assertions vacuously, and no
/// assertion in the file can tell that apart from a refusal that correctly
/// declined to dispatch. This one can, because it is the only case where the
/// retry route is expected to arrive.
///
/// This was RED until `a69e2bc5` wired the retry route — `handlers.rs` answered
/// every retry with a blanket `-32602` and the recorder never filled. Green is
/// what licenses the rest: while this case fails, every "the backend received
/// nothing" assertion in the file is vacuous rather than evidence, so a
/// regression here silently empties the others of meaning.
#[tokio::test]
async fn fixture_control_a_valid_retry_reaches_the_backend() {
    let (state, received, _store_dir) = state_with_fixture().await;
    let args = arguments();
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &args).await;

    let (_status, response) = post(&state, &retry_body(1, TOOL_INTERIM, &args, &handle)).await;

    let calls = received.lock().expect("recorder").clone();
    assert_eq!(
        calls.len(),
        1,
        "a retry the gateway itself minted, presented unaltered, must reach the \
         fixture backend; it recorded {calls:?} and the gateway answered {response}"
    );
}

// ---------------------------------------------------------------------------
// MRTR.1 — a retry carries its continuation fields to the backend
// ---------------------------------------------------------------------------

/// A retry routed the way `fresh_body` routes, with the continuation fields
/// as siblings of `name` — where the specification puts them, and where
/// `RetryFields::from_params` reads them (`src/protocol/mrtr.rs:99-111`).
fn retry_via_invoke(
    id: u64,
    tool: &str,
    args: &Value,
    handle: Option<&str>,
    responses: Option<Value>,
) -> Value {
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), json!("gateway_invoke"));
    params.insert(
        "arguments".to_string(),
        json!({ "server": BACKEND, "tool": tool, "arguments": args }),
    );
    if let Some(handle) = handle {
        params.insert("requestState".to_string(), json!(handle));
    }
    if let Some(responses) = responses {
        params.insert("inputResponses".to_string(), responses);
    }
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params })
}

/// GIVEN a minted handle, WHEN a retry presents it with or without answers, THEN
/// the backend receives the continuation it sealed and nothing client-authored.
/// Answers WITHOUT the handle are refused -32602 over this same HTTP hop and never
/// reach the backend: MRTR client rule 2 makes the client echo the requestState
/// this gateway always sends (MIK-7325.RETRY.1). The fourth shape, neither field,
/// is the fresh call (`fixture_control_a_fresh_call_reaches_the_backend`).
/// `requestState` must be the backend's own sealed state, not the handle presented:
/// echoing the client's envelope would hand a server a value it never issued
/// (`src/protocol/continuation.rs:71`).
#[tokio::test]
async fn ac_mrtr_1_a_retry_reaches_the_backend_carrying_what_it_continued() {
    let answers = json!({ "city": "Helsinki" });
    let cases: [(&str, bool, Option<Value>); 3] = [
        ("both fields", true, Some(answers.clone())),
        ("responses only", false, Some(answers.clone())),
        ("state only", true, None),
    ];

    for (index, (case, with_state, responses)) in cases.into_iter().enumerate() {
        let (state, _store_dir) = app_state().await;
        let (url, received) = spawn_fixture_backend().await;
        register_fixture_backend(&state, &url);
        let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &arguments()).await;

        let body = retry_via_invoke(
            index as u64 + 1,
            TOOL_INTERIM,
            &arguments(),
            with_state.then_some(handle.as_str()),
            responses.clone(),
        );
        let (_status, response) = post(&state, &body).await;

        let calls = received.lock().expect("recorder").clone();
        if !with_state {
            let code = response.pointer("/error/code").and_then(Value::as_i64);
            assert_eq!(code, Some(-32602), "{case}: must be refused: {response}");
            assert!(calls.is_empty(), "{case}: reached the backend: {calls:?}");
            continue;
        }
        let why = format!("{case}: the retry must reach the backend; gateway answered {response}");
        assert_eq!(calls.len(), 1, "{why}, it recorded {calls:?}");
        let arrived = &calls[0];
        assert_eq!(
            arrived.get("requestState").and_then(Value::as_str),
            with_state.then_some(SEALED_STATE),
            "{case}: the backend must receive the state it issued, not the client's handle"
        );
        assert_eq!(
            arrived.get("inputResponses"),
            responses.as_ref(),
            "{case}: the answers must arrive verbatim, under the keys the server asked with"
        );
    }
}

// ---------------------------------------------------------------------------
// MRTR.2 — the backend's own state never reaches the client
// ---------------------------------------------------------------------------

/// GIVEN a backend that answers with a `requestState` of its own, WHEN the
/// interim result travels back, THEN the client is handed a handle the gateway
/// minted and the backend's string appears nowhere on the wire.
///
/// The negative alone is not enough: a gateway that dropped the field entirely
/// would satisfy it while leaving the exchange unresumable. So the same case
/// carries the positive — some value in the response opens under the gateway's
/// own keyring, and what it seals is the backend's state.
///
/// STOP, and why the red here is not the red MRTR.2 is about. The case fails on
/// the positive, with `-32003 … cannot be continued for this caller`: nothing
/// is minted because `principal_fingerprint` is `None` for an API-key-only
/// caller (`src/protocol/mrtr.rs:357-365`), and what the gateway should use as
/// that principal is undecided in the code, not merely unwired. So today the
/// negative passes for the wrong reason — a refusal relays nothing, which is
/// vacuously not-a-passthrough. The row is written anyway, is red, and must be
/// re-read once the principal question is answered: only then does its negative
/// half start discriminating a correct gateway from a silent one.
#[tokio::test]
async fn ac_mrtr_2_the_backends_own_state_is_never_relayed_to_the_client() {
    let (state, _store_dir) = app_state().await;
    let (url, _received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);

    let (_status, response) = post(&state, &fresh_body(1, TOOL_INTERIM, &arguments())).await;

    let wire = serde_json::to_string(&response).expect("the response must serialise");
    assert!(
        !wire.contains(SEALED_STATE),
        "the backend's own state must not reach the client, it was relayed in {wire}"
    );

    let handle = handle_the_client_received(&state, &response).unwrap_or_else(|| {
        panic!("the client must receive a handle the gateway minted; it received {wire}")
    });
    let payload = state
        .continuation
        .keyring()
        .open(&handle, now_secs())
        .expect("the handle just opened, so it opens again");
    assert_eq!(
        payload.backend_request_state.as_deref(),
        Some(SEALED_STATE),
        "the handle must seal the backend's state, or the exchange cannot be resumed"
    );
}
