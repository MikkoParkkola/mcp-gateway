// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An input-required round keeps its idempotency key reserved for its
//! continuation: while the client has not answered, a same-key call is
//! answered "in progress"; the continuation with the minted `requestState`
//! claims the key and runs. Meta route, on the parent's scripted backend.

use super::*;
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::mrtr::RetryFields;

const IN_PROGRESS: &str = "Duplicate request in progress";

fn alice() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@example.invalid".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example.invalid".to_string(),
    }
}

/// The parent's key with no continuation fields.
fn fresh() -> RetryFields {
    keyed(KEY)
}

fn keyed(key: &str) -> RetryFields {
    RetryFields {
        idempotency_key: Some(key.to_owned()),
        ..Default::default()
    }
}

/// `key`'s continuation of `state`, answering `q1` with `action`.
fn answer(key: &str, state: &Value, action: &str) -> RetryFields {
    RetryFields {
        idempotency_key: Some(key.to_owned()),
        request_state: state.as_str().map(str::to_owned),
        input_responses: Some(json!({"q1": {"action": action, "content": {"ok": true}}})),
        ..Default::default()
    }
}

/// One call of `svc:act` from a modern client that declared form elicitation,
/// as `who` (a verified caller a continuation can be bound to) or anonymous.
async fn modern(
    meta: &MetaMcp,
    client: &Client,
    retry: &RetryFields,
    who: Option<&VerifiedIdentity>,
) -> crate::Result<Value> {
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}}
        }})),
        None,
    )
    .declared_capabilities();
    let context = MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        authentication: if who.is_some() {
            crate::gateway::meta_mcp::Authentication::Authenticated
        } else {
            crate::gateway::meta_mcp::Authentication::Anonymous
        },
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: true,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: who,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: declared,
        retry,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Modern,
        channel: client,
    };
    let args = json!({"server": "svc", "tool": "act", "arguments": {}});
    meta.invoke_tool(&args, Some("session-1962"), &context)
        .await
}

fn interim_with(state: &str) -> Value {
    let mut round = interim();
    round["requestState"] = json!(state);
    round
}

/// Round 1 as alice: relayed as input required, one tools/call.
async fn asked(meta: &MetaMcp, client: &Client, wire: &Scripted) -> Value {
    let first = modern(meta, client, &fresh(), Some(&alice()))
        .await
        .expect("round 1 is answered");
    assert_eq!(
        first.get("resultType"),
        Some(&json!("input_required")),
        "premise: round 1 is relayed as input required: {first}"
    );
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        1,
        "premise: one tools/call"
    );
    first
}

fn in_progress(outcome: &crate::Result<Value>) -> bool {
    matches!(outcome, Err(e) if e.to_string().contains(IN_PROGRESS))
}

fn may_have_run(outcome: &crate::Result<Value>) -> bool {
    let text = match outcome {
        Ok(value) => value.to_string(),
        Err(e) => e.to_string(),
    };
    text.contains("it may have executed")
}

/// P1 (fail-fast): during the wait, a fresh same-key call is answered in
/// progress and does not run the tool.
#[tokio::test]
async fn p1_a_same_key_call_during_the_wait_is_in_progress() {
    let (meta, wire) = gateway(vec![Step::Answer(interim()), Step::Answer(done())]);
    let client = answering();
    asked(&meta, &client, &wire).await;
    let fresh_call = modern(&meta, &client, &fresh(), Some(&alice())).await;
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        1,
        "a fresh same-key call during the wait ran the tool again: {fresh_call:?}"
    );
    assert!(
        in_progress(&fresh_call),
        "not the in-progress answer: {fresh_call:?}"
    );
}

/// P2 (control): the continuation with the minted `requestState` runs and
/// completes; a later replay of it is served its stored answer.
#[tokio::test]
async fn p2_the_continuation_runs_and_its_replay_is_stored() {
    let (meta, wire) = gateway(vec![Step::Answer(interim()), Step::Answer(done())]);
    let client = answering();
    let first = asked(&meta, &client, &wire).await;
    let resume = answer(KEY, &first["requestState"], "accept");
    let resumed = modern(&meta, &client, &resume, Some(&alice()))
        .await
        .expect("the continuation completes");
    assert_eq!(
        resumed["content"],
        done()["content"],
        "the continuation's answer"
    );
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        2,
        "round 1 + the continuation"
    );
    let replay = modern(&meta, &client, &resume, Some(&alice())).await;
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        2,
        "the replay ran: {replay:?}"
    );
    assert_eq!(
        replay.ok().map(|value| value["content"].clone()),
        Some(done()["content"].clone()),
        "the replay's stored answer"
    );
}

/// P3: a same-key call carrying another exchange's valid envelope, or a
/// garbage one, is not admitted: in progress, count unchanged.
#[tokio::test]
async fn p3_another_exchanges_envelope_or_garbage_is_not_admitted() {
    let (meta, wire) = gateway(vec![
        Step::Answer(interim()),
        Step::Answer(interim_with("backend-state-other")),
        Step::Answer(done()),
    ]);
    let client = answering();
    asked(&meta, &client, &wire).await;
    let other = modern(&meta, &client, &keyed("k-other"), Some(&alice()))
        .await
        .expect("the other exchange asks too");
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        2,
        "premise: two rounds sent"
    );
    for state in [other["requestState"].clone(), json!("not-an-envelope")] {
        let outcome = modern(
            &meta,
            &client,
            &answer(KEY, &state, "accept"),
            Some(&alice()),
        )
        .await;
        assert_eq!(
            wire.calls.load(Ordering::SeqCst),
            2,
            "a continuation not minted for this key's round ran: {outcome:?}"
        );
        assert!(
            in_progress(&outcome),
            "{state}: not in progress: {outcome:?}"
        );
    }
}

/// P5: round 2 asks again. It is parked under round 2's envelope: a fresh
/// same-key call is in progress, and round 1's envelope replayed is not
/// admitted. P5b (control): round 2's envelope continues and completes.
#[tokio::test]
async fn p5_a_round_that_asks_again_is_parked_under_its_own_envelope() {
    let (meta, wire) = gateway(vec![
        Step::Answer(interim()),
        Step::Answer(interim_with("backend-state-round-2")),
        Step::Answer(done()),
    ]);
    let client = answering();
    let first = asked(&meta, &client, &wire).await;
    let round_1 = first["requestState"].clone();
    let second = modern(
        &meta,
        &client,
        &answer(KEY, &round_1, "accept"),
        Some(&alice()),
    )
    .await
    .expect("round 2 asks again");
    assert_eq!(
        second.get("resultType"),
        Some(&json!("input_required")),
        "{second}"
    );
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        2,
        "premise: two rounds sent"
    );
    let fresh_call = modern(&meta, &client, &fresh(), Some(&alice())).await;
    assert!(
        in_progress(&fresh_call),
        "round 2 is not parked: {fresh_call:?}"
    );
    let stale = modern(
        &meta,
        &client,
        &answer(KEY, &round_1, "decline"),
        Some(&alice()),
    )
    .await;
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        2,
        "round 1's envelope ran: {stale:?}"
    );
    let done_now = modern(
        &meta,
        &client,
        &answer(KEY, &second["requestState"], "accept"),
        Some(&alice()),
    )
    .await
    .expect("round 2's envelope continues");
    assert_eq!(
        done_now["content"],
        done()["content"],
        "P5b: round 3 completes"
    );
    assert_eq!(wire.calls.load(Ordering::SeqCst), 3, "P5b: three rounds");
}

/// P7 (D2a): an anonymous caller cannot be bound to a continuation, so round
/// 1 is refused as today; the backend received it, so the key is kept: a
/// same-key retry is served the may-have-run notice and the tool runs once.
#[tokio::test]
async fn p7_an_anonymous_callers_asking_tool_keeps_its_key() {
    let (meta, wire) = gateway(vec![Step::Answer(interim()), Step::Answer(done())]);
    let client = answering();
    let first = modern(&meta, &client, &fresh(), None).await;
    assert_eq!(
        first.as_ref().err().map(crate::Error::to_rpc_code),
        Some(-32003),
        "premise: refused as an unbindable continuation: {first:?}"
    );
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        1,
        "premise: one tools/call"
    );
    let retry = modern(&meta, &client, &fresh(), None).await;
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        1,
        "the retry ran: {retry:?}"
    );
    assert!(
        may_have_run(&retry),
        "not the may-have-run notice: {retry:?}"
    );
}

/// P10 (control): an accept and a decline on one envelope: the first runs,
/// the second is a different request under a used key (Mismatch).
#[tokio::test]
async fn p10_two_answers_on_one_envelope_run_once() {
    let (meta, wire) = gateway(vec![Step::Answer(interim()), Step::Answer(done())]);
    let client = answering();
    let first = asked(&meta, &client, &wire).await;
    let state = first["requestState"].clone();
    modern(
        &meta,
        &client,
        &answer(KEY, &state, "accept"),
        Some(&alice()),
    )
    .await
    .expect("the accept runs");
    let decline = modern(
        &meta,
        &client,
        &answer(KEY, &state, "decline"),
        Some(&alice()),
    )
    .await;
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        2,
        "the decline ran too: {decline:?}"
    );
    assert!(decline.is_err(), "the decline was answered: {decline:?}");
}
