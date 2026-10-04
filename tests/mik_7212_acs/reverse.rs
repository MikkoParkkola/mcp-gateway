// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::mrtr::{Bridge, InputRequired};
use serde_json::json;

fn input_required() -> InputRequired {
    InputRequired::from_result(&json!({
        "resultType": "input_required",
        "inputRequests": {
            "confirm": {
                "method": "elicitation/create",
                "params": { "message": "Delete everything?" }
            }
        },
        "requestState": "backend-opaque"
    }))
    .expect("a well-formed interim result")
}

#[test]
fn ac_mrtr_7_an_interim_result_is_recognised() {
    let interim = input_required();
    assert_eq!(interim.request_state.as_deref(), Some("backend-opaque"));
    assert_eq!(interim.requests.len(), 1);
}

#[test]
fn ac_mrtr_7_a_declined_shape_is_still_a_backend_that_stopped_to_ask() {
    // Two different questions, and the post-dispatch idempotency gate needs
    // the second one. `from_result` answers "can the gateway carry this
    // exchange"; `claims_input_required` answers "did the backend say it
    // acted". Every shape below answers no to the first and yes to the
    // second, and a gate reading the first would settle each of them with
    // the final-shaped "side effect executed" placeholder — over a backend
    // that had stopped to ask.
    for declined in [
        json!({ "resultType": "input_required" }),
        json!({
            "resultType": "input_required",
            "inputRequests": "not-an-object",
            "requestState": "state-that-would-make-it-look-valid",
        }),
    ] {
        assert!(
            InputRequired::from_result(&declined).is_none(),
            "precondition: this shape is one from_result declines"
        );
        assert!(
            InputRequired::claims_input_required(&declined),
            "a declined shape still claimed input_required: {declined}"
        );
    }

    // And the discriminator is the whole test: a completed result, and one
    // omitting `resultType` as every pre-2026 backend does, must both read
    // as the backend having acted.
    assert!(!InputRequired::claims_input_required(
        &json!({ "resultType": "complete", "tools": [] })
    ));
    assert!(!InputRequired::claims_input_required(
        &json!({ "tools": [] })
    ));
}

#[test]
fn ac_mrtr_7_a_completed_result_is_not_mistaken_for_one() {
    // `resultType` is what separates them, and a result omitting it is
    // complete by the client rule — so a legacy backend's ordinary answer
    // must never be read as a question.
    assert!(InputRequired::from_result(&json!({ "tools": [] })).is_none());

    // An exchange with no question and no state can be advanced by nobody,
    // so classifying it as interim mints a handle that holds a keyring slot
    // until it expires and can never be redeemed. The neighbouring
    // `ac_mrtr_7_a_state_only_interim_result_needs_no_client_round_trip`
    // fixes the case this must not catch: a state-only result is a real
    // exchange the gateway advances without asking the client anything.
    assert!(
        InputRequired::from_result(&json!({ "resultType": "input_required" })).is_none(),
        "an interim result with neither a question nor state is not an exchange"
    );

    // A malformed `inputRequests` must not read as an absent one. The
    // state-carrying case is the one that matters: without the distinction
    // it becomes a state-only exchange, which is valid, and the malformed
    // requests are never seen by the capability gate at all.
    assert!(
        InputRequired::from_result(&json!({
            "resultType": "input_required",
            "inputRequests": "not-an-object",
            "requestState": "state-that-would-make-it-look-valid",
        }))
        .is_none(),
        "a malformed inputRequests is a fault, not an absent field"
    );
    // #2416: a present requestState that is not a string is a malformed
    // shape too, not an absent one. Read as absent, a question would be
    // resumed later with answers and no backend continuation at all.
    for state in [json!({ "k": 1 }), json!(7), json!(["x"]), json!(null)] {
        assert!(
            InputRequired::from_result(&json!({
                "resultType": "input_required",
                "inputRequests": { "q": { "method": "elicitation/create" } },
                "requestState": state,
            }))
            .is_none(),
            "a non-string requestState is a fault, not an absent field: {state}"
        );
    }
    assert!(
        InputRequired::from_result(&json!({ "resultType": "complete", "tools": [] })).is_none()
    );
}

/// Row 308, projection half only.
///
/// The row names an SSE session: a legacy client receives the request "on
/// its own connection". This test calls the projection in process, so it
/// proves the shape and not the delivery. A bridge whose projection is
/// perfect and whose SSE path never writes passes here.
///
/// The delivery half is DEFERRED, not assumed:
/// - owner: MIK-7212, this branch
/// - resolved by: an SSE row asserting an `elicitation/create` frame
///   reaching a client stream, written against the wired bridge
/// - when: the commit that wires `InputBridge::run` into the router — the
///   row cannot fail honestly before then, because nothing dispatches
/// - if it resolves badly: the SSE path needs its own dispatch and row 308
///   is not met by the projection alone, however green this file is
#[test]
fn ac_mrtr_7_a_legacy_client_is_asked_the_way_it_expects() {
    // The translation: each input request becomes a server-initiated call
    // on the client's own connection, which is the only shape a 2025 client
    // understands.
    let interim = input_required();
    let outbound = Bridge::to_legacy_client(&interim);

    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].method, "elicitation/create");
    assert_eq!(outbound[0].key, "confirm");
    assert_eq!(outbound[0].params["message"], "Delete everything?");
}

#[test]
fn ac_mrtr_7_the_clients_answers_are_returned_under_the_servers_own_keys() {
    // The server assigned those identifiers and will look for them again.
    // Returning answers under any other key loses them as surely as
    // dropping them.
    let interim = input_required();
    let answers = vec![("confirm".to_string(), json!({ "action": "accept" }))];

    let retry = Bridge::retry_params(&interim, answers);
    assert_eq!(retry["requestState"], "backend-opaque");
    assert_eq!(retry["inputResponses"]["confirm"]["action"], "accept");
}

#[test]
fn ac_mrtr_7_a_request_the_client_refused_is_carried_as_a_refusal() {
    // A client that declines is not an error and not a silence: the server
    // asked, and "no" is an answer it must receive, or it will ask again
    // forever.
    let interim = input_required();
    let retry = Bridge::retry_params(
        &interim,
        vec![("confirm".to_string(), json!({ "action": "decline" }))],
    );
    assert_eq!(retry["inputResponses"]["confirm"]["action"], "decline");
}

#[test]
fn ac_mrtr_7_a_state_only_interim_result_needs_no_client_round_trip() {
    // A server may return `requestState` with no `inputRequests` — it needs
    // nothing from the user, only another turn. Asking the client anything
    // here would invent a question nobody posed.
    let interim = InputRequired::from_result(&json!({
        "resultType": "input_required",
        "requestState": "just-more-work"
    }))
    .expect("state-only interim result is well formed");

    assert!(interim.requests.is_empty());
    assert!(Bridge::to_legacy_client(&interim).is_empty());

    let retry = Bridge::retry_params(&interim, Vec::new());
    assert_eq!(retry["requestState"], "just-more-work");
    assert!(
        retry.get("inputResponses").is_none(),
        "no answers were asked for, so none are sent"
    );
}
