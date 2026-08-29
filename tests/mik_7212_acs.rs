// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7212 — the multi-round-trip continuation
//! envelope.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 5".
//!
//! A backend hands the gateway an opaque `requestState`. The gateway must reach
//! the client, and on retry reach that same backend with that same state —
//! while the client is forbidden from inspecting or altering what it echoes.
//! So the gateway mints its own envelope with the backend's blob inside.
//!
//! Every value here is attacker-controlled by construction: it travels through
//! the client. These tests are the fixtures NFR.SEC.4 requires, and each one
//! must fail closed for the reason it names.

use mcp_gateway::protocol::continuation::{ContinuationError, Keyring, Payload};

fn payload() -> Payload {
    Payload {
        backend_id: "weather".to_string(),
        backend_request_state: "AEAD-protected blob from the backend".to_string(),
        principal_fingerprint: "sha256:caller-a".to_string(),
        original_request_digest: "sha256:req-1".to_string(),
        origin_replica: "gw-1".to_string(),
        issued_at: 1_000,
        expires_at: 2_000,
        jti: "jti-1".to_string(),
    }
}

#[test]
fn ac_mrtr_2_a_minted_envelope_round_trips() {
    let keyring = Keyring::for_test();
    let token = keyring.mint(&payload()).expect("minting must succeed");
    let opened = keyring
        .open(&token, 1_500)
        .expect("the gateway must be able to open what it minted");
    assert_eq!(
        opened.backend_request_state,
        payload().backend_request_state
    );
    assert_eq!(opened.backend_id, "weather");
}

#[test]
fn ac_mrtr_2_the_backends_state_is_not_readable_by_the_client() {
    // Confidentiality, not just integrity. A backend's state may encode its own
    // authorization; handing the client a signed-but-readable copy gives it a
    // token it should never hold.
    let keyring = Keyring::for_test();
    let token = keyring.mint(&payload()).expect("mint");
    assert!(
        !token.contains("AEAD-protected"),
        "the backend's state must not appear in what the client receives"
    );
    assert!(
        !token.contains("weather"),
        "nor the backend's identity, which tells the client where to aim: {token}"
    );
}

#[test]
fn ac_mrtr_3_a_tampered_envelope_is_refused() {
    let keyring = Keyring::for_test();
    let token = keyring.mint(&payload()).expect("mint");

    // Flip one character of the ciphertext. Every position must fail closed:
    // the client writes this string.
    for index in (token.len() / 2)..(token.len() / 2 + 8).min(token.len()) {
        let mut bytes: Vec<char> = token.chars().collect();
        bytes[index] = if bytes[index] == 'A' { 'B' } else { 'A' };
        let tampered: String = bytes.into_iter().collect();
        if tampered == token {
            continue;
        }
        assert!(
            keyring.open(&tampered, 1_500).is_err(),
            "a modified envelope must be refused, not decoded: {tampered}"
        );
    }
}

#[test]
fn ac_mrtr_3_a_garbage_envelope_is_refused_without_panicking() {
    let keyring = Keyring::for_test();
    for junk in ["", "not-base64!!", "AAAA", "v1", &"A".repeat(10_000)] {
        assert!(
            keyring.open(junk, 1_500).is_err(),
            "arbitrary client input must be refused: {junk}"
        );
    }
}

#[test]
fn ac_mrtr_5_an_expired_envelope_is_refused() {
    let keyring = Keyring::for_test();
    let token = keyring.mint(&payload()).expect("mint");
    assert!(matches!(
        keyring.open(&token, 2_001),
        Err(ContinuationError::Expired)
    ));
    // And exactly at the boundary it is still live, so the rule is a deadline
    // rather than an off-by-one.
    assert!(keyring.open(&token, 2_000).is_ok());
}

// ===========================================================================
// MIK-7212.MRTR.4 — bound to the principal and to the original request, and
// usable for neither a different caller nor a different request.
//
// Authenticity alone does not give this. An envelope we minted is authentic no
// matter who presents it or what they present it with, so the binding has to be
// checked, not assumed from a successful decrypt.
// ===========================================================================

#[test]
fn ac_mrtr_4_another_caller_cannot_redeem_it() {
    let keyring = Keyring::for_test();
    let token = keyring.mint(&payload()).expect("mint");

    // Caller B presents caller A's continuation. It decrypts — we minted it —
    // so only the binding check stands between them.
    let opened = keyring.open(&token, 1_500).expect("authentic");
    assert!(
        opened
            .redeemable_by("sha256:caller-b", "sha256:req-1")
            .is_err(),
        "a continuation minted for one caller must not redeem for another"
    );
    assert!(
        opened
            .redeemable_by("sha256:caller-a", "sha256:req-1")
            .is_ok()
    );
}

#[test]
fn ac_mrtr_4_it_cannot_be_used_for_a_different_request() {
    // The specification confines these fields to the retry of the original
    // request: "They MUST NOT be used for any other request that the client may
    // be sending in parallel."
    let keyring = Keyring::for_test();
    let token = keyring.mint(&payload()).expect("mint");
    let opened = keyring.open(&token, 1_500).expect("authentic");

    assert!(
        opened
            .redeemable_by("sha256:caller-a", "sha256:req-2")
            .is_err(),
        "a continuation must not carry over to a parallel request"
    );
}

// ===========================================================================
// NFR.SEC.3 — the envelope is versioned and its key rotatable.
// ===========================================================================

#[test]
fn ac_sec_3_a_rotated_key_still_opens_continuations_in_flight() {
    // Rotation with no overlap breaks every open elicitation, and a redeploy
    // then looks exactly like an attack.
    let old = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
    let token = old.mint(&payload()).expect("mint");

    // New key mints; the old one is retained for verification.
    let rotated = Keyring::new(&[(2, [9u8; 32]), (1, [7u8; 32])]).expect("keyring");
    assert!(
        rotated.open(&token, 1_500).is_ok(),
        "a continuation minted before rotation must still open"
    );

    // And the new key is the one now minting.
    let fresh = rotated.mint(&payload()).expect("mint");
    let old_only = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
    assert_eq!(
        old_only.open(&fresh, 1_500),
        Err(ContinuationError::UnknownKey(2)),
        "a gateway without the new key must say so rather than fail vaguely"
    );
}

#[test]
fn ac_sec_3_a_key_that_was_dropped_no_longer_opens_anything() {
    // Retention is bounded. Past it, the answer is a clear refusal.
    let minted_with = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
    let token = minted_with.mint(&payload()).expect("mint");
    let dropped = Keyring::new(&[(2, [9u8; 32])]).expect("keyring");
    assert_eq!(
        dropped.open(&token, 1_500),
        Err(ContinuationError::UnknownKey(1))
    );
}

#[test]
fn ac_sec_3_a_wrong_key_cannot_forge_an_envelope() {
    // Same key id, different material: the shape is right and the seal is not.
    let real = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
    let impostor = Keyring::new(&[(1, [8u8; 32])]).expect("keyring");
    let forged = impostor.mint(&payload()).expect("mint");
    assert_eq!(
        real.open(&forged, 1_500),
        Err(ContinuationError::NotAuthentic)
    );
}

// ===========================================================================
// MIK-7212.MRTR.5 — single use, enforced server-side.
//
// This is the property AEAD does not give. An envelope is authentic every time
// it is presented; authenticity says nothing about how many times. The spec is
// explicit: servers for which a state must be consumed at most once "MUST
// enforce that invariant server-side".
// ===========================================================================

mod ledger {
    use std::sync::Arc;

    use mcp_gateway::protocol::continuation::ConsumedLedger;

    #[tokio::test]
    async fn ac_mrtr_5_a_continuation_redeems_once() {
        let ledger = ConsumedLedger::new(1_000);
        assert!(
            ledger.consume("jti-1", 2_000).await,
            "first redemption wins"
        );
        assert!(
            !ledger.consume("jti-1", 2_000).await,
            "a replay must be refused"
        );
    }

    #[tokio::test]
    async fn ac_mrtr_5_two_racing_redemptions_produce_exactly_one_winner() {
        // Check-then-consume as two steps loses this: both callers check, both
        // see it unconsumed, and a destructive continuation runs twice. The
        // race is the test — a sequential pair would pass either way.
        let ledger = Arc::new(ConsumedLedger::new(1_000));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let ledger = Arc::clone(&ledger);
            handles.push(tokio::spawn(async move {
                tokio::task::yield_now().await;
                ledger.consume("jti-race", 2_000).await
            }));
        }
        let mut winners = 0;
        for handle in handles {
            if handle.await.expect("task must not panic") {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one redemption may succeed");
    }

    #[tokio::test]
    async fn ac_mrtr_8_the_ledger_is_bounded_and_evicts_on_expiry() {
        // A client that starts continuations and walks away is the common case:
        // the spec says a server MUST NOT assume the client will retry. An
        // unbounded ledger keyed on abandonment is a memory-exhaustion vector
        // reachable by any client.
        let ledger = ConsumedLedger::new(1_000);
        for n in 0..500 {
            ledger.consume(&format!("jti-{n}"), 2_000).await;
        }
        assert_eq!(ledger.len().await, 500);

        // Past every deadline, the entries go.
        ledger.evict_expired(2_001).await;
        assert_eq!(
            ledger.len().await,
            0,
            "entries must not outlive the continuations they guard"
        );
    }

    #[tokio::test]
    async fn ac_mrtr_8_the_ledger_refuses_to_grow_without_limit() {
        // Even before anything expires. Eviction on a deadline is not a bound
        // when the attacker chooses the arrival rate.
        let ledger = ConsumedLedger::new(64);
        for n in 0..1_000 {
            ledger.consume(&format!("jti-{n}"), 9_999).await;
        }
        assert!(
            ledger.len().await <= 64,
            "the ledger must hold its capacity against an unbounded arrival rate"
        );
    }

    #[tokio::test]
    async fn ac_mrtr_5_retention_outlives_the_continuation_it_guards() {
        // A ledger that forgets before the envelope expires is a replay window
        // with extra steps: the envelope still opens, and nothing remembers it
        // was spent.
        let ledger = ConsumedLedger::new(1_000);
        assert!(ledger.consume("jti-live", 2_000).await);
        ledger.evict_expired(1_999).await;
        assert!(
            !ledger.consume("jti-live", 2_000).await,
            "an unexpired continuation must still be remembered as spent"
        );
    }
}

// ===========================================================================
// MIK-7212.MRTR.1 — the retry fields must survive extraction.
//
// The defect this ticket was filed for, confirmed at source: the gateway's
// `tools/call` extraction returns `(name, arguments)` and nothing else, while
// an MRTR retry carries `inputResponses` and `requestState` as their siblings.
// Both were dropped silently — so a modern client's elicitation never
// completed, and the destructive-confirmation gate ran without the human answer
// it exists to collect.
// ===========================================================================

mod retry {
    use mcp_gateway::protocol::mrtr::RetryFields;
    use serde_json::json;

    #[test]
    fn ac_mrtr_1_a_retry_carries_its_inputs_and_state() {
        let params = json!({
            "name": "get_weather",
            "arguments": { "location": "Helsinki" },
            "inputResponses": {
                "confirm": { "action": "accept", "content": { "ok": true } }
            },
            "requestState": "opaque-envelope"
        });

        let fields = RetryFields::from_params(Some(&params));
        assert_eq!(fields.request_state.as_deref(), Some("opaque-envelope"));
        assert!(
            fields
                .input_responses
                .as_ref()
                .is_some_and(|r| r.get("confirm").is_some()),
            "the client's answers must reach the backend that asked for them"
        );
    }

    #[test]
    fn ac_mrtr_1_an_ordinary_call_carries_neither() {
        // The common case stays exactly as it was: no retry fields, no change.
        let fields = RetryFields::from_params(Some(&json!({
            "name": "get_weather", "arguments": {}
        })));
        assert!(fields.request_state.is_none());
        assert!(fields.input_responses.is_none());
        assert!(!fields.is_retry(), "an ordinary call is not a retry");
    }

    #[test]
    fn ac_mrtr_1_either_field_alone_marks_a_retry() {
        // The spec: a server MUST include at least one of `inputRequests` or
        // `requestState`, so a retry may legitimately carry only one back.
        // Requiring both would drop the state-only retry, which is the shape a
        // server uses when it needs no further input.
        let state_only = RetryFields::from_params(Some(&json!({
            "name": "t", "requestState": "envelope"
        })));
        assert!(state_only.is_retry());

        let inputs_only = RetryFields::from_params(Some(&json!({
            "name": "t", "inputResponses": { "a": {} }
        })));
        assert!(inputs_only.is_retry());
    }

    #[test]
    fn ac_mrtr_1_a_non_string_request_state_is_not_read_as_one() {
        // `requestState` is a string the client echoes verbatim. A client that
        // sends an object has not echoed anything, and coercing it would put a
        // shape the gateway invented where the backend's own state belongs.
        let fields = RetryFields::from_params(Some(&json!({
            "name": "t", "requestState": { "not": "a string" }
        })));
        assert!(fields.request_state.is_none());
    }
}

// ===========================================================================
// MIK-7212.MRTR.6 — a modern client retrying against a LEGACY backend that is
// holding an open request.
//
// The bridge, and the one direction that cannot be stateless on the backend
// side: the legacy backend is sitting inside an RPC waiting for an answer, and
// that RPC lives on exactly one replica. A stateless client's retry may land on
// any of them.
// ===========================================================================

mod inflight {
    use std::sync::Arc;

    use mcp_gateway::protocol::continuation::{InFlight, Routing};

    #[tokio::test]
    async fn ac_mrtr_6_a_retry_reaching_the_holding_replica_is_served_here() {
        let table = InFlight::new("gw-1", 100);
        let key = table.hold("weather", 2_000).await.expect("capacity");

        assert!(matches!(table.route(&key, "gw-1"), Routing::Here));
    }

    #[tokio::test]
    async fn ac_mrtr_6_a_retry_landing_elsewhere_is_sent_to_the_holder() {
        // Not started afresh. Beginning a second exchange would leave the first
        // one hanging on another replica and ask the user the same question
        // twice — and for a destructive tool, the second answer would authorise
        // a call the first one already authorised.
        // gw-1 holds the open request; the retry lands on gw-2.
        let table = InFlight::new("gw-1", 100);
        let key = table.hold("weather", 2_000).await.expect("capacity");

        match table.route(&key, "gw-2") {
            Routing::Elsewhere { replica } => assert_eq!(
                replica, "gw-1",
                "the retry belongs where the exchange is held, not where it arrived"
            ),
            other => panic!("a retry for another replica must be routed there, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ac_mrtr_6_an_unknown_exchange_fails_explicitly() {
        // The replica that held it died, or the entry was evicted. Either way
        // the honest answer is a refusal the client can act on — never a silent
        // second exchange.
        let table = InFlight::new("gw-1", 100);
        assert!(matches!(table.route("no-such-key", "gw-1"), Routing::Gone));
    }

    #[tokio::test]
    async fn ac_mrtr_8_the_table_is_bounded() {
        // A client may abandon a continuation, and the specification says a
        // server MUST NOT assume otherwise. So entries arrive at a rate the
        // client sets, and refusing at capacity is the difference between a
        // bounded table and a memory-exhaustion vector.
        let table = InFlight::new("gw-1", 4);
        for _ in 0..4 {
            assert!(table.hold("weather", 9_999).await.is_some());
        }
        assert!(
            table.hold("weather", 9_999).await.is_none(),
            "at capacity the gateway must refuse to start a new exchange rather \
             than grow, and refusing is what the caller turns into an error the \
             client can see"
        );
    }

    #[tokio::test]
    async fn ac_mrtr_8_an_abandoned_exchange_is_reclaimed() {
        let table = InFlight::new("gw-1", 4);
        let key = table.hold("weather", 1_000).await.expect("capacity");

        table.reap(1_001).await;
        assert!(
            matches!(table.route(&key, "gw-1"), Routing::Gone),
            "an abandoned exchange must not hold its slot forever"
        );
        assert!(
            table.hold("weather", 9_999).await.is_some(),
            "and its slot must come back"
        );
    }

    #[tokio::test]
    async fn ac_mrtr_6_the_key_is_not_something_the_client_chooses() {
        // Two exchanges for the same backend must not collide, and a client
        // must not be able to name someone else's.
        let table = Arc::new(InFlight::new("gw-1", 100));
        let a = table.hold("weather", 9_999).await.expect("capacity");
        let b = table.hold("weather", 9_999).await.expect("capacity");
        assert_ne!(a, b, "each exchange gets its own key");
    }
}

// ===========================================================================
// MIK-7212.MRTR.7 — a MODERN backend eliciting through to a LEGACY client.
//
// The mirror of the bridge, and the direction an earlier design waved through
// as mechanical. It is the same state machine reflected, and it is the likelier
// one in practice: backends move to a new revision before every client does.
//
// The asymmetry is what makes it its own contract. A modern backend returns an
// InputRequiredResult and expects a retry. A legacy client expects the server
// to ask it a question mid-call. So the gateway holds the backend's
// continuation, asks the client the legacy way, and retries the backend with
// what comes back — the client never learning that a retry happened.
// ===========================================================================

mod reverse {
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
    fn ac_mrtr_7_a_completed_result_is_not_mistaken_for_one() {
        // `resultType` is what separates them, and a result omitting it is
        // complete by the client rule — so a legacy backend's ordinary answer
        // must never be read as a question.
        assert!(InputRequired::from_result(&json!({ "tools": [] })).is_none());
        assert!(
            InputRequired::from_result(&json!({ "resultType": "complete", "tools": [] })).is_none()
        );
    }

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
}

// ===========================================================================
// MIK-7212.MRTR.10 — the idempotency key covers the continuation, and an
// interim result is never cached as a completed one.
// ===========================================================================

mod idempotency {
    use mcp_gateway::idempotency::derive_key;
    use mcp_gateway::protocol::cacheable::result_type_of;
    use serde_json::json;

    #[test]
    fn ac_mrtr_10_a_retry_does_not_collide_with_the_call_it_continues() {
        // Same tool, same arguments, different continuation. A key derived from
        // the tool and arguments alone would call the retry a duplicate and
        // replay the interim result forever — the call could never finish.
        let original = derive_key("book_flight", &json!({ "seat": "12A" }));
        let retry = derive_key(
            "book_flight",
            &json!({
                "seat": "12A",
                "inputResponses": { "confirm": { "action": "accept" } },
                "requestState": "envelope"
            }),
        );
        assert_ne!(
            original, retry,
            "the continuation must participate in what identifies the call"
        );
    }

    #[test]
    fn ac_mrtr_10_two_callers_continuations_do_not_collide() {
        // Two users answering the same question about the same flight. Without
        // the continuation in the key, the second is served the first's result.
        let a = derive_key("book_flight", &json!({ "requestState": "envelope-a" }));
        let b = derive_key("book_flight", &json!({ "requestState": "envelope-b" }));
        assert_ne!(a, b);
    }

    #[test]
    fn ac_mrtr_10_a_reissued_identical_call_still_deduplicates() {
        // The property re-issue safety needs, unharmed: a stream broke, the
        // client re-sent the same call with a new request id, and the key is
        // the same because the request id was never part of it.
        assert_eq!(
            derive_key("book_flight", &json!({ "seat": "12A" })),
            derive_key("book_flight", &json!({ "seat": "12A" }))
        );
    }

    #[test]
    fn ac_mrtr_10_an_interim_result_is_not_a_completed_call() {
        // The other half. Caching an `input_required` as a completion would
        // make the tool answer "still waiting" to every later caller, forever,
        // without ever asking anyone anything.
        assert_eq!(
            result_type_of(&json!({
                "resultType": "input_required",
                "requestState": "envelope"
            })),
            "input_required",
            "an interim result is distinguishable from a completed one, which is \
             what lets the cache refuse to store it"
        );
        assert_ne!(
            result_type_of(&json!({ "resultType": "input_required" })),
            "complete"
        );
    }
}
