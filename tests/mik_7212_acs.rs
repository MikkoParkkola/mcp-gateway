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
        backend_request_state: Some("AEAD-protected blob from the backend".to_string()),
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
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
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
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
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
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
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
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
    for junk in ["", "not-base64!!", "AAAA", "v1", &"A".repeat(10_000)] {
        assert!(
            keyring.open(junk, 1_500).is_err(),
            "arbitrary client input must be refused: {junk}"
        );
    }
}

#[test]
fn ac_mrtr_5_an_expired_envelope_is_refused() {
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
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
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
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
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
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
            ledger.consume("jti-1", 2_000, 1_000).await,
            "first redemption wins"
        );
        assert!(
            !ledger.consume("jti-1", 2_000, 1_000).await,
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
                ledger.consume("jti-race", 2_000, 1_000).await
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
            ledger.consume(&format!("jti-{n}"), 2_000, 1_000).await;
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
            ledger.consume(&format!("jti-{n}"), 9_999, 1_000).await;
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
        assert!(ledger.consume("jti-live", 2_000, 1_000).await);
        ledger.evict_expired(1_999).await;
        assert!(
            !ledger.consume("jti-live", 2_000, 1_000).await,
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

        assert!(matches!(table.route(&key, "gw-1").await, Routing::Here));
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

        match table.route(&key, "gw-2").await {
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
        assert!(matches!(
            table.route("no-such-key", "gw-1").await,
            Routing::Gone
        ));
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
            matches!(table.route(&key, "gw-1").await, Routing::Gone),
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

// ===========================================================================
// Review hardening — findings raised against `src/protocol/continuation.rs`
// by an independent reviewer, each pinned by a row that fails without the fix.
//
// These are not new acceptance criteria. They are the criteria NFR.SEC.4
// already asserted, re-stated at the points where the first implementation
// met them in letter and not in fact.
// ===========================================================================

mod hardening {
    use mcp_gateway::protocol::continuation::{
        ConsumedLedger, ContinuationError, InFlight, Keyring, Payload, Routing,
    };

    fn payload() -> Payload {
        Payload {
            backend_id: "weather".into(),
            backend_request_state: Some("Bearer super-secret-backend-token".into()),
            principal_fingerprint: "sha256:caller-a".into(),
            original_request_digest: "sha256:req-1".into(),
            origin_replica: "gw-1".into(),
            issued_at: 1_000,
            expires_at: 2_000,
            jti: "jti-1".into(),
        }
    }

    #[test]
    fn a_formatted_payload_never_carries_sealed_state_or_bindings() {
        // The envelope is sealed on the wire and plaintext in memory. A derived
        // `Debug` undoes the sealing the moment anything logs one: the backend's
        // own state may carry the authorization it was issued, and the caller
        // bindings identify who may redeem the exchange.
        let formatted = format!("{:?}", payload());

        for secret in [
            "super-secret-backend-token",
            "sha256:caller-a",
            "sha256:req-1",
        ] {
            assert!(
                !formatted.contains(secret),
                "formatting a Payload leaked {secret}: {formatted}"
            );
        }
        assert!(
            formatted.contains("jti-1") && formatted.contains("weather"),
            "redaction must still leave a Payload diagnosable: {formatted}"
        );
    }

    #[test]
    fn a_wrong_binding_of_any_length_is_refused_identically() {
        // The behavioural half of the constant-time fix. Stated as what it
        // proves: this row cannot observe timing, and it passes against the
        // short-circuiting implementation too — verified by running it against
        // one. The timing property itself is a code-shape property, asserted by
        // reading `redeemable_by`, and it is recorded that way rather than
        // dressed up as a test that catches it.
        let sealed = payload();
        for wrong in ["", "x", "sha256:caller-", "sha256:caller-a-and-then-some"] {
            assert_eq!(
                sealed.redeemable_by(wrong, "sha256:req-1"),
                Err(ContinuationError::NotAuthentic),
                "a wrong principal of any length must be refused identically"
            );
        }
        assert_eq!(
            sealed.redeemable_by("sha256:caller-a", "sha256:req-1"),
            Ok(())
        );
    }

    #[test]
    fn a_keyring_refuses_two_keys_sharing_one_id() {
        // Lookup takes the first match, so a duplicate id silently shadows a key
        // that is still expected to verify. The failure surfaces one replica at
        // a time, on envelopes minted before the deploy — the worst possible
        // shape for a configuration error.
        assert_eq!(
            Keyring::new(&[(1, [7u8; 32]), (1, [9u8; 32])]).err(),
            Some(ContinuationError::Malformed),
            "a keyring with a duplicated key id must be refused at construction"
        );
        assert!(Keyring::new(&[(1, [7u8; 32]), (2, [9u8; 32])]).is_ok());
    }

    #[test]
    fn a_refusal_shown_to_a_client_names_no_key_or_version() {
        // The internal cause stays for the operator; the client is told only
        // that the continuation was refused. Reporting *which* key id or wire
        // version was wrong lets a caller map the active keyring and the build,
        // one probe at a time.
        for internal in [
            ContinuationError::UnknownKey(3),
            ContinuationError::UnknownVersion(9),
            ContinuationError::NotAuthentic,
            ContinuationError::Expired,
            ContinuationError::Malformed,
        ] {
            let shown = internal.client_message();
            assert!(
                !shown.contains('3') && !shown.contains('9'),
                "a client-facing refusal must not fingerprint the keyring: {shown}"
            );
        }
        // The operator still gets the detail.
        assert!(ContinuationError::UnknownKey(3).to_string().contains('3'));
    }

    #[tokio::test]
    async fn the_ledger_refuses_a_new_entry_rather_than_forget_a_live_one() {
        // At capacity there are two ways to stay bounded: forget something
        // already spent, or refuse something new. Forgetting reopens a replay
        // window on a continuation whose envelope still opens — the exact
        // property this ledger exists to hold. Refusing costs a caller one
        // retry. The bounded-ness test alone cannot tell these apart, which is
        // why it is not the only row.
        let ledger = ConsumedLedger::new(2);
        assert!(ledger.consume("jti-a", 9_999, 1_000).await);
        assert!(ledger.consume("jti-b", 9_999, 1_000).await);

        assert!(
            !ledger.consume("jti-c", 9_999, 1_000).await,
            "a full ledger must refuse a new continuation, not evict a live one"
        );
        assert!(
            !ledger.consume("jti-a", 9_999, 1_000).await,
            "the entries already spent must still be remembered as spent"
        );
        assert!(!ledger.consume("jti-b", 9_999, 1_000).await);
    }

    #[tokio::test]
    async fn expired_entries_are_reclaimed_before_a_refusal() {
        // Refusing while holding entries nobody can replay would be a denial of
        // service dressed as caution.
        let ledger = ConsumedLedger::new(2);
        assert!(ledger.consume("jti-old", 1_000, 1_000).await);
        assert!(ledger.consume("jti-live", 9_999, 1_000).await);

        assert!(
            ledger.consume("jti-new", 9_999, 5_000).await,
            "capacity held by an expired entry must be reclaimed, not refused"
        );
        assert!(
            !ledger.consume("jti-live", 9_999, 5_000).await,
            "reclaiming must take the expired entry, never the live one"
        );
    }

    #[tokio::test]
    async fn a_completed_exchange_releases_its_capacity() {
        // Without an explicit completion, capacity counts every exchange ever
        // started until its deadline passes, so a healthy gateway refuses new
        // elicitations because of ones that finished long ago.
        let table = InFlight::new("gw-1", 1);
        let key = table.hold("weather", 9_999).await.expect("capacity");
        assert!(table.hold("weather", 9_999).await.is_none());

        assert!(
            table.complete(&key).await,
            "completing must report the release"
        );
        assert!(
            table.hold("weather", 9_999).await.is_some(),
            "a finished exchange must return its slot"
        );
        assert!(
            !table.complete("no-such-key").await,
            "completing an unknown exchange must report that it released nothing"
        );
    }

    #[tokio::test]
    async fn a_completed_exchange_is_gone_for_routing() {
        let table = InFlight::new("gw-1", 4);
        let key = table.hold("weather", 9_999).await.expect("capacity");
        assert!(table.complete(&key).await);

        assert!(
            matches!(table.route(&key, "gw-1").await, Routing::Gone),
            "a retry against a finished exchange must fail explicitly"
        );
    }

    // Multi-threaded on purpose: on a current-thread runtime the lock is never
    // held across an await, so a `try_lock` implementation would never collide
    // and this row could not fail.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn routing_waits_for_the_lock_rather_than_reporting_the_exchange_gone() {
        // `Gone` means the exchange no longer exists, and a caller acts on it by
        // failing the retry. Answering it for a lock held by a concurrent reaper
        // turns ordinary contention into a lost elicitation, which is precisely
        // what the routing table exists to prevent.
        use std::sync::Arc;

        let table = Arc::new(InFlight::new("gw-1", 4));
        let key = table.hold("weather", 9_999).await.expect("capacity");

        // Hammer routing while reaping runs concurrently: reaping takes the same
        // lock, so a `try_lock` implementation reports `Gone` for an exchange
        // that is plainly still held.
        let reaper = {
            let table = Arc::clone(&table);
            tokio::spawn(async move {
                for _ in 0..500 {
                    table.reap(0).await;
                    tokio::task::yield_now().await;
                }
            })
        };
        for _ in 0..500 {
            assert!(
                matches!(table.route(&key, "gw-1").await, Routing::Here),
                "a held exchange must route to its holder even under contention"
            );
            tokio::task::yield_now().await;
        }
        reaper.await.expect("reaper");
    }
}

mod mint_budget {
    use mcp_gateway::protocol::continuation::{ContinuationError, Keyring, Payload};

    fn payload() -> Payload {
        Payload {
            backend_id: "weather".into(),
            backend_request_state: Some("state".into()),
            principal_fingerprint: "sha256:caller-a".into(),
            original_request_digest: "sha256:req-1".into(),
            origin_replica: "gw-1".into(),
            issued_at: 1_000,
            expires_at: 2_000,
            jti: "jti-1".into(),
        }
    }

    #[test]
    fn a_key_stops_minting_once_it_has_spent_its_budget() {
        // AES-GCM with a random 96-bit nonce collides on the birthday bound, and
        // a nonce reused under one key loses confidentiality outright rather
        // than gradually. Rotation is what keeps a deployment under the bound;
        // this is what makes the bound enforced instead of hoped for.
        let keyring = Keyring::new(&[(1, [7u8; 32])])
            .expect("keyring")
            .with_mint_budget(2);

        assert!(keyring.mint(&payload()).is_ok());
        assert!(keyring.mint(&payload()).is_ok());
        assert_eq!(
            keyring.mint(&payload()).err(),
            Some(ContinuationError::MintBudgetExhausted),
            "a key must refuse to seal past its budget"
        );
        // And it stays refused rather than recovering on the next call.
        assert_eq!(
            keyring.mint(&payload()).err(),
            Some(ContinuationError::MintBudgetExhausted)
        );
    }

    #[test]
    fn the_budget_cannot_be_raised_above_the_ceiling() {
        // The ceiling is a property of AES-GCM with random nonces, not a
        // preference, so a caller may rotate sooner and may not rotate later.
        let raised = Keyring::new(&[(1, [7u8; 32])])
            .expect("keyring")
            .with_mint_budget(u64::MAX);
        assert_eq!(
            raised.mint_budget_remaining(),
            1_u64 << 32,
            "a budget above the ceiling must clamp to it, not disable the check"
        );

        let lowered = Keyring::new(&[(1, [7u8; 32])])
            .expect("keyring")
            .with_mint_budget(8);
        assert_eq!(lowered.mint_budget_remaining(), 8);
        lowered.mint(&payload()).expect("mint");
        assert_eq!(
            lowered.mint_budget_remaining(),
            7,
            "the remaining budget must fall as envelopes are sealed"
        );
    }

    #[test]
    fn an_exhausted_key_still_verifies_what_it_already_sealed() {
        // Refusing to mint must not orphan the envelopes already in flight.
        let keyring = Keyring::new(&[(1, [7u8; 32])])
            .expect("keyring")
            .with_mint_budget(1);
        let token = keyring.mint(&payload()).expect("first mint");
        assert!(keyring.mint(&payload()).is_err());

        assert_eq!(
            keyring.open(&token, 1_500).expect("opens").jti,
            "jti-1",
            "an exhausted key must keep verifying envelopes it already minted"
        );
    }
}

mod envelope_size {
    use mcp_gateway::protocol::continuation::{ContinuationError, Keyring, Payload};

    fn payload_with_state(state: String) -> Payload {
        Payload {
            backend_id: "weather".into(),
            backend_request_state: Some(state),
            principal_fingerprint: "sha256:caller-a".into(),
            original_request_digest: "sha256:req-1".into(),
            origin_replica: "gw-1".into(),
            issued_at: 1_000,
            expires_at: 2_000,
            jti: "jti-1".into(),
        }
    }

    #[test]
    fn an_oversized_token_is_refused_before_it_is_decoded() {
        // The token is client-controlled and arrives on every retry. Decoding
        // first means an attacker sizes the gateway's allocation and its AEAD
        // work with a string, which is a denial of service that needs no valid
        // key. The bound is checked against the encoded length, so nothing is
        // allocated on its behalf.
        let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
        let huge = "A".repeat(64 * 1024);

        assert_eq!(
            keyring.open(&huge, 1_500).err(),
            Some(ContinuationError::TooLarge),
            "an oversized continuation must be refused on its length alone"
        );
    }

    #[test]
    fn a_payload_too_large_to_open_is_never_minted() {
        // Minting an envelope the gateway would then refuse to open is a bug
        // that surfaces only on the retry, long after the cause. Both ends
        // enforce the same bound so that cannot happen.
        let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");

        assert_eq!(
            keyring
                .mint(&payload_with_state("s".repeat(32 * 1024)))
                .err(),
            Some(ContinuationError::TooLarge),
            "a backend state too large to redeem must be refused at mint"
        );
    }

    #[test]
    fn a_token_of_exactly_the_permitted_size_is_judged_on_its_contents() {
        // The bound is "longer than", so a token *at* the limit passes the
        // length gate and is refused, if at all, for what it contains. Nothing
        // pinned that boundary: the oversized test above uses 64 KiB and the
        // ordinary one a few hundred bytes, so relaxing the comparison to `>=`
        // changed no test's outcome. `cargo-mutants` made exactly that
        // substitution in `Keyring::open` and the suite stayed green.
        let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
        // `MAX_ENVELOPE_LEN` is private to its module; 8 KiB is its value, and
        // a token one byte longer is the case the test above covers.
        let at_limit = "A".repeat(8 * 1024);

        let refusal = keyring.open(&at_limit, 1_500).err();
        assert!(
            refusal.is_some() && refusal != Some(ContinuationError::TooLarge),
            "a token at the limit must be judged on its contents, not its length: {refusal:?}"
        );
    }

    #[test]
    fn a_client_facing_refusal_still_tells_the_caller_something() {
        // Its sibling above pins what a refusal must not reveal, and an empty
        // string satisfies that perfectly — which is why `cargo-mutants` could
        // replace `client_message` with `""` and leave the suite green. A
        // refusal a caller cannot read is not a refusal.
        for internal in [
            ContinuationError::UnknownKey(3),
            ContinuationError::UnknownVersion(9),
            ContinuationError::NotAuthentic,
            ContinuationError::Expired,
            ContinuationError::Malformed,
            ContinuationError::TooLarge,
        ] {
            let shown = internal.client_message();
            assert!(
                shown.contains("continuation"),
                "a refusal must name what was refused: {shown:?}"
            );
        }
    }

    #[test]
    fn an_ordinary_envelope_is_unaffected_by_the_bound() {
        // The bound must sit above real backend state, or it is an outage
        // rather than a guard.
        let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
        let token = keyring
            .mint(&payload_with_state("s".repeat(2_048)))
            .expect("2 KiB of backend state is ordinary and must mint");

        assert_eq!(
            keyring
                .open(&token, 1_500)
                .expect("opens")
                .backend_request_state
                .expect("the state that was minted must come back")
                .len(),
            2_048
        );
    }
}

// ===========================================================================
// Mirrored-header findings raised by review against the transport wiring.
// The specification makes header/body agreement a MUST for a server that
// processes the body, precisely so a routing decision and an execution
// decision cannot be taken from different sources. Both rows below are ways
// that guarantee failed while the check appeared to run.
// ===========================================================================

mod mirrored_headers {
    use mcp_gateway::protocol::headers::{HeaderCheck, mcp_name_body_field, mcp_name_required};

    #[test]
    fn resources_read_mirrors_its_uri_and_never_a_decoy_name() {
        // `resources/read` executes on `uri`. Reading `name` with a fallback to
        // `uri` lets a caller attach a permitted-looking `name`, satisfy the
        // header check against it, and have the gateway read the `uri` beside
        // it — a decoy that authorises one resource and fetches another.
        assert_eq!(mcp_name_body_field("resources/read"), Some("uri"));
        assert_eq!(mcp_name_body_field("tools/call"), Some("name"));
        assert_eq!(mcp_name_body_field("prompts/get"), Some("name"));
        assert_eq!(
            mcp_name_body_field("tools/list"),
            None,
            "a method with nothing to name must not demand a mirrored name"
        );
    }

    #[test]
    fn the_required_set_and_the_mirrored_field_cannot_disagree() {
        // Two lists of the same three methods drift apart, and the drift is a
        // bypass: a method required to carry the header with no field to
        // compare it against would pass every check.
        for method in [
            "tools/call",
            "resources/read",
            "prompts/get",
            "tools/list",
            "initialize",
            "ping",
        ] {
            assert_eq!(
                mcp_name_required(method),
                mcp_name_body_field(method).is_some(),
                "{method}: the header requirement and the mirrored field must agree"
            );
        }
    }

    #[test]
    fn a_name_that_disagrees_with_the_body_is_still_refused() {
        // The check itself, unchanged — guarding against a fix to the field
        // selection that quietly stops comparing anything.
        let check = HeaderCheck {
            header_protocol_version: Some("2026-07-28"),
            body_protocol_version: Some("2026-07-28"),
            header_method: Some("resources/read"),
            body_method: "resources/read",
            header_name: Some("file:///allowed"),
            body_name: Some("file:///etc/shadow"),
        };
        assert!(
            check.validate().is_err(),
            "a mirrored name that disagrees with the body must be refused"
        );
    }
}

// ===========================================================================
// Round-4 and round-5 findings: the classifier decided an era from the body
// alone, so a request could declare itself modern in a header the gateway
// never read and take the legacy path past every modern check.
// ===========================================================================

mod classification {
    use mcp_gateway::protocol::meta::{RequestShape, classify_request};
    use serde_json::json;

    fn modern_meta() -> serde_json::Value {
        json!({"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}
        }})
    }

    #[test]
    fn a_modern_version_header_without_body_metadata_is_malformed() {
        // The bypass: upstream routes on the header, the gateway classifies on
        // the body, and the two disagree about which protocol this even is.
        // Answering Legacy here skips the feature gate and every mirrored-header
        // check behind it.
        let shape = classify_request(Some(&json!({})), Some("2026-07-28"));
        assert!(
            matches!(shape, RequestShape::Malformed { .. }),
            "a header declaring 2026-07-28 with no body metadata must be refused, got {shape:?}"
        );
    }

    #[test]
    fn an_unserved_2026_version_header_without_body_metadata_is_malformed() {
        // Adversarial review, 2026-08-30, confirmed at source: the router skips
        // session minting on `declares_modern_era` (any `2026-*`) while the
        // classifier read the narrower `MODERN_VERSIONS`. A revision this build
        // does not serve therefore got no session AND the legacy path — the
        // legacy destructive-confirmation policy, with an empty session id,
        // never reaching the -32022 unsupported-version refusal. Two predicates
        // deciding one question is the defect; the answer is one predicate.
        let shape = classify_request(Some(&json!({})), Some("2026-11-25"));
        assert!(
            matches!(shape, RequestShape::Malformed { .. }),
            "a header declaring an unserved 2026 revision with no body metadata \
             must be refused, not treated as legacy, got {shape:?}"
        );
    }

    #[test]
    fn a_legacy_version_header_is_not_a_modern_declaration() {
        // 2025 defines this header too. Treating its mere presence as a modern
        // declaration would refuse every conforming 2025 client — the likelier
        // and more damaging mistake.
        let shape = classify_request(Some(&json!({})), Some("2025-11-25"));
        assert!(
            matches!(shape, RequestShape::Legacy),
            "a 2025 client sending its own version header must stay legacy, got {shape:?}"
        );
    }

    #[test]
    fn a_modern_header_agreeing_with_modern_body_classifies_modern() {
        let shape = classify_request(Some(&modern_meta()), Some("2026-07-28"));
        assert!(matches!(shape, RequestShape::Modern(_)), "got {shape:?}");
    }

    #[test]
    fn body_metadata_alone_still_classifies_modern() {
        // No header at all: the body remains a sufficient declaration.
        let shape = classify_request(Some(&modern_meta()), None);
        assert!(matches!(shape, RequestShape::Modern(_)), "got {shape:?}");
    }

    #[test]
    fn capabilities_present_but_not_an_object_is_malformed() {
        // Presence satisfied the required-field check while the value was
        // unusable, so an invalid declaration reached dispatch looking valid.
        for bad in [json!(null), json!(7), json!("caps"), json!([])] {
            let params = json!({"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": bad
            }});
            let shape = classify_request(Some(&params), None);
            assert!(
                matches!(shape, RequestShape::Malformed { .. }),
                "clientCapabilities {bad} must be refused, got {shape:?}"
            );
        }
    }

    #[test]
    fn a_modern_only_optional_key_declares_the_era() {
        // clientInfo and logLevel are 2026 keys. A request carrying one and
        // omitting the required pair has declared an era and failed to complete
        // the declaration, which is malformed rather than legacy.
        for key in [
            "io.modelcontextprotocol/clientInfo",
            "io.modelcontextprotocol/logLevel",
        ] {
            let params = json!({"_meta": { key: {"name": "x"} }});
            let shape = classify_request(Some(&params), None);
            assert!(
                matches!(shape, RequestShape::Malformed { .. }),
                "{key} alone must be malformed, got {shape:?}"
            );
        }
    }

    #[test]
    fn an_unrelated_meta_key_is_still_legacy() {
        // A 2025 client sending a trace context has declared nothing.
        let params = json!({"_meta": {"traceparent": "00-abc-def-01"}});
        assert!(matches!(
            classify_request(Some(&params), None),
            RequestShape::Legacy
        ));
    }
}

mod validation {
    use mcp_gateway::protocol::extensions::ExtensionSet;
    use mcp_gateway::protocol::mrtr::RetryFields;
    use serde_json::json;

    #[test]
    fn a_retry_field_that_is_present_and_unusable_is_neither_a_retry_nor_a_fresh_call() {
        // The two fields used to fail differently for the same mistake: a
        // malformed `inputResponses` was carried through as a retry, while a
        // malformed `requestState` vanished and the call became a fresh one.
        // A retry that silently becomes a fresh call repeats whatever the first
        // attempt already did.
        for bad in [json!("answers"), json!(7), json!([]), json!(null)] {
            let fields = RetryFields::from_params(Some(&json!({ "inputResponses": bad })));
            assert!(
                fields.is_malformed(),
                "inputResponses {bad} must be refused"
            );
            assert!(fields.input_responses.is_none());
        }

        let fields = RetryFields::from_params(Some(&json!({ "requestState": { "a": 1 } })));
        assert!(
            fields.is_malformed(),
            "a non-string requestState must be refused, not dropped"
        );
    }

    #[test]
    fn a_well_formed_retry_is_unaffected() {
        let fields = RetryFields::from_params(Some(&json!({
            "inputResponses": { "confirm": { "action": "accept" } },
            "requestState": "sealed-envelope"
        })));

        assert!(!fields.is_malformed());
        assert!(fields.is_retry());
        assert_eq!(fields.request_state.as_deref(), Some("sealed-envelope"));
    }

    #[test]
    fn an_extension_whose_settings_are_not_an_object_is_not_negotiated() {
        // Presence is not agreement. A key whose value is unusable switched on
        // behaviour the peer never validly declared.
        for bad in [json!(null), json!(true), json!(3), json!("on"), json!([])] {
            let caps = json!({ "extensions": { "io.modelcontextprotocol/tasks": bad } });
            assert!(
                ExtensionSet::from_capabilities(&caps).is_empty(),
                "settings {bad} must not count as a declaration"
            );
        }
    }

    #[test]
    fn an_extension_with_object_settings_is_negotiated() {
        let caps = json!({ "extensions": { "io.modelcontextprotocol/tasks": {} } });
        assert!(
            !ExtensionSet::from_capabilities(&caps).is_empty(),
            "a well-formed declaration must still be read"
        );
    }
}

mod era_resolution {
    use mcp_gateway::protocol::era::{Era, EraCache, ProbeOutcome, classify};
    use serde_json::json;

    fn discovery(versions: &serde_json::Value) -> serde_json::Value {
        json!({ "supportedVersions": versions, "capabilities": {} })
    }

    #[test]
    fn a_result_that_is_not_a_discovery_document_is_not_modern() {
        // An unrelated result carrying a familiar key is not a peer announcing
        // this revision. Reading one as modern sends a request the peer never
        // said it could parse.
        let impostor = json!({ "supportedVersions": ["2026-07-28"] });
        assert_eq!(
            classify(&ProbeOutcome::Result(impostor)),
            Era::Legacy,
            "a document without capabilities is not a discovery document"
        );

        assert_eq!(
            classify(&ProbeOutcome::Result(discovery(&json!(["2026-07-28"])))),
            Era::Modern,
            "a complete document still resolves modern"
        );
    }

    #[tokio::test]
    async fn a_probe_that_never_answered_is_not_remembered() {
        // Legacy is the right way to treat the next request and the wrong thing
        // to remember: a backend briefly unreachable would be pinned to the
        // legacy path for the life of the process, and a dual-era peer that
        // recovered would never be spoken to properly again.
        let cache = EraCache::new();

        let first = cache
            .resolve_with(|| async { ProbeOutcome::NoAnswer })
            .await;
        assert_eq!(first, Era::Legacy, "silence is served as legacy");

        let second = cache
            .resolve_with(|| async { ProbeOutcome::Result(discovery(&json!(["2026-07-28"]))) })
            .await;
        assert_eq!(
            second,
            Era::Modern,
            "a recovered peer must be re-probed, not served from a cached failure"
        );
    }

    #[tokio::test]
    async fn a_conclusive_answer_is_remembered() {
        // The cache must still do its job: one probe, then no more.
        let cache = EraCache::new();
        let first = cache
            .resolve_with(|| async { ProbeOutcome::Result(discovery(&json!(["2026-07-28"]))) })
            .await;
        assert_eq!(first, Era::Modern);

        let second = cache
            .resolve_with(|| async { panic!("the cached era must be reused") })
            .await;
        assert_eq!(second, Era::Modern);
    }
}

// ── MRTR.10 — the retry pair discriminates a cached result ───────────────────
//
// A client's idempotency key is an opaque string it chose, and a retry reuses
// it: the retry *is* the same logical request. So the key alone cannot tell one
// continuation of that request from another, and the fingerprint bound to it
// must. Without the retry pair in that fingerprint, a user who answers a
// confirmation gate "accept" and then, on a second continuation, "decline" is
// served the first answer's result — one side effect standing in for the
// opposite one.

use mcp_gateway::protocol::mrtr::RetryFields;
use serde_json::json;

fn retry(input_responses: Option<serde_json::Value>, request_state: Option<&str>) -> RetryFields {
    RetryFields {
        input_responses,
        request_state: request_state.map(str::to_string),
        idempotency_key: None,
        malformed: Vec::new(),
    }
}

#[test]
fn ac_mrtr_10_a_fresh_call_contributes_nothing_to_the_key() {
    // GIVEN a call carrying neither retry field
    let fresh = retry(None, None);
    // THEN it must not perturb the key, or every warm cache entry in every
    // deployment is silently dropped by the upgrade that adds this.
    assert_eq!(
        fresh.key_discriminator(),
        "",
        "a fresh call must derive the same key it derived before MRTR.10"
    );
}

#[test]
fn ac_mrtr_10_different_answers_derive_different_keys() {
    // GIVEN two continuations of one request that differ only in the answer
    let accepted = retry(Some(json!({"confirm": {"action": "accept"}})), Some("st-1"));
    let declined = retry(
        Some(json!({"confirm": {"action": "decline"}})),
        Some("st-1"),
    );
    // THEN the stored result of one must be unreachable by the other
    assert_ne!(
        accepted.key_discriminator(),
        declined.key_discriminator(),
        "answering a confirmation gate differently must not replay the first answer"
    );
}

#[test]
fn ac_mrtr_10_different_backend_state_derives_a_different_key() {
    // GIVEN two continuations with the same answer against different state
    let first = retry(Some(json!({"confirm": true})), Some("st-1"));
    let second = retry(Some(json!({"confirm": true})), Some("st-2"));
    // THEN they are distinct exchanges and must not share a cached result
    assert_ne!(
        first.key_discriminator(),
        second.key_discriminator(),
        "the backend's own state distinguishes two exchanges"
    );
}

#[test]
fn ac_mrtr_10_the_same_retry_derives_the_same_key() {
    // GIVEN the same retry expressed with its JSON keys in either order
    let one = retry(Some(json!({"a": 1, "b": 2})), Some("st-1"));
    let two = retry(Some(json!({"b": 2, "a": 1})), Some("st-1"));
    // THEN duplicate protection still recognises it, or the guard protects
    // nothing: a key that changes per attempt admits every attempt.
    assert_eq!(
        one.key_discriminator(),
        two.key_discriminator(),
        "the discriminator must be stable across JSON key ordering"
    );
}

#[test]
fn ac_mrtr_10_the_two_fields_cannot_be_transposed() {
    // GIVEN one retry whose state is a value, and another where that same value
    // appears in the answers instead
    let state_carries_it = retry(None, Some("x"));
    let answers_carry_it = retry(Some(json!({"": "x"})), None);
    // THEN they must not collide: concatenation without a separator is how two
    // different requests come to share one key.
    assert_ne!(
        state_carries_it.key_discriminator(),
        answers_carry_it.key_discriminator(),
        "the fields must be separated, not concatenated"
    );
}

// ===========================================================================
// MRTR.9 — the gateway MUST NOT relay an `inputRequest` of a type the client
// has not declared support for.
//
// The declaration is per capability, so the refusal is per entry: a client that
// declared `elicitation` and not `sampling` may be asked the one and not the
// other, and a verdict over the whole result cannot express that.
// ===========================================================================

mod capability_gate {
    use mcp_gateway::protocol::mrtr::InputRequired;
    use serde_json::json;

    fn interim(requests: &serde_json::Value) -> InputRequired {
        InputRequired::from_result(&json!({
            "resultType": "input_required",
            "inputRequests": requests,
            "requestState": "backend-opaque"
        }))
        .expect("a well-formed interim result")
    }

    fn declared(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[test]
    fn ac_mrtr_9_a_declared_type_is_relayed() {
        // GIVEN a client that declared `elicitation`
        // WHEN the backend asks for an elicitation
        let interim = interim(&json!({
            "confirm": { "method": "elicitation/create", "params": {} }
        }));
        // THEN nothing is refused: the gate must not block the exchange it
        // exists to make safe.
        assert!(
            interim.undeclared(&declared(&["elicitation"])).is_none(),
            "a declared capability must be relayable"
        );
    }

    #[test]
    fn ac_mrtr_9_an_undeclared_type_is_refused() {
        // GIVEN a client that declared `elicitation` and nothing else
        // WHEN the backend asks for sampling
        let interim = interim(&json!({
            "draft": { "method": "sampling/createMessage", "params": {} }
        }));
        let refused = interim
            .undeclared(&declared(&["elicitation"]))
            .expect("sampling was never declared");
        // THEN the refusal names the capability the client would have had to
        // declare, so the client can act on it rather than guess.
        assert_eq!(refused.capability, Some("sampling"));
        assert_eq!(refused.key, "draft");
    }

    #[test]
    fn ac_mrtr_9_each_entry_is_judged_on_its_own_capability() {
        // GIVEN one result carrying both a declared and an undeclared type
        let interim = interim(&json!({
            "confirm": { "method": "elicitation/create", "params": {} },
            "draft": { "method": "sampling/createMessage", "params": {} }
        }));
        // THEN the undeclared entry is found whichever position it holds — a
        // check that stopped at the first entry would pass this result.
        let refused = interim
            .undeclared(&declared(&["elicitation"]))
            .expect("the sampling entry must still be caught");
        assert_eq!(refused.key, "draft");
        assert_eq!(refused.capability, Some("sampling"));
    }

    #[test]
    fn ac_mrtr_9_an_unrecognised_type_is_refused_and_names_no_capability() {
        // A method outside the revision's vocabulary cannot have been declared:
        // the declaration is a list of capability names, and this has none.
        let interim = interim(&json!({
            "odd": { "method": "vendor/askSomething", "params": {} }
        }));
        let refused = interim
            .undeclared(&declared(&["elicitation", "sampling", "roots"]))
            .expect("an unclassifiable request must not be relayed");
        assert_eq!(refused.method, "vendor/askSomething");
        assert_eq!(
            refused.capability, None,
            "no capability may be named, or the client is told to declare one that does not exist"
        );
    }

    #[test]
    fn ac_mrtr_9_an_entry_carrying_no_method_is_refused() {
        // Fail closed. Skipping an entry the gate cannot read would relay it.
        let interim = interim(&json!({ "nameless": { "params": {} } }));
        assert!(
            interim
                .undeclared(&declared(&["elicitation", "sampling", "roots"]))
                .is_some(),
            "an entry with no method must be refused, not skipped"
        );
    }

    #[test]
    fn ac_mrtr_9_a_client_that_declared_nothing_is_asked_nothing() {
        let interim = interim(&json!({
            "confirm": { "method": "elicitation/create", "params": {} }
        }));
        assert!(
            interim.undeclared(&[]).is_some(),
            "an empty declaration permits no question at all"
        );
    }
}
