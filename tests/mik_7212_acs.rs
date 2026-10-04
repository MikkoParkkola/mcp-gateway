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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use mcp_gateway::protocol::continuation::{
    ContinuationError, ContinuationPurpose, Keyring, Payload,
};

fn payload() -> Payload {
    Payload {
        backend_id: "weather".to_string(),
        backend_request_state: Some("AEAD-protected blob from the backend".to_string()),
        principal_fingerprint: "sha256:caller-a".to_string(),
        original_request_digest: "sha256:req-1".to_string(),
        origin_replica: "gw-1".to_string(),
        // 200s wide, and every `open` below is called at 1_500 inside it.
        // `Keyring::mint` refuses a window wider than
        // `CONTINUATION_LIFETIME_SECS` (300), so a fixture spanning
        // 1_000..2_000 no longer seals — see MRTR.8b.
        issued_at: 1_400,
        expires_at: 1_600,
        jti: "jti-1".to_string(),
        hold_key: "exchange-1".to_string(),
        next_step: None,
        rounds_used: 0,
        // A backend `input_required` continuation: this file's envelopes are
        // the ones a backend retry redeems, not confirmation grants.
        purpose: ContinuationPurpose::BackendInput,
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

    // Decoded, not as the base64 string the client is handed. A signed-but-
    // readable envelope — plain JSON with a tag on it — is exactly the failure
    // this criterion names, and searching the *encoded* text would miss it:
    // "weather" is not a substring of the base64 of "weather".
    let decoded = B64
        .decode(&token)
        .expect("the envelope the client receives must at least be base64");
    let plain = String::from_utf8_lossy(&decoded);
    for secret in [
        "AEAD-protected",
        "weather",
        "sha256:caller-a",
        "sha256:req-1",
        "gw-1",
        "exchange-1",
    ] {
        assert!(
            !plain.contains(secret),
            "the client must not be able to read {secret:?} out of the \
             envelope it echoes back"
        );
    }
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
            matches!(
                keyring.open(&tampered, 1_500),
                Err(ContinuationError::NotAuthentic)
            ),
            "a modified envelope must be refused as inauthentic. `is_err()` \
             alone would also pass if it were refused for length or version, \
             which would not prove the AEAD tag is what caught it: {tampered}"
        );
    }
}

#[test]
fn ac_mrtr_3_a_garbage_envelope_is_refused_without_panicking() {
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
    for (junk, expected) in [
        ("", ContinuationError::Malformed),
        ("not-base64!!", ContinuationError::Malformed),
        ("AAAA", ContinuationError::Malformed),
        ("v1", ContinuationError::Malformed),
        (&"A".repeat(10_000), ContinuationError::TooLarge),
    ] {
        assert_eq!(
            keyring.open(junk, 1_500).err(),
            Some(expected),
            "arbitrary client input must be refused for the reason that \
             actually applies, so a refusal cannot drift onto another one \
             unnoticed: {junk}"
        );
    }
}

#[test]
fn ac_mrtr_5_an_expired_envelope_is_refused() {
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
    let token = keyring.mint(&payload()).expect("mint");
    assert!(matches!(
        keyring.open(&token, 1_601),
        Err(ContinuationError::Expired)
    ));
    // And exactly at the boundary it is still live, so the rule is a deadline
    // rather than an off-by-one.
    assert!(keyring.open(&token, 1_600).is_ok());
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
    assert_eq!(
        opened
            .redeemable_by("sha256:caller-b", "sha256:req-1")
            .err(),
        Some(ContinuationError::NotAuthentic),
        "a continuation minted for one caller must not redeem for another, and \
         the refusal must be the binding check rather than any other failure"
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

    assert_eq!(
        opened
            .redeemable_by("sha256:caller-a", "sha256:req-2")
            .err(),
        Some(ContinuationError::NotAuthentic),
        "a continuation must not carry over to a parallel request, and must \
         refuse it as a binding failure rather than any other refusal"
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

#[path = "mik_7212_acs/ledger.rs"]
mod ledger;

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

#[path = "mik_7212_acs/retry.rs"]
mod retry;

// ===========================================================================
// MIK-7212.MRTR.6 — a modern client retrying against a LEGACY backend that is
// holding an open request.
//
// The bridge, and the one direction that cannot be stateless on the backend
// side: the legacy backend is sitting inside an RPC waiting for an answer, and
// that RPC lives on exactly one replica. A stateless client's retry may land on
// any of them.
// ===========================================================================

#[path = "mik_7212_acs/inflight.rs"]
mod inflight;

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

#[path = "mik_7212_acs/reverse.rs"]
mod reverse;

// ===========================================================================
// MIK-7212.MRTR.10 — the idempotency key covers the continuation, and an
// interim result is never cached as a completed one.
// ===========================================================================

#[path = "mik_7212_acs/idempotency.rs"]
mod idempotency;

// ===========================================================================
// Review hardening — findings raised against `src/protocol/continuation.rs`
// by an independent reviewer, each pinned by a row that fails without the fix.
//
// These are not new acceptance criteria. They are the criteria NFR.SEC.4
// already asserted, re-stated at the points where the first implementation
// met them in letter and not in fact.
// ===========================================================================

#[path = "mik_7212_acs/hardening.rs"]
mod hardening;

#[path = "mik_7212_acs/mint_budget.rs"]
mod mint_budget;

#[path = "mik_7212_acs/envelope_size.rs"]
mod envelope_size;

// ===========================================================================
// Mirrored-header findings raised by review against the transport wiring.
// The specification makes header/body agreement a MUST for a server that
// processes the body, precisely so a routing decision and an execution
// decision cannot be taken from different sources. Both rows below are ways
// that guarantee failed while the check appeared to run.
// ===========================================================================

#[path = "mik_7212_acs/mirrored_headers.rs"]
mod mirrored_headers;

// ===========================================================================
// Round-4 and round-5 findings: the classifier decided an era from the body
// alone, so a request could declare itself modern in a header the gateway
// never read and take the legacy path past every modern check.
// ===========================================================================

#[path = "mik_7212_acs/classification.rs"]
mod classification;

#[path = "mik_7212_acs/validation.rs"]
mod validation;

#[path = "mik_7212_acs/era_resolution.rs"]
mod era_resolution;

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
    // Assigned field by field: `RetryFields` has a crate-private field, so a
    // struct literal cannot be written outside the crate.
    let mut retry = RetryFields::default();
    retry.input_responses = input_responses;
    retry.request_state = request_state.map(str::to_string);
    retry
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

#[path = "mik_7212_acs/capability_gate.rs"]
mod capability_gate;

// ===========================================================================
// MRTR.9a — the gateway MUST NOT relay an elicitation request in a MODE the
// client has not declared support for.
//
// Distinct from MRTR.9, which is per capability NAME and is met. The
// declaration is a substructure, not a name: a client says
// `{"elicitation": {"form": {}}}` and means "form, and not url". The spec is
// explicit that both halves exist —
//
//   "Clients declaring the `elicitation` capability MUST support at least one
//    mode (`form` or `url`)."
//   "Servers MUST NOT send elicitation requests with modes that are not
//    supported by the client."
//     — https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation#capabilities
//
// and it pins both wire shapes this fixture uses, so neither is the test's
// invention: the declaration `{"elicitation": {"form": {}, "url": {}}}`, and
// the request `{"mode": "url", "url": ..., "message": ...}` inside
// `InputRequiredResult.inputRequests` (spec §"URL Mode Elicitation Requests":
// such a request "MUST specify `mode: \"url\"`, a `message`", and a `url`).
// An omitted `mode` "defaults to `\"form\"`", which is what makes the positive
// control below a legal form-mode request. The URL's own host is the only
// invented value and it is not load-bearing — the gate never dereferences it,
// and the spec's own illustration uses a reserved documentation domain this
// repository's tooling refuses to carry.
//
// LEVEL, stated because it is a concession. The obligation is discharged on
// the live invoke path, where `interim.undeclared(caller.input_capabilities)`
// refuses before the relay (`src/gateway/meta_mcp/invoke.rs`). This case joins
// the two production halves — `classify_request` reading the declaration, and
// `undeclared` judging the request — by hand, because the code that joins them
// is in `src/`, and `src/` is out of scope for this change. Both halves are
// production code and neither is stubbed; only the wiring between them is the
// test's.
//
// DE-9 is untouched: these assert THAT a request is refused, never under which
// error code. The code is the deferred decision, and it is not this test's.
// ===========================================================================

#[path = "mik_7212_acs/elicitation_mode_gate.rs"]
mod elicitation_mode_gate;

// ===========================================================================
// MIK-7212.MRTR.9a — the coverage matrix
//
// Seven declaration shapes against four requested modes, from the test plan's
// table (`docs/design/2026-09-03-mrtr-9a-test-plan.md`). Every cell states
// relay or refusal; the last row stands for four non-object values and each is
// run in full, so 28 cells expand to 40 assertions.
//
// Every declaration arrives through `classify_request`, the production parser.
// A fixture that built the flags by hand would agree with itself about
// normalization the gate is supposed to own — and would pass the
// `{"telepathy":{}}` row by construction rather than by checking it.
// ===========================================================================

#[path = "mik_7212_acs/elicitation_mode_matrix.rs"]
mod elicitation_mode_matrix;
