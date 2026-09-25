// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7246.CONFIRM.2` — the confirmation gate MUST be reachable through the
//! modern (2026-07-28) stateless path.
//!
//! Written before the mechanism existed. The mechanism has since landed —
//! `handlers.rs:1462` hands a modern caller `ConfirmationChannel::InBand`
//! where it once built `Elicit` unconditionally, and `meta_mcp/mod.rs:2164`
//! mints the envelope and answers `input_required` — so these two tests are no
//! longer failing-by-construction. Both now execute and pass against a build,
//! so the ledger's `MET` cell for this row rests on measurement rather than on
//! a reading of the mechanism.
//!
//! The shape asserted is the one fixed by
//! `docs/design/2026-09-09-confirm-2-in-band-schema-and-wiring.md`, spelled in
//! the wire vocabulary `src/protocol/mrtr.rs:238-249` parses.
//!
//! What is deliberately NOT asserted: the `Unsupported` refusal. It is now the
//! legacy path's outcome, not the modern one, and `tests/mik_7215_acs.rs`
//! covers CONFIRM.1a on that substring. Asserting it here would observe the
//! other era's branch.

mod common;

use axum::http::StatusCode;
use common::{Fixture, modern, post, state};
use mcp_gateway::config::{ApiKeyConfig, AuthConfig};
use serde_json::{Value, json};

/// Server-assigned and echoed back verbatim by the client, so the version
/// lives here and nowhere else. Spelled once: a second spelling is a
/// discriminator that can disagree with itself.
const CONFIRMATION_KEY: &str = "io.mcp-gateway.destructive-confirmation.v1";

/// Admin, because `gateway_kill_server` — the only tool this build annotates
/// `destructiveHint: true` — is refused for everyone else by the admin check,
/// which runs *before* the confirmation gate. A non-admin caller never reaches
/// the code this criterion is about, and a 403 would look like a red test.
async fn admin_state() -> (
    std::sync::Arc<mcp_gateway::gateway::test_helpers::AppState>,
    tempfile::TempDir,
) {
    state(Fixture {
        auth: AuthConfig {
            enabled: true,
            bearer_token: None,
            api_keys: vec![ApiKeyConfig {
                key: None,
                key_sha256: Some(mcp_gateway::config::api_key_digest_spec(
                    "admin-key".as_bytes(),
                )),
                expires_at: None,
                name: "admin-client".to_string(),
                rate_limit: 0,
                backends: vec!["*".to_string()],
                allowed_tools: None,
                denied_tools: None,
                admin: true,
            }],
            public_paths: Vec::new(),
            client_circuit_breaker: None,
            single_user: false,
        },
        ..Fixture::default()
    })
    .await
}

const ADMIN_BEARER: (&str, &str) = ("authorization", "Bearer admin-key");

/// `crate::protocol::mrtr::IDEMPOTENCY_KEY_META`. A modern `tools/call` is
/// refused before it reaches the confirmation gate without one, so the key is
/// a precondition of this row, not part of what it asserts.
const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";

fn destructive_call() -> Value {
    let mut request = modern(
        "tools/call",
        json!({
            "name": "gateway_kill_server",
            "arguments": { "server": "confirm2-sentinel" }
        }),
    );
    request["params"]["_meta"][IDEMPOTENCY_KEY_META] = json!("confirm2-acs");
    request
}

/// `MIK-7246.CONFIRM.2` — a modern stateless caller is ASKED, not refused.
#[tokio::test]
async fn modern_destructive_call_asks_in_band() {
    let (state, _store_dir) = admin_state().await;
    let (status, body) = post(&state, destructive_call(), &[ADMIN_BEARER]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "JSON-RPC reports errors in the body: {body}"
    );

    // The row in one assertion: an unfinished round, not an error. A modern
    // caller that gets `/error` here has been refused for want of a session,
    // which is the defect CONFIRM.2 names.
    assert_eq!(
        body.pointer("/result/resultType").and_then(Value::as_str),
        Some("input_required"),
        "a modern destructive call must reach the gate and be ASKED, not refused: {body}"
    );

    assert!(
        body.pointer("/result/inputRequests")
            .and_then(|r| r.get(CONFIRMATION_KEY))
            .is_some(),
        "the ask must carry the versioned confirmation key, or an answer is \
         ambiguous about which question it answers: {body}"
    );

    // Without the sealed envelope the answer has nothing to come back on and
    // the ask degrades into a loop generator — strictly worse than the honest
    // refusal it replaced.
    assert!(
        body.pointer("/result/requestState")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty()),
        "the ask must carry the sealed continuation envelope: {body}"
    );
}

/// `MIK-7246.CONFIRM.2` — anything but JSON `true` is a decline, fail-closed.
///
/// Same mechanism as above: the redemption cannot exist until a mint does.
/// Kept separate so the two failures stay distinguishable rather than one
/// assertion standing for both branches.
#[tokio::test]
async fn non_true_answer_declines_rather_than_erroring() {
    let (state, _store_dir) = admin_state().await;
    let (_, ask) = post(&state, destructive_call(), &[ADMIN_BEARER]).await;
    let envelope = ask
        .pointer("/result/requestState")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    assert!(
        !envelope.is_empty(),
        "no envelope to redeem — the ask half did not mint one, so the \
         decline branch cannot be exercised: {ask}"
    );

    // `RetryFields::from_params` reads both at the top level of `params`
    // (`src/protocol/mrtr.rs:100-135`), not inside `_meta`.
    let mut retry = destructive_call();
    retry["params"]["inputResponses"] = json!({ CONFIRMATION_KEY: "yes" });
    retry["params"]["requestState"] = json!(envelope);
    let (_, body) = post(&state, retry, &[ADMIN_BEARER]).await;

    // A malformed answer DECLINES, never errors: an error hands a caller a way
    // to turn a decline into a retryable condition.
    let message = body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("Operator declined"),
        "a non-`true` answer must decline, distinguishably from the \
         no-confirmation-available refusal: {body}"
    );
}

/// `MIK-7246.CONFIRM.2` — an answered-`true` retry runs the action.
///
/// The branch neither test above reaches. Both stop at a refusal: one at the
/// ask, one at the decline, and a refusal returns before the call is
/// dispatched. Only `true` carries a *redeemed* envelope past the gate, which
/// is where a second consumer of a single-use continuation would be handed an
/// already-spent handle and answer `continuation rejected` — the approved
/// action silently becoming a stale-retry error.
#[tokio::test]
async fn true_answer_runs_the_action_rather_than_rejecting_the_continuation() {
    let (state, _store_dir) = admin_state().await;
    let (_, ask) = post(&state, destructive_call(), &[ADMIN_BEARER]).await;
    let envelope = ask
        .pointer("/result/requestState")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    assert!(!envelope.is_empty(), "no envelope to redeem: {ask}");

    let mut retry = destructive_call();
    retry["params"]["inputResponses"] = json!({ CONFIRMATION_KEY: true });
    retry["params"]["requestState"] = json!(envelope);
    let (_, body) = post(&state, retry, &[ADMIN_BEARER]).await;

    let message = body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();

    // `ContinuationError::client_message` — `src/protocol/continuation.rs:331`.
    // One string for every cause, so this substring is the whole MRTR.3
    // refusal family.
    assert!(
        !message.contains("continuation rejected"),
        "the approved call was refused as a spent continuation: the envelope \
         was redeemed by the gate and then presented again below it: {body}"
    );
    assert!(
        !message.contains("Operator declined"),
        "`true` is an approval, not a decline: {body}"
    );
    assert_ne!(
        body.pointer("/result/resultType").and_then(Value::as_str),
        Some("input_required"),
        "an answered call must not be asked the same question again: {body}"
    );
}
