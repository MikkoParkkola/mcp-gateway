// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7246.CONFIRM.2` — the confirmation gate MUST be reachable through the
//! modern (2026-07-28) stateless path.
//!
//! Written before the mechanism exists, so the failure is the free one: it
//! fails because the in-band ask is unbuilt, not because a fixture was bent to
//! make it fail. The shape asserted is the one fixed by
//! `docs/design/2026-09-09-confirm-2-in-band-schema-and-wiring.md`, spelled in
//! the wire vocabulary `src/protocol/mrtr.rs:238-249` parses.
//!
//! What is deliberately NOT asserted: the refusal branch. On unmodified source
//! a modern destructive call is already refused with `none could be obtained`
//! (`src/gateway/router/handlers.rs:1425-1434` builds `Elicit` unconditionally;
//! `src/gateway/destructive_confirmation.rs:75-95` refuses on `Unsupported`),
//! and `tests/mik_7215_acs.rs` closes CONFIRM.1a on that substring. A test of
//! that branch passes against source nobody has touched, which proves nothing
//! about this row.

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
fn admin_state() -> std::sync::Arc<mcp_gateway::gateway::test_helpers::AppState> {
    state(Fixture {
        auth: AuthConfig {
            enabled: true,
            bearer_token: None,
            api_keys: vec![ApiKeyConfig {
                key: "admin-key".to_string(),
                name: "admin-client".to_string(),
                rate_limit: 0,
                backends: Vec::new(),
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
}

const ADMIN_BEARER: (&str, &str) = ("authorization", "Bearer admin-key");

fn destructive_call() -> Value {
    modern(
        "tools/call",
        json!({
            "name": "gateway_kill_server",
            "arguments": { "server": "confirm2-sentinel" }
        }),
    )
}

/// `MIK-7246.CONFIRM.2` — a modern stateless caller is ASKED, not refused.
#[tokio::test]
async fn modern_destructive_call_asks_in_band() {
    let state = admin_state();
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
    let state = admin_state();
    let (_, ask) = post(&state, destructive_call(), &[ADMIN_BEARER]).await;
    let envelope = ask
        .pointer("/result/requestState")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    assert!(
        !envelope.is_empty(),
        "no envelope to redeem — the ask half is unbuilt, so the decline \
         branch cannot be exercised: {ask}"
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
