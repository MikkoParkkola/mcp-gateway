// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7212 cluster A — the MRTR criteria that only the request path can prove.
//!
//! `tests/mik_7212_acs.rs` proves the continuation primitives against values a
//! test constructs. These drive the gateway's own `tools/call` path with a
//! handle minted by the production `ContinuationState`, which is where the
//! criteria actually live: a property held by `Keyring` and never consulted by
//! a handler is not a property of this gateway.
//!
//! ## What these assert, and why it is not "a refusal happened"
//!
//! Every well-formed retry is refused today at
//! `src/gateway/router/handlers.rs:1051-1067` with `-32602 "retry forwarding is
//! not available on this build"` — before any binding, ledger or deadline is
//! consulted. A case asserting only that a retry was refused is green today for
//! a reason that has nothing to do with its criterion, and stays green when the
//! criterion is later broken.
//!
//! So each negative asserts the refusal is in the *continuation* vocabulary —
//! `ContinuationError::client_message()`, the sentence the guard answers with —
//! and each criterion carries a positive control that must NOT be refused. The
//! pair is what a blanket-refusal implementation cannot pass.
//!
//! One limit, recorded rather than worked around: `client_message()` is
//! deliberately one sentence for every variant
//! (`src/protocol/continuation.rs:233-236`), so *which* guard refused is not
//! observable at the wire. A component case cannot separate "wrong principal"
//! from "expired"; the unit cases in `mik_7212_acs.rs` do that, and these prove
//! the guard is reached at all.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::Config;
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::protocol::continuation::{ContinuationError, ContinuationState, Payload};
use mcp_gateway::protocol::mrtr::original_request_digest;
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The backend and tool every case in this file continues.
const BACKEND: &str = "backend";
const TOOL: &str = "tool";
/// The principal a handle is minted for. Opaque to the gateway — what matters
/// is that the negative pair differs from it in exactly one field.
const PRINCIPAL_A: &str = "fingerprint-a";
const PRINCIPAL_B: &str = "fingerprint-b";

/// One gateway process, built the way `serve` builds it.
///
/// `continuation` comes from `ContinuationState::new()` — the production
/// constructor — so handles minted here are minted under the key material the
/// running gateway would use, not bytes a test chose.
fn app_state() -> Arc<AppState> {
    let config = Config::default();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let agent_registry = Arc::new(AgentRegistry::new());
    Arc::new(AppState {
        env: None,
        meta_mcp: Arc::new(MetaMcp::new(Arc::clone(&backends))),
        backends,
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        auth_config: Arc::new(ResolvedAuthConfig::from_config(&config.auth)),
        key_server: None,
        tool_policy: Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default())),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
        sanitize_input: false,
        ssrf_protection: false,
        trust_configured_backends: false,
        inflight: Arc::new(tokio::sync::Semaphore::new(100)),
        agent_auth: AgentAuthState::new(false, agent_registry),
        gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        subscriptions: Arc::new(
            mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
        continuation: Arc::new(ContinuationState::new()),
    })
}

/// The arguments the original call carried, and the retry repeats.
fn arguments() -> Value {
    json!({ "city": "Helsinki" })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_secs()
}

/// A handle the *gateway* minted, for this principal and this original call.
///
/// The request binding comes from `mrtr::original_request_digest` — the
/// gateway's own derivation — rather than a digest this file recomputes. A
/// fixture that re-derived the binding by the same rule as the implementation
/// would agree with whatever the implementation did, which is the failure mode
/// the test plan is written against.
fn mint_for(state: &Arc<AppState>, principal: &str, tool: &str, args: &Value) -> String {
    let payload = Payload::mint(
        BACKEND.to_string(),
        Some("backend-opaque-state".to_string()),
        principal.to_string(),
        original_request_digest(BACKEND, tool, args),
        state.continuation.replica().to_string(),
        now_secs(),
    );
    state
        .continuation
        .keyring()
        .mint(&payload)
        .expect("the production keyring must mint")
}

/// A retry presented on the wire: `requestState` and `inputResponses` are
/// siblings of `name` and `arguments`, as the specification places them.
fn retry_body(id: u64, tool: &str, args: &Value, handle: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": args,
            "requestState": handle,
            "inputResponses": { "city": "Helsinki" }
        }
    })
}

async fn post(state: &Arc<AppState>, body: &Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).expect("body")))
        .expect("request");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router must answer");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The error message the response carries, or `None` when it carried a result.
fn error_message(response: &Value) -> Option<String> {
    response
        .get("error")?
        .get("message")?
        .as_str()
        .map(str::to_string)
}

/// THEN: the continuation guard refused this handle.
///
/// Asserted on the guard's own sentence, not on the fact of a refusal. The
/// blanket refusal at `handlers.rs:1051-1067` answers every retry, so
/// `is_err()` would pass today against a build that never looks at the handle.
fn assert_refused_by_the_continuation_guard(response: &Value, case: &str) {
    let message = error_message(response)
        .unwrap_or_else(|| panic!("{case}: the retry must be refused, and it was answered"));
    assert!(
        message.contains(ContinuationError::Malformed.client_message()),
        "{case}: refusal must come from the continuation guard, got {message:?}"
    );
}

/// THEN: the continuation guard did not refuse this handle.
///
/// The positive control of each pair. It says nothing about whether the call
/// then succeeded — no backend is registered, so it will not — only that the
/// handle was not what stopped it. Without this half, an implementation that
/// refuses every retry passes every negative in this file.
fn assert_not_refused_by_the_continuation_guard(response: &Value, case: &str) {
    if let Some(message) = error_message(response) {
        assert!(
            !message.contains(ContinuationError::Malformed.client_message()),
            "{case}: a valid handle must not be refused, got {message:?}"
        );
        assert!(
            !message.contains("retry forwarding is not available"),
            "{case}: a valid handle must reach the backend dispatch, got {message:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// MRTR.4 — a continuation is bound to its principal and its original request
// ---------------------------------------------------------------------------
//
// STOP, recorded per the "write down why" rule rather than faked.
//
// The negative half of the principal pair is expressible; the *positive* half
// is not, and the same gap makes the tool pair's control provisional.
//
// `mrtr::principal_fingerprint` (`src/protocol/mrtr.rs:357-365`) takes an
// `Option<&VerifiedIdentity>` and returns `None` without one. This `AppState`
// carries no OIDC identity, so a test cannot construct the value the gateway
// would compute for its own caller, and therefore cannot mint a handle whose
// principal *matches* that caller. What the gateway should use as the
// principal of an API-key-only caller is undecided in the code, not merely
// unwired.
//
// The negatives below survive that gap: `PRINCIPAL_A` and `PRINCIPAL_B` are
// plain words, and `principal_fingerprint` returns SHA-256 hex, so neither can
// ever equal a computed fingerprint whatever the decision turns out to be. The
// positive control cannot: it asserts a handle is *not* refused, and once
// forwarding is wired that assertion's fate depends on the undecided value.
// It is written anyway, and it is red today on its own assertion, but it must
// be revisited when the principal question is answered — a control whose
// correctness depends on an open design question is not yet a control.

/// GIVEN a handle minted for one principal, WHEN another presents it,
/// THEN the continuation guard refuses it.
#[tokio::test]
async fn ac_mrtr_4_a_handle_minted_for_one_principal_is_refused_for_another() {
    let state = app_state();
    let handle = mint_for(&state, PRINCIPAL_B, TOOL, &arguments());

    let (_status, response) = post(&state, &retry_body(1, TOOL, &arguments(), &handle)).await;

    assert_refused_by_the_continuation_guard(&response, "handle minted for a different principal");
}

/// GIVEN a handle minted against one tool, WHEN it is presented on another,
/// THEN the continuation guard refuses it.
#[tokio::test]
async fn ac_mrtr_4_a_handle_minted_for_one_tool_is_refused_for_another() {
    let state = app_state();
    let handle = mint_for(&state, PRINCIPAL_A, TOOL, &arguments());

    let (_status, response) =
        post(&state, &retry_body(1, "other-tool", &arguments(), &handle)).await;

    assert_refused_by_the_continuation_guard(&response, "handle minted against a different tool");
}

/// GIVEN a handle, WHEN presented on exactly what it was minted for,
/// THEN the continuation guard does not refuse it.
///
/// The load-bearing half: without it, an implementation that refuses every
/// retry passes both negatives above. See the STOP note for why this control
/// is provisional.
#[tokio::test]
async fn ac_mrtr_4_the_handle_it_was_minted_for_is_not_refused() {
    let state = app_state();
    let handle = mint_for(&state, PRINCIPAL_A, TOOL, &arguments());

    let (_status, response) = post(&state, &retry_body(1, TOOL, &arguments(), &handle)).await;

    assert_not_refused_by_the_continuation_guard(&response, "the handle's own request");
}

// ---------------------------------------------------------------------------
// MRTR.5a-c — single use, expiry, and atomicity on the minting process
// ---------------------------------------------------------------------------

/// GIVEN a handle already redeemed once, WHEN it is presented again,
/// THEN the second presentation is refused.
///
/// Both halves in one case on purpose: a ledger that refuses everything and a
/// ledger that refuses nothing are told apart only by asserting the first
/// redemption was *not* refused.
#[tokio::test]
async fn ac_mrtr_5a_a_handle_is_refused_on_its_second_redemption() {
    let state = app_state();
    let handle = mint_for(&state, PRINCIPAL_A, TOOL, &arguments());
    let body = retry_body(1, TOOL, &arguments(), &handle);

    let (_status, first) = post(&state, &body).await;
    let (_status, second) = post(&state, &body).await;

    assert_not_refused_by_the_continuation_guard(&first, "first redemption");
    assert_refused_by_the_continuation_guard(&second, "second redemption of the same handle");
}

/// GIVEN a handle whose deadline has passed, WHEN it is presented,
/// THEN it is refused.
///
/// The payload is built field by field rather than through `Payload::mint`,
/// which derives `expires_at` from the clock and so cannot be asked for a
/// deadline in the past. Every other field is what `mint_for` would produce,
/// including the gateway's own request digest.
#[tokio::test]
async fn ac_mrtr_5b_a_handle_past_its_deadline_is_refused() {
    let state = app_state();
    let now = now_secs();
    let payload = Payload {
        backend_id: BACKEND.to_string(),
        backend_request_state: Some("backend-opaque-state".to_string()),
        principal_fingerprint: PRINCIPAL_A.to_string(),
        original_request_digest: original_request_digest(BACKEND, TOOL, &arguments()),
        origin_replica: state.continuation.replica().to_string(),
        issued_at: now - 7200,
        expires_at: now - 3600,
        jti: "expired-handle".to_string(),
    };
    let handle = state
        .continuation
        .keyring()
        .mint(&payload)
        .expect("the production keyring must mint an expired payload too");

    let (_status, response) = post(&state, &retry_body(1, TOOL, &arguments(), &handle)).await;

    assert_refused_by_the_continuation_guard(&response, "handle one hour past its deadline");
}

/// GIVEN one handle, WHEN two redemptions race on the minting process,
/// THEN exactly one of them is refused.
///
/// A non-atomic ledger — read, decide, then mark — lets both observe the
/// handle unspent and both succeed. Asserting on the *count* rather than on
/// which one won is what makes the case deterministic under a scheduler that
/// may order the two either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ac_mrtr_5c_two_racing_redemptions_yield_exactly_one_success() {
    let state = app_state();
    let handle = mint_for(&state, PRINCIPAL_A, TOOL, &arguments());
    let body = retry_body(1, TOOL, &arguments(), &handle);

    let (left, right) = {
        let (a, b) = (Arc::clone(&state), Arc::clone(&state));
        let (one, two) = (body.clone(), body);
        let first = tokio::spawn(async move { post(&a, &one).await.1 });
        let second = tokio::spawn(async move { post(&b, &two).await.1 });
        (
            first.await.expect("first redemption task"),
            second.await.expect("second redemption task"),
        )
    };

    let refused = [&left, &right]
        .iter()
        .filter(|response| {
            error_message(response).is_some_and(|message| {
                message.contains(ContinuationError::Malformed.client_message())
            })
        })
        .count();
    assert_eq!(
        refused, 1,
        "exactly one of two racing redemptions must be refused, {refused} were: {left:?} {right:?}"
    );
}
