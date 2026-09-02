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
use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{BackendConfig, Config, FailsafeConfig, TransportConfig};
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
/// The fixture tool that answers with an interim result of its own.
const TOOL_INTERIM: &str = "tool-interim";
/// The principal a handle is minted for. Opaque to the gateway — what matters
/// is that the negative pair differs from it in exactly one field.
/// The backend's own opaque state, sealed inside every handle minted here.
/// A retry must deliver *this* to the backend — never the client's envelope.
const SEALED_STATE: &str = "backend-opaque-state";
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
        Some(SEALED_STATE.to_string()),
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

/// The sentence the build-time refusal raises, copied from production.
///
/// It is a bare literal on both sides — production raises it inline
/// (`src/gateway/router/handlers.rs:1064`) and nothing but this constant ties
/// the two together. The coupling matters because the assertion using it is
/// *negated*: reword the production message and `contains` stops matching, the
/// negation becomes true, and the control goes green having stopped checking
/// the thing it exists to check. Making it a compile error needs a `pub const`
/// in production, which is a `src/` edit this test-first batch does not take.
/// `production_still_raises_the_retry_unavailable_sentence` is the substitute:
/// it turns the drift into a red test instead of a silent pass.
const RETRY_UNAVAILABLE: &str = "retry forwarding is not available";

/// CONTROL, not an acceptance criterion: the literal above still exists in
/// production. Red the moment someone rewords the refusal, which is the moment
/// `assert_not_refused_by_the_continuation_guard` would otherwise go vacuous.
#[test]
fn production_still_raises_the_retry_unavailable_sentence() {
    let handlers = include_str!("../src/gateway/router/handlers.rs");
    assert!(
        handlers.contains(RETRY_UNAVAILABLE),
        "production no longer raises {RETRY_UNAVAILABLE:?} — the negated assertion in \
         assert_not_refused_by_the_continuation_guard is now vacuous. Re-point both at the \
         new sentence, or promote it to a shared `pub const`."
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
            !message.contains(RETRY_UNAVAILABLE),
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
        backend_request_state: Some(SEALED_STATE.to_string()),
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

// ---------------------------------------------------------------------------
// The backend fixture — shared by every row that asserts on what *arrived*
// ---------------------------------------------------------------------------
//
// MRTR.1 and MRTR.2 assert on what the backend received. Nothing arrives today,
// because the retry is refused at the router. That means a fixture which never
// worked would produce exactly the same red as a working fixture observing a
// correct refusal — the two are indistinguishable without a control. So the
// fixture carries its own: a *fresh* call must reach it and be recorded. Until
// that control passes, no row asserting on arrival is honest evidence.

/// Every `tools/call` params object the fixture backend received, in order.
type Received = Arc<std::sync::Mutex<Vec<Value>>>;

/// A loopback MCP server, and the record of what reached it.
async fn spawn_fixture_backend() -> (String, Received) {
    let received: Received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&received);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let sink = Arc::clone(&sink);
            async move { axum::Json(fixture_answer(&request, &sink)) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture backend must bind a loopback port");
    let address = listener.local_addr().expect("the bound port must be known");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}/"), received)
}

/// The fixture's whole protocol surface: enough to be discovered and called.
fn fixture_answer(request: &Value, sink: &Received) -> Value {
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "fixture", "version": "0" }
        }),
        Some("tools/list") => json!({
            "tools": [
                { "name": TOOL, "description": "d", "inputSchema": { "type": "object" } },
                { "name": TOOL_INTERIM, "description": "d", "inputSchema": { "type": "object" } }
            ]
        }),
        Some("tools/call") => {
            let params = request.get("params").cloned().unwrap_or(Value::Null);
            let interim = params.get("name").and_then(Value::as_str) == Some(TOOL_INTERIM);
            sink.lock()
                .expect("the recorder is never poisoned")
                .push(params);
            if interim {
                // The shape `InputRequired::from_result` classifies as interim
                // (`src/protocol/mrtr.rs:225-262`), carrying the backend's own
                // opaque state — the value MRTR.2 says must never be relayed.
                // State-only, and deliberately: a result carrying questions
                // would be refused by the capability gate before any handle is
                // minted (MRTR.9), and MRTR.2 is about the state, not the
                // questions. `from_result` accepts this shape
                // (`src/protocol/mrtr.rs:250-262`).
                json!({ "resultType": "input_required", "requestState": SEALED_STATE })
            } else {
                json!({ "content": [ { "type": "text", "text": "ok" } ] })
            }
        }
        _ => json!({}),
    };
    json!({
        "jsonrpc": "2.0",
        "id": request.get("id").cloned().unwrap_or(Value::Null),
        "result": result
    })
}

/// Put the fixture behind the name every case in this file continues.
fn register_fixture_backend(state: &Arc<AppState>, url: &str) {
    let config = BackendConfig {
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    let backend = Backend::new(
        BACKEND,
        config,
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    );
    assert!(
        state.backends.register(Arc::new(backend)),
        "the fixture backend must register under a name nothing else holds"
    );
}

/// A fresh call, carrying neither continuation field.
///
/// Routed through `gateway_invoke`. A backend tool is reachable from
/// `tools/call` by its own name only when an operator has pinned it into the
/// surfaced map (`src/gateway/meta_mcp/mod.rs:1371`); every other backend tool
/// arrives this way. The criteria are about what the gateway forwards to a
/// backend, not about which of the two exposures the operator chose, so the
/// case takes the one that needs no configuration to exist.
fn fresh_body(id: u64, tool: &str, args: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": tool, "arguments": args }
        }
    })
}

/// GIVEN the fixture backend, WHEN a fresh call is made, THEN it arrives.
///
/// Not an acceptance criterion — the control that makes MRTR.1 and MRTR.2
/// readable. If this fails, every "the backend received nothing" assertion in
/// this file is measuring the fixture rather than the gateway.
#[tokio::test]
async fn fixture_control_a_fresh_call_reaches_the_backend() {
    let state = app_state();
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

/// GIVEN a handle the gateway minted, WHEN a retry presents it in each of the
/// three shapes a server may legitimately send back, THEN the backend receives
/// the continuation the handle sealed — and nothing the client authored.
///
/// The fourth shape, neither field, is the fresh call: it is
/// `fixture_control_a_fresh_call_reaches_the_backend`, which passes today and
/// is what stops this row's red from being a broken fixture.
///
/// `requestState` is asserted to be the backend's own sealed state, not the
/// handle presented. Echoing the client's envelope back to the backend would
/// hand a server a value it never issued, which is the whole reason the
/// gateway mints one (`src/protocol/continuation.rs:71`).
#[tokio::test]
async fn ac_mrtr_1_a_retry_reaches_the_backend_carrying_what_it_continued() {
    let answers = json!({ "city": "Helsinki" });
    let cases: [(&str, bool, Option<Value>); 3] = [
        ("both fields", true, Some(answers.clone())),
        ("responses only", false, Some(answers.clone())),
        ("state only", true, None),
    ];

    for (index, (case, with_state, responses)) in cases.into_iter().enumerate() {
        let state = app_state();
        let (url, received) = spawn_fixture_backend().await;
        register_fixture_backend(&state, &url);
        let handle = mint_for(&state, PRINCIPAL_A, TOOL, &arguments());

        let body = retry_via_invoke(
            index as u64 + 1,
            TOOL,
            &arguments(),
            with_state.then_some(handle.as_str()),
            responses.clone(),
        );
        let (_status, response) = post(&state, &body).await;

        let calls = received.lock().expect("recorder").clone();
        assert_eq!(
            calls.len(),
            1,
            "{case}: the retry must reach the backend, it recorded {calls:?}; \
             the gateway answered {response}"
        );
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

/// The first string anywhere in `value` that the *production* keyring opens.
///
/// Deliberately not "the field named `requestState`": the criterion is about
/// which value reaches the client, not where it sits, and a test that knew the
/// path would still pass if the gateway relayed the backend's string under a
/// different one. Strings that are themselves JSON are descended into, because
/// an invoke result travels back as text.
fn handle_the_client_received(state: &Arc<AppState>, value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            if state.continuation.keyring().open(text, now_secs()).is_ok() {
                return Some(text.clone());
            }
            let nested: Value = serde_json::from_str(text).ok()?;
            handle_the_client_received(state, &nested)
        }
        Value::Array(items) => items
            .iter()
            .find_map(|item| handle_the_client_received(state, item)),
        Value::Object(map) => map
            .values()
            .find_map(|item| handle_the_client_received(state, item)),
        _ => None,
    }
}

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
    let state = app_state();
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

// ---------------------------------------------------------------------------
// MRTR.3 — a client-presented handle is attacker-controlled (wire half)
// ---------------------------------------------------------------------------
//
// The plan's original oracle — four presentations "each refused with a distinct
// reason" — is not satisfiable here and must not be faked. `client_message()`
// answers one constant for every variant
// (`src/protocol/continuation.rs:234-236`); the per-variant text exists only in
// `Display` (`:239-253`) and never reaches a client. So:
//
//   * distinctness is proved at unit level, on the `ContinuationError` variant;
//   * the wire proves the constant, and nothing more.
//
// The gap between those two is a finding about the requirement, not a hole in
// this file: "each refused with a distinct reason" is unobservable at the wire
// by design, and nobody should later read these cases as covering it. The
// collapse is treated as the specification — a verifier that tells an attacker
// whether a forgery failed for want of a signature, a known key, or an intact
// tag tells them which to fix next.
//
// Four identical refusals cannot fail against a verifier that refuses
// everything, which is exactly what this build does today. The positive control
// is therefore not decoration; it is the only case at this level that
// discriminates a correct verifier from a blanket one.

/// A handle minted by a *different* gateway process.
///
/// `ContinuationState::new()` draws its own key material, so this is the
/// arrangement the accepted design deploys — independent keys per process, no
/// shared store (`docs/design/2026-08-30-shared-continuation-state.md:107-120`).
/// The payload is identical in every field; only the minting key differs.
fn mint_on_a_foreign_process(tool: &str, args: &Value) -> String {
    let foreign = ContinuationState::new();
    let payload = Payload::mint(
        BACKEND.to_string(),
        Some(SEALED_STATE.to_string()),
        PRINCIPAL_A.to_string(),
        original_request_digest(BACKEND, tool, args),
        foreign.replica().to_string(),
        now_secs(),
    );
    foreign
        .keyring()
        .mint(&payload)
        .expect("the foreign keyring must mint")
}

/// Flip one character in the middle of an envelope, leaving its length intact.
///
/// The tampered byte lands in the sealed body, so the envelope stays
/// well-formed and only its authentication can catch it.
fn tamper(handle: &str) -> String {
    let mut chars: Vec<char> = handle.chars().collect();
    let middle = chars.len() / 2;
    chars[middle] = if chars[middle] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

#[tokio::test]
async fn ac_mrtr_3_every_forged_presentation_is_refused_by_the_continuation_guard() {
    // GIVEN: a genuine handle, and four ways a client can present something else.
    let state = app_state();
    let args = arguments();
    let genuine = mint_for(&state, PRINCIPAL_A, TOOL, &args);

    let presentations = [
        (
            "in the clear, with no envelope at all",
            json!({
                "backend": BACKEND,
                "principal": PRINCIPAL_A,
                "backend_request_state": SEALED_STATE
            })
            .to_string(),
        ),
        (
            "minted by a process with independent key material",
            mint_on_a_foreign_process(TOOL, &args),
        ),
        (
            "truncated envelope",
            genuine[..genuine.len() - 8].to_string(),
        ),
        ("tampered body, envelope otherwise intact", tamper(&genuine)),
    ];

    // Every row is driven before anything is asserted, so one failing
    // presentation cannot hide the colour of the three behind it.
    let mut offenders: Vec<String> = Vec::new();
    for (index, (case, handle)) in presentations.iter().enumerate() {
        // WHEN: it is presented on the retry path.
        let (_, response) = post(&state, &retry_body(index as u64 + 1, TOOL, &args, handle)).await;

        // THEN: refused in the continuation vocabulary — the same sentence for
        // all four, which is what the wire specifies. The HTTP status is not
        // asserted: a 400 and a 200-with-error are both refusals, and pinning
        // one would fail a case for a reason that is not its criterion.
        let message = error_message(&response)
            .unwrap_or_else(|| format!("not refused at all, response was {response}"));
        if !message.contains(ContinuationError::Malformed.client_message()) {
            offenders.push(format!("{case}: got {message:?}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "every forged presentation must be refused by the continuation guard; these were not: \
         {offenders:#?}"
    );
}

#[tokio::test]
async fn ac_mrtr_3_a_genuine_handle_is_still_accepted() {
    // GIVEN: the handle this gateway minted, for this principal and this call.
    let state = app_state();
    let args = arguments();
    let genuine = mint_for(&state, PRINCIPAL_A, TOOL, &args);

    // WHEN: presented unaltered.
    let (_, response) = post(&state, &retry_body(1, TOOL, &args, &genuine)).await;

    // THEN: the guard did not stop it. Without this half, refusing every
    // presentation passes all four negatives above.
    assert_not_refused_by_the_continuation_guard(&response, "a genuine handle");
}

// ---------------------------------------------------------------------------
// MRTR.5d — a handle does not travel between processes
// ---------------------------------------------------------------------------
//
// The plan files this at `integration`, on the reading that a second process is
// needed. What the criterion actually asserts is that key material is per
// process and a foreign envelope cannot be opened — and two `ContinuationState`
// values already have independent key material, because that is what
// `ContinuationState::new()` does. A second OS process would add a port and a
// binary, not a stronger assertion: the envelope is refused for the same reason
// either way, and this level can observe the refusal's vocabulary, which a
// process boundary would only make harder to read.
//
// Recorded as a plan-vs-code disagreement rather than silently re-levelled. If
// the operator wants the process boundary itself proved, that is a different
// criterion — about deployment, not about continuations.

#[tokio::test]
async fn ac_mrtr_5d_a_handle_minted_by_another_process_is_refused() {
    // GIVEN: a handle minted under key material this process never held.
    let state = app_state();
    let args = arguments();
    let foreign = mint_on_a_foreign_process(TOOL, &args);

    // WHEN: presented to this process.
    let (_, response) = post(&state, &retry_body(1, TOOL, &args, &foreign)).await;

    // THEN: refused explicitly, in the continuation vocabulary — never silently
    // treated as a fresh call, which is the failure mode a status-only
    // assertion would miss.
    assert_refused_by_the_continuation_guard(&response, "a foreign process's handle");
}

// ---------------------------------------------------------------------------
// MRTR.8 — the bounded table is the gateway's, not just the type's
// ---------------------------------------------------------------------------

/// An exchange the gateway opened must occupy a slot in the bounded table.
///
/// Both bounds MRTR.8 names are already held at `unit` against the type, and
/// held well: `tests/mik_7212_acs.rs:439` refuses at capacity rather than
/// growing, and `:457` reclaims an abandoned exchange *and* asserts its slot
/// comes back, which is the non-vacuous form the test plan asks for. Neither
/// says anything about the gateway. Nothing in `src/` calls `InFlight::hold`
/// — `ContinuationState` builds the table (`src/protocol/continuation.rs:767`)
/// and exposes it (`:786`) to no production caller — so the request path never
/// puts an entry there to bound. A table the gateway never fills is bounded
/// the way an empty room is quiet.
///
/// This is the half no unit case can reach, and it is the whole of what MRTR.8
/// still owes: the count bound and the lifetime bound are proved; their
/// subject is not.
#[tokio::test]
async fn ac_mrtr_8_an_exchange_the_gateway_opened_occupies_a_slot() {
    let state = app_state();
    let (url, _received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);

    let (_status, response) = post(&state, &fresh_body(1, TOOL_INTERIM, &arguments())).await;

    assert_eq!(
        state.continuation.in_flight().len().await,
        1,
        "a backend that asked for input leaves an exchange open, and an open \
         exchange must occupy a slot in the bounded table; the table holds \
         nothing, and the gateway answered {response}"
    );
}

/// The discriminator for the case above: a call that finished holds no slot.
///
/// Green today, and for the same reason everything about this table is green
/// today — nothing is ever written to it. It earns its place once the table is
/// wired: without it, an implementation that holds a slot for *every* call
/// satisfies the positive above while leaking a slot per request, which is the
/// exhaustion the bound exists to prevent.
#[tokio::test]
async fn ac_mrtr_8_a_call_that_finished_holds_no_slot() {
    let state = app_state();
    let (url, _received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);

    let (_status, response) = post(&state, &fresh_body(1, TOOL, &arguments())).await;

    assert_eq!(
        state.continuation.in_flight().len().await,
        0,
        "a call the backend answered outright opened no exchange, so it must \
         hold no slot; the gateway answered {response}"
    );
}
