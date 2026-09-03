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
//!
//! ## This file is RED on purpose, and may not merge alone
//!
//! 15 of the 19 cases fail today, all on the same cause: the retry route
//! answers every presentation with the blanket `-32602` above, so no guard is
//! ever reached. They were written before the wiring so their first failure is
//! free — a case written afterwards is drafted against code its author has
//! already convinced themselves is correct.
//!
//! They are NOT `#[ignore]`d. An ignored test is one nobody runs and nobody
//! un-ignores, and the point of writing these first is lost the moment they
//! stop being consulted. The cost is the honest one: **this file merges with
//! the wiring increment or after it, never before**, because on `main` alone
//! it is a red suite with no path to green.
//!
//! The number is what separates "expected red" from "regression": 15 failing,
//! 4 passing, and `fixture_control_a_valid_retry_reaches_the_backend` among
//! the failures. A different count means something other than the missing
//! route is wrong, and the delta is where to look.
//!
//! The count is scaffolding for exactly one state of the tree. **The increment
//! that wires the retry route deletes this whole section**, because once the
//! route exists the expected count is zero failures and a pinned 15 becomes a
//! false alarm that outlives what it described.

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
use mcp_gateway::key_server::oidc::VerifiedIdentity;
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::protocol::continuation::{ContinuationError, ContinuationState, Payload};
use mcp_gateway::protocol::mrtr::{original_request_digest, principal_fingerprint};
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
/// Two callers the gateway can actually identify.
///
/// Subjects, not fingerprints: the fingerprint is derived by production from
/// the identity the request carries, and this file never computes one.
const CALLER_A: &str = "alice";
const CALLER_B: &str = "bob";

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
    // One continuation state, taken from the meta-MCP instance exactly as
    // `serve` takes it (`src/gateway/server/mod.rs:1175`). Constructing a
    // second one here would give the mint path and this file's assertions
    // different key material, and every genuine envelope would read as a
    // forgery.
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));
    let continuation = meta_mcp.continuation();
    Arc::new(AppState {
        env: None,
        meta_mcp,
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
        continuation,
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

/// The identity a request carries, as the OIDC layer would have left it.
///
/// Inserted as a request extension, which is where `handlers.rs:477` reads it
/// from; auth is disabled in this `AppState`, so no middleware overwrites it
/// (the same seam `src/gateway/router/tests.rs:1179` uses).
fn caller(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@corp"),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp".to_string(),
    }
}

/// The fingerprint production derives for `subject`.
///
/// Called, not reimplemented: the rule stays in `principal_fingerprint`, so a
/// hand-built payload that must match a real caller cannot drift from it.
fn fingerprint_of(subject: &str) -> String {
    principal_fingerprint(Some(&caller(subject))).expect("a verified identity has a fingerprint")
}

/// A handle obtained the way a client obtains one: the gateway minted it.
///
/// Nothing here recomputes a binding. The caller's principal fingerprint and
/// the original-request digest are both derived inside `mint_continuation`
/// (`src/gateway/meta_mcp/invoke.rs:372-394`) from the request this helper
/// posts. A fixture that re-derived either by the same rule as the
/// implementation would agree with whatever the implementation did, which is
/// the failure mode the test plan is written against.
///
/// The recorder is reset before returning: minting is arrange, and a case
/// that observed the mint's own backend call would be observing its own
/// setup.
///
/// `tool` must be one the fixture backend answers with an interim exchange —
/// a final answer mints nothing, which is the production contract, not a
/// fixture limitation.
async fn mint_for(
    state: &Arc<AppState>,
    received: &Received,
    subject: &str,
    tool: &str,
    args: &Value,
) -> String {
    let (_status, response) = post_as(state, &fresh_body(1, tool, args), subject).await;
    let handle = handle_the_client_received(state, &response).unwrap_or_else(|| {
        panic!("the gateway must mint a continuation for an interim exchange, answered {response}")
    });
    // The mint's own call is arrange, not evidence. Cleared here rather than at
    // each case, because a case that forgets does not fail loudly: it reads the
    // mint's call as the retry's and passes.
    received.lock().expect("recorder").clear();
    handle
}

/// An `AppState` with the fixture backend already behind `BACKEND`.
///
/// Every case that needs a minted handle needs a backend to mint against, now
/// that the handle comes from the production path rather than a hand-built
/// payload.
async fn state_with_fixture() -> (Arc<AppState>, Received) {
    let state = app_state();
    let (url, received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);
    (state, received)
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
    post_as(state, body, CALLER_A).await
}

/// The same request, made by a named caller.
///
/// Every request in this file carries an identity. An unauthenticated caller
/// resolves to the empty string (`src/gateway/router/handlers.rs:154-161`),
/// which is not an identity and which the controls keyed on it refuse — so a
/// retry posted without one can never be dispatched however correct the
/// wiring is, and every positive control would be permanently red for a
/// reason that has nothing to do with continuations.
async fn post_as(state: &Arc<AppState>, body: &Value, subject: &str) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).expect("body")))
        .expect("request");
    request.extensions_mut().insert(caller(subject));
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
///
/// It cannot say *which* guard refused, and no assertion here can:
/// `ContinuationError::client_message` (`src/protocol/continuation.rs:234-236`)
/// answers "continuation rejected" for all seven variants, deliberately. So a
/// case naming the expiry check is satisfied by the binding check refusing
/// first. Discriminating them is DE-9's to decide — the deferred question of
/// what a refusal answers under
/// (`docs/design/2026-08-30-mrtr-wiring.md`, DE-8) — and it has an owner there.
/// Recorded, not worked around: a substring hierarchy invented here would be a
/// test asserting a vocabulary production never agreed to.
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
// Both halves are expressible, because the handle comes from the production
// mint path and the request carries an identity.
//
// `mrtr::principal_fingerprint` (`src/protocol/mrtr.rs:357-365`) takes an
// `Option<&VerifiedIdentity>`, and the gateway reads that identity off the
// request extension (`src/gateway/router/handlers.rs:477`). So the negative is
// a handle minted while `CALLER_B` held the request and presented while
// `CALLER_A` does, and the positive is the same caller both times — neither
// side asserting a principal this file invented.
//
// What remains undecided is the principal of an API-key-only caller: the key
// is not retained past validation (`src/protocol/mrtr.rs:331-364`), so the
// verified-agent scheme is the only constructible one today. These cases do
// not depend on that answer.

/// GIVEN a handle minted for one principal, WHEN another presents it,
/// THEN the continuation guard refuses it.
#[tokio::test]
async fn ac_mrtr_4_a_handle_minted_for_one_principal_is_refused_for_another() {
    let (state, received) = state_with_fixture().await;
    let handle = mint_for(&state, &received, CALLER_B, TOOL_INTERIM, &arguments()).await;

    let (_status, response) =
        post(&state, &retry_body(1, TOOL_INTERIM, &arguments(), &handle)).await;

    assert_refused_by_the_continuation_guard(&response, "handle minted for a different principal");
}

/// GIVEN a handle minted against one tool, WHEN it is presented on another,
/// THEN the continuation guard refuses it.
#[tokio::test]
async fn ac_mrtr_4_a_handle_minted_for_one_tool_is_refused_for_another() {
    let (state, received) = state_with_fixture().await;
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &arguments()).await;

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
    let (state, received) = state_with_fixture().await;
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &arguments()).await;

    let (_status, response) =
        post(&state, &retry_body(1, TOOL_INTERIM, &arguments(), &handle)).await;

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
    let (state, received) = state_with_fixture().await;
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &arguments()).await;
    let body = retry_body(1, TOOL_INTERIM, &arguments(), &handle);

    let (_status, first) = post(&state, &body).await;
    let (_status, second) = post(&state, &body).await;

    assert_not_refused_by_the_continuation_guard(&first, "first redemption");
    assert_refused_by_the_continuation_guard(&second, "second redemption of the same handle");
}

/// GIVEN a handle whose deadline has passed, WHEN it is presented,
/// THEN it is refused.
///
/// The deadline is the only thing this case may stage. `Payload::mint` derives
/// `expires_at` from the clock and cannot be asked for a past one, so the
/// payload is re-minted with two timestamps moved — and every other field is
/// taken from a real production mint rather than rebuilt by hand.
///
/// Hand-building all eight fields is what this avoids, and the avoidance is not
/// stylistic: a hand-written `original_request_digest` silently drifted from the
/// tool the retry posts, and a digest mismatch is refused by the *binding*
/// guard, which would leave this case green in a build with no deadline check at
/// all. Deriving the fields makes that drift unconstructible.
///
/// The `jti` is inherited with the rest. It is unconsumed and its exchange is
/// still open, which is what a legitimate retry carries — presenting it is a
/// first presentation, not a replay, so it stages no second defect for a guard
/// to refuse ahead of the deadline.
///
/// `assert_refused_by_the_continuation_guard` cannot name the reason: every
/// `ContinuationError` variant renders to one client sentence by design
/// (`src/protocol/continuation.rs:224-236`, deferred as DE-9a), so the route
/// assertion proves the refusal came from this guard and nothing finer. The
/// `keyring().open` assertion below is what names expiry, at the one place the
/// distinction survives.
#[tokio::test]
async fn ac_mrtr_5b_a_handle_past_its_deadline_is_refused() {
    let (state, received) = state_with_fixture().await;
    let args = arguments();
    let live = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &args).await;
    let now = now_secs();
    let minted = state
        .continuation
        .keyring()
        .open(&live, now)
        .expect("a handle the gateway just minted must open");

    let expired = Payload {
        issued_at: now - 7200,
        expires_at: now - 3600,
        ..minted
    };
    let handle = state
        .continuation
        .keyring()
        .mint(&expired)
        .expect("the production keyring must mint an expired payload too");
    assert!(
        matches!(
            state.continuation.keyring().open(&handle, now),
            Err(ContinuationError::Expired)
        ),
        "the deadline must be this handle's only defect, or the refusal below \
         proves whichever guard runs first"
    );

    let (_status, response) = post(&state, &retry_body(1, TOOL_INTERIM, &args, &handle)).await;

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
    let (state, received) = state_with_fixture().await;
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &arguments()).await;
    let body = retry_body(1, TOOL_INTERIM, &arguments(), &handle);

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
/// **Expected RED until the retry route is wired.** Today `handlers.rs`
/// answers every retry with the blanket `-32602 "retry forwarding is not
/// available on this build"`, so the recorder stays empty. That red is the
/// point: when it turns green the other cases' empty recorders start carrying
/// information, and until it does they are marked as vacuous rather than
/// mistaken for evidence.
#[tokio::test]
async fn fixture_control_a_valid_retry_reaches_the_backend() {
    let (state, received) = state_with_fixture().await;
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
        fingerprint_of(CALLER_A),
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
    let (state, received) = state_with_fixture().await;
    let args = arguments();
    let genuine = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &args).await;

    let presentations = [
        (
            "in the clear, with no envelope at all",
            json!({
                "backend": BACKEND,
                "principal": fingerprint_of(CALLER_A),
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
    let (state, received) = state_with_fixture().await;
    let args = arguments();
    let genuine = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &args).await;

    // WHEN: presented unaltered.
    let (_, response) = post(&state, &retry_body(1, TOOL_INTERIM, &args, &genuine)).await;

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
///
/// Red today for two independent reasons, and it cannot yet tell them apart:
/// nothing writes the table, *and* the mint refuses this caller for want of a
/// principal (the answer in the message is the `-32003` refusal, not an
/// interim result). The second reason clears with DE-6; the first needs the
/// MRTR.7 bridge to exist. Stated here so a future reader does not read a
/// green as proof of wiring when it may only prove a principal arrived.
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

// ---------------------------------------------------------------------------
// MRTR.6 — a retry reaches the replica holding the exchange, or fails
// ---------------------------------------------------------------------------
//
// The criterion offers two arms and the accepted design took the second:
// `docs/design/2026-08-30-shared-continuation-state.md:116` forecloses affinity
// and `:103-104` prices the consequence. `6e744936` deleted `Routing::Elsewhere`
// accordingly, so "reach the holder" is not a behaviour this gateway can be
// tested for. What remains testable is the half the criterion actually forbids:
// **it MUST NOT silently start a second exchange.**
//
// That is why both cases below assert on the *fixture backend's recorder* and
// not only on the refusal. A refusal-only assertion is green today against the
// blanket `-32602`, green tomorrow against a correct implementation, and green
// against the one implementation MRTR.6 exists to forbid — one that answers the
// client with an error after having already opened a second exchange with the
// backend. The recorder is the only witness that separates those three.
//
// Can these fail for the wrong reason? Today, yes in one direction and it is
// stated rather than hidden: the recorder is empty because *nothing* dispatches,
// so the "no backend call" half passes vacuously and the red comes from the
// vocabulary half. `fixture_control_a_valid_retry_reaches_the_backend` is what
// stops that vacuity being permanent — it is the same route these cases drive,
// so once it is green an empty recorder here means a refusal that dispatched
// nothing rather than a route that cannot dispatch at all. The fresh-call
// control proves only that the recorder records.

/// GIVEN an exchange one replica holds, WHEN the retry arrives at a different
/// replica, THEN that replica refuses it and opens nothing with the backend.
///
/// Two whole `AppState`s, because that is what two replicas are. A single
/// process with a hand-swapped key proves AES key separation; it does not prove
/// that the production constructor builds a distinct key per process, which is
/// the property the whole cross-replica claim rests on.
///
/// The origin is asserted afterwards to still hold the handle unspent — the
/// neighbour's refusal must be the neighbour not knowing, never the attempt
/// having consumed a token the origin was still owed.
#[tokio::test]
async fn ac_mrtr_6_a_retry_at_another_replica_is_refused_and_opens_no_exchange() {
    // GIVEN: replica A minted the handle; replica B has a backend to dispatch to.
    let origin = app_state();
    let neighbour = app_state();
    let (url, received) = spawn_fixture_backend().await;
    register_fixture_backend(&origin, &url);
    register_fixture_backend(&neighbour, &url);
    let args = arguments();
    let handle = mint_for(&origin, &received, CALLER_A, TOOL_INTERIM, &args).await;
    // The exchange the origin is holding. Staged directly: no non-test caller
    // writes to this table yet, and `Payload` carries no hold key, so "the hold
    // for this handle" cannot be expressed — what can be is that the origin
    // holds an exchange and still holds it afterwards.
    let held = origin
        .continuation
        .in_flight()
        .hold(BACKEND, now_secs() + 60)
        .await
        .expect("the bounded table must admit one exchange");

    // WHEN: the retry lands on B, as a round-robin balancer will send it.
    let (_status, response) = post(&neighbour, &retry_body(1, TOOL_INTERIM, &args, &handle)).await;

    // THEN: refused in the continuation vocabulary — an explicit failure, which
    // is the arm this design took.
    assert_refused_by_the_continuation_guard(&response, "a neighbour replica's handle");

    // AND: nothing was opened with the backend. This is the half MRTR.6 forbids
    // by name, and the half a refusal-only assertion cannot see.
    let calls = received.lock().expect("recorder").clone();
    assert!(
        calls.is_empty(),
        "a replica that does not hold the exchange must not start a second one; \
         the fixture backend recorded {calls:?}"
    );

    // AND: the origin still holds it, in both senses. `open` answers only
    // authenticity — it verifies the seal and the deadline and never consults
    // the ledger — so on its own it would stay green through exactly the
    // cross-replica consumption this case exists to forbid. The ledger is what
    // says unspent; `open` is here so that an empty ledger cannot be satisfied
    // by a handle that was never real.
    assert!(
        origin
            .continuation
            .keyring()
            .open(&handle, now_secs())
            .is_ok(),
        "the handle must still be authentic, or what follows proves nothing"
    );
    assert_eq!(
        origin.continuation.ledger().len().await,
        0,
        "the neighbour's refusal must not consume the handle the origin still owes"
    );
    assert_eq!(
        origin.continuation.in_flight().len().await,
        1,
        "the neighbour's refusal must not end an exchange the origin is holding"
    );
    assert!(
        origin.continuation.in_flight().complete(&held).await,
        "the origin must still hold *that* exchange, not merely one of the same \
         shape"
    );
}

/// GIVEN a handle the origin minted for an exchange it no longer holds — the
/// deadline passed, or the backend connection dropped — WHEN the client retries
/// on that same origin, THEN it is refused rather than dispatched.
///
/// This is the one MRTR.6 outcome that survives on the *origin*, and the only
/// one no key-separation property can cover: the token opens, the ledger has it
/// unspent, and every check except the in-flight pin says yes. Without that pin
/// the gateway opens a second exchange with a legacy backend, which is exactly
/// what the criterion names.
///
/// The exchange is staged and then ended, never merely absent. An empty table
/// is the *never existed* state, and a gateway that refuses every exchange it
/// does not recognise satisfies that without one ever having existed — the
/// criterion is about an exchange this origin **no longer** holds, which only a
/// table that once held it can present. `complete` ends it rather than `reap`,
/// so the case turns on the exchange being gone and not on deadline timing.
///
/// The hold is staged directly because no non-test caller writes to the
/// in-flight table yet, and because a handle carries no correlation to a hold
/// key: `Payload` has no such field, so "the hold for *this* handle" is not
/// constructible today. The strongest available statement is that this origin
/// held an exchange against this backend and holds it no longer.
#[tokio::test]
async fn ac_mrtr_6_a_retry_whose_exchange_the_origin_no_longer_holds_is_refused() {
    // GIVEN: a handle this replica minted, and no exchange open for it.
    let state = app_state();
    let (url, received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);
    let args = arguments();
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &args).await;
    let held = state
        .continuation
        .in_flight()
        .hold(BACKEND, now_secs() + 60)
        .await
        .expect("the bounded table must admit one exchange");
    assert!(
        state.continuation.in_flight().complete(&held).await,
        "the staged exchange must be the one that ends, or the state under test \
         is not the one this case names"
    );
    assert_eq!(
        state.continuation.in_flight().len().await,
        0,
        "the exchange this handle continues must be gone before the retry, or \
         the case is not the one it names"
    );

    // WHEN: the client retries on the replica that minted it.
    let (_status, response) = post(&state, &retry_body(1, TOOL_INTERIM, &args, &handle)).await;

    // THEN: refused, and nothing was opened. The backend assertion carries the
    // criterion; the vocabulary assertion only says which guard answered.
    let calls = received.lock().expect("recorder").clone();
    assert!(
        calls.is_empty(),
        "a retry for an exchange that is gone must not silently start a second \
         one; the fixture backend recorded {calls:?}"
    );
    assert_refused_by_the_continuation_guard(&response, "a handle whose exchange is gone");
}

// ---------------------------------------------------------------------------
// MRTR.5d — single-use holds across replicas, under concurrency
// ---------------------------------------------------------------------------

/// GIVEN one handle, WHEN it is retried at two replicas at the same moment,
/// THEN exactly one backend call is made in total.
///
/// `ac_mrtr_5c_two_racing_redemptions_yield_exactly_one_success` races two
/// retries inside one process, where a shared ledger decides the winner.
/// `ac_mrtr_5d_a_handle_minted_by_another_process_is_refused` presents a foreign
/// handle sequentially. Neither reaches the implementation this row exists to
/// forbid: one that shares key material across replicas to make cross-replica
/// redemption *work*, and then has two independent ledgers that never consult
/// each other. That build passes 5c (one process, one ledger) and passes 5d in
/// the direction 5d asserts, while double-spending here.
///
/// Counted across both recorders rather than asserted per replica, because
/// which replica wins is not a property — only that the pair yields one.
#[tokio::test]
async fn ac_mrtr_5d_one_handle_retried_at_two_replicas_yields_one_backend_call() {
    let origin = app_state();
    let neighbour = app_state();
    let (origin_url, origin_calls) = spawn_fixture_backend().await;
    let (neighbour_url, neighbour_calls) = spawn_fixture_backend().await;
    register_fixture_backend(&origin, &origin_url);
    register_fixture_backend(&neighbour, &neighbour_url);
    let args = arguments();
    let handle = mint_for(&origin, &origin_calls, CALLER_A, TOOL_INTERIM, &args).await;

    // WHEN: both land together. `join` rather than sequential posts, so a
    // check-then-insert ledger has the window it needs to be wrong in.
    let here = retry_body(1, TOOL_INTERIM, &args, &handle);
    let there = retry_body(2, TOOL_INTERIM, &args, &handle);
    let (_a, _b) = tokio::join!(post(&origin, &here), post(&neighbour, &there));

    let total = origin_calls.lock().expect("recorder").len()
        + neighbour_calls.lock().expect("recorder").len();
    assert_eq!(
        total, 1,
        "one handle must buy exactly one backend call however many replicas see \
         it; the two fixture backends recorded {total} between them"
    );
}
