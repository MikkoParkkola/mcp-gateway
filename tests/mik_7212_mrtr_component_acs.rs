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
//! Every well-formed retry used to be refused at
//! `src/gateway/router/handlers.rs` with `-32602 "retry forwarding is not
//! available on this build"` — before any binding, ledger or deadline was
//! consulted. A case asserting only that a retry was refused was green then for
//! a reason that had nothing to do with its criterion, and would have stayed
//! green when the criterion was later broken. That placeholder is gone now that
//! the route is wired, but the shape of these cases is what it left behind and
//! is worth keeping: a blanket refusal can be reintroduced by accident.
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

#[path = "mik_7212_mrtr_component_acs/arrival.rs"]
mod arrival;
#[path = "mik_7212_mrtr_component_acs/forgery_and_bounds.rs"]
mod forgery_and_bounds;
#[path = "mik_7212_mrtr_component_acs/principal_and_single_use.rs"]
mod principal_and_single_use;
#[path = "mik_7212_mrtr_component_acs/replicas.rs"]
mod replicas;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{BackendConfig, Config, FailsafeConfig, TransportConfig};
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::subscription_registry::SubscriptionRegistry;
use mcp_gateway::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, auth_state, create_router, open_runtime,
};
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
///
/// The `TempDir` is handed back with the state: the task store leases its
/// directory for as long as the service lives, so a directory dropped here
/// would be deleted under a gateway still answering. A fresh one per call keeps
/// the two-replica cases below two processes rather than one.
async fn app_state() -> (Arc<AppState>, tempfile::TempDir) {
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

    // One registry, shared with the executor that publishes through it.
    let subscriptions = Arc::new(SubscriptionRegistry::new(64, auth_state(&config.auth)));
    let store_dir = tempfile::tempdir().expect("a private task-store directory");
    let (tasks, task_executor) = open_runtime(
        &store_dir.path().join("tasks"),
        config.tasks.max_workers,
        StoreLimits::default(),
        Arc::clone(&subscriptions),
    )
    .await
    .expect("the fixture task store opens");

    let state = Arc::new(AppState {
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
        control_plane_base: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks,
        task_executor,
        subscriptions,
        continuation,
        session_lifecycle: None,
    });
    (state, store_dir)
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
async fn state_with_fixture() -> (Arc<AppState>, Received, tempfile::TempDir) {
    let (state, store_dir) = app_state().await;
    let (url, received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);
    (state, received, store_dir)
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
/// Asserted on the guard's own sentence, not on the fact of a refusal. An
/// `is_err()` assertion is satisfied by any build that refuses every retry
/// without ever reading the handle — the blanket refusal these cases were
/// written against, retired in `a69e2bc5`. Naming the sentence is what makes a
/// pass mean the guard ran, and a blanket refusal is exactly the thing that
/// gets reintroduced by accident.
///
/// It cannot say *which* guard refused, and no assertion here can:
/// `ContinuationError::client_message` (`src/protocol/continuation.rs:234-236`)
/// answers "continuation rejected" for all seven variants, deliberately. So a
/// case naming the expiry check is satisfied by the binding check refusing
/// first. Discriminating them is DE-9a's to decide — one client sentence for
/// seven causes, and what it costs a test
/// (`docs/design/2026-08-30-mrtr-wiring.md:687`) — and it has an owner there.
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

/// THEN: the continuation guard did not refuse this handle.
///
/// The positive control of each pair. It says nothing about whether the call
/// then succeeded — no backend is registered, so it will not — only that the
/// handle was not what stopped it. Without this half, an implementation that
/// refuses every retry passes every negative in this file.
///
/// One assertion covers every refusal the guard can raise, not just the
/// `Malformed` one it is spelled with: `ContinuationError::client_message`
/// returns the same sentence for every variant on purpose
/// (`src/protocol/continuation.rs:234`), so naming a variant here selects a
/// spelling, never a subset.
fn assert_not_refused_by_the_continuation_guard(response: &Value, case: &str) {
    if let Some(message) = error_message(response) {
        assert!(
            !message.contains(ContinuationError::Malformed.client_message()),
            "{case}: a valid handle must not be refused, got {message:?}"
        );
    }
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
