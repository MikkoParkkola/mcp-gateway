// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ADR-012 acceptance suite (MIK-7272.SUB.4): the idempotency guard records
//! execution, not admission.
//!
//! One test per acceptance row in
//! `docs/adr/ADR-012-idempotency-under-uncertain-execution.md`.
//!
//! The resend rows count deliveries that actually arrive at a backend rather
//! than attempts made by `with_retry`. The primitive takes a policy and a
//! closure and is told nothing about the request, so a row stated against it
//! would demand that it suppress retries its own policy enables — a
//! requirement no implementation can meet without breaking the contract
//! `src/failsafe/retry.rs:144` pins for every other caller. The decision the
//! ADR governs is made one level up, where `src/backend/ops.rs:218` knows the
//! method and chooses the policy it passes; a counting mock backend is what
//! observes that choice.
//!
//! The seams those rows were once gated on now exist: the `Failed` terminal
//! and the amendment A2 liveness token both ship, and `age_in_flight` reaches
//! the aged state without a five-minute wall-clock wait. One row remains
//! `#[ignore]`d, with a comment naming what it waits on, rather than faked
//! green or faked red.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};

use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{BackendConfig, Config, FailsafeConfig, TransportConfig};
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
use mcp_gateway::idempotency::{
    CheckOutcome, GuardOutcome, IN_FLIGHT_TIMEOUT, IdempotencyCache, IdempotencyReservation,
    enforce,
};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::protocol::mrtr::IDEMPOTENCY_KEY_META;
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use tower::ServiceExt;

/// A mutation. Carries no annotations at all, which under amendment A1 is the
/// same answer as `readOnlyHint: false`: deny.
const MUTATION: &str = "charge_card";

/// The permission the deny default is a default *for*: the backend states
/// `readOnlyHint: true` explicitly.
const ANNOTATED_READ: &str = "read_ledger";

/// A name that reads like a query and is not one. Amendment A1 exists because
/// an implementation may not infer permission from a name, so the row pinning
/// the deny default uses the name most likely to tempt one.
const READ_LOOKING_MUTATION: &str = "get_and_increment";

/// How the mock fails the `tools/call` it is sent.
#[derive(Clone, Copy)]
enum Fault {
    /// No answer ever comes and the caller's own request timeout fires. The
    /// request was delivered and the backend's answer is unknown.
    Silence,
    /// The request was read and the response body dies mid-flight — the
    /// dispatch boundary amendment A3 is phrased against, with the bytes
    /// already on the wire.
    BrokenResponse,
    /// A 200 carrying the JSON-RPC error a remote sends once it has forgotten
    /// the session, which drives the HTTP recovery path at
    /// `src/transport/http/mod.rs:1486-1510`.
    SessionExpired,
    /// The backend answered, and its answer is a refusal. Dispatch is not in
    /// doubt: the request arrived and the tool decided. Each refusal names its
    /// own delivery, so a replay is proved by content and not by a count alone.
    Refused,
}

struct Mock {
    fault: Fault,
    /// The tool name of every `tools/call` that arrived. Deliveries, not
    /// attempts: a resend that never left the gateway is not one.
    calls: Vec<String>,
}

fn tool(name: &str, annotations: Option<Value>) -> Value {
    let mut entry = json!({
        "name": name,
        "description": name,
        "inputSchema": {"type": "object", "properties": {}}
    });
    if let Some(annotations) = annotations {
        entry["annotations"] = annotations;
    }
    entry
}

async fn mcp_handler(State(mock): State<Arc<Mutex<Mock>>>, Json(body): Json<Value>) -> Response {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    match method.as_str() {
        "initialize" => (
            // A session id is what makes the recovery path at `mod.rs:1491`
            // reachable: it only re-handshakes for a caller that had a session
            // to lose.
            [(
                header::HeaderName::from_static("mcp-session-id"),
                "sub4-session",
            )],
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": mcp_gateway::protocol::PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "sub4-mock", "version": "0"}
                }
            })),
        )
            .into_response(),
        "tools/list" => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"tools": [
                tool(MUTATION, None),
                tool(ANNOTATED_READ, Some(json!({"readOnlyHint": true}))),
                tool(READ_LOOKING_MUTATION, None),
            ]}
        }))
        .into_response(),
        "tools/call" => {
            let (fault, delivery) = {
                let mut slot = mock.lock().expect("mock mutex poisoned");
                slot.calls.push(
                    body["params"]["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
                (slot.fault, slot.calls.len())
            };
            match fault {
                Fault::Silence => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Json(json!({"jsonrpc": "2.0", "id": id, "result": {}})).into_response()
                }
                Fault::BrokenResponse => {
                    let broken = futures::stream::once(async {
                        Err::<axum::body::Bytes, std::io::Error>(std::io::Error::other(
                            "connection reset after the request was written",
                        ))
                    });
                    (StatusCode::OK, axum::body::Body::from_stream(broken)).into_response()
                }
                Fault::SessionExpired => Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32015, "message": "Session not found"}
                }))
                .into_response(),
                Fault::Refused => Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32000, "message": format!("backend refused delivery {delivery}")}
                }))
                .into_response(),
            }
        }
        _ => Json(json!({"jsonrpc": "2.0", "id": id, "result": {}})).into_response(),
    }
}

async fn start_mock(fault: Fault) -> (String, Arc<Mutex<Mock>>) {
    let mock = Arc::new(Mutex::new(Mock {
        fault,
        calls: Vec::new(),
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(Arc::clone(&mock));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/mcp"), mock)
}

/// The production failsafe shape — retries enabled, the configured attempt
/// count — with only the sleep shortened, so the suite keeps testing the
/// policy the gateway actually runs rather than a copy of its values.
fn failsafe() -> FailsafeConfig {
    let mut config = FailsafeConfig::default();
    assert!(
        config.retry.enabled && config.retry.max_attempts > 1,
        "the resend rows need the shipped default to permit a resend, or they \
         pass without exercising anything"
    );
    config.retry.initial_backoff = Duration::from_millis(1);
    config.retry.max_backoff = Duration::from_millis(2);
    config
}

/// Which of the two backend-forwarding arms in
/// `src/gateway/router/backend_handlers.rs` a registered backend routes
/// through.
///
/// The choice is made by one config field and nothing else: the security gate
/// returns `Some(Ok(None))` for a pass-through backend
/// (`backend_handlers.rs:132`), so the request never reaches the tool-name
/// forward and falls through to the generic one. Each arm settles its own
/// failure, so each needs its own row.
#[derive(Clone, Copy)]
enum ForwardArm {
    /// `passthrough: false` — params are sanitized and sent by the tool-name
    /// arm.
    Sanitized,
    /// `passthrough: true` — the trusted-internal mode, forwarded verbatim by
    /// the fallback arm.
    Fallback,
}

fn backend_for(name: &str, url: &str, arm: ForwardArm) -> Backend {
    let config = BackendConfig {
        description: "ADR-012 resend mock".to_string(),
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        stop_when_idle_for: None,
        // Short enough that `Fault::Silence` reads as a backend timeout
        // without the suite waiting for one.
        timeout: Duration::from_millis(300),
        env: HashMap::default(),
        headers: HashMap::default(),
        oauth: None,
        secrets: Vec::new(),
        passthrough: matches!(arm, ForwardArm::Fallback),
        allow_cleartext_credentials: false,
        runtime_profile: None,
        identity_propagation: None,
    };
    Backend::new(name, config, &failsafe(), Duration::from_secs(300))
}

/// Deliveries of `name` that reached the backend for one failing `tools/call`.
///
/// Discovery runs first, exactly as it does in production: a `tools/call` is
/// always preceded by a `tools/list`, which is what puts the backend's
/// annotations within reach of the resend decision.
async fn deliveries(fault: Fault, name: &str) -> usize {
    let (url, mock) = start_mock(fault).await;
    let backend = backend_for("sub4-mock", &url, ForwardArm::Sanitized);
    backend
        .get_tools()
        .await
        .expect("discovery populates the tool cache");

    let outcome = backend
        .request("tools/call", Some(json!({"name": name, "arguments": {}})))
        .await;
    assert!(
        outcome.is_err() || matches!(&outcome, Ok(response) if response.error.is_some()),
        "the injected failure must surface rather than being answered normally"
    );

    let calls = mock.lock().expect("mock mutex poisoned").calls.clone();
    assert!(
        calls.iter().all(|called| called == name),
        "only the tool under test may be called, got: {calls:?}"
    );
    calls.len()
}

/// The reservation a dispatched call holds, admitted exactly as
/// `MetaMcp::direct_route_idempotency` admits one.
fn admit(cache: &Arc<IdempotencyCache>, key: &str) -> IdempotencyReservation {
    match enforce(cache, key, "backend:charge_card|{}").expect("first admission proceeds") {
        GuardOutcome::Proceed(reservation) => reservation,
        GuardOutcome::CachedResult(value) => panic!("unexpected cached result: {value}"),
        GuardOutcome::CachedError(error) => panic!("unexpected cached error: {error}"),
    }
}

/// The backend name the direct route rows register under, and the path segment
/// their requests address.
const ROUTE_BACKEND: &str = "sub4-route";

/// One gateway with the idempotency cache enabled, wired the way
/// `src/gateway/router/backend_handlers.rs` expects to find it.
///
/// The route rows run against the real router rather than the guard primitive
/// because the decision they pin — release or settle — is taken in the handler,
/// from an error the transport raised. A row that called `release()` itself
/// would assert the transition the test author chose, not the one the gateway
/// takes.
fn route_state() -> Arc<AppState> {
    let config = Config::default();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));

    let mut meta = MetaMcp::new(Arc::clone(&backends));
    meta.enable_idempotency(
        Arc::new(IdempotencyCache::new()),
        mcp_gateway::idempotency::CLEANUP_INTERVAL,
    );
    let meta_mcp = Arc::new(meta);
    let continuation = meta_mcp.continuation();

    Arc::new(AppState {
        session_lifecycle: None,
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
        agent_auth: AgentAuthState::new(false, Arc::new(AgentRegistry::new())),
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
        tasks: Arc::new(mcp_gateway::protocol::task_store::TaskStore::new()),
        subscriptions: Arc::new(
            mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
        continuation,
    })
}

fn register_route_backend(state: &Arc<AppState>, url: &str, arm: ForwardArm) {
    assert!(
        state
            .backends
            .register(Arc::new(backend_for(ROUTE_BACKEND, url, arm))),
        "the fixture backend must register under a name nothing else holds"
    );
}

/// A client's own direct-route `tools/call` frame, carrying `idempotency_key`
/// where a client can actually put it.
///
/// `id` varies per call because a re-issue after a broken stream is a second
/// JSON-RPC request; that is the whole shape the criterion is about.
fn keyed_call(id: u32, key: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": MUTATION,
            "arguments": {},
            "_meta": {IDEMPOTENCY_KEY_META: key}
        }
    })
}

/// POST to the direct backend route and read the status and body back.
async fn post_direct(state: &Arc<AppState>, body: Value) -> (StatusCode, Value) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{ROUTE_BACKEND}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .body(axum::body::Body::from(
            serde_json::to_vec(&body).expect("frame serializes"),
        ))
        .expect("request builds");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router must answer");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must read");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Row 1 — settling a dispatched call that errored stores a terminal outcome,
/// and the retry of that key is served the stored error rather than readmitted.
///
/// A transport failure after the backend performed the side effect is
/// indistinguishable from one before it, so the guard treats a dispatched
/// error as an outcome (ADR-012 consequence 1). This row pins the primitive;
/// the wiring is pinned at the route by
/// `direct_route_keeps_the_key_of_a_dispatched_call_that_errored` in
/// `tests/mik_7272_sub4_three_routes.rs`, which counts backend deliveries.
///
/// `Proceed` and `InFlight` are both refused: a key left wedged in flight also
/// keeps the retry away from the backend, but it strands the caller until
/// `IN_FLIGHT_TIMEOUT` instead of answering, and that is a different failure,
/// not a pass.
#[tokio::test]
async fn a_settled_dispatched_error_keeps_its_key() {
    let cache = Arc::new(IdempotencyCache::new());
    let mut reservation = admit(&cache, "key-dispatched-error");

    reservation.fail(&json!({ "code": -32000, "message": "backend refused" }));
    drop(reservation);

    let outcome = cache.check("key-dispatched-error");
    assert!(
        !matches!(outcome, CheckOutcome::Proceed),
        "a dispatched call answered with a backend error must keep its key \
         (ADR-012 consequence 1); the guard released it and would admit the \
         retry as a first attempt against a mutation that may already have \
         committed"
    );
    assert!(
        !matches!(outcome, CheckOutcome::InFlight),
        "the owner has dropped: the retry must be served the settled error, \
         not told to wait out `IN_FLIGHT_TIMEOUT` on a call nobody is running"
    );
    let CheckOutcome::Failed(error) = outcome else {
        panic!("a settled dispatched error must be served as a failed terminal");
    };
    assert_eq!(
        error.get("message").and_then(Value::as_str),
        Some("backend refused"),
        "the served value must carry the error the caller would otherwise have seen"
    );
}

/// Row 2 — a pre-dispatch failure releases its key, and the retry is a first
/// attempt.
///
/// It states the behaviour the other rows must not cost. Without it, an
/// implementation that settles *every* failure as `Failed` passes the rest of
/// this suite while wedging keys of calls that never left.
///
/// The failure is the ADR's own example — the backend is unreachable, so the
/// connection is refused and nothing was written — and the gateway raises it
/// through the real handler, which is where the release-or-settle decision is
/// taken (`settle_direct_failure`, `backend_handlers.rs:981`). A row that
/// called `release()` itself would assert the transition its author picked.
///
/// The status code is what separates the two answers: a served terminal is a
/// 200 carrying the stored error (`GuardOutcome::CachedError`), a live attempt
/// that failed again is a 500. So a second 500 is proof the retry was admitted
/// rather than answered from the cache.
///
/// **Do not weaken this row to an `is_connect()`-only assertion.** The
/// classification it depends on is a conjunction
/// (`security/http_diagnostics.rs:66`): reqwest must report `is_connect()`
/// *and* the failing hop's URL must still equal the URL the caller posted to.
/// The second half is a silent-failure hinge — hand the classifier a
/// reconstructed URL, a base URL, or a differently normalised trailing slash
/// and the comparison quietly returns false, the upgrade to
/// `Error::TransportConnect` never fires, and the behaviour reverts to
/// releasing nothing. Nothing panics and no log line changes, because
/// `TransportConnect` and `Transport` share a byte-identical `Display`. This
/// row is the only thing that observes it.
#[tokio::test]
async fn pre_dispatch_failure_releases_its_key() {
    // A port nothing listens on: bind it to learn an address that is free, then
    // give it up. Connecting is refused before a byte of the request is written.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let address = closed.local_addr().expect("local addr");
    drop(closed);

    let state = route_state();
    register_route_backend(
        &state,
        &format!("http://{address}/mcp"),
        ForwardArm::Sanitized,
    );

    let (first_status, first) = post_direct(&state, keyed_call(1, "key-unreachable")).await;
    assert_eq!(
        first_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the unreachable backend must surface as a failure, or the row proves \
         nothing about what that failure did to the key: {first}"
    );

    let (second_status, second) = post_direct(&state, keyed_call(2, "key-unreachable")).await;
    assert_eq!(
        second_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a failure raised before the request left for the backend must free the \
         key so the retry is a first attempt (ADR-012 decision, case 1); the \
         retry was served a stored terminal instead: {second}"
    );
}

/// Row 2b — the boundary row 2 must not cost: a transport failure raised
/// *after* the request was written KEEPS its key.
///
/// Row 2 can be turned green by widening whatever the gateway treats as
/// provably pre-dispatch until plain `Transport` is in it. That also releases
/// the key of a stream that broke with the bytes already on the wire, which is
/// the criterion itself — a side effect that may have committed, retried on a
/// clean key. Neither existing row catches it: row 1 pins a backend-*answered*
/// error against the guard primitive, and row 8 counts `with_retry` deliveries
/// without a key or a route in sight.
///
/// The count is asserted as a delta across the two POSTs rather than an
/// absolute, because what the resend sites do inside the first call is row 8's
/// question, not this one's.
#[tokio::test]
async fn a_post_dispatch_transport_failure_keeps_its_key() {
    let (url, mock) = start_mock(Fault::BrokenResponse).await;
    let state = route_state();
    register_route_backend(&state, &url, ForwardArm::Sanitized);

    let (_, first) = post_direct(&state, keyed_call(1, "key-broken-stream")).await;
    let dispatched = mock.lock().expect("mock mutex poisoned").calls.len();
    assert!(
        dispatched > 0,
        "the row is about a failure raised after dispatch, so the first call \
         must actually have reached the backend: {first}"
    );

    let (status, second) = post_direct(&state, keyed_call(2, "key-broken-stream")).await;

    assert_eq!(
        mock.lock().expect("mock mutex poisoned").calls.len(),
        dispatched,
        "a stream that broke with the request already written is not provably \
         pre-dispatch: its key must be settled, not released, or the retry \
         re-runs a mutation that may have committed (ADR-012 decision, case 3); \
         first={first}, second={second}"
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "the retry must be served the stored terminal, which is an answer: {second}"
    );
    assert_eq!(
        second.pointer("/error/message"),
        first.pointer("/error/message"),
        "the served terminal must carry the error the first caller saw"
    );
}

/// Row 2c — the same guarantee on the *other* forward arm: a pass-through
/// backend's failure keeps its key too.
///
/// Row 2b covers the tool-name arm only. A pass-through backend takes the
/// generic forward instead, which settles at its own call site
/// (`backend_handlers.rs:965`) — delete that one line and row 2b stays green
/// while a trusted-internal backend releases the key of a call it may have
/// executed. The two arms are the same rule written twice, so they need two
/// rows.
///
/// The assertion has to be a second HTTP request rather than a re-check of the
/// key, because `IdempotencyReservation`'s `Drop` releases an unsettled
/// reservation on the way out of the handler: anything asked after the handler
/// returns sees a freed key whether the settle ran or not. A second POST is
/// what distinguishes them — it is served the stored terminal only if the
/// first call settled before dropping.
#[tokio::test]
async fn a_passthrough_forward_failure_keeps_its_key() {
    let (url, mock) = start_mock(Fault::BrokenResponse).await;
    let state = route_state();
    register_route_backend(&state, &url, ForwardArm::Fallback);

    let (_, first) = post_direct(&state, keyed_call(1, "key-passthrough")).await;
    let dispatched = mock.lock().expect("mock mutex poisoned").calls.len();
    assert!(
        dispatched > 0,
        "the pass-through arm must actually forward, or this row is asserting \
         against a request the security gate rejected: {first}"
    );

    let (status, second) = post_direct(&state, keyed_call(2, "key-passthrough")).await;

    assert_eq!(
        mock.lock().expect("mock mutex poisoned").calls.len(),
        dispatched,
        "a pass-through backend's dispatched failure settles its key like any \
         other (ADR-012 consequence 1); the retry re-executed instead: \
         first={first}, second={second}"
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "the retry must be served the stored terminal: {second}"
    );
    assert_eq!(
        second.pointer("/error/message"),
        first.pointer("/error/message"),
        "the served terminal must carry the error the first caller saw"
    );
}

/// Row 3 — an unannotated `tools/call` that times out reaches the backend
/// exactly once.
///
/// `src/backend/ops.rs:218` passes `entry.failsafe.retry_policy` whatever the
/// method is, and a timeout is not provably pre-dispatch, so today the call is
/// delivered three times inside one reservation. Per amendment A1 resend
/// permission comes only from an explicit backend `readOnlyHint`/
/// `idempotentHint` of `true`; absent means deny.
#[tokio::test]
async fn unannotated_backend_timeout_reaches_the_backend_once() {
    let delivered = deliveries(Fault::Silence, MUTATION).await;

    assert_eq!(
        delivered, 1,
        "a `tools/call` carrying no explicit read-only or idempotent hint must \
         not be resent beneath the guard (ADR-012 consequence 2); the backend \
         received it {delivered} times inside one reservation"
    );
}

/// Row 3b — the permission the deny default is a default *for*: a call the
/// backend annotates `readOnlyHint: true` is still resent.
///
/// Deliberately green, and the reason row 3 is worth having. An
/// implementation that satisfies row 3 by disabling retries for every
/// `tools/call` turns this row red, which is the cost the ADR declines to pay.
#[tokio::test]
async fn an_explicitly_read_only_call_is_still_resent() {
    let delivered = deliveries(Fault::Silence, ANNOTATED_READ).await;

    assert!(
        delivered > 1,
        "a call the backend explicitly annotates `readOnlyHint: true` keeps its \
         resend permission (ADR-012 A1); it was delivered {delivered} time(s), \
         so the deny default has been applied to a call that granted permission"
    );
}

/// Row 4a — a second caller arriving on a key whose reservation passed
/// `IN_FLIGHT_TIMEOUT` while its owner is still alive is told in-flight, not
/// admitted.
///
/// Admission is the whole of this row. `decide_check_plan`
/// (`src/idempotency.rs:246-258`) answers `CheckPlan::InFlight` for a live
/// owner and a dead one alike, so the *staleness* of the dead half is
/// deliberately unobservable here — reclaiming is the sweep's job, which is
/// row 4b. Both halves are asserted anyway, because what this row pins is that
/// ageing past the timeout readmits nobody.
#[test]
fn live_owner_past_the_timeout_is_told_in_flight() {
    let cache = Arc::new(IdempotencyCache::new());
    let _reservation = admit(&cache, "key-live-aged");

    assert!(
        cache.age_in_flight("key-live-aged", IN_FLIGHT_TIMEOUT + Duration::from_secs(1)),
        "the seam must find the in-flight entry it is asked to age"
    );

    assert!(
        matches!(cache.check("key-live-aged"), CheckOutcome::InFlight),
        "a call still running past the timeout keeps its entry through \
         admission (ADR-012 A2): the second caller is told in-flight rather \
         than admitted against a key whose mutation is still running"
    );
    assert!(
        enforce(&cache, "key-live-aged", "backend:charge_card|{}").is_err(),
        "`enforce` must refuse the duplicate rather than mint a second \
         reservation for a key that is still owned"
    );

    // The never-readmit half: an aged entry whose owner is gone answers the
    // same way, because `decide_check_plan` maps `StaleInFlight` to
    // `CheckPlan::InFlight` too. Admission never trades staleness for a fresh
    // attempt; only the sweep acts on it.
    cache.mark_in_flight("key-dead-aged");
    assert!(cache.age_in_flight("key-dead-aged", IN_FLIGHT_TIMEOUT + Duration::from_secs(1)));
    assert!(
        matches!(cache.check("key-dead-aged"), CheckOutcome::InFlight),
        "an aged entry with no live owner is still not an invitation to re-run \
         the call at the admission surface: an admission that freed a key here \
         is the second execution on one key ADR-012 exists to stop"
    );
}

/// Row 4b — that same entry survives an explicit `evict_expired` sweep, and
/// an aged entry whose owner is gone does not.
///
/// A separate row because the sweep is the only public surface on which
/// staleness is observable at all: `evict_expired`
/// (`src/idempotency.rs:534`) retains on `!is_reclaimable(classify(entry))`,
/// the same predicate admission uses, so *"a call running past the timeout
/// keeps its entry through the background cleanup as well as through
/// admission"* (ADR-012 consequence 3).
///
/// Both halves are asserted, and that is what makes the row non-vacuous:
/// demanding survival of every aged in-flight entry would demand it of one
/// whose owner died too, removing the eviction consequence 3 depends on. The
/// requirement is that liveness decide the sweep, not that the sweep stop
/// deciding — the timeout then does what it was introduced for, *"reclaiming
/// entries whose owner is gone — and nothing else"*.
#[test]
fn a_live_reservation_survives_an_evict_expired_sweep() {
    let cache = Arc::new(IdempotencyCache::new());

    // Owned: `enforce` mints the token and the reservation holds it alive.
    let _live = admit(&cache, "key-live");
    // Ownerless by construction: `mark_in_flight` stores `Weak::new()`.
    cache.mark_in_flight("key-dead");

    let past_the_timeout = IN_FLIGHT_TIMEOUT + Duration::from_secs(1);
    assert!(cache.age_in_flight("key-live", past_the_timeout));
    assert!(cache.age_in_flight("key-dead", past_the_timeout));

    cache.evict_expired();

    assert!(
        matches!(cache.check("key-live"), CheckOutcome::InFlight),
        "the sweep must not reclaim a key whose call is still running: \
         evicting it readmits the next caller fresh against a mutation in \
         progress, which is the duplicate execution ADR-012 A2 closes"
    );
    assert!(
        matches!(cache.check("key-dead"), CheckOutcome::Proceed),
        "the sweep must still reclaim an aged entry whose owner is gone — \
         a liveness rule that retains everything past the timeout removes the \
         eviction consequence 3 depends on"
    );
}

/// Row 4c — a sweep landing while a reservation's settlement is in progress
/// does not evict its entry.
///
/// The race amendment A2 exists for, and the one rows 4a and 4b cannot state:
/// `Arc` drops the strong count to zero *before* running the inner value's
/// `Drop`, so `Weak::upgrade` returns `None` while the reservation is still
/// storing `Failed` (ADR-012:150-163). A liveness rule built on the
/// reservation's own refcount passes 4a and 4b and still loses the entry here,
/// admitting the next caller fresh against a key whose mutation may have
/// committed.
/// Stated as a one-sided invariant under arbitrary interleaving rather than a
/// single-shot failing test: the damage is the *transient* `Proceed` a
/// concurrent caller reads and acts on, and settlement re-inserts the entry
/// afterwards either way (`mark_completed_bound` inserts unconditionally), so
/// a post-hoc scan of the finished keys cannot fail. A checker thread reading
/// the published key while a sweeper runs is the only oracle. The read is
/// racy in one direction only, which is what makes it sound: a stale read can
/// name a key that has since settled, and a settled key answers `Completed`,
/// so the checker cannot false-positive.
#[test]
fn a_sweep_during_settlement_does_not_evict_the_entry() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const ROUNDS: usize = 500;
    const FINGERPRINT: &str = "backend:charge_card|{}";

    let cache = Arc::new(IdempotencyCache::new());
    let published: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let readmitted = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));

    let sweeper = {
        let cache = Arc::clone(&cache);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                cache.evict_expired();
            }
        })
    };
    let checker = {
        let cache = Arc::clone(&cache);
        let published = Arc::clone(&published);
        let readmitted = Arc::clone(&readmitted);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let key = published.lock().expect("published mutex poisoned").clone();
                if let Some(key) = key
                    && matches!(cache.check(&key), CheckOutcome::Proceed)
                {
                    readmitted.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    };

    for round in 0..ROUNDS {
        let key = format!("key-settling-{round}");
        let outcome = enforce(&cache, &key, FINGERPRINT).expect("a fresh key is admitted");
        let GuardOutcome::Proceed(mut reservation) = outcome else {
            panic!("a fresh key must be admitted, not answered from the cache");
        };
        *published.lock().expect("published mutex poisoned") = Some(key.clone());
        // Aged so the sweeper actually considers the entry; the owner is alive,
        // so only the settlement window can make it look reclaimable.
        assert!(cache.age_in_flight(&key, IN_FLIGHT_TIMEOUT + Duration::from_secs(1)));

        reservation.complete(&json!({"resultType": "complete", "content": []}));
        drop(reservation);

        *published.lock().expect("published mutex poisoned") = None;
    }

    done.store(true, Ordering::Relaxed);
    sweeper.join().expect("sweeper thread panicked");
    checker.join().expect("checker thread panicked");

    assert_eq!(
        readmitted.load(Ordering::Relaxed),
        0,
        "a sweep landing inside a reservation's settlement must not free its \
         key: every `Proceed` counted here is a caller told to run a mutation \
         whose first execution had already reached the backend (ADR-012 A2, \
         ADR-012:150-163)"
    );
}

/// Row 5 — a dispatched call answered with a well-formed `input_required`
/// interim releases its key, and the client's answer under the same key reaches
/// the backend rather than being served a cached sentence.
///
/// Deliberately green: the `Failed` terminal must not swallow this case. A rule
/// phrased as "release only before dispatch" would wedge the key of a call that
/// stopped to ask a question (ADR-012 decision, case 2; MIK-7212.MRTR.10b).
#[tokio::test]
async fn input_required_interim_releases_its_key() {
    let cache = Arc::new(IdempotencyCache::new());
    let mut reservation = admit(&cache, "key-input-required");

    reservation.complete(&json!({
        "resultType": "input_required",
        "content": [{"type": "text", "text": "Which card should I charge?"}]
    }));
    drop(reservation);

    assert!(
        matches!(cache.check("key-input-required"), CheckOutcome::Proceed),
        "a well-formed `input_required` interim is the backend stopping to ask \
         a question, not a side effect: the key must be free for the client's \
         answer to reach the backend"
    );
}

/// Row 6 — a backend session expiry does not resend an unannotated
/// `tools/call`.
///
/// The second resend site. HTTP session recovery
/// (`src/transport/http/mod.rs:1486-1510`) re-handshakes and replays the
/// original request once, outside `with_retry` and without consulting any
/// annotation, so amendment A3's deny default has to be applied there too or
/// the row below stays red however row 3 is fixed.
#[tokio::test]
async fn session_expiry_does_not_resend_an_unannotated_call() {
    let delivered = deliveries(Fault::SessionExpired, MUTATION).await;

    assert_eq!(
        delivered, 1,
        "an expired backend session is a reason to re-handshake, not permission \
         to replay a mutation the backend may already have run (ADR-012 A3); \
         the recovery path delivered it {delivered} times"
    );
}

/// Row 6b — the permission half of row 6: recovery still replays a call the
/// backend annotates read-only.
///
/// Row 6 alone is satisfiable by refusing to replay anything, which would
/// retire the session recovery MIK-5982 added. This row is what stops that:
/// the recovery path must read the same permission the retry path does, so
/// `resend_permission` is threaded to it rather than duplicated beside it.
#[tokio::test]
async fn session_expiry_still_recovers_an_explicitly_read_only_call() {
    let delivered = deliveries(Fault::SessionExpired, ANNOTATED_READ).await;

    assert!(
        delivered > 1,
        "an expired session must still be re-handshaked and the call replayed \
         when the backend annotates it `readOnlyHint: true` (ADR-012 A1); it \
         was delivered {delivered} time(s), so the deny default reached a call \
         that granted permission"
    );
}

/// Row 7 — a retry served a `Failed` terminal receives a JSON-RPC error
/// envelope carrying its own request id, not the original's.
///
/// The criterion is about a call re-issued *with a new request id*, so the id
/// on the served answer is the half a client uses to correlate it at all. An
/// envelope carrying the first call's id is a reply to a request this client
/// never sent, and every correlating client drops it — which is the same
/// outcome as the hang the guard exists to prevent.
///
/// Message equality is asserted alongside because an id that matched on a
/// freshly executed second call would satisfy the id claim while breaking the
/// criterion; the delivery count settles which of the two happened.
#[tokio::test]
async fn a_served_failed_terminal_adopts_the_retry_request_id() {
    let (url, mock) = start_mock(Fault::Refused).await;
    let state = route_state();
    register_route_backend(&state, &url, ForwardArm::Sanitized);

    let (_, first) = post_direct(&state, keyed_call(1, "key-served-terminal")).await;
    let (status, second) = post_direct(&state, keyed_call(7, "key-served-terminal")).await;

    assert_eq!(
        mock.lock().expect("mock mutex poisoned").calls.len(),
        1,
        "the retry of a dispatched call the backend refused must be served the \
         stored terminal, not delivered again; first={first}, second={second}"
    );
    assert_eq!(
        second.get("id").and_then(Value::as_u64),
        Some(7),
        "a served `Failed` terminal must adopt the retry's request id, exactly \
         as a served `Completed` does (ADR-012, \"The `Failed` state, \
         enumerated\"); the answer was: {second}"
    );
    assert_ne!(
        second.get("id"),
        first.get("id"),
        "the served envelope kept the original call's id, which is a reply to a \
         request the retrying client never sent"
    );
    assert_eq!(
        second.pointer("/error/message"),
        first.pointer("/error/message"),
        "the retry must be served the stored error rather than a fresh one"
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "a replayed terminal is an answer, not a live failure: {second}"
    );
}

/// Row 8 — an unannotated `tools/call` whose transport fails *after* the
/// request was written and before any backend answer reaches the backend
/// exactly once.
///
/// The dispatch boundary the resend rule is phrased against (amendment A3).
/// `is_retryable` (`src/failsafe/retry.rs:96-101`) matches on the error variant
/// alone, so a failure raised with the bytes already on the wire is resent on
/// the same terms as a refused connection.
#[tokio::test]
async fn a_post_dispatch_transport_failure_reaches_the_backend_once() {
    let delivered = deliveries(Fault::BrokenResponse, MUTATION).await;

    assert_eq!(
        delivered, 1,
        "a transport failure raised after the connection was established and \
         the request written is not provably pre-dispatch, so the call must not \
         be resent (ADR-012 A3); the backend received it {delivered} times"
    );
}

/// Row 9 — a name that reads like a query grants no resend permission.
///
/// The row amendment A1 is phrased for. `get_and_increment` is a mutation
/// whose name invites the inference the ADR forbids, and it carries no
/// annotation, so every resend site must deny it.
#[tokio::test]
async fn a_resend_site_denies_by_default_without_an_annotation() {
    let delivered = deliveries(Fault::Silence, READ_LOOKING_MUTATION).await;

    assert_eq!(
        delivered, 1,
        "the resend default at every site is deny: a request carrying no \
         explicit annotation — including one whose name merely looks read-only, \
         such as `{READ_LOOKING_MUTATION}` — must be resent nowhere (ADR-012 A1, \
         A3); the backend received it {delivered} times"
    );
}
