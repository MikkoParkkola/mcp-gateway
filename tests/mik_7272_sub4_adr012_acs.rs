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
//! Rows that need a production seam that does not exist yet — the `Failed`
//! terminal, the liveness token of amendment A2 — are `#[ignore]`d with a
//! comment naming what they wait on, rather than faked green or faked red.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};

use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use mcp_gateway::idempotency::{
    CheckOutcome, GuardOutcome, IdempotencyCache, IdempotencyReservation, enforce,
};

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
            let fault = {
                let mut slot = mock.lock().expect("mock mutex poisoned");
                slot.calls.push(
                    body["params"]["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
                slot.fault
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

fn backend_for(url: &str) -> Backend {
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
        passthrough: false,
        allow_cleartext_credentials: false,
        runtime_profile: None,
        identity_propagation: None,
    };
    Backend::new("sub4-mock", config, &failsafe(), Duration::from_secs(300))
}

/// Deliveries of `name` that reached the backend for one failing `tools/call`.
///
/// Discovery runs first, exactly as it does in production: a `tools/call` is
/// always preceded by a `tools/list`, which is what puts the backend's
/// annotations within reach of the resend decision.
async fn deliveries(fault: Fault, name: &str) -> usize {
    let (url, mock) = start_mock(fault).await;
    let backend = backend_for(&url);
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
/// Deliberately green: it states the behaviour the other rows must not cost.
/// Without it, an implementation that settles *every* failure as `Failed`
/// passes the rest of this suite while wedging keys of calls that never left.
#[tokio::test]
async fn pre_dispatch_failure_releases_its_key() {
    let cache = Arc::new(IdempotencyCache::new());
    let mut reservation = admit(&cache, "key-unreachable");

    // The backend was unreachable: nothing was dispatched.
    reservation.release();

    assert!(
        matches!(cache.check("key-unreachable"), CheckOutcome::Proceed),
        "a failure raised before the request left for the backend must free the \
         key so the retry is a first attempt (ADR-012 decision, case 1)"
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
#[tokio::test]
#[ignore = "waits on the ADR-012 A2 liveness token: `IdempotencyState::InFlight` \
            carries a start instant read against the process clock, so the only \
            running form of this row is a five-minute wall-clock wait"]
async fn live_owner_past_the_timeout_is_told_in_flight() {
    unimplemented!("needs the liveness token from ADR-012 amendment A2");
}

/// Row 4b — that same entry survives an explicit `evict_expired` sweep.
///
/// A separate assertion because the sweep does not consult
/// `decide_check_plan`: `evict_expired` (`src/idempotency.rs:398`) retains on
/// `!entry.state.is_expired()`, and staleness for an in-flight entry is a bare
/// clock reading (`:84`) rather than a liveness question.
///
/// Gated for the same reason as row 4a, with one addition that decides the
/// shape of the fix: demanding `!is_expired()` of an aged in-flight entry
/// built from today's state would demand it of *every* aged in-flight entry,
/// including one whose owner died — which removes the eviction consequence 3
/// depends on. The requirement is that liveness decide the sweep, not that the
/// sweep stop deciding.
#[tokio::test]
#[ignore = "waits on the ADR-012 A2 liveness token: a live owner and a dead one \
            are the same value to `evict_expired`, and reaching the aged state \
            without a clock seam costs five minutes of wall clock"]
async fn a_live_reservation_survives_an_evict_expired_sweep() {
    unimplemented!("needs the liveness token from ADR-012 amendment A2");
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
#[tokio::test]
#[ignore = "waits on the ADR-012 A2 liveness token: the window this row has to \
            open — settlement started, admission still published — exists only \
            once a token is held from before publication until settlement ends"]
async fn a_sweep_during_settlement_does_not_evict_the_entry() {
    unimplemented!("needs the liveness token from ADR-012 amendment A2");
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
#[tokio::test]
#[ignore = "waits on the per-request resend flag of ADR-012 consequence 2: \
            recovery lives inside the transport, which is handed a method and \
            params and no annotation, so today this row cannot tell the \
            permitted half from the denied one"]
async fn session_expiry_still_recovers_an_explicitly_read_only_call() {
    unimplemented!("needs the resend flag threaded to HTTP session recovery");
}

/// Row 7 — a retry served a `Failed` terminal receives a JSON-RPC error
/// envelope carrying its own request id, not the original's.
#[tokio::test]
#[ignore = "waits on the `Failed` terminal of ADR-012's decision table: there \
            is no terminal to serve, so asserting anything here would only \
            restate row 1's redness"]
async fn a_served_failed_terminal_adopts_the_retry_request_id() {
    unimplemented!("needs OnDrop::Failed and its CacheEntryStatus/CheckPlan arms");
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
