// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one fixture every row in this suite drives.
//!
//! Three rules hold the suite together, and each of them is a rule because the
//! alternative produces a row that passes without observing anything.
//!
//! **The route is the real one.** Every request below goes through
//! `create_router` and the production `/mcp` handler. Nothing here calls a
//! handler function directly, constructs an `AppState` of its own, or reaches
//! into the task store: the adapter's claim is about what a client sees, and a
//! test that reads private state cannot tell a wired route from an unwired one.
//!
//! **The backend is real transport, and it is counted.** [`MockBackend`] lives
//! in [`backend`] and is injected with the same `set_transport_for_test` seam
//! the router's own tests use, so a dispatch reaches it through `Backend` -> the
//! invoke chokepoint -> the pool, exactly as a production call does. Its
//! `tools/call` counter is the suite's primary oracle — "exactly once" is the
//! whole adapter.
//!
//! **Every wait is a barrier at a lifecycle seam.** [`GateHandle`] tells the
//! test when a dispatch has actually arrived at the backend and holds that
//! dispatch until the test lets it answer. No row sleeps to "give the worker
//! time"; the only loop in this file is [`poll_until_terminal`], which is the
//! client's own polling contract and is bounded by attempts, not by a clock.
//!
//! ## Persistent paths
//!
//! Nothing here opens a store or names a directory. `AppState` comes from
//! `router/tests.rs`'s existing `test_router_app_state_with_auth`, which is
//! lane 1's file and lane 1's to retype; when it becomes
//! `async fn(..) -> (Arc<AppState>, TempDir)` per design §9, [`fixture_state`]
//! below is the single line in this suite that changes and the `TempDir` it
//! returns is bound for the lifetime of the test. No shared path, no env
//! mutation, no fallback is introduced here, because no path is named here.
use super::super::*;

mod backend;

pub(super) use backend::{Answer, GateHandle, MockBackend, TOOL};

/// The backend name every row dispatches to.
pub(super) const BACKEND: &str = "mock";

/// A second registered backend that no key in [`two_principal_auth`] may reach.
/// Used by the rows that need a refusal which is real rather than arranged.
pub(super) const FORBIDDEN_BACKEND: &str = "vault";

/// The tasks extension a task-augmented request must declare, per request.
pub(super) const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

/// Where a task-augmented call carries its idempotency key
/// (`crate::protocol::mrtr::IDEMPOTENCY_KEY_META`, spelled out so a rename of
/// the constant shows up here as a compile error rather than as a silently
/// keyless call that is refused for the wrong reason).
pub(super) const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";

// =====================================================================
// State
// =====================================================================

/// Two credentialled principals plus one scoped away from [`FORBIDDEN_BACKEND`].
///
/// Authentication is ON. With it off every caller is the same principal, and
/// every ownership and identity assertion in this suite would hold by
/// construction — a fixture that removes the condition it observes.
pub(super) fn two_principal_auth() -> AuthConfig {
    let key = |k: &str, name: &str, admin: bool| ApiKeyConfig {
        key: k.to_string(),
        name: name.to_string(),
        rate_limit: 0,
        // Named rather than empty: an empty list is "every backend", and the
        // refusal rows need a backend this credential provably cannot reach.
        backends: vec![BACKEND.to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
    };
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![
            key("key-a", "principal-a", false),
            key("key-b", "principal-b", false),
            key("key-admin", "principal-admin", true),
        ],
        public_paths: Vec::new(),
        client_circuit_breaker: None,
        single_user: false,
    }
}

/// The suite's `AppState`.
///
/// Deliberately the router suite's own fixture and not a local copy. Lane 1
/// owns `AppState.tasks` and every existing construction site; a copy here
/// would be a twenty-fourth site it does not own, and would drift from the
/// production wiring the moment the retype lands. This function is the single
/// place the suite adapts when that fixture becomes
/// `async fn(..) -> (Arc<AppState>, TempDir)`.
///
/// Two properties of that fixture the rows depend on, recorded because they are
/// what keeps several oracles honest:
/// * `MetaMcp::new` carries `cache: None` and `idempotency_cache: None`
///   (`meta_mcp/mod.rs:488`), so a repeated dispatch can never be answered from
///   a response cache. Every counter assertion measures dispatch, not caching.
/// * `Config::default()` has `server.modern_protocol = true`
///   (`config/mod.rs:1236`), so the modern era these requests declare is served
///   rather than refused.
pub(super) async fn fixture_state(auth: &AuthConfig) -> (Arc<AppState>, tempfile::TempDir) {
    test_router_app_state_with_auth(auth).await
}

/// Register a mock under `name`, with its transport already injected.
pub(super) fn register(state: &Arc<AppState>, name: &str, mock: &Arc<MockBackend>) {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig {
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport: Arc<dyn Transport> = Arc::clone(mock) as Arc<dyn Transport>;
    backend.set_transport_for_test(transport);
    assert!(
        state.backends.register(backend),
        "the fixture backend '{name}' must register under a name nothing else holds"
    );
}

/// The suite's standard state: authentication on, one counted mock backend.
///
/// Rows that also need a backend the credential cannot reach register
/// [`FORBIDDEN_BACKEND`] themselves, so a row that never uses it is not carrying
/// a fixture it does not exercise.
pub(super) async fn state_with(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store) = fixture_state(&two_principal_auth()).await;
    register(&state, BACKEND, mock);
    (state, store)
}

/// Register a SEPARATE counted mock under [`FORBIDDEN_BACKEND`], and hand it
/// back so the row can assert on its own counter.
///
/// Separate on purpose. Registering one `Arc<MockBackend>` under two names gives
/// the two backends one shared counter, and "the refused call reached no
/// backend" then cannot be told apart from "it reached the other one" — which is
/// precisely the confusion these rows exist to rule out. Registered rather than
/// merely named, so a refusal is the credential's scope answering and not a
/// backend that was never there.
pub(super) fn register_forbidden(state: &Arc<AppState>) -> Arc<MockBackend> {
    let forbidden = MockBackend::answering(Answer::ok());
    register(state, FORBIDDEN_BACKEND, &forbidden);
    forbidden
}

// =====================================================================
// Requests
// =====================================================================

/// A modern request. `declares_tasks` is per request, because the declaration
/// is a statement about the message carrying it.
pub(super) fn modern(id: i64, method: &str, params: Value, declares_tasks: bool) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": if declares_tasks {
            json!({ "extensions": { TASKS_EXTENSION: {} } })
        } else {
            json!({})
        },
        "io.modelcontextprotocol/clientInfo": { "name": "AdapterSuite", "version": "1.0.0" }
    });
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

/// Declare `elicitation` alongside whatever the request already declared.
///
/// Only the interim-round rows need it, and they need it to fail for the right
/// reason. `input_capabilities` is the CREATING request's `Declared` (design
/// §3), and the capability gate refuses an input request a client never said it
/// could answer (`invoke.rs:712`, `undeclared_input_request`). Without this the
/// interim round would be refused before the settlement classifier ever saw it,
/// and X7 would be green on a refusal rather than on the abandonment rule.
pub(super) fn declaring_elicitation(mut body: Value) -> Value {
    body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["elicitation"] =
        json!({});
    body
}

/// Add the idempotency key to an already-built modern request.
pub(super) fn keyed(mut body: Value, key: &str) -> Value {
    body["params"]["_meta"][IDEMPOTENCY_KEY_META] = json!(key);
    body
}

/// A task-augmented `gateway_invoke` at the mock backend, with a key.
#[expect(
    clippy::needless_pass_by_value,
    reason = "every call site across this adapter suite passes an owned json! literal; \
              taking &Value would force a borrow at each of them for no benefit"
)]
pub(super) fn task_invoke(id: i64, key: &str, arguments: Value) -> Value {
    keyed(
        modern(
            id,
            "tools/call",
            json!({
                "name": "gateway_invoke",
                "arguments": { "server": BACKEND, "tool": TOOL, "arguments": arguments },
                "task": {}
            }),
            true,
        ),
        key,
    )
}

/// The same call with no `task` member: the ordinary synchronous path, and the
/// positive control every "the backend was reached" assertion rests on.
#[expect(
    clippy::needless_pass_by_value,
    reason = "every call site across this adapter suite passes an owned json! literal; \
              taking &Value would force a borrow at each of them for no benefit"
)]
pub(super) fn sync_invoke(id: i64, arguments: Value) -> Value {
    modern(
        id,
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": TOOL, "arguments": arguments }
        }),
        true,
    )
}

/// A `tasks/*` request for one task.
pub(super) fn task_method(id: i64, method: &str, params: Value) -> Value {
    modern(id, method, params, true)
}

/// Build the HTTP request the modern route requires.
///
/// `Mcp-Name` is derived from `mcp_name_body_field` — the production rule — so a
/// request is never refused by the header/body mirror check for a reason no row
/// is about.
fn http_request(principal: Option<&str>, body: &Value) -> axum::http::Request<axum::body::Body> {
    let method = body["method"].as_str().unwrap_or_default().to_string();
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", &method);
    if let Some(principal) = principal {
        builder = builder.header("authorization", format!("Bearer {principal}"));
    }
    if let Some(field) = crate::protocol::headers::mcp_name_body_field(&method)
        && let Some(name) = body
            .pointer(&format!("/params/{field}"))
            .and_then(Value::as_str)
    {
        builder = builder.header("mcp-name", name);
    }
    let mut request = builder
        .body(axum::body::Body::from(
            serde_json::to_vec(body).expect("a fixture body serialises"),
        ))
        .expect("a fixture request builds");
    // The strong verified owner design §2 names. Placed in request extensions,
    // which is the ONLY way one ever arrives — `handlers.rs:596` reads it from
    // there and `auth.rs:918,939` are the two middleware sites that put it
    // there, both behind a key server this in-process router has none of. The
    // credential beside it is real: the bearer above goes through the actual
    // auth middleware, and the principal every ownership row compares is
    // whichever of the two the route reads. Nothing here fabricates a digest —
    // admission derives that itself — and nothing introduces a second identity
    // scheme: `principal-a` and `alice` name the same caller in both schemes,
    // and `principal-b`/`bob` differ in both, so no row can pass by reading the
    // scheme that happens to suit it. See `router/tests.rs:1248` for the same
    // injection in this file's parent.
    if let Some(principal) = principal
        && let Some(subject) = verified_subject(principal)
    {
        request
            .extensions_mut()
            .insert(crate::key_server::oidc::VerifiedIdentity {
                subject: subject.to_string(),
                email: format!("{subject}@adapter.test"),
                name: None,
                groups: Vec::new(),
                issuer: "https://idp.adapter.test".to_string(),
            });
    }
    request
}

/// The OIDC subject that belongs to each credential.
fn verified_subject(principal: &str) -> Option<&'static str> {
    match principal {
        "key-a" => Some("alice"),
        "key-b" => Some("bob"),
        "key-admin" => Some("root"),
        _ => None,
    }
}

/// POST as `principal`, returning the parsed JSON body.
pub(super) async fn post(state: &Arc<AppState>, principal: &str, body: Value) -> Value {
    post_full(state, principal, body).await.1
}

/// POST as `principal`, returning status and body.
pub(super) async fn post_full(
    state: &Arc<AppState>,
    principal: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = create_router(Arc::clone(state))
        .oneshot(http_request(Some(principal), &body))
        .await
        .expect("the router must answer");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must read");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// =====================================================================
// Reading the answers
// =====================================================================

/// The `taskId` a create answered with, or a failure naming the whole body.
pub(super) fn task_id(created: &Value) -> String {
    created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("a task-augmented call must be answered with a task handle, got {created}")
        })
        .to_string()
}

/// One `tasks/get`.
pub(super) async fn get_task(state: &Arc<AppState>, principal: &str, id: &str) -> Value {
    post(
        state,
        principal,
        task_method(9_000, "tasks/get", json!({ "taskId": id })),
    )
    .await
}

/// The status `tasks/get` reports, or `""` when it reported none.
pub(super) fn status_of(body: &Value) -> String {
    body.pointer("/result/status")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Whether a status is one a task never leaves.
pub(super) fn is_terminal(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "cancelled")
}

/// Poll `tasks/get` until the task is terminal, bounded by attempts.
///
/// Not a sleep and not a timeout: every row that needs the worker to have
/// *started* uses [`GateHandle::wait_for_dispatch`], and every row that needs it
/// to *answer* releases the gate first. This loop only observes the settlement
/// that those barriers already made inevitable, which is also the client's own
/// contract — a task is polled, not awaited. `yield_now` hands the runtime back
/// so the worker (and any `spawn_blocking` durable write it awaits) can make
/// progress between attempts.
pub(super) async fn poll_until_terminal(state: &Arc<AppState>, principal: &str, id: &str) -> Value {
    const ATTEMPTS: usize = 5_000;
    let mut last = Value::Null;
    for _ in 0..ATTEMPTS {
        last = get_task(state, principal, id).await;
        if is_terminal(&status_of(&last)) {
            return last;
        }
        tokio::task::yield_now().await;
    }
    panic!(
        "task {id} never reached a terminal status in {ATTEMPTS} polls; \
         the last answer was {last}"
    );
}

/// Assert a task is `completed` carrying exactly the mock's successful result.
pub(super) fn assert_carries_the_backend_result(fetched: &Value) {
    std::assert_eq!(
        status_of(fetched),
        "completed",
        "a dispatch the backend answered settles `completed`: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/structuredContent/marker"),
        Some(&json!("mock-backend-answered")),
        "the settled task carries the backend's own result, verbatim: {fetched}"
    );
}
