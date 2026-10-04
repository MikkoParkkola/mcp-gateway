// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

/// The subscription ceiling every fixture in this file is built with.
///
/// Read back by `available()` to tell "the listener went away" apart from
/// "the listener was never admitted", so the two uses must agree: a second
/// copy of this number would turn a fixture change into a test that spins
/// to its deadline instead of failing on what changed.
pub const SUBSCRIPTION_CAPACITY: usize = 64;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::{ApiKeyConfig, AuthConfig, Config};
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::subscription_registry::SubscriptionRegistry;
use mcp_gateway::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, auth_state, create_router, open_runtime,
};
use mcp_gateway::key_server::oidc::VerifiedIdentity;
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::protocol::headers::mcp_name_body_field;
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::fixture::{self, CountedBackend, GateHandle, ServerGuard};

pub(super) const TASKS: &str = "io.modelcontextprotocol/tasks";

/// Where a task-augmented call carries its idempotency key
/// (`crate::protocol::mrtr::IDEMPOTENCY_KEY_META` in the gateway, spelled
/// out here because an integration test cannot name a private constant —
/// the internal adapter suite's `support.rs` spells the same string for the
/// same reason).
pub(super) const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";

/// Two API keys, so "a different principal" is a fact of the fixture rather
/// than a wish. With auth disabled every caller is the same principal and
/// the ownership rows would pass by construction — a fixture that removes
/// the condition it observes.
///
/// `backends` names [`fixture::BACKEND`] rather than being empty: an empty
/// list is "every backend", and a credential that may reach anything cannot
/// show that a task-producing call was authorized on its own merits. The
/// scope is narrow and it is real — the same middleware that reads it on a
/// production request reads it here.
fn two_principal_auth() -> AuthConfig {
    let key = |k: &str, name: &str| ApiKeyConfig {
        key: None,
        key_sha256: Some(mcp_gateway::config::api_key_digest_spec(k.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec![fixture::BACKEND.to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: mcp_gateway::config::ApiKeyKind::Shared,
    };
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![key("key-a", "principal-a"), key("key-b", "principal-b")],
        public_paths: Vec::new(),
        ..AuthConfig::default()
    }
}

/// Everything one test's gateway owns, held together for the test's whole
/// life.
///
/// The `TempDir` is a FIELD rather than a returned tuple element so it
/// cannot be dropped by a destructuring `let` that only wanted the state:
/// the task store leases that directory for as long as the service lives,
/// and a store whose directory has been removed underneath it fails in ways
/// that read as task defects. Bind the whole `Fixture`; never take it
/// apart.
///
/// `backend` is the per-fixture counter. Per fixture, never static, so two
/// tests in one binary cannot read each other's dispatch count.
///
/// `_server` is the fixture's own loopback HTTP listener, held for the same
/// reason and dropped with the same `Fixture`: the registered backend
/// reaches it over a real socket, so a guard dropped early turns every
/// later dispatch into a connection error. It is deliberately NOT stored on
/// `AppState` — the state would then own the server that serves the state,
/// a cycle that keeps both alive past the test.
pub(super) struct Fixture {
    pub(super) state: Arc<AppState>,
    pub(super) backend: Arc<CountedBackend>,
    _server: ServerGuard,
    /// `None` when the TEST owns the directory, which is how one store
    /// outlives one gateway: a reconnect fixture opens a second state over
    /// a directory the test keeps alive across both.
    _store_dir: Option<tempfile::TempDir>,
}

/// The suite's standard gateway: authentication on, two principals, one
/// counted eligible backend that answers immediately.
pub(super) async fn state() -> Fixture {
    state_from(two_principal_auth()).await
}

/// The shape in which an unauthenticated caller REACHES `/mcp`:
/// authentication is on, and `/mcp` is listed public so ordinary tools stay
/// open. Without the public listing the middleware answers 401 and no task
/// code runs, so a case built on `state()` cannot observe what an
/// unattributed caller can do.
///
/// No shipped configuration writes it: `gateway.example.yaml`, the helm
/// configmap and the k8s configmap all list `/health` alone. What keeps the
/// scenario startable — and the guard below off the dead-code pile — is
/// `network_bind_refusal`, which returns `None` for a loopback bind with no
/// declared `server.public_url` (`src/gateway/server/support.rs:554`), the
/// shape `Config::default()` gives this fixture. The same answer for a
/// loopback install that lists `/mcp` public is pinned at
/// `src/gateway/server/support.rs:979-986`. Only a NON-loopback
/// `public_url` turns this shape into a refusal.
pub(super) fn public_mcp_auth() -> AuthConfig {
    let mut auth = two_principal_auth();
    auth.public_paths = vec!["/mcp".to_string()];
    auth
}

pub(super) async fn state_public_mcp() -> Fixture {
    state_from(public_mcp_auth()).await
}

/// The standard gateway, but its backend HOLDS every dispatch until the
/// returned handle releases it.
///
/// For the one row that must observe a task while it is genuinely running.
/// A backend that answers immediately races the executor there: the task
/// can settle between the create and the update, and the row would then be
/// reporting on a terminal task while claiming to report on a working one.
/// The gate replaces that race with a barrier — no sleep, and no clock.
pub(super) async fn state_holding() -> (Fixture, GateHandle) {
    let (backend, gate) = CountedBackend::holding();
    (state_from_with(two_principal_auth(), backend).await, gate)
}

pub(super) async fn state_from(auth: AuthConfig) -> Fixture {
    state_from_with(auth, CountedBackend::open()).await
}

pub(super) async fn state_from_with(auth: AuthConfig, backend: Arc<CountedBackend>) -> Fixture {
    let store_dir = tempfile::tempdir().expect("a private task-store directory");
    let fixture = state_in(auth, backend, store_dir.path()).await;
    Fixture {
        _store_dir: Some(store_dir),
        ..fixture
    }
}

/// A gateway over a store directory the CALLER owns.
///
/// The reconnect rows need two gateways over one store, which is only
/// possible if the directory outlives the first fixture. The custody lease
/// (`store.lease`, taken with a non-blocking `try_acquire`) is released when
/// the previous fixture's last `Arc` drops, and a worker thread can still be
/// finishing at that instant, so the open is retried to [`fixture::BOUND`]
/// rather than raced. A lease that never frees fails here by name instead of
/// surfacing as an unrelated store error inside a task assertion.
pub(super) async fn state_over(store_root: &std::path::Path) -> Fixture {
    state_in(two_principal_auth(), CountedBackend::open(), store_root).await
}

async fn state_in(
    auth: AuthConfig,
    backend: Arc<CountedBackend>,
    store_root: &std::path::Path,
) -> Fixture {
    let mut config = Config::default();
    config.server.modern_protocol = true;
    config.auth = auth;
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));

    // One registry, shared between the state the router reads and the
    // executor that publishes through it.
    let authorizer = auth_state(&config.auth);
    let auth_config = Arc::clone(&authorizer.auth_config);
    let subscriptions = Arc::new(SubscriptionRegistry::new(SUBSCRIPTION_CAPACITY, authorizer));
    let tasks_dir = store_root.join("tasks");
    let deadline = tokio::time::Instant::now() + fixture::BOUND;
    let (tasks, task_executor) = loop {
        match open_runtime(
            &tasks_dir,
            config.tasks.max_workers,
            StoreLimits::default(),
            Arc::clone(&subscriptions),
        )
        .await
        {
            Ok(runtime) => break runtime,
            Err(error) if tokio::time::Instant::now() < deadline => {
                // EVERY failure is retried, not only custody contention:
                // the open does not report a reason this helper could
                // branch on, so naming one here would be a guess. What the
                // retry buys is the one case a reconnect row creates — a
                // previous custodian still letting go — and the bound is
                // what keeps any other cause finite.
                let _ = error;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(error) => panic!(
                "the task store at {} could not be opened within {:?}; the last \
                 attempt failed with: {error:?}",
                tasks_dir.display(),
                fixture::BOUND
            ),
        }
    };

    let state = Arc::new(AppState {
        continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
        session_lifecycle: None,
        env: None,
        meta_mcp: Arc::new(
            MetaMcp::new(Arc::clone(&backends)).with_surfaced_tools(backend.surfaced_tools()),
        ),
        backends,
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        auth_config,
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
        control_plane_base: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks,
        task_executor,
        subscriptions,
    });
    // Registered AFTER the state exists and BEFORE any request runs, so
    // every row sees the same gateway a production caller would: a real
    // backend behind a real transport, reachable only by a credential
    // scoped to it.
    let server = fixture::register(&state, &backend).await;
    Fixture {
        state,
        backend,
        _server: server,
        _store_dir: None,
    }
}

/// A modern request. `declares_tasks` is per request on purpose: the whole
/// point of `.4` and `.13` is that a declaration on an earlier request
/// carries nothing forward.
pub(super) fn modern(id: i64, method: &str, params: Value, declares_tasks: bool) -> Value {
    let capabilities = if declares_tasks {
        json!({ "extensions": { TASKS: {} } })
    } else {
        json!({})
    };
    modern_declaring(id, method, params, capabilities)
}

/// A modern request carrying a verbatim client-capabilities object.
///
/// [`modern`] covers the two declarations every other row needs; this one
/// exists for the rows that put something the specification does not allow
/// under the extension identifier, which a `bool` cannot express.
pub(super) fn modern_declaring(id: i64, method: &str, params: Value, capabilities: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" }
    });
    params["_meta"]["io.modelcontextprotocol/clientCapabilities"] = capabilities;
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

/// Add the client idempotency key to an already-built modern request.
///
/// The dedupe key is `(authenticated principal, client idempotency key)`, so
/// a create that carries none is not a logical request the gateway can
/// recognise on retry. Logical retries share a key; distinct creates carry
/// distinct ones, which is why every call site below names its own row.
pub(super) fn keyed(mut body: Value, key: &str) -> Value {
    body["params"]["_meta"][IDEMPOTENCY_KEY_META] = json!(key);
    body
}

/// A task-augmented `gateway_invoke` at the counted backend, keyed.
///
/// `gateway_invoke` selecting a registered backend and one of its declared
/// tools, rather than a governed built-in wearing a `task` member: the
/// built-ins are answered synchronously in I1 and correctly so, and a
/// fixture that relabelled one to get a task handle would be asserting
/// against a route the gateway does not have. No target hint is inherited
/// and none is set — the tool is read-only and non-destructive as declared,
/// so nothing here borrows a destructive-authorization decision.
pub(super) fn task_invoke(id: i64, key: &str) -> Value {
    keyed(
        modern(
            id,
            "tools/call",
            json!({
                "name": "gateway_invoke",
                "arguments": {
                    "server": fixture::BACKEND,
                    "tool": fixture::TOOL,
                    "arguments": {}
                },
                "task": {}
            }),
            true,
        ),
        key,
    )
}

/// The `taskId` a create was answered with, or a failure naming the whole
/// body.
///
/// Deliberately a panic and not a fallback id. A fallback let an ownership
/// row compare two unrelated refusals and report agreement — the create had
/// silently produced no task at all, and the row passed on a gateway that
/// never made one.
pub(super) fn task_id_of(created: &Value) -> String {
    created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("a declared task-augmented call must be answered with a task handle: {created}")
        })
        .to_string()
}

/// POST to `/mcp` as `principal`, returning status and body.
///
/// The `Mcp-Name` mirror is derived from `mcp_name_body_field` — the
/// production rule — so these requests keep sending what the gateway
/// requires once `.7` lands. That is not circular: `.7` asserts the rule
/// directly as a unit case, and nothing here asserts the header.
pub(super) async fn post(principal: &str, body: Value) -> (StatusCode, Value) {
    // Bound until this helper returns, which is after the response body has
    // been read: the store's directory outlives the request made on it.
    let fixture = state().await;
    post_against(Arc::clone(&fixture.state), principal, body).await
}

pub(super) async fn post_against(
    state: Arc<AppState>,
    principal: &str,
    body: Value,
) -> (StatusCode, Value) {
    post_as(state, Some(principal), body).await
}

/// A request carrying NO credential. Only reaches the handlers when `/mcp`
/// is public — see [`state_public_mcp`].
///
/// It carries no [`VerifiedIdentity`] either, and that is the point: an
/// unattributed caller is unattributed in BOTH schemes, so no row can pass
/// by reading the one that happens to suit it.
pub(super) async fn post_unattributed(state: Arc<AppState>, body: Value) -> (StatusCode, Value) {
    post_as(state, None, body).await
}

/// Poll `tasks/get` as an unattributed caller until the task it names is
/// TERMINAL, and return that answer.
///
/// A bounded barrier, not a delay. Nothing sleeps: each turn is a real
/// request over the real router, and the loop ends the moment the store
/// reports a terminal status. The bound is [`fixture::BOUND`] — the suite's
/// one outer bound, shared with the counted backend's waits rather than
/// respelled — so a task that is created and then never settled FAILS its
/// row finitely instead of hanging the binary.
///
/// Each poll carries its own JSON-RPC id, counted up from `id_from`: a
/// stateless client correlates answers to requests by id, and reusing one
/// would make two answers indistinguishable.
pub(super) async fn poll_unattributed_until_terminal(
    state: Arc<AppState>,
    id_from: i64,
    task_id: &str,
) -> Value {
    let mut last = Value::Null;
    tokio::time::timeout(fixture::BOUND, async {
        let mut request_id = id_from;
        loop {
            let (_, body) = post_unattributed(
                Arc::clone(&state),
                modern(request_id, "tasks/get", json!({ "taskId": task_id }), true),
            )
            .await;
            request_id += 1;
            if let Some("completed" | "failed" | "cancelled") =
                body.pointer("/result/status").and_then(Value::as_str)
            {
                return body;
            }
            last = body;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "'{task_id}' never reached a terminal status within {:?}; \
             the task was created and never settled: {last}",
            fixture::BOUND
        )
    })
}

/// The OIDC subject that belongs to each credential.
///
/// Two distinct subjects from one issuer, matching the internal adapter
/// suite's convention: `principal-a`/`alice` name the same caller in both
/// schemes and `principal-b`/`bob` differ in both, so the strong actor id
/// and the API key can never disagree about who is calling.
fn verified_subject(principal: &str) -> Option<&'static str> {
    match principal {
        "key-a" => Some("alice"),
        "key-b" => Some("bob"),
        _ => None,
    }
}

/// The answer to a request, keeping the content type apart from the body.
///
/// `post_as` collapses two different answers to a null `Value`: an admitted
/// stream, which has no body to collect, and a non-JSON response, which
/// fails to parse. A row that reads admission off `is_null()` therefore
/// cannot tell an open stream from a 200 that carried nothing, so the rows
/// that turn on an admission read this instead.
#[derive(Debug)]
pub(super) struct Answer {
    pub status: StatusCode,
    pub content_type: String,
    pub body: Value,
}

impl Answer {
    /// An admitted `subscriptions/listen` is an open SSE stream. Nothing
    /// else on this route answers with that content type.
    pub fn is_open_stream(&self) -> bool {
        self.status == StatusCode::OK && self.content_type.starts_with("text/event-stream")
    }
}

pub(super) async fn post_as(
    state: Arc<AppState>,
    principal: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let answer = post_answer(state, principal, body).await;
    (answer.status, answer.body)
}

/// As [`post_as`], keeping the content type the body decision was made on.
pub(super) async fn post_answer_against(
    state: Arc<AppState>,
    principal: &str,
    body: Value,
) -> Answer {
    post_answer(state, Some(principal), body).await
}

/// POST to the per-backend route `/mcp/{fixture::BACKEND}` as `principal`.
///
/// Same headers, auth middleware and verified identity as [`post_as`]; only
/// the path differs, so a refusal seen here is the route's and not the
/// request's.
pub(super) async fn post_direct(
    state: Arc<AppState>,
    principal: &str,
    body: Value,
) -> (StatusCode, Value) {
    let uri = format!("/mcp/{}", fixture::BACKEND);
    let answer = post_answer_to(state, &uri, Some(principal), body).await;
    (answer.status, answer.body)
}

async fn post_answer(state: Arc<AppState>, principal: Option<&str>, body: Value) -> Answer {
    post_answer_to(state, "/mcp", principal, body).await
}

async fn post_answer_to(
    state: Arc<AppState>,
    uri: &str,
    principal: Option<&str>,
    body: Value,
) -> Answer {
    let response = send_to(state, uri, principal, body).await;
    let status = response.status();
    // An admitted `subscriptions/listen` is an OPEN STREAM by design, so
    // draining its body never returns. Content-type is what separates the
    // two answers: a refusal is `application/json` and must be read and
    // compared; a stream is `text/event-stream` and has no body to collect.
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if content_type.starts_with("text/event-stream") {
        return Answer {
            status,
            content_type,
            body: Value::Null,
        };
    }
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    Answer {
        status,
        content_type,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

/// One request through the real router, answered but NOT drained.
///
/// Split out of [`post_answer`] so a listen stream can be held open and
/// read frame by frame: the same headers, the same auth middleware and the
/// same verified identity as every other call in this suite, so a stream
/// row cannot pass through a door the other rows do not use.
pub(super) async fn send(
    state: Arc<AppState>,
    principal: Option<&str>,
    body: Value,
) -> axum::http::Response<Body> {
    send_to(state, "/mcp", principal, body).await
}

async fn send_to(
    state: Arc<AppState>,
    uri: &str,
    principal: Option<&str>,
    body: Value,
) -> axum::http::Response<Body> {
    let method = body["method"].as_str().unwrap_or_default().to_string();
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", &method);
    if let Some(principal) = principal {
        builder = builder.header("authorization", format!("Bearer {principal}"));
    }
    if let Some(field) = mcp_name_body_field(&method)
        && let Some(name) = body
            .pointer(&format!("/params/{field}"))
            .and_then(Value::as_str)
    {
        builder = builder.header("mcp-name", name);
    }
    let mut request = builder
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    // The strong verified owner the design names. Placed in request
    // extensions, which is the ONLY way one ever arrives: the two
    // middleware sites that insert it both sit behind a key server this
    // in-process router has none of. The credential beside it is real — the
    // bearer above goes through the actual auth middleware, and the API-key
    // scope stays in force. Nothing here fabricates a digest, and nothing
    // widens what a caller may reach.
    if let Some(principal) = principal
        && let Some(subject) = verified_subject(principal)
    {
        request.extensions_mut().insert(VerifiedIdentity {
            subject: subject.to_string(),
            email: format!("{subject}@task-1.test"),
            name: None,
            groups: Vec::new(),
            issuer: "https://idp.task-1.test".to_string(),
        });
    }
    create_router(state)
        .oneshot(request)
        .await
        .expect("router must answer")
}
