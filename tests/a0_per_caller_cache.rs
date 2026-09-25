// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A0 — per-caller response cache and idempotency principal.
//!
//! Two callers presenting different credentials, mTLS certificates, OAuth
//! agents or trusted identity headers must never share a cached result or a
//! stored idempotent result, on the meta route (`gateway_invoke`) or on the
//! direct route (`/mcp/{name}`). One caller repeating itself still hits.
//!
//! Every backend answer carries its delivery number (`call-N`), so a replay is
//! proved by content as well as by the delivery count.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::cache::ResponseCache;
use mcp_gateway::config::{
    ApiKeyConfig, AuthConfig, BackendConfig, Config, FailsafeConfig, TransportConfig,
};
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{
    AgentAuthState, AgentIdentity, AgentRegistry, GatewayKeyPair, Scope,
};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, create_router, open_runtime,
};
use mcp_gateway::mtls::{CertIdentity, MtlsConfig, MtlsPolicy};
use mcp_gateway::protocol::mrtr::IDEMPOTENCY_KEY_META;
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use telemetry_metrics::{
    Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};
use tower::ServiceExt;

const BACKEND: &str = "backend";
const TOOL: &str = "tool";
const ALICE: &str = "alice-secret";
const BOB: &str = "bob-secret";

// ── Fixture ─────────────────────────────────────────────────────────────────

async fn spawn_counting_backend(calls: Arc<AtomicUsize>) -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let calls = Arc::clone(&calls);
            async move { axum::Json(answer(&request, &calls)) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture backend must bind a loopback port");
    let address = listener.local_addr().expect("the bound port must be known");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/")
}

fn answer(request: &Value, calls: &AtomicUsize) -> Value {
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "fixture", "version": "0" }
        }),
        Some("tools/list") => json!({
            "tools": [ { "name": TOOL, "description": "d", "inputSchema": { "type": "object" } } ]
        }),
        Some("tools/call") => {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            json!({ "content": [ { "type": "text", "text": format!("call-{n}") } ] })
        }
        _ => json!({}),
    };
    json!({
        "jsonrpc": "2.0",
        "id": request.get("id").cloned().unwrap_or(Value::Null),
        "result": result
    })
}

fn api_key(name: &str, key: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: key.to_string(),
        name: name.to_string(),
        rate_limit: 0,
        backends: Vec::new(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
    }
}

/// `auth.enabled = true` with two configured keys, distinct names and secrets.
fn two_keys() -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![api_key("alice", ALICE), api_key("bob", BOB)],
        public_paths: Vec::new(),
        client_circuit_breaker: None,
        single_user: false,
    }
}

/// What the gateway under test has switched on.
struct Setup {
    auth: AuthConfig,
    response_cache: bool,
    trust_identity_headers: bool,
}

impl Setup {
    fn auth_off() -> Self {
        Self {
            auth: Config::default().auth,
            response_cache: false,
            trust_identity_headers: false,
        }
    }

    fn two_keys(response_cache: bool) -> Self {
        Self {
            auth: two_keys(),
            response_cache,
            trust_identity_headers: false,
        }
    }
}

/// A gateway with idempotency ON and the counting backend registered. The
/// `TempDir` holds the task store and must outlive the test.
async fn gateway(setup: Setup, calls: &Arc<AtomicUsize>) -> (Arc<AppState>, tempfile::TempDir) {
    let config = Config {
        auth: setup.auth,
        ..Config::default()
    };
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));

    let cache = setup.response_cache.then(|| Arc::new(ResponseCache::new()));
    let mut meta = MetaMcp::with_features(
        Arc::clone(&backends),
        cache,
        None,
        None,
        std::time::Duration::from_secs(300),
    )
    .with_trusted_identity_headers(setup.trust_identity_headers);
    meta.enable_idempotency(
        Arc::new(mcp_gateway::idempotency::IdempotencyCache::new()),
        mcp_gateway::idempotency::CLEANUP_INTERVAL,
    );
    let meta_mcp = Arc::new(meta);
    let continuation = meta_mcp.continuation();

    let subscriptions =
        Arc::new(mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64));
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
        control_plane_base: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks,
        task_executor,
        subscriptions,
        continuation,
    });

    let url = spawn_counting_backend(Arc::clone(calls)).await;
    let backend = Backend::new(
        BACKEND,
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: true,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    );
    assert!(state.backends.register(Arc::new(backend)));
    (state, store_dir)
}

// ── Requests ────────────────────────────────────────────────────────────────

/// Who sends a request. The bearer rides on `Authorization`, where the auth
/// middleware validates it; the identity extensions stand in for layers the
/// auth middleware never writes (TLS, the agent JWT middleware, OIDC).
#[derive(Default)]
struct Caller {
    bearer: Option<&'static str>,
    cert: Option<CertIdentity>,
    agent: Option<AgentIdentity>,
    headers: Vec<(&'static str, &'static str)>,
}

fn with_key(key: &'static str) -> Caller {
    Caller {
        bearer: Some(key),
        ..Caller::default()
    }
}

fn mtls(san: &str) -> Caller {
    Caller {
        cert: Some(CertIdentity {
            san_uris: vec![san.to_string()],
            display_name: "cosmetic".to_string(),
            ..CertIdentity::default()
        }),
        ..Caller::default()
    }
}

fn agent(client_id: &str) -> Caller {
    Caller {
        agent: Some(AgentIdentity {
            client_id: client_id.to_string(),
            agent_name: "cosmetic".to_string(),
            scopes: vec![Scope::parse("tools:*:*:*").expect("wildcard scope")],
            raw_scopes: vec!["tools:*:*:*".to_string()],
            quota_principal: None,
        }),
        ..Caller::default()
    }
}

fn trusted_header(subject: &'static str) -> Caller {
    Caller {
        headers: vec![
            ("x-gateway-identity-subject", subject),
            ("x-gateway-identity-authority", "corp-sso"),
        ],
        ..Caller::default()
    }
}

async fn send(
    state: &Arc<AppState>,
    uri: &str,
    body: &Value,
    caller: Caller,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28");
    if let Some(m) = body.get("method").and_then(Value::as_str) {
        builder = builder.header("mcp-method", m);
    }
    if let Some(n) = body.pointer("/params/name").and_then(Value::as_str) {
        builder = builder.header("mcp-name", n);
    }
    if let Some(bearer) = caller.bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    for (name, value) in &caller.headers {
        builder = builder.header(*name, *value);
    }
    let mut request = builder
        .body(Body::from(serde_json::to_vec(body).expect("body")))
        .expect("request");
    if let Some(cert) = caller.cert {
        request.extensions_mut().insert(cert);
    }
    if let Some(agent) = caller.agent {
        request.extensions_mut().insert(agent);
    }
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

fn client_meta(key: Option<&str>) -> Value {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" }
    });
    if let Some(key) = key {
        meta[IDEMPOTENCY_KEY_META] = json!(key);
    }
    meta
}

/// `gateway_invoke` of the fixture tool on the META route, same arguments
/// every time, carrying a client idempotency key.
///
/// A modern non-read-only call must carry a key (`admission.rs`), so the
/// response-cache cases send a DIFFERENT key per call: the retry guard then
/// cannot deduplicate, and only the response cache can serve a repeat.
async fn post_meta(
    state: &Arc<AppState>,
    id: u32,
    key: Option<&str>,
    caller: Caller,
) -> (StatusCode, Value) {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": TOOL, "arguments": { "a": 1 } },
            "_meta": client_meta(key)
        }
    });
    send(state, "/mcp", &body, caller).await
}

/// A `tools/call` of the fixture tool on the DIRECT route with a client key.
async fn post_direct(
    state: &Arc<AppState>,
    id: u32,
    key: &str,
    caller: Caller,
) -> (StatusCode, Value) {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": TOOL,
            "arguments": { "a": 1 },
            "_meta": { IDEMPOTENCY_KEY_META: key }
        }
    });
    send(state, &format!("/mcp/{BACKEND}"), &body, caller).await
}

/// Which backend delivery a response carries, e.g. `Some("call-1")`.
fn delivery(body: &Value) -> Option<String> {
    let text = body.to_string();
    let start = text.find("call-")?;
    let digits: String = text[start + 5..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    (!digits.is_empty()).then(|| format!("call-{digits}"))
}

// ── Fail-closed counters ────────────────────────────────────────────────────

/// The two counters A0 emits when a caller resolves to no principal. Every
/// caller in this file IS resolvable, so both must stay at zero: without this,
/// an implementation that marked every caller `Unresolved` (and so skipped the
/// guard for everyone) would pass the separation cells for the wrong reason.
const FAIL_CLOSED: [&str; 2] = [
    "mcp_cache_bypass_total",
    "mcp_idempotency_guard_skipped_total",
];

#[derive(Clone, Default)]
struct Tally(Arc<AtomicU64>);

impl CounterFn for Tally {
    fn increment(&self, value: u64) {
        self.0.fetch_add(value, Ordering::SeqCst);
    }
    fn absolute(&self, value: u64) {
        self.0.fetch_max(value, Ordering::SeqCst);
    }
}

/// A thread-local recorder that tallies only the fail-closed counters.
/// `#[tokio::test]` runs on one thread, so the router and the backend it
/// reaches report here.
struct FailClosed(Tally);

impl Recorder for FailClosed {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        if FAIL_CLOSED.contains(&key.name()) {
            Counter::from_arc(Arc::new(self.0.clone()))
        } else {
            Counter::noop()
        }
    }
    fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }
    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

/// Run one case under the recorder and assert no caller was left unresolved.
async fn resolved<T>(case: impl std::future::Future<Output = T>) -> T {
    let tally = Tally::default();
    let recorder = FailClosed(tally.clone());
    let out = {
        let _guard = telemetry_metrics::set_default_local_recorder(&recorder);
        case.await
    };
    assert_eq!(
        tally.0.load(Ordering::SeqCst),
        0,
        "a resolvable caller was treated as unresolved (cache bypassed or guard skipped)"
    );
    out
}

fn ok(label: &str, (status, body): &(StatusCode, Value)) {
    assert_eq!(*status, StatusCode::OK, "{label}: {body}");
    assert!(body.get("error").is_none(), "{label}: {body}");
}

// ── Meta route ──────────────────────────────────────────────────────────────

/// T1 — two API keys, same tool and arguments, response cache on: the second
/// key must not be served the first key's cached result.
#[tokio::test]
async fn meta_route_cache_does_not_serve_one_api_key_callers_result_to_another() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(Setup::two_keys(true), &calls).await;

    let (a, b) = resolved(async {
        let a = post_meta(&state, 1, Some("k-1"), with_key(ALICE)).await;
        (a, post_meta(&state, 2, Some("k-2"), with_key(BOB)).await)
    })
    .await;
    ok("alice", &a);
    ok("bob", &b);

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "bob hit alice's entry: {}",
        b.1
    );
    assert_eq!(delivery(&b.1).as_deref(), Some("call-2"), "bob: {}", b.1);
}

/// T2 — positive control: one key repeating itself still hits the cache.
#[tokio::test]
async fn meta_route_same_api_key_still_hits_cache() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(Setup::two_keys(true), &calls).await;

    let (first, second) = resolved(async {
        let first = post_meta(&state, 1, Some("k-1"), with_key(ALICE)).await;
        (
            first,
            post_meta(&state, 2, Some("k-2"), with_key(ALICE)).await,
        )
    })
    .await;
    ok("first", &first);
    ok("second", &second);

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the repeat missed the cache"
    );
    assert_eq!(delivery(&second.1).as_deref(), Some("call-1"));
}

/// T3 — two API keys, one idempotency key, response cache OFF so only the
/// retry key can separate or pool them: no replay across keys.
#[tokio::test]
async fn meta_route_idempotency_key_does_not_replay_across_api_keys() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(Setup::two_keys(false), &calls).await;

    let (a, b) = resolved(async {
        let a = post_meta(&state, 1, Some("shared"), with_key(ALICE)).await;
        (a, post_meta(&state, 2, Some("shared"), with_key(BOB)).await)
    })
    .await;
    ok("alice", &a);
    ok("bob", &b);

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "bob replayed alice: {}",
        b.1
    );
    assert_eq!(delivery(&b.1).as_deref(), Some("call-2"));
}

/// T3b — positive control, response cache OFF: one key sending one
/// idempotency key twice is deduplicated by the guard. Fails for an
/// implementation that skips the guard for every authenticated caller.
#[tokio::test]
async fn meta_route_same_api_key_idempotency_key_still_deduplicates() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(Setup::two_keys(false), &calls).await;

    let (first, second) = resolved(async {
        let first = post_meta(&state, 1, Some("k1"), with_key(ALICE)).await;
        (
            first,
            post_meta(&state, 2, Some("k1"), with_key(ALICE)).await,
        )
    })
    .await;
    ok("first", &first);
    ok("second", &second);

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the keyed repeat ran twice"
    );
    assert_eq!(delivery(&second.1).as_deref(), Some("call-1"));
}

// ── Direct route ────────────────────────────────────────────────────────────

/// Two direct-route calls with one idempotency key; returns the deliveries.
/// Runs under [`resolved`], so every direct cell also asserts that neither
/// caller was left unresolved.
async fn direct_pair(setup: Setup, first: Caller, second: Caller) -> (usize, Value) {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(setup, &calls).await;
    let (a, b) = resolved(async {
        let a = post_direct(&state, 1, "shared", first).await;
        let b = post_direct(&state, 2, "shared", second).await;
        (a, b)
    })
    .await;
    ok("first", &a);
    ok("second", &b);
    (calls.load(Ordering::SeqCst), b.1)
}

/// T4 — two API keys on the direct route, one idempotency key.
#[tokio::test]
async fn direct_route_idempotency_separates_api_key_callers() {
    let (calls, second) = direct_pair(Setup::two_keys(false), with_key(ALICE), with_key(BOB)).await;
    assert_eq!(calls, 2, "bob replayed alice on the direct route: {second}");
}

/// T5 — two mTLS certificates with different SANs, auth off.
#[tokio::test]
async fn direct_route_idempotency_separates_mtls_callers() {
    let (calls, second) = direct_pair(
        Setup::auth_off(),
        mtls("spiffe://example.test/alice"),
        mtls("spiffe://example.test/bob"),
    )
    .await;
    assert_eq!(calls, 2, "two certificates shared one entry: {second}");
}

/// T6 (i) — two OAuth agents, auth off and no credential, so only the agent
/// identity can separate the callers.
#[tokio::test]
async fn direct_route_idempotency_separates_oauth_agents() {
    let (calls, second) = direct_pair(Setup::auth_off(), agent("agent-a"), agent("agent-b")).await;
    assert_eq!(calls, 2, "two OAuth agents shared one entry: {second}");
}

/// T5 control — one certificate sending one key twice is deduplicated, so
/// the separation above is not the guard being skipped for everyone.
#[tokio::test]
async fn direct_route_same_mtls_caller_still_deduplicates() {
    let (calls, second) = direct_pair(
        Setup::auth_off(),
        mtls("spiffe://example.test/alice"),
        mtls("spiffe://example.test/alice"),
    )
    .await;
    assert_eq!(calls, 1, "the keyed repeat ran twice: {second}");
    assert_eq!(delivery(&second).as_deref(), Some("call-1"));
}

/// T6 (i) control — one OAuth agent sending one key twice is deduplicated.
#[tokio::test]
async fn direct_route_same_oauth_agent_still_deduplicates() {
    let (calls, second) = direct_pair(Setup::auth_off(), agent("agent-a"), agent("agent-a")).await;
    assert_eq!(calls, 1, "the keyed repeat ran twice: {second}");
    assert_eq!(delivery(&second).as_deref(), Some("call-1"));
}

/// T6 (ii) control — one trusted subject sending one key twice is deduplicated.
#[tokio::test]
async fn direct_route_same_trusted_header_still_deduplicates() {
    let setup = Setup {
        trust_identity_headers: true,
        ..Setup::auth_off()
    };
    let (calls, second) =
        direct_pair(setup, trusted_header("alice"), trusted_header("alice")).await;
    assert_eq!(calls, 1, "the keyed repeat ran twice: {second}");
    assert_eq!(delivery(&second).as_deref(), Some("call-1"));
}

/// T6 (ii) — trusted identity headers, trust ON, auth off, no credential.
#[tokio::test]
async fn direct_route_idempotency_separates_trusted_headers() {
    let setup = Setup {
        trust_identity_headers: true,
        ..Setup::auth_off()
    };
    let (calls, second) = direct_pair(setup, trusted_header("alice"), trusted_header("bob")).await;
    assert_eq!(calls, 2, "two trusted subjects shared one entry: {second}");
}

/// T6 control — trust OFF: the headers are ignored, both requests are the
/// anonymous principal, and they pool. Headers are not trusted by default.
#[tokio::test]
async fn direct_route_ignores_identity_headers_when_trust_is_off() {
    let (calls, second) = direct_pair(
        Setup::auth_off(),
        trusted_header("alice"),
        trusted_header("bob"),
    )
    .await;
    assert_eq!(calls, 1, "untrusted headers separated callers: {second}");
    assert_eq!(delivery(&second).as_deref(), Some("call-1"));
}

/// T7 — positive control: one API key sending one idempotency key twice on
/// the direct route is deduplicated, and the replay is the first result.
#[tokio::test]
async fn direct_route_same_caller_still_deduplicates() {
    let (calls, second) =
        direct_pair(Setup::two_keys(false), with_key(ALICE), with_key(ALICE)).await;
    assert_eq!(calls, 1, "the keyed repeat ran twice: {second}");
    assert_eq!(delivery(&second).as_deref(), Some("call-1"));
}
