// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 liveness rows, part 3: a token-exchange backend (a
//! per-caller mint with no `account:`), its live `IdP` fixture, and the lift
//! rows built on it (R6m, T12, S2b, L0, L4', L5).

use super::*;

/// R6m support: a token-exchange backend whose `IdP` is the key-server `IdP`
/// pattern from `token_exchange_live_tests`, with `kill()`.
mod r6m_token_exchange {
    use std::sync::Arc;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    use axum::{Router, routing::get};
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    use crate::config::{
        KeyServerConfig, KeyServerPolicyConfig, KeyServerProviderConfig, PolicyMatchConfig,
        PolicyScopesConfig,
    };
    use crate::gateway::oauth::{GatewayKeyPair, jwks_handler};
    use crate::key_server::policy::PolicyEngine;
    use crate::key_server::{
        InMemoryTokenStore, KeyServer, OidcVerifier, handler::key_server_routes,
    };

    const GATEWAY_ASSERTION_ISSUER: &str = "mcp-gateway";

    /// The in-process key-server `IdP`: `/auth/token` plus `/.well-known/jwks.json`.
    pub(super) struct LiveIdp {
        addr: std::net::SocketAddr,
        server: tokio::task::JoinHandle<()>,
    }

    impl LiveIdp {
        pub(super) async fn start(key: &Arc<GatewayKeyPair>) -> Self {
            let config = KeyServerConfig {
                enabled: true,
                oidc: vec![KeyServerProviderConfig {
                    issuer: GATEWAY_ASSERTION_ISSUER.to_string(),
                    jwks_uri: Some(String::new()),
                    discovery_url: None,
                    auto_discover: false,
                    audiences: Vec::new(),
                    allowed_domains: Vec::new(),
                }],
                policies: vec![KeyServerPolicyConfig {
                    match_criteria: PolicyMatchConfig {
                        domain: None,
                        issuer: GATEWAY_ASSERTION_ISSUER.to_string(),
                        email: None,
                        group: None,
                    },
                    scopes: PolicyScopesConfig {
                        backends: vec!["*".to_string()],
                        tools: vec!["*".to_string()],
                        rate_limit: 42,
                    },
                }],
                ..KeyServerConfig::default()
            };
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind an ephemeral port");
            let addr = listener.local_addr().expect("a local address");
            let mut config = config;
            config.oidc[0].jwks_uri = Some(format!("http://{addr}/.well-known/jwks.json"));
            let key_server = Arc::new(KeyServer {
                store: Arc::new(InMemoryTokenStore::new()),
                oidc: Arc::new(OidcVerifier::with_http_client(
                    config.oidc.clone(),
                    reqwest::Client::new(),
                )),
                policy: Arc::new(PolicyEngine::new(config.policies.clone())),
                config,
            });
            let jwks_router = Router::new()
                .route("/.well-known/jwks.json", get(jwks_handler))
                .with_state(Arc::clone(key));
            let app = key_server_routes(key_server).merge(jwks_router);
            let server = tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .expect("the in-process IdP serves");
            });
            Self { addr, server }
        }

        pub(super) fn endpoint(&self) -> String {
            format!("http://{}/auth/token", self.addr)
        }

        /// Kill the `IdP` outright: any later mint must fail without it.
        pub(super) fn kill(self) {
            self.server.abort();
        }
    }

    /// A counting backend transport: `tools/call` answers the marker;
    /// listings answer the one tool without counting.
    /// The token-exchange backend R6m calls: per-caller propagation, no
    /// `account:`.
    pub(super) const TX: &str = "tx";

    /// The verified caller the `IdP` mints for.
    pub(super) fn alice() -> crate::key_server::oidc::VerifiedIdentity {
        crate::key_server::oidc::VerifiedIdentity {
            subject: "alice-subject".to_string(),
            email: "alice@corp.example".to_string(),
            name: None,
            groups: vec!["eng".to_string()],
            issuer: "https://corp-idp.example".to_string(),
        }
    }

    /// The router over [`TX`]. Its counting transport serves `alice`'s
    /// per-user slot (the binding token exchange mints under), so a mint that
    /// succeeds reaches it. Returns the send counter and the directories to
    /// keep alive.
    pub(super) async fn gateway(
        key: &Arc<crate::gateway::oauth::GatewayKeyPair>,
        endpoint: String,
        alice: &crate::key_server::oidc::VerifiedIdentity,
    ) -> (
        axum::Router,
        Arc<AtomicUsize>,
        (tempfile::TempDir, tempfile::TempDir),
    ) {
        gateway_armed(key, endpoint, alice, |meta| meta).await
    }

    /// [`gateway`], with `arm` applied to the `MetaMcp` before it serves.
    pub(super) async fn gateway_armed(
        key: &Arc<crate::gateway::oauth::GatewayKeyPair>,
        endpoint: String,
        alice: &crate::key_server::oidc::VerifiedIdentity,
        arm: impl FnOnce(crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp,
    ) -> (
        axum::Router,
        Arc<AtomicUsize>,
        (tempfile::TempDir, tempfile::TempDir),
    ) {
        use crate::config::{BackendConfig, TransportConfig};
        use crate::identity_propagation::{
            IdentityPropagationConfig, PropagationStrategyKind, SessionMode, TokenExchangeStrategy,
        };
        const AUDIENCE: &str = "https://tx.internal";
        const SCOPE: &str = "backends:tx tools:read";
        let sends = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(crate::backend::Backend::new(
            TX,
            BackendConfig {
                transport: TransportConfig::Http {
                    http_url: "https://tx.internal/mcp".to_string(),
                    streamable_http: Some(true),
                    protocol_version: None,
                },
                identity_propagation: Some(IdentityPropagationConfig {
                    strategy: PropagationStrategyKind::TokenExchange,
                    audience: AUDIENCE.to_string(),
                    required: true,
                    session_mode: SessionMode::Stateless,
                    token_exchange_endpoint: Some(endpoint.clone()),
                    token_exchange_scope: Some(SCOPE.to_string()),
                }),
                ..BackendConfig::r2_off()
            },
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        let counting: Arc<dyn crate::transport::Transport> = Arc::new(Counting {
            sends: Arc::clone(&sends),
        });
        backend.set_transport_for_test(Arc::clone(&counting));
        // The per-user slot token exchange dispatches on, keyed as its
        // `exchange_cache_key` builds it: `cache_binding(subject, audience)`
        // widened by the length-prefixed endpoint and scope.
        let subject = alice.stable_actor_id();
        let binding = format!(
            "idp:{}:{}:{}:{}:{}:{}:{}:{}",
            subject.len(),
            subject,
            AUDIENCE.len(),
            AUDIENCE,
            endpoint.len(),
            endpoint,
            SCOPE.len(),
            SCOPE,
        );
        backend
            .set_pooled_transport_for_test(&crate::backend::PoolKey::PerUser { binding }, counting);
        let tool: crate::protocol::Tool = serde_json::from_value(json!({
            "name": super::TOOL,
            "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
        }))
        .expect("a tool");
        backend.store_shared_tools_for_test(vec![tool]);
        let registry = Arc::new(crate::backend::BackendRegistry::new());
        assert!(registry.register(backend), "the fixture backend registers");

        let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&registry));
        meta.set_identity_propagation(Arc::new(TokenExchangeStrategy::with_http_client(
            Arc::clone(key),
            300,
            reqwest::Client::new(),
        )));
        let log_dir = tempfile::tempdir().expect("a log directory");
        let log = Arc::new(
            crate::security::TransparencyLogger::open(Arc::new(
                crate::security::transparency_log::TransparencyLogConfig {
                    enabled: true,
                    path: log_dir
                        .path()
                        .join("audit.jsonl")
                        .to_string_lossy()
                        .into_owned(),
                    key_id: "r6m".to_string(),
                    ..crate::security::transparency_log::TransparencyLogConfig::default()
                },
            ))
            .expect("the transparency log opens"),
        );
        meta.enable_transparency_log(Arc::clone(&log));
        let auth = crate::config::AuthConfig::default();
        let (mut state, store) =
            crate::gateway::router::tests::test_router_app_state_with_auth(&auth).await;
        let state_mut = Arc::get_mut(&mut state).expect("state is unique");
        state_mut.backends = registry;
        state_mut.meta_mcp = Arc::new(arm(meta));
        state_mut.transparency_log = Some(log);
        (
            crate::gateway::router::create_router(state),
            sends,
            (log_dir, store),
        )
    }

    /// A `tools/call` as `alice`, whose verified identity rides the request.
    pub(super) async fn send_as(
        router: &axum::Router,
        alice: &crate::key_server::oidc::VerifiedIdentity,
        params: Value,
    ) -> Value {
        send_method_as(router, alice, ("tools/call", "gateway_invoke"), params).await
    }

    /// [`send_as`] for any `(method, name)`.
    pub(super) async fn send_method_as(
        router: &axum::Router,
        alice: &crate::key_server::oidc::VerifiedIdentity,
        (method, name): (&str, &str),
        params: Value,
    ) -> Value {
        let body = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method)
            .header("mcp-name", name)
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        request.extensions_mut().insert(alice.clone());
        let response = router.clone().oneshot(request).await.expect("an answer");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    pub(super) struct Counting {
        pub(super) sends: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::transport::Transport for Counting {
        async fn request(
            &self,
            method: &str,
            _params: Option<Value>,
        ) -> crate::Result<crate::protocol::JsonRpcResponse> {
            use crate::protocol::{JsonRpcResponse, RequestId};
            if method == "tools/call" {
                self.sends.fetch_add(1, Ordering::SeqCst);
                return Ok(JsonRpcResponse::success(
                    RequestId::Number(1),
                    json!({"content": [{"type": "text", "text": super::MARKER}]}),
                ));
            }
            if method == "tools/list" {
                return Ok(JsonRpcResponse::success(
                    RequestId::Number(1),
                    json!({"tools": [{"name": super::TOOL, "inputSchema": {"type": "object"}}]}),
                ));
            }
            Ok(JsonRpcResponse::success(RequestId::Number(1), json!({})))
        }

        async fn request_with_headers(
            &self,
            method: &str,
            params: Option<Value>,
            _extra_headers: &[(String, String)],
            _identity_key: Option<&str>,
            _resend: crate::transport::ResendPermission,
        ) -> crate::Result<crate::protocol::JsonRpcResponse> {
            self.request(method, params).await
        }

        async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
            Ok(())
        }

        fn is_connected(&self) -> bool {
            true
        }

        async fn close(&self) -> crate::Result<()> {
            Ok(())
        }
    }
}

/// R6m (E7 meta level, through the REAL replay entry): a keyed call succeeds
/// via token exchange; the `IdP` is killed and the clock moved past the cached
/// token's TTL; the same keyed repeat is refused, with nothing sent and no
/// stored output. Current-thread: the forced clock is this thread's.
#[tokio::test]
async fn r6m_token_exchange_replay_after_idp_kill_and_ttl_is_refused() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let call = || {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some("r6m"), false)})
    };

    // A keyed call succeeds through token exchange, over the real HTTP route.
    let first = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the token-exchange call did not dispatch: {first}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1, "premise: {first}");

    // The `IdP` dies and the cached token's TTL (one hour) passes; the
    // retained result (one day) is still present.
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);

    // The same keyed repeat, through the same route: admission replays it with
    // its target, the replay defers (E7), the live mint fails without the
    // `IdP`, and nothing stored goes out.
    let again = r6m_token_exchange::send_as(&router, &alice, call()).await;
    eprintln!("R6m answer: {again}");
    assert!(
        !again.to_string().contains(MARKER),
        "R6m: the stored output was served: {again}"
    );
    assert!(again.get("error").is_some(), "R6m: not a refusal: {again}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "R6m: the call reached the backend: {again}"
    );
}

/// T12 (site 5, M38): a task-augmented keyed call to a token-exchange backend
/// (per-caller mint, no `account:`, so Unjudged and still visible) completes;
/// the `IdP` dies and the cached token's TTL passes; the same keyed task call
/// is repeated. E9 does not apply (not Unavailable) and the catalogue passes,
/// so site 5 proves the account by resolving, which fails: the repeat answers
/// exactly as the same call made live does (normalising only `id`), never with
/// the stored task. Bypassing site 5 (M38) must fail this row.
/// Current-thread: the forced clock is this thread's.
#[tokio::test]
async fn t12_token_exchange_task_repeat_after_idp_kill_answers_as_live() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let call = |key: &str, task: bool| {
        let mut params = json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some(key), task)});
        if task {
            params["task"] = json!({});
        }
        params
    };
    let made = r6m_token_exchange::send_as(&router, &alice, call("t12", true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if sends.load(Ordering::SeqCst) >= 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task dispatched: {made}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    loop {
        let params = json!({"taskId": id, "_meta": meta(None, true)});
        let got =
            r6m_token_exchange::send_method_as(&router, &alice, ("tasks/get", &id), params).await;
        let status = got.pointer("/result/status").and_then(Value::as_str);
        if matches!(status, Some("completed" | "failed" | "cancelled")) {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task settled: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let sent = sends.load(Ordering::SeqCst);
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);
    let again = r6m_token_exchange::send_as(&router, &alice, call("t12", true)).await;
    let live = r6m_token_exchange::send_as(&router, &alice, call("t12-live", false)).await;
    eprintln!("T12 repeat: {again}");
    eprintln!("T12 live: {live}");
    assert!(
        live.get("error").is_some(),
        "premise: the live call is refused: {live}"
    );
    assert_ne!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "T12: the stored task was answered back after the IdP died: {again}"
    );
    let (mut again_id, mut live_id) = (again.clone(), live.clone());
    again_id["id"] = Value::Null;
    live_id["id"] = Value::Null;
    assert_eq!(
        again_id, live_id,
        "T12: the repeat differs from the live call: {again} vs {live}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        sent,
        "T12: the call reached the backend: {again}"
    );
}

/// T12r (product seat finding 2): T12's setup, counting the identity
/// propagation audit records (`idp_*`) each answer writes. The repeat's
/// refusal is the live call's, so it writes exactly the records the live call
/// writes: one failed resolution per call, never a second one at site 5.
/// Current-thread: the forced clock is this thread's.
#[tokio::test]
async fn t12r_a_failed_task_repeat_writes_the_live_calls_idp_records() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let log = dirs.0.path().join("audit.jsonl");
    let idp_records = || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains("\"action\":\"idp_"))
            .count()
    };
    let call = |key: &str, task: bool| {
        let mut params = json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some(key), task)});
        if task {
            params["task"] = json!({});
        }
        params
    };
    let made = r6m_token_exchange::send_as(&router, &alice, call("t12r", true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let params = json!({"taskId": id, "_meta": meta(None, true)});
        let got =
            r6m_token_exchange::send_method_as(&router, &alice, ("tasks/get", &id), params).await;
        let status = got.pointer("/result/status").and_then(Value::as_str);
        if matches!(status, Some("completed" | "failed" | "cancelled")) {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task settled: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        sends.load(Ordering::SeqCst) >= 1,
        "premise: the task dispatched"
    );
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);

    let before = idp_records();
    let live = r6m_token_exchange::send_as(&router, &alice, call("t12r-live", false)).await;
    let live_records = idp_records() - before;
    let before = idp_records();
    let again = r6m_token_exchange::send_as(&router, &alice, call("t12r", true)).await;
    let repeat_records = idp_records() - before;
    eprintln!("T12r live ({live_records} idp records): {live}");
    eprintln!("T12r repeat ({repeat_records} idp records): {again}");
    assert!(
        live.get("error").is_some(),
        "premise: the live call is refused: {live}"
    );
    assert!(
        live_records >= 1,
        "premise: the live refusal writes an idp record"
    );
    assert_eq!(
        repeat_records, live_records,
        "T12r: the repeat wrote a different number of idp records than the live call"
    );
}

/// S2b (mutant M28): the token-exchange backend's keyed replay with the
/// `IdP` ALIVE. Admission replays it with its target, the replay defers (E7:
/// a per-caller mint), resolution succeeds, and the lift serves the retained
/// result: the stored bytes, nothing sent again. A lift that refuses or
/// re-dispatches after a successful resolution (M28) must fail this row.
#[tokio::test]
async fn s2b_token_exchange_replay_is_lifted_when_the_mint_succeeds() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let call = || {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some("s2b"), false)})
    };
    let first = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1, "premise: {first}");
    let again = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        again.to_string().contains(MARKER),
        "S2b: the lifted replay was not served: {again}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "S2b: the replay was re-sent: {again}"
    );
    drop(idp);
}

/// L0 (mutant M2b): with the meta idempotency cache armed, as the boot path
/// always arms it, the lift answers before the key check: the keyed repeat
/// is the first answer byte-for-byte and nothing is re-sent. Lifting after
/// the key check (M2b) lets the cache answer instead, re-stamped as a fresh
/// cache hit.
#[tokio::test]
async fn l0_the_lift_answers_before_an_armed_idempotency_cache() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_armed(&key, idp.endpoint(), &alice, |mut meta| {
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                std::time::Duration::from_secs(60),
            );
            meta
        })
        .await;
    let call = || {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some("l0"), false)})
    };
    let first = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let again = r6m_token_exchange::send_as(&router, &alice, call()).await;
    eprintln!("L0 first: {first}");
    eprintln!("L0 again: {again}");
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "L0: re-sent: {again}"
    );
    assert_eq!(again, first, "L0: the repeat is not the first answer");
    drop(idp);
}

/// L5 (mutant M4): a lifted replay keeps its signing nonce spent. Alice's
/// signed call under nonce `n1` dispatches; its keyed repeat, signed under a
/// fresh `n2` (the nonce is not part of the fingerprint), is lifted with no
/// second send; a fresh-key call re-using `n2` is then refused as a replay
/// and never sent, while `n3` is served (control). A lift that hands its
/// nonce back (M4) lets the re-used `n2` through.
#[tokio::test]
async fn l5_a_lifted_replay_keeps_its_nonce_spent() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_armed(&key, idp.endpoint(), &alice, |mut meta| {
            meta.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    b"l5-signing-key-0123456789abcdef-l5".to_vec(),
                    None,
                    "l5".into(),
                ),
                std::time::Duration::from_secs(300),
                true,
            );
            meta
        })
        .await;
    let call = |idem: &str, nonce: &str| {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}, "nonce": nonce},
            "_meta": meta(Some(idem), false)})
    };
    let first = r6m_token_exchange::send_as(&router, &alice, call("l5", "n1")).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "premise: one send: {first}"
    );
    let again = r6m_token_exchange::send_as(&router, &alice, call("l5", "n2")).await;
    assert!(
        again.to_string().contains(MARKER),
        "premise: the lifted replay was served: {again}"
    );
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "premise: the replay was lifted: {again}"
    );
    let reused = r6m_token_exchange::send_as(&router, &alice, call("l5-reuse", "n2")).await;
    eprintln!("L5 reused nonce: {reused}");
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "L5: a re-used nonce was sent after a lift: {reused}"
    );
    assert!(
        !reused.to_string().contains(MARKER),
        "L5: a re-used nonce was served: {reused}"
    );
    let fresh = r6m_token_exchange::send_as(&router, &alice, call("l5-fresh", "n3")).await;
    assert!(
        fresh.to_string().contains(MARKER),
        "control: a fresh nonce is served: {fresh}"
    );
    drop(idp);
}

/// L4' (mutants M8, M2b): a lifted replay writes ONE invocation record, and
/// it reads as the first execution's did: the same request hash (the
/// envelope the route stage passes, `gateway_invoke`'s own arguments) and the
/// same response hash (the stored execution's facts, MIK-7641), and the
/// same backend and tool, which come from the envelope the lift hands
/// `audit_replay`. A wrong envelope (M8) loses the backend and tool.
#[tokio::test]
async fn l4_a_lifted_replay_records_the_first_execution_s_hashes() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, _sends, dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let log = dirs.0.path().join("audit.jsonl");
    let call = || {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some("l4"), false)})
    };
    // The invocation records (those carrying a request hash) since `skip`.
    let invocations = |skip: usize| -> Vec<Value> {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .skip(skip)
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|record| record.get("request_hash").is_some())
            .collect()
    };
    let start = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .count();
    let first = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let original = invocations(start);
    assert_eq!(
        original.len(),
        1,
        "premise: one first-run record: {original:?}"
    );
    let before = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .count();
    let again = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        again.to_string().contains(MARKER),
        "premise: the lifted replay was served: {again}"
    );
    let replayed = invocations(before);
    eprintln!("L4' first: {original:?}");
    eprintln!("L4' replay: {replayed:?}");
    assert_eq!(
        replayed.len(),
        1,
        "L4': not one replay record: {replayed:?}"
    );
    for field in [
        "request_hash",
        "response_hash",
        "outcome",
        "server",
        "tool",
        "route",
    ] {
        assert_eq!(
            replayed[0].get(field),
            original[0].get(field),
            "L4': the replay's {field} differs from the first execution's"
        );
    }
    drop(idp);
}
