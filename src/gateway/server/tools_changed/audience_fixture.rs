// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture of the MIK-8350 `list_changed` audience rows: one in-process HTTP
//! gateway with the real tools-changed drain, two API keys (`k-std`, and
//! `k-deny` denied `read` and `fetch`), temporary-token principals, a shared
//! backend `alpha` (surfaces `read`/`write`, offers `scan`/`fetch`), a
//! per-user backend `beta` with a shared fallback, a required per-user
//! backend `gamma`, and a capability source `caps`.
//!
//! "Told" is read without wall-clock waits: a settle marker (a catalogue
//! nudge no listener hears) is queued behind every change, and the drain's
//! completion signal (`drain_seam`) says everything before it is delivered.
//! A listen stream is then flushed with a sentinel notification the stream
//! also subscribes to, so what precedes the sentinel is all it was sent.
//! Tests must run on the default one-thread `#[tokio::test]` runtime.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::drain_seam::{self, SETTLE_PREFIX};
use crate::backend::tools_nudge::ToolsNudge;
use crate::backend::{Backend, PoolKey};
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::router::AppState;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::key_server::oidc_test_harness::{Harness, ISS_A, config_yaml};
use crate::key_server::{KeyServer, TemporaryToken};
use crate::protocol::{JsonRpcResponse, RequestId, Tool};

/// Bound on every wait for something that must happen.
pub(super) const ARRIVAL: Duration = Duration::from_secs(20);
pub(super) const LIST_CHANGED: &str = "notifications/tools/list_changed";
pub(super) const SENTINEL: &str = "notifications/resources/list_changed";

/// A tool with `name` whose description is `description`.
pub(in crate::gateway::server) fn tool(name: &str, description: &str) -> Tool {
    serde_json::from_value(json!({
        "name": name, "description": description, "inputSchema": { "type": "object" }
    }))
    .expect("a tool")
}

/// Mints `Bearer minted-for-<subject>` bound to `<subject>@<audience>`.
struct PerIdentityMint;

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for PerIdentityMint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        let subject_key = identity.subject.clone();
        Ok(crate::identity_propagation::PropagatedCredential {
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer minted-for-{subject_key}"),
            )],
            expires_at: i64::MAX,
            cache_binding: format!("{subject_key}@{}", backend.audience),
            subject_key,
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// One pool slot's transport: a `tools/list` that names its tools, and
/// success for everything else.
struct Wire(Vec<Tool>);

#[async_trait::async_trait]
impl crate::transport::Transport for Wire {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({ "tools": self.0 })
        } else {
            json!({})
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), body))
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

fn api_key(name: &str, denied: &[&str]) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(name.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: (!denied.is_empty())
            .then(|| denied.iter().map(|d| (*d).to_string()).collect()),
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// A key-server temporary token for `subject`, allowed every fixture backend.
pub(super) fn principal_token(subject: &str) -> TemporaryToken {
    use crate::key_server::InMemoryTokenStore;
    let now = crate::clock::unix_secs().expect("clock after 1970");
    TemporaryToken {
        jti: InMemoryTokenStore::generate_jti(),
        token: InMemoryTokenStore::generate_bearer(),
        identity: VerifiedIdentity {
            subject: subject.to_string(),
            email: format!("{subject}@example.invalid"),
            name: None,
            groups: vec![],
            issuer: "https://idp.example.invalid".to_string(),
        },
        scopes: crate::key_server::store::TokenScopes {
            backends: ["alpha", "beta", "gamma", "caps"]
                .map(String::from)
                .to_vec(),
            tools: vec![],
            rate_limit: 0,
        },
        iat: now,
        exp: now + 3600,
        client_ip: None,
    }
}

/// As [`principal_token`], narrowed to the tools in `tools`: the token sees
/// those and no others.
pub(super) fn scoped_token(subject: &str, tools: &[&str]) -> TemporaryToken {
    let mut token = principal_token(subject);
    token.scopes.tools = tools.iter().map(|t| (*t).to_string()).collect();
    token
}

pub(in crate::gateway::server) fn per_user_backend(name: &str, required: bool) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: name.to_string(),
                required,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Wire(vec![tool("shared_beta", "shared")])));
    backend
}

fn shared_backend(name: &str) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Wire(Vec::new())));
    backend
}

/// The pool binding a principal's slot on `backend` has.
pub(in crate::gateway::server) fn binding(subject: &str, backend: &str) -> String {
    format!("{subject}@{backend}")
}

fn capability_yaml(description: &str) -> String {
    format!(
        "fulcrum: \"1.0\"\nname: hidden_cap\ndescription: {description}\n\
schema:\n  input:\n    type: object\n    properties: {{}}\n\
providers:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.invalid\n      path: /p\n      method: GET\n\
auth:\n  required: false\n  type: none\n"
    )
}

/// The Open `WebUI` installation and header the adapter rows configure.
pub(super) const ADAPTER_INSTALLATION: &str = "inst";
const ADAPTER_HEADER: &str = "x-openwebui-assertion";
const ADAPTER_SECRET: &str = "audience-adapter-signing-secret-0123456789";

/// Attach `assertion` as the Open `WebUI` adapter's header; untouched without one.
fn asserted(request: &mut axum::http::Request<Body>, assertion: Option<&str>) {
    if let Some(assertion) = assertion {
        request
            .headers_mut()
            .insert(ADAPTER_HEADER, assertion.parse().expect("a header value"));
    }
}

/// An adapter assertion for end user `sub`, signed as the installation signs.
pub(super) fn adapter_assertion(sub: &str) -> String {
    let now = crate::clock::unix_secs().expect("clock after 1970");
    let claims = json!({ "iss": "open-webui", "sub": sub, "iat": now, "exp": now + 120 });
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(ADAPTER_SECRET.as_bytes()),
    )
    .expect("sign")
}

/// The gateway under test and the handles rows drive it with.
pub(super) struct World {
    pub state: Arc<AppState>,
    pub router: axum::Router,
    pub key_server: Arc<KeyServer>,
    pub caps: Arc<crate::capability::CapabilityBackend>,
    feed: tokio::sync::mpsc::UnboundedSender<ToolsNudge>,
    /// The minted id of each legacy session, by the label a row gave it:
    /// production mints every id (F9), so the label is not the id.
    pub(super) minted: std::cell::RefCell<std::collections::HashMap<String, String>>,
    _shutdown: tokio::sync::broadcast::Sender<()>,
    _store: tempfile::TempDir,
    _audit: tempfile::NamedTempFile,
    /// The adapter's env file, kept alive for [`Self::start_adapter`].
    _adapter: Option<tempfile::TempDir>,
}

impl World {
    pub(super) async fn start() -> Self {
        Self::start_with(|meta| meta).await
    }

    /// As [`Self::start`], with `configure` applied to the Meta-MCP last.
    pub(super) async fn start_with(configure: impl FnOnce(MetaMcp) -> MetaMcp) -> Self {
        let key_server = Arc::new(KeyServer::new(crate::config::KeyServerConfig::default()));
        Self::start_on(key_server, None, configure).await
    }

    /// As [`Self::start_with`], with an Open `WebUI` adapter that k-std may
    /// present ([`adapter_assertion`] mints its assertions).
    pub(super) async fn start_adapter(configure: impl FnOnce(MetaMcp) -> MetaMcp) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = dir.path().join("adapter.env");
        crate::gateway::test_helpers::write_owner_only(
            &env,
            format!(
                "AUDIENCE_OWUI_HMAC={ADAPTER_SECRET}\n\
                 AUDIENCE_OWUI_STORE=UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=\n"
            ),
        )
        .expect("write env");
        let config: crate::config::Config = serde_yaml::from_str(&format!(
            "env_files: ['{}']\naccounts:\n  schema_version: accounts.v1\n  enabled: false\n  \
             deployment: single_process\n  instance_id: audience\n  \
             store_dir: /unused/audience-store\n  authority_dir: /unused/audience-authority\n  \
             current_key_id: primary\n  keys:\n    primary: env:AUDIENCE_OWUI_STORE\n  \
             adapters:\n    - kind: openwebui_signed_header\n      \
             installation_id: {ADAPTER_INSTALLATION}\n      header: {ADAPTER_HEADER}\n      \
             issuer: open-webui\n      hmac_secret_ref: env:AUDIENCE_OWUI_HMAC\n      \
             allowed_api_key_names: [k-std]\n",
            env.display().to_string().replace('\'', "''")
        ))
        .expect("adapter config parses");
        let key_server = Arc::new(KeyServer::new(crate::config::KeyServerConfig::default()));
        Self::start_on(key_server, Some((config, dir)), configure).await
    }

    /// As [`Self::start`], with a real OIDC key server: one provider
    /// (`ISS_A`) whose policy grants every backend, and delegated bearers on.
    pub(super) async fn start_oidc() -> (Self, Harness) {
        Self::start_oidc_with(&format!(
            "  - match: {{ issuer: \"{ISS_A}\" }}\n    \
             scopes: {{ backends: [\"*\"], tools: [\"*\"], rate_limit: 0 }}\n"
        ))
        .await
    }

    /// As [`Self::start_oidc`], with these key-server `policies` rules.
    pub(super) async fn start_oidc_with(policies: &str) -> (Self, Harness) {
        let extra = format!("delegated_bearer: true\npolicies:\n{policies}");
        let oidc = Harness::start(&config_yaml("[]", &extra)).await;
        (
            Self::start_on(Arc::clone(&oidc.ks), None, |meta| meta).await,
            oidc,
        )
    }

    async fn start_on(
        key_server: Arc<KeyServer>,
        live: Option<(crate::config::Config, tempfile::TempDir)>,
        configure: impl FnOnce(MetaMcp) -> MetaMcp,
    ) -> Self {
        let auth = AuthConfig {
            enabled: true,
            api_keys: vec![
                api_key("k-std", &[]),
                api_key("k-deny", &["read", "fetch", "hidden_cap"]),
                ApiKeyConfig {
                    backends: vec!["beta".to_string()],
                    ..api_key("k-narrow", &[])
                },
            ],
            ..AuthConfig::default()
        };
        let audit = tempfile::NamedTempFile::new().expect("tempfile");
        let logger = crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path: audit.path().to_string_lossy().to_string(),
                key_id: "mik-8350".to_string(),
                ..crate::security::TransparencyLogConfig::default()
            },
        ))
        .expect("transparency logger opens");
        let caps = Arc::new(crate::capability::CapabilityBackend::new(
            "caps",
            Arc::new(crate::capability::CapabilityExecutor::new()),
        ));
        let surfaced = [
            ("alpha", "read"),
            ("alpha", "write"),
            ("caps", "hidden_cap"),
        ]
        .map(|(server, tool)| SurfacedToolConfig {
            server: server.to_string(),
            tool: tool.to_string(),
        })
        .to_vec();
        let wire_caps = Arc::clone(&caps);
        let (mut state, store) = crate::gateway::router::tests::audience_state(
            &auth,
            Some(Arc::clone(&key_server)),
            move |meta| {
                let mut meta = meta.with_surfaced_tools(surfaced);
                meta.enable_transparency_log(Arc::new(logger));
                meta.set_identity_propagation(Arc::new(PerIdentityMint));
                meta.set_capabilities(wire_caps);
                configure(meta)
            },
        )
        .await;
        let (feed, nudges) = tokio::sync::mpsc::unbounded_channel();
        let st = Arc::get_mut(&mut state).expect("state is unique");
        let adapter = live.map(|(config, dir)| {
            st.live_config = Arc::new(crate::config_reload::LiveConfig::new(config));
            dir
        });
        st.backends.set_change_feed(feed.clone());
        for backend in [
            shared_backend("alpha"),
            per_user_backend("beta", false),
            per_user_backend("gamma", true),
        ] {
            assert!(st.backends.register(backend), "fixture registration");
        }
        let router = crate::gateway::router::create_router(Arc::clone(&state));
        let (shutdown, stop) = tokio::sync::broadcast::channel(1);
        super::spawn_drain(Arc::clone(&state), nudges, stop);
        let world = Self {
            state,
            router,
            key_server,
            caps,
            feed,
            minted: std::cell::RefCell::default(),
            _shutdown: shutdown,
            _store: store,
            _audit: audit,
            _adapter: adapter,
        };
        let all = vec![
            tool("read", "r"),
            tool("write", "w"),
            tool("scan", "s"),
            tool("fetch", "f"),
        ];
        world.store_shared("alpha", all);
        world.settle().await;
        world
    }

    /// Everything queued so far has been decided and announced.
    pub(super) async fn settle(&self) {
        // One sequence for the process: the seam's record is per thread and
        // never cleared, so a second World in one test must not reuse a
        // marker the first one already finished.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let label = format!("{SETTLE_PREFIX}{n}");
        self.feed
            .send(ToolsNudge::Catalogue {
                name: label.clone(),
            })
            .expect("the drain runs");
        tokio::time::timeout(ARRIVAL, drain_seam::wait_finished(&label))
            .await
            .expect("the drain settles");
    }

    pub(super) fn backend(&self, name: &str) -> Arc<Backend> {
        self.state.backends.get(name).expect("fixture backend")
    }

    pub(super) fn store_shared(&self, backend: &str, tools: Vec<Tool>) {
        self.backend(backend).store_shared_tools_for_test(tools);
    }

    pub(super) fn store_user(&self, backend: &str, subject: &str, tools: Vec<Tool>) {
        self.backend(backend)
            .store_per_user_tools_for_test(&binding(subject, backend), tools);
    }

    /// Revoke `subject`'s grant on `backend`: evict its slots.
    pub(super) fn revoke(&self, backend: &str, subject: &str) {
        self.backend(backend)
            .evict_identity_slots(&binding(subject, backend));
    }

    /// The upstream a warm-up fetch of `subject`'s slot on `backend` reaches.
    pub(super) fn slot_serves(&self, backend: &str, subject: &str, tools: Vec<Tool>) {
        let key = PoolKey::PerUser {
            binding: binding(subject, backend),
        };
        self.backend(backend)
            .set_pooled_transport_for_test(&key, Arc::new(Wire(tools)));
    }

    /// `alpha`'s shared slot answers calls (with `{}`), so an invocation
    /// through it succeeds.
    #[cfg(feature = "spec-preview")]
    pub(super) fn alpha_answers_calls(&self, tools: Vec<Tool>) {
        self.backend("alpha")
            .set_pooled_transport_for_test(&PoolKey::Shared, Arc::new(Wire(tools)));
    }

    /// Register or rewrite the hidden capability, and nudge its catalogue.
    pub(super) fn set_capability(&self, description: &str) {
        self.set_capability_yaml(&capability_yaml(description));
    }

    /// Register or rewrite the capability `yaml` defines, and nudge the
    /// catalogue.
    pub(super) fn set_capability_yaml(&self, yaml: &str) {
        let definition = crate::capability::parse_capability(yaml).expect("a capability");
        self.caps
            .register_capability(definition)
            .expect("registers");
        self.feed
            .send(ToolsNudge::Catalogue {
                name: "caps".to_string(),
            })
            .expect("the drain runs");
    }

    /// A principal's bearer: a live temporary token for `subject`.
    pub(super) async fn principal(&self, subject: &str) -> String {
        let token = principal_token(subject);
        let bearer = token.token.clone();
        self.key_server.store.insert(token).await;
        bearer
    }
}

impl World {
    /// `POST /mcp` with `bearer`.
    pub(super) async fn post(&self, bearer: &str, method: &str, params: Value) -> Value {
        self.post_as(bearer, (None, None), method, params).await
    }

    /// `POST /mcp` with `bearer`, inside legacy session `id` (its minted id).
    pub(super) async fn post_in(
        &self,
        bearer: &str,
        id: &str,
        method: &str,
        params: Value,
    ) -> Value {
        let minted = self
            .minted
            .borrow()
            .get(id)
            .cloned()
            .expect("a legacy session");
        self.post_as(bearer, (Some(&minted), None), method, params)
            .await
    }

    /// `POST /mcp` with `bearer`, in a session and
    /// with an Open `WebUI` assertion, each when given.
    async fn post_as(
        &self,
        bearer: &str,
        (session, assertion): (Option<&str>, Option<&str>),
        method: &str,
        params: Value,
    ) -> Value {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json");
        if let Some(session) = session {
            request = request.header("mcp-session-id", session);
        }
        let mut request = request
            .body(Body::from(
                json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
                    .to_string(),
            ))
            .expect("a request");
        asserted(&mut request, assertion);
        let response = self.router.clone().oneshot(request).await.expect("served");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        serde_json::from_slice(&body).expect("a JSON body")
    }

    /// The `tools/list` result's tools for `bearer`.
    pub(super) async fn served(&self, bearer: &str) -> Vec<Value> {
        let reply = self.post(bearer, "tools/list", json!({})).await;
        reply["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list failed: {reply}"))
            .clone()
    }

    /// The names `tools/list` serves `bearer`.
    pub(super) async fn served_names(&self, bearer: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .served(bearer)
            .await
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_owned))
            .collect();
        names.sort();
        names
    }

    /// The names `gateway_list_tools` shows `bearer` for `server`, which also
    /// warms the caller's own slot when `server` is per-user.
    pub(super) async fn discovered(&self, bearer: &str, server: &str) -> Vec<String> {
        self.discovered_as(bearer, None, server).await
    }

    /// As [`Self::discovered`], with an Open `WebUI` `assertion`.
    pub(super) async fn discovered_as(
        &self,
        bearer: &str,
        assertion: Option<&str>,
        server: &str,
    ) -> Vec<String> {
        let reply = self
            .post_as(
                bearer,
                (None, assertion),
                "tools/call",
                json!({ "name": "gateway_list_tools", "arguments": { "server": server } }),
            )
            .await;
        let text = reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("gateway_list_tools failed: {reply}"));
        let parsed: Value = serde_json::from_str(text).unwrap_or(Value::Null);
        let mut names: Vec<String> = parsed["tools"]
            .as_array()
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|t| t["name"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// A legacy GET session held by `bearer`, as the MCP handler opens one.
    pub(super) async fn legacy(&self, id: &str, bearer: &str) -> Ear {
        self.legacy_with(id, &[("authorization", format!("Bearer {bearer}"))])
            .await
    }

    /// Resume legacy session `id` under a new bearer, as a re-keyed request does.
    pub(super) fn rekey(&self, id: &str, bearer: &str) {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {bearer}").parse().expect("a header value"),
        );
        let held = crate::gateway::auth::live::held_credential(&headers);
        let owner = crate::gateway::session_id::SessionOwner::Credential(id.to_string());
        assert!(
            self.state
                .multiplexer
                .resume_session_id_scoped(
                    self.minted.borrow().get(id).map(String::as_str),
                    &owner,
                    held
                )
                .is_some(),
            "premise: the session resumes"
        );
    }

    /// A live dashboard-session cookie value, as the middleware would set.
    pub(super) fn dashboard_cookie(&self) -> String {
        let handle = self.state.dashboard_bootstrap.issue_session();
        format!("{}={handle}", crate::gateway::auth::SESSION_COOKIE)
    }

    /// A 2026 `subscriptions/listen` stream held by `bearer`, past its
    /// acknowledgement, through the real route.
    pub(super) async fn listen(&self, bearer: &str) -> Ear {
        self.listen_as(bearer, None).await
    }

    /// As [`Self::listen`], with an Open `WebUI` `assertion`.
    pub(super) async fn listen_as(&self, bearer: &str, assertion: Option<&str>) -> Ear {
        let mut ear = self.listen_undrained(bearer, assertion).await;
        // The constant attach hint (M-B10) is not a change: rows count what a
        // change sends after attach, so it is read here and set aside.
        let Ear::Listen(events) = &mut ear else {
            unreachable!("a listen stream")
        };
        events
            .next()
            .await
            .expect("the attach hint follows the acknowledgement");
        ear
    }

    /// As [`Self::listen_as`], stopping at the acknowledgement: the attach
    /// hint is still unread.
    pub(super) async fn listen_undrained(&self, bearer: &str, assertion: Option<&str>) -> Ear {
        let body = json!({
            "jsonrpc": "2.0", "id": "listen", "method": "subscriptions/listen",
            "params": {
                "notifications": { "toolsListChanged": true, "resourcesListChanged": true },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        });
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "subscriptions/listen")
            .header("accept", "application/json, text/event-stream")
            .body(Body::from(body.to_string()))
            .expect("a request");
        let mut request = request;
        asserted(&mut request, assertion);
        let response = self.router.clone().oneshot(request).await.expect("served");
        assert!(
            response.status().is_success(),
            "listen refused: {}",
            response.status()
        );
        let mut events = Events {
            stream: Box::pin(response.into_body().into_data_stream()),
            buffer: String::new(),
        };
        events
            .next()
            .await
            .expect("the acknowledgement opens the stream");
        Ear::Listen(events)
    }

    /// A legacy GET stream held by `bearer`, opened through the real route
    /// (`mcp_sse_handler`), so the write path (`credential_at_write`, the write
    /// acknowledgement) runs for every frame it is sent. [`Self::legacy`] reads
    /// a bare receiver and never reaches it.
    pub(super) async fn sse(&self, bearer: &str) -> Ear {
        self.sse_as(bearer, None).await
    }

    /// As [`Self::sse`], with an Open `WebUI` `assertion`.
    pub(super) async fn sse_as(&self, bearer: &str, assertion: Option<&str>) -> Ear {
        self.sse_open(bearer, assertion, None).await
    }

    /// Reopen the GET stream of `session` under `bearer`: the same session,
    /// resumed by the credential that owns it.
    pub(super) async fn sse_resume(&self, bearer: &str, session: &str) -> Ear {
        self.sse_open(bearer, None, Some(session)).await
    }

    async fn sse_open(&self, bearer: &str, assertion: Option<&str>, resume: Option<&str>) -> Ear {
        let mut builder = axum::http::Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("authorization", format!("Bearer {bearer}"))
            .header("accept", "text/event-stream");
        if let Some(session) = resume {
            builder = builder.header("mcp-session-id", session);
        }
        let mut request = builder.body(Body::empty()).expect("a request");
        asserted(&mut request, assertion);
        let response = self.router.clone().oneshot(request).await.expect("served");
        assert!(
            response.status().is_success(),
            "sse refused: {}",
            response.status()
        );
        let session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .expect("the stream names its session")
            .to_string();
        let mut body = Events {
            stream: Box::pin(response.into_body().into_data_stream()),
            buffer: String::new(),
        };
        let (tx, events) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(event) = body.next_unbounded().await {
                if tx.send(event).is_err() {
                    break;
                }
            }
        });
        Ear::Sse { events, session }
    }
}

pub(super) use super::audience_ear::{Ear, Events};
