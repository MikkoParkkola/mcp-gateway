// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture of the MIK-8350 list_changed audience rows: one in-process HTTP
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

use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use futures::StreamExt as _;
use serde_json::{Value, json};
use tokio::sync::broadcast::Receiver;
use tower::ServiceExt as _;

use super::drain_seam::{self, SETTLE_PREFIX};
use crate::backend::tools_nudge::ToolsNudge;
use crate::backend::{Backend, PoolKey};
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::router::AppState;
use crate::gateway::streaming::SessionFrame;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::key_server::{KeyServer, TemporaryToken};
use crate::protocol::{JsonRpcResponse, RequestId, Tool};

/// Bound on every wait for something that must happen.
pub(super) const ARRIVAL: Duration = Duration::from_secs(20);
pub(super) const LIST_CHANGED: &str = "notifications/tools/list_changed";
const SENTINEL: &str = "notifications/resources/list_changed";

/// A tool with `name` whose description is `description`.
pub(super) fn tool(name: &str, description: &str) -> Tool {
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

fn per_user_backend(name: &str, required: bool) -> Arc<Backend> {
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
pub(super) fn binding(subject: &str, backend: &str) -> String {
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

/// The gateway under test and the handles rows drive it with.
pub(super) struct World {
    pub state: Arc<AppState>,
    pub router: axum::Router,
    pub key_server: Arc<KeyServer>,
    pub caps: Arc<crate::capability::CapabilityBackend>,
    feed: tokio::sync::mpsc::UnboundedSender<ToolsNudge>,
    seq: Cell<usize>,
    /// The minted id of each legacy session, by the label a row gave it:
    /// production mints every id (F9), so the label is not the id.
    minted: std::cell::RefCell<std::collections::HashMap<String, String>>,
    _shutdown: tokio::sync::broadcast::Sender<()>,
    _store: tempfile::TempDir,
    _audit: tempfile::NamedTempFile,
}

impl World {
    pub(super) async fn start() -> Self {
        Self::start_with(|meta| meta).await
    }

    /// As [`Self::start`], with `configure` applied to the Meta-MCP last.
    pub(super) async fn start_with(configure: impl FnOnce(MetaMcp) -> MetaMcp) -> Self {
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
        let key_server = Arc::new(KeyServer::new(crate::config::KeyServerConfig::default()));
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
            seq: Cell::new(0),
            minted: std::cell::RefCell::default(),
            _shutdown: shutdown,
            _store: store,
            _audit: audit,
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
        let n = self.seq.get() + 1;
        self.seq.set(n);
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

    /// Register or rewrite the hidden capability, and nudge its catalogue.
    pub(super) fn set_capability(&self, description: &str) {
        let definition = crate::capability::parse_capability(&capability_yaml(description))
            .expect("a capability");
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
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
                    .to_string(),
            ))
            .expect("a request");
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
        let reply = self
            .post(
                bearer,
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
    pub(super) fn legacy(&self, id: &str, bearer: &str) -> Ear {
        self.legacy_with(id, &[("authorization", format!("Bearer {bearer}"))])
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

    /// A legacy GET session opened with exactly these request headers.
    pub(super) fn legacy_with(&self, id: &str, presented: &[(&str, String)]) -> Ear {
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in presented {
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                value.parse().expect("a header value"),
            );
        }
        let held = crate::gateway::auth::live::held_credential(&headers);
        let owner = crate::gateway::session_id::SessionOwner::Credential(id.to_string());
        let (minted, rx) =
            self.state
                .multiplexer
                .get_or_create_session_scoped(Some(id), &owner, held);
        self.minted.borrow_mut().insert(id.to_string(), minted);
        Ear::Legacy(rx)
    }

    /// A 2026 `subscriptions/listen` stream held by `bearer`, past its
    /// acknowledgement, through the real route.
    pub(super) async fn listen(&self, bearer: &str) -> Ear {
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
}

/// A listen response body read as SSE `data:` events.
pub(super) struct Events {
    stream: std::pin::Pin<Box<axum::body::BodyDataStream>>,
    buffer: String,
}

impl Events {
    /// The next event, or `None` if the stream ends or `ARRIVAL` passes.
    pub(super) async fn next(&mut self) -> Option<Value> {
        let deadline = tokio::time::Instant::now() + ARRIVAL;
        loop {
            if let Some(end) = self.buffer.find("\n\n") {
                let block: String = self.buffer.drain(..end + 2).collect();
                if let Some(data) = block.lines().find_map(|l| l.strip_prefix("data:"))
                    && let Ok(value) = serde_json::from_str(data.trim())
                {
                    return Some(value);
                }
                continue;
            }
            let chunk = tokio::time::timeout_at(deadline, self.stream.next())
                .await
                .ok()??
                .ok()?;
            self.buffer.push_str(&String::from_utf8_lossy(&chunk));
        }
    }
}

/// One listener: a legacy GET session or a listen stream.
pub(super) enum Ear {
    Legacy(Receiver<SessionFrame>),
    Listen(Events),
}

impl Ear {
    /// The methods of every frame this listener was sent since the last call,
    /// once the drain has delivered all queued changes.
    pub(super) async fn frames(&mut self, world: &World) -> Vec<String> {
        world.settle().await;
        match self {
            Self::Legacy(rx) => {
                let mut methods = Vec::new();
                while let Ok(frame) = rx.try_recv() {
                    methods.push(
                        frame.data["method"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string(),
                    );
                }
                methods
            }
            Self::Listen(events) => {
                world.state.subscriptions.publish(json!({
                    "jsonrpc": "2.0", "method": SENTINEL
                }));
                let mut methods = Vec::new();
                while let Some(event) = events.next().await {
                    let method = event["method"].as_str().unwrap_or_default().to_string();
                    if method == SENTINEL {
                        return methods;
                    }
                    methods.push(method);
                }
                panic!("the listen stream ended before its sentinel: {methods:?}");
            }
        }
    }

    /// How many `tools/list_changed` frames this listener was sent.
    pub(super) async fn told(&mut self, world: &World) -> usize {
        self.frames(world)
            .await
            .iter()
            .filter(|m| *m == LIST_CHANGED)
            .count()
    }
}
