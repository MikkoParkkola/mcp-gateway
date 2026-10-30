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
pub(super) struct PerIdentityMint(pub(super) Arc<Probe>);

/// What the fixture's backends and minter were asked to do: a row that
/// requires the write path to stay on caches reads the counters, and arms the
/// mint to hang so a mint under a held lock fails by timeout.
#[derive(Default)]
pub(super) struct Probe {
    pub(super) mints: std::sync::atomic::AtomicUsize,
    pub(super) fetches: std::sync::atomic::AtomicUsize,
    pub(super) hang_mints: std::sync::atomic::AtomicBool,
}

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
        use std::sync::atomic::Ordering::SeqCst;
        self.0.mints.fetch_add(1, SeqCst);
        if self.0.hang_mints.load(SeqCst) {
            std::future::pending::<()>().await;
        }
        let subject_key = identity.subject.clone();
        Ok(crate::identity_propagation::PropagatedCredential {
            expiry_synthetic: false,
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
struct Wire(Vec<Tool>, Arc<Probe>);

#[async_trait::async_trait]
impl crate::transport::Transport for Wire {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let body = if method == "tools/list" {
            self.1
                .fetches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

pub(super) fn api_key_for(name: &str, secret: &[u8]) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(secret)),
        ..api_key(name, &[])
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
        ..Default::default()
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
    per_user_backend_probed(name, required, &Arc::default())
}

fn per_user_backend_probed(name: &str, required: bool, probe: &Arc<Probe>) -> Arc<Backend> {
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
    backend.set_transport_for_test(Arc::new(Wire(
        vec![tool("shared_beta", "shared")],
        Arc::clone(probe),
    )));
    backend
}

fn shared_backend(name: &str, probe: &Arc<Probe>) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Wire(Vec::new(), Arc::clone(probe))));
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

/// When the API key `k-exp` expires, in unix seconds: a row expires it by
/// forcing the clock past this.
pub(super) const K_EXP_UNTIL: i64 = 4_102_444_800;

/// The Open `WebUI` installation and header the adapter rows configure.
pub(super) const ADAPTER_INSTALLATION: &str = "inst";
const ADAPTER_HEADER: &str = "x-openwebui-assertion";
const ADAPTER_SECRET: &str = "audience-adapter-signing-secret-0123456789";

/// Attach `assertion` as the Open `WebUI` adapter's header; untouched without one.
pub(super) fn asserted(request: &mut axum::http::Request<Body>, assertion: Option<&str>) {
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

/// The fixture's credentials under `access`: `k-std`, `k-deny` (denied
/// `read`, `fetch` and the capability), `k-narrow` (`beta` alone), `k-exp`
/// (expiring at [`K_EXP_UNTIL`]) and the agents' keys.
fn fixture_auth(access: &super::audience_access::McpAccess) -> AuthConfig {
    let mut auth = AuthConfig {
        // An `AgentOnly` caller presents its agent token and no API key.
        enabled: !matches!(access, super::audience_access::McpAccess::AgentOnly(_)),
        public_paths: super::audience_access::public_paths(access),
        api_keys: vec![
            api_key("k-std", &[]),
            api_key("k-deny", &["read", "fetch", "hidden_cap"]),
            ApiKeyConfig {
                backends: vec!["beta".to_string()],
                ..api_key("k-narrow", &[])
            },
            ApiKeyConfig {
                expires_at: chrono::DateTime::from_timestamp(K_EXP_UNTIL, 0),
                ..api_key("k-exp", &[])
            },
        ],
        ..AuthConfig::default()
    };
    auth.api_keys
        .extend(super::audience_access::agent_api_keys(access));
    auth
}

/// The gateway under test and the handles rows drive it with.
pub(super) struct World {
    pub state: Arc<AppState>,
    pub router: axum::Router,
    pub key_server: Arc<KeyServer>,
    pub caps: Arc<crate::capability::CapabilityBackend>,
    feed: tokio::sync::mpsc::UnboundedSender<ToolsNudge>,
    pub(super) probe: Arc<Probe>,
    /// The minted id of each legacy session, by the label a row gave it:
    /// production mints every id (F9), so the label is not the id.
    pub(super) minted: std::cell::RefCell<std::collections::HashMap<String, String>>,
    _shutdown: tokio::sync::broadcast::Sender<()>,
    _store: crate::gateway::router::tests::FixtureDir,
    _audit: crate::security::transparency_log::temp::TempLog,
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
        Self::start_on(
            key_server,
            None,
            configure,
            super::audience_access::McpAccess::Authenticated,
        )
        .await
    }

    /// As [`Self::start_with`], with an Open `WebUI` adapter that k-std may
    /// present ([`adapter_assertion`] mints its assertions).
    pub(super) async fn start_adapter(configure: impl FnOnce(MetaMcp) -> MetaMcp) -> Self {
        Self::start_adapter_as(configure, super::audience_access::McpAccess::Authenticated).await
    }

    /// As [`Self::start_adapter`], under `access` (the fixture agents' keys are
    /// allowed to present assertions too).
    pub(super) async fn start_adapter_as(
        configure: impl FnOnce(MetaMcp) -> MetaMcp,
        access: super::audience_access::McpAccess,
    ) -> Self {
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
        let config: crate::config::Config = crate::yaml::from_str(&format!(
            "env_files: ['{}']\naccounts:\n  schema_version: accounts.v1\n  enabled: false\n  \
             deployment: single_process\n  instance_id: audience\n  \
             store_dir: /unused/audience-store\n  authority_dir: /unused/audience-authority\n  \
             current_key_id: primary\n  keys:\n    primary: env:AUDIENCE_OWUI_STORE\n  \
             adapters:\n    - kind: openwebui_signed_header\n      \
             installation_id: {ADAPTER_INSTALLATION}\n      header: {ADAPTER_HEADER}\n      \
             issuer: open-webui\n      hmac_secret_ref: env:AUDIENCE_OWUI_HMAC\n      \
             allowed_api_key_names: [k-std, shared]\n",
            env.display().to_string().replace('\'', "''")
        ))
        .expect("adapter config parses");
        let key_server = Arc::new(KeyServer::new(crate::config::KeyServerConfig::default()));
        Self::start_on(key_server, Some((config, dir)), configure, access).await
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
            Self::start_on(
                Arc::clone(&oidc.ks),
                None,
                |meta| meta,
                super::audience_access::McpAccess::Authenticated,
            )
            .await,
            oidc,
        )
    }

    pub(super) async fn start_on(
        key_server: Arc<KeyServer>,
        live: Option<(crate::config::Config, tempfile::TempDir)>,
        configure: impl FnOnce(MetaMcp) -> MetaMcp,
        access: super::audience_access::McpAccess,
    ) -> Self {
        let agents = super::audience_access::agent_registry(&access);
        let auth = fixture_auth(&access);
        let audit = crate::security::transparency_log::temp::TempLog::new();
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
        let probe = Arc::<Probe>::default();
        let wire_probe = Arc::clone(&probe);
        let (mut state, store) = crate::gateway::router::tests::audience_state(
            &auth,
            (Some(Arc::clone(&key_server)), agents),
            move |meta| {
                let mut meta = meta.with_surfaced_tools(surfaced);
                meta.enable_transparency_log(Arc::new(logger));
                meta.set_identity_propagation(Arc::new(PerIdentityMint(Arc::clone(&wire_probe))));
                meta.set_capabilities(wire_caps);
                configure(meta)
            },
        )
        .await;
        let (feed, nudges) = tokio::sync::mpsc::unbounded_channel();
        let st = Arc::get_mut(&mut state).expect("state is unique");
        let adapter = live.map(|(config, dir)| {
            // The security flags off, as every router fixture's generation
            // has them: the views read SSRF protection from the generation
            // (ADR-023), and on it hides the fixture's loopback backends.
            st.live_config = Arc::new(crate::config_reload::LiveConfig::new(
                crate::config_reload::flags_off(config),
            ));
            dir
        });
        super::audience_access::apply(st, &access);
        st.backends.set_change_feed(feed.clone());
        for backend in [
            shared_backend("alpha", &probe),
            per_user_backend_probed("beta", false, &probe),
            per_user_backend_probed("gamma", true, &probe),
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
            probe,
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

    /// Register a shared backend `name` serving `tools` after listeners have
    /// attached, as a reload that adds a server does.
    pub(super) fn register_late(&self, name: &str, tools: Vec<Tool>) {
        let backend = shared_backend(name, &self.probe);
        assert!(
            self.state.backends.register(Arc::clone(&backend)),
            "late registration"
        );
        backend.store_shared_tools_for_test(tools);
    }

    /// `POST /mcp` with `bearer` inside the GET stream's session `session`.
    pub(super) async fn post_session(
        &self,
        bearer: &str,
        session: &str,
        method: &str,
        params: Value,
    ) -> Value {
        self.post_as(bearer, (Some(session), None), method, params)
            .await
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
            .set_pooled_transport_for_test(&key, Arc::new(Wire(tools, Arc::clone(&self.probe))));
    }

    /// `alpha`'s shared slot answers calls (with `{}`), so an invocation
    /// through it succeeds.
    #[cfg(feature = "spec-preview")]
    pub(super) fn alpha_answers_calls(&self, tools: Vec<Tool>) {
        self.backend("alpha").set_pooled_transport_for_test(
            &PoolKey::Shared,
            Arc::new(Wire(tools, Arc::clone(&self.probe))),
        );
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

#[path = "audience_fixture_requests.rs"]
mod requests;

pub(super) use super::audience_ear::{Ear, Events};
