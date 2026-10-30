// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D2 (MIK-7570.AUDIT.2): the direct route `POST /mcp/{name}` writes the same
//! invocation record as the meta route, refusals included.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext, anonymous_caller};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;
use crate::transport::Transport;

pub(in crate::gateway::router) mod anon_intake;
mod extras;
use extras::{Extra, Log, arm_extras, audit_log, backend_config, harden};
mod anon_key;
mod backend_oracle;
mod composite_refusals;
mod counting;
mod delivery;
mod delivery_who;
mod empty_grant;
mod late_refusals;
mod latency;
mod lost_round;
mod meta_malformed_retry;
mod meta_refusal;
mod meta_replay;
mod refused_effect;
/// MIK-8689 R-RECJUDGE: the judge's verdict rides the delivery record.
#[cfg(feature = "firewall")]
mod response_judge;
mod rewritten_effect;
mod route_records;
mod sealed_refusal;
#[cfg(feature = "firewall")]
mod session_less;
#[cfg(feature = "firewall")]
mod slot_release;
#[cfg(feature = "firewall")]
mod tenants;
mod unvouched_effect;

/// A backend that answers `tools/list` with its one tool `t` and anything
/// else with a text result, or with a JSON-RPC error when `error` is set.
struct Scripted {
    calls: Arc<AtomicUsize>,
    /// MIK-8382: every `tools/list`, which `calls` skips.
    lists: Arc<AtomicUsize>,
    /// MIK-8382: the cell's transport switches, [`Extra::ListFail`] (a
    /// `tools/list` fails, as an unreachable backend's cold list does) and
    /// [`Extra::Hang`] (every request is counted, then never answered) and
    /// [`Extra::HangCall`] (only calls hang).
    extras: &'static [Extra],
    error: Option<i32>,
    /// MIK-7979: the call is counted, then the transport fails with this.
    fail: Option<fn() -> crate::Error>,
    reply: Option<Value>,
    /// Every notification is refused for want of a caller slot (a 429).
    notify_refused: bool,
}

#[async_trait::async_trait]
impl Transport for Scripted {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        // MIK-8176: a progress token gets a notification first.
        #[cfg(feature = "firewall")]
        if slot_release::notify_first(method, params.as_ref()) {
            tokio::task::yield_now().await;
        }
        #[cfg(not(feature = "firewall"))]
        let _ = &params;
        // F13: a cold `tools/call` lists the backend first. The list names the
        // tool the rows call, and it is not a call, so `calls` skips it.
        if method == "tools/list" {
            self.lists.fetch_add(1, Ordering::SeqCst);
            if self.extras.contains(&Extra::Hang) {
                std::future::pending::<()>().await;
            }
            if self.extras.contains(&Extra::ListFail) {
                return Err(crate::Error::Transport("connection refused".into()));
            }
            let tool = json!({"name": "t", "inputSchema": extras::listed_schema(self.extras)});
            return Ok(JsonRpcResponse::success(id, json!({ "tools": [tool] })));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.extras.contains(&Extra::Hang) || self.extras.contains(&Extra::HangCall) {
            std::future::pending::<()>().await;
        }
        if let Some(fail) = self.fail {
            return Err(fail());
        }
        Ok(match (method, self.error) {
            (_, Some(code)) => JsonRpcResponse::error(Some(id), code, "backend says no"),
            _ => JsonRpcResponse::success(
                id,
                self.reply.clone().unwrap_or_else(
                    || json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
                ),
            ),
        })
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        if self.notify_refused {
            return Err(crate::Error::IdentitySlotsExhausted {
                backend: "alpha".to_string(),
                limit: "backend",
            });
        }
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

struct Fixture {
    state: Arc<super::AppState>,
    router: axum::Router,
    log: Arc<TransparencyLogger>,
    path: std::path::PathBuf,
    calls: Arc<AtomicUsize>,
    lists: Arc<AtomicUsize>,
    _dirs: (tempfile::TempDir, crate::gateway::router::tests::FixtureDir),
}

/// A direct `tools/call` of `t` naming `customer_id`, optionally keyed.
fn direct_call(tenant: &str, idempotency_key: Option<&str>) -> String {
    let mut params = json!({"name": "t", "arguments": {"customer_id": tenant}});
    if let Some(key) = idempotency_key {
        params["_meta"] = json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key});
    }
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params}).to_string()
}

/// POST as a modern `caller`: the era that carries an idempotency key. The
/// body declares the revision the header does, as `/mcp` requires of it and
/// the direct route now does too (MIK-8040).
async fn post_modern_as(
    fx: &Fixture,
    uri: &str,
    body: &str,
    caller: &Caller,
) -> (StatusCode, Value) {
    let mut call: Value = serde_json::from_str(body).unwrap();
    let meta = &mut call["params"]["_meta"];
    meta["io.modelcontextprotocol/protocolVersion"] =
        json!(crate::protocol::meta::MODERN_VERSIONS[0]);
    meta["io.modelcontextprotocol/clientCapabilities"] = json!({});
    post_to(fx, uri, &call.to_string(), caller).await
}

/// Knobs a cell varies; everything else is the plain auth-off gateway.
#[derive(Default)]
struct Setup {
    auth: Option<AuthConfig>,
    /// T21: whether either route has a transparency log.
    log: Log,
    fail_closed: bool,
    backend_error: Option<i32>,
    /// MIK-7979: the backends' transport fails after counting each call.
    backend_fail: Option<fn() -> crate::Error>,
    agent_identity: Option<crate::config::AgentIdentityConfig>,
    /// The router's request firewall, scanning arguments (#2420).
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    request_firewall: bool,
    /// The backend's `tools/call` result, instead of a plain "ok".
    reply: Option<Value>,
    /// MIK-7116.MIN.1: `arg_keys` on both routes' firewalls, guard at `limit`
    /// (0 = guard off, attribution only).
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    tenant_limit: Option<usize>,
    /// Response firewall rules (YAML) beside the tenant guard; `None`, none.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    response_rules: Option<&'static str>,
    /// The read judge beside `tenant_limit`: `Block` withholds a caller's
    /// second tenant (MIK-8176 SLOT.1). Default observe.
    #[cfg(feature = "firewall")]
    cross_tenant_reads: crate::security::firewall::tenant_guard::CrossTenantReads,
    /// Relay detection on both routes' firewalls, with `alpha:t` as its
    /// source (MIK-8176 SLOT.6). Needs `tenant_limit`.
    #[cfg(feature = "firewall")]
    relay: Relay,
    meta_mode: MetaMode,
    /// The backends refuse every notification (L1254).
    notify_refused: bool,
    /// MIK-8382: the [`Extra`] switches this cell turns on.
    extras: &'static [Extra],
    /// The backends' chain policy; under `Require` the gateway also has a
    /// chain identity, so their unchained answers are refused unread (MIK-7636).
    chain: crate::config::ChainMode,
    /// `security.caller_identity` (MIK-7938 ATTR.4).
    caller_identity: Option<crate::security::caller_identity::CallerIdentityConfig>,
    /// `security.sanitize_input` on both routes (MIK-8387 N1).
    sanitize: Sanitize,
}

/// Whether both routes sanitize input (`security.sanitize_input`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Sanitize {
    #[default]
    Off,
    On,
}

/// Whether both routes' firewalls run relay detection (MIK-8176 SLOT.6).
#[cfg(feature = "firewall")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Relay {
    #[default]
    Off,
    On,
}

/// One optional meta-layer switch a cell turns on (MIK-7116.MIN.1 cells).
#[derive(Default, PartialEq)]
enum MetaMode {
    #[default]
    Plain,
    /// Response inspection refuses a HIGH finding instead of annotating it.
    #[cfg(feature = "firewall")]
    InspectionBlocks,
    /// The idempotency cache is on, so a re-issued key replays.
    Idempotent,
    /// `alpha`'s tool `t` is surfaced, so it is called by name on `/mcp`.
    SurfacedT,
    /// Code mode is on, so `gateway_execute` runs chains (MIK-8387 rows).
    CodeMode,
    /// Only the dispatch layer has a firewall, so the send's own rescan is
    /// what refuses a dangerous argument.
    #[cfg(feature = "firewall")]
    DispatchFirewall,
    /// Only `gateway_list_servers` is exposed: `gateway_invoke` is no tool.
    InvokeHidden,
    /// A fail-closed response contract with none declared refuses every answer.
    ContractRefuses,
}

impl MetaMode {
    /// `meta` with this mode's switch turned on.
    fn arm(&self, mut meta: MetaMcp) -> MetaMcp {
        match self {
            Self::Plain => {}
            #[cfg(feature = "firewall")]
            Self::InspectionBlocks => meta.enable_response_inspection_action_mode(),
            Self::Idempotent => meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                crate::idempotency::CLEANUP_INTERVAL,
            ),
            Self::CodeMode => return meta.with_code_mode(true),
            Self::ContractRefuses => {
                meta.set_response_contract(crate::config::ResponseContractConfig {
                    enabled: true,
                    action_mode: true,
                    fail_closed: true,
                    ..Default::default()
                });
            }
            #[cfg(feature = "firewall")]
            Self::DispatchFirewall => meta.set_firewall(Some(Arc::new(
                crate::security::firewall::Firewall::from_config(
                    crate::security::firewall::FirewallConfig {
                        enabled: true,
                        scan_requests: true,
                        ..crate::security::firewall::FirewallConfig::default()
                    },
                    None,
                ),
            ))),
            Self::InvokeHidden => {
                return meta.with_exposed_meta_tools(&["gateway_list_servers".to_string()]);
            }
            Self::SurfacedT => {
                return meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
                    server: "alpha".to_string(),
                    tool: "t".to_string(),
                }]);
            }
        }
        meta
    }
}

/// `security.sanitize_input` on the published config (ADR-023).
fn sanitizing(state: &super::AppState, on: bool) {
    state.live_config.edit(|c| c.security.sanitize_input = on);
}

/// Backends `alpha` and `beta`, one logger shared by both routes.
async fn fixture(setup: Setup) -> Fixture {
    let (audit, path, log) = audit_log(setup.fail_closed);
    let (mut state, store) = match &setup.auth {
        Some(auth) => super::tests::test_router_app_state_with_auth(auth).await,
        None => super::tests::test_router_app_state().await,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let lists = Arc::new(AtomicUsize::new(0));
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    if setup.has(Extra::Hardened) {
        harden(state_mut);
    }
    for name in ["alpha", "beta"] {
        let backend = Arc::new(Backend::new(
            name,
            backend_config(&setup, name),
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        backend.set_transport_for_test(Arc::new(Scripted {
            calls: Arc::clone(&calls),
            lists: Arc::clone(&lists),
            extras: setup.extras,
            error: setup.backend_error,
            fail: setup.backend_fail,
            reply: setup.reply.clone(),
            notify_refused: setup.notify_refused,
        }));
        assert!(state_mut.backends.register(backend), "fixture registration");
    }
    // Copied out before `agent_identity` is moved from `setup` below.
    let extras = setup.extras;
    if let Some(config) = setup.agent_identity {
        state_mut.agent_identity_config = config;
    }
    sanitizing(state_mut, setup.sanitize == Sanitize::On);
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    #[cfg(feature = "firewall")]
    if setup.request_firewall {
        state_mut.firewall = Some(Arc::new(
            crate::security::firewall::Firewall::from_config(
                crate::security::firewall::FirewallConfig {
                    enabled: true,
                    scan_requests: true,
                    ..crate::security::firewall::FirewallConfig::default()
                },
                None,
            )
            .with_continuations(meta.continuation()),
        ));
    }
    if setup.log == Log::On {
        meta.enable_transparency_log(Arc::clone(&log));
    }
    meta = arm_extras(meta, extras);
    if setup.chain == crate::config::ChainMode::Require {
        meta.set_chain_signer(
            crate::security::signature_chain::ChainSigner::from_seed(&[7; 32], "gw-test")
                .expect("signer"),
            crate::config::ChainEmit::OnRequest,
        );
    }
    #[cfg(feature = "firewall")]
    if let Some(limit) = setup.tenant_limit {
        tenants::guard_tenants(
            state_mut,
            &mut meta,
            (limit, setup.response_rules),
            (setup.cross_tenant_reads, setup.relay),
        );
    }
    if let Some(config) = setup.caller_identity {
        meta = meta.with_caller_identity(config);
    }
    state_mut.meta_mcp = Arc::new(setup.meta_mode.arm(meta));
    state_mut.transparency_log = (setup.log == Log::On).then(|| Arc::clone(&log));
    let router = create_router(Arc::clone(&state));
    Fixture {
        state,
        router,
        log,
        path,
        calls,
        lists,
        _dirs: (audit, store),
    }
}

/// An auth config with one key, `k`, scoped to `alpha`.
fn key_for_alpha(denied_tools: Option<Vec<String>>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(b"k")),
            expires_at: None,
            name: "alpha-client".to_string(),
            rate_limit: 0,
            backends: vec!["alpha".to_string()],
            allowed_tools: None,
            denied_tools,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: crate::config::DashboardSessionConfig::default(),
    }
}

/// MIK-8672 C1/C2: the static bearer secret. Differs from the API key's `k`:
/// an equal token classifies only as the static bearer.
const BEARER_TOKEN: &str = "mik-8672-static-bearer";

/// How a cell presents itself to the gateway.
enum Caller {
    Anonymous,
    Oidc,
    Key,
    /// Anonymous, carrying an `mcp-session-id` header.
    Session,
    /// Anonymous, declaring the modern era by header: no session at all.
    Modern,
    /// Anonymous, with a verified client certificate (MIK-7938).
    Cert,
    /// Anonymous, with a verified OAuth agent token (MIK-7938).
    Agent,
    /// [`Caller::Modern`] with a verified OIDC identity: an execution
    /// principal, so a keyed direct call is admitted (MIK-8154 ANON.1).
    ModernOidc,
    /// The static bearer token of [`bearer_auth`] (MIK-8672 C1/C2): the client
    /// `bearer`, as is the API key that fixture also holds.
    Bearer,
}

/// Put the verified identity a `Caller` stands for on `request`.
fn insert_identity(request: &mut axum::http::Request<axum::body::Body>, caller: &Caller) {
    let extensions = request.extensions_mut();
    match caller {
        Caller::Cert => {
            extensions.insert(crate::mtls::CertIdentity {
                common_name: Some("cert-7938".to_string()),
                organizational_unit: None,
                san_uris: vec!["spiffe://example.invalid/cert-7938".to_string()],
                san_dns_names: vec![],
                display_name: "cert-7938".to_string(),
                quota_principal: None,
            });
        }
        Caller::Agent => {
            extensions.insert(crate::gateway::oauth::OAuthAgentIdentity {
                client_id: "agent-7938".to_string(),
                agent_name: "Agent 7938".to_string(),
                scopes: vec![],
                raw_scopes: vec![],
                quota_principal: None,
            });
        }
        _ => {}
    }
}

async fn post(fx: &Fixture, backend: &str, body: &str, caller: &Caller) -> (StatusCode, Value) {
    post_to(fx, &format!("/mcp/{backend}"), body, caller).await
}

async fn post_to(fx: &Fixture, uri: &str, body: &str, caller: &Caller) -> (StatusCode, Value) {
    let (status, bytes) = post_to_raw(fx, uri, body, caller).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// [`post_to`] with the response body as sent, for byte-identity rows.
async fn post_to_raw(
    fx: &Fixture,
    uri: &str,
    body: &str,
    caller: &Caller,
) -> (StatusCode, axum::body::Bytes) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if matches!(caller, Caller::Key) {
        builder = builder.header("authorization", "Bearer k");
    }
    if matches!(caller, Caller::Bearer) {
        builder = builder.header("authorization", format!("Bearer {BEARER_TOKEN}"));
    }
    if matches!(caller, Caller::Session) {
        builder = builder.header("mcp-session-id", "sess-d2");
    }
    if matches!(caller, Caller::Modern | Caller::ModernOidc) {
        // The modern era also requires the method and name headers to echo
        // the body, or the call is refused (-32020) before any audit path.
        let parsed: Value = serde_json::from_str(body).unwrap();
        builder = builder
            .header(
                "mcp-protocol-version",
                crate::protocol::meta::MODERN_VERSIONS[0],
            )
            .header("mcp-method", parsed["method"].as_str().unwrap())
            .header("mcp-name", parsed["params"]["name"].as_str().unwrap());
    }
    let mut request = builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    if matches!(caller, Caller::Oidc | Caller::ModernOidc) {
        // Auth is off in the OIDC cells, so the middleware leaves it in place.
        request.extensions_mut().insert(VerifiedIdentity {
            subject: "1".to_string(),
            email: "one@example.invalid".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://a.example.invalid".to_string(),
        });
    }
    insert_identity(&mut request, caller);
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    (
        status,
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("an in-memory body reads"),
    )
}

fn tools_call(tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
           "params": {"name": tool, "arguments": {"q": 1}}})
    .to_string()
}

/// Every invocation record in the log (entries that carry a `request_hash`).
fn invocations(fx: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry.get("request_hash").is_some())
        .collect()
}

fn only_invocation(fx: &Fixture) -> Value {
    let mut all = invocations(fx);
    assert_eq!(
        all.len(),
        1,
        "expected exactly one invocation record: {all:?}"
    );
    all.remove(0)
}

#[cfg(feature = "metrics")]
#[path = "security_metrics_tests.rs"]
mod security_metrics;

#[path = "direct_audit_tail_tests.rs"]
mod tail_tests;
