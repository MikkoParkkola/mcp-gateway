//! NFR.OBS.1 and NFR.OBS.2 — the gateway's own record of what it observed.
//!
//! Both criteria are about a record existing, so both tests capture the real
//! `tracing` output of a real request through the real router. A unit test of
//! a formatting helper passes even when the handler stops calling it.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tracing::field::{Field, Visit};
use tracing::subscriber::set_global_default;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::Registry;

/// One captured event: its target and its fields, stringified.
#[derive(Clone, Debug)]
struct Record {
    target: String,
    fields: HashMap<String, String>,
}

impl Record {
    fn field(&self, name: &str) -> &str {
        self.fields.get(name).map_or("", String::as_str)
    }
}

fn captured() -> &'static Mutex<Vec<Record>> {
    static CAPTURED: OnceLock<Mutex<Vec<Record>>> = OnceLock::new();
    CAPTURED.get_or_init(|| Mutex::new(Vec::new()))
}

/// The global subscriber is process-wide, so tests take this lock for the
/// duration of a request and read the buffer they alone filled. The guard is
/// held across the request's awaits, so the lock has to be the async one.
async fn capture_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    let guard = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    install();
    captured().lock().expect("buffer").clear();
    guard
}

struct Collector;

impl<S: tracing::Subscriber> Layer<S> for Collector {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut fields = HashMap::new();
        event.record(&mut FieldVisitor(&mut fields));
        captured().lock().expect("buffer").push(Record {
            target: event.metadata().target().to_string(),
            fields,
        });
    }
}

struct FieldVisitor<'a>(&'a mut HashMap<String, String>);

impl Visit for FieldVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

fn install() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        // The handler records at INFO; the default max level would keep a DEBUG
        // sibling out, so the filter is explicit rather than inherited.
        let subscriber = Registry::default()
            .with(Collector)
            .with(tracing::level_filters::LevelFilter::DEBUG);
        set_global_default(subscriber).expect("no other global subscriber in this test binary");
    });
}

/// Records the gateway emits about what it observed, newest last.
fn observation_records() -> Vec<Record> {
    captured()
        .lock()
        .expect("buffer")
        .iter()
        .filter(|r| r.target == "mcp_gateway::observed")
        .cloned()
        .collect()
}

mod http {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use mcp_gateway::backend::BackendRegistry;
    use mcp_gateway::config::Config;
    use mcp_gateway::gateway::auth::ResolvedAuthConfig;
    use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
    use mcp_gateway::gateway::proxy::ProxyManager;
    use mcp_gateway::gateway::streaming::NotificationMultiplexer;
    use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
    use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
    use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::{Record, capture_lock, observation_records};

    fn state() -> Arc<AppState> {
        let mut config = Config::default();
        config.server.modern_protocol = true;
        let backends = Arc::new(BackendRegistry::new());
        let multiplexer = Arc::new(NotificationMultiplexer::new(
            Arc::clone(&backends),
            config.streaming.clone(),
        ));
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
        let agent_registry = Arc::new(AgentRegistry::new());
        Arc::new(AppState {
            continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
            env: None,
            meta_mcp: Arc::new(MetaMcp::new(Arc::clone(&backends))),
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
            agent_auth: AgentAuthState::new(false, agent_registry),
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
            subscriptions: Arc::new(
                mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
            ),
        })
    }

    async fn post_with_headers(body: Value, headers: &[(&str, &str)]) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        let response = create_router(state())
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

    fn modern_body(method: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
    }

    fn only<F: Fn(&Record) -> bool>(predicate: F) -> Record {
        let matching: Vec<Record> = observation_records()
            .into_iter()
            .filter(&predicate)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "expected exactly one matching observation record, got {:?}",
            observation_records()
        );
        matching.into_iter().next().expect("checked above")
    }

    /// NFR.OBS.1 — a modern request carries its revision in `_meta`, and the
    /// record must say so, not merely that a revision was seen.
    #[tokio::test]
    async fn a_modern_request_records_the_revision_and_that_meta_carried_it() {
        let _capture = capture_lock().await;

        let (status, body) = post_with_headers(
            modern_body("tools/list"),
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/list"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let record = only(|r| r.fields.contains_key("revision_source"));
        assert_eq!(record.field("protocol_revision"), "2026-07-28");
        assert_eq!(
            record.field("revision_source"),
            "_meta",
            "a modern request declares its revision in `_meta`"
        );
    }

    /// NFR.OBS.1 — a legacy client's revision comes from the handshake, and a
    /// record that cannot tell the two sources apart closes nothing.
    #[tokio::test]
    async fn a_legacy_request_records_the_handshake_as_the_source() {
        let _capture = capture_lock().await;

        let (status, body) = post_with_headers(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": "2025-06-18", "capabilities": {} }
            }),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let record = only(|r| r.fields.contains_key("revision_source"));
        assert_eq!(record.field("protocol_revision"), "2025-06-18");
        assert_eq!(record.field("revision_source"), "handshake");
    }

    /// NFR.OBS.2 — the record names the filters that ran, and the cacheScope it
    /// names must be the one the response actually advertises. Asserting a
    /// literal would keep passing after the two sites diverge, which is the
    /// only failure this criterion exists to catch.
    #[tokio::test]
    async fn a_modern_tools_list_records_its_filters_and_the_advertised_cache_scope() {
        let _capture = capture_lock().await;

        let (status, body) = post_with_headers(
            modern_body("tools/list"),
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/list"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let advertised = body["result"]["cacheScope"]
            .as_str()
            .unwrap_or_else(|| panic!("a modern tools/list advertises a cacheScope: {body}"));

        let record = only(|r| r.fields.contains_key("cache_scope"));
        assert_eq!(
            record.field("cache_scope"),
            advertised,
            "the recorded scope must be the scope the client is handed"
        );
        assert_eq!(record.field("cache_scope_advertised"), "true");
        let filters = record.field("filters");
        assert!(
            filters.contains("meta_tool_exposure"),
            "exposure filtering runs on every tools/list path: {filters:?}"
        );
        assert!(
            filters.contains("session_profile"),
            "the session profile selects the surface: {filters:?}"
        );
    }

    /// NFR.OBS.2 — a legacy `tools/list` is handed no `cacheScope`, so a record
    /// claiming one would be advertised is a false record.
    #[tokio::test]
    async fn a_legacy_tools_list_records_that_no_cache_scope_is_advertised() {
        let _capture = capture_lock().await;

        let (status, body) = post_with_headers(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["result"]["cacheScope"].is_null(),
            "legacy results carry no cacheScope: {body}"
        );

        let record = only(|r| r.fields.contains_key("cache_scope"));
        assert_eq!(record.field("cache_scope_advertised"), "false");
    }
}
