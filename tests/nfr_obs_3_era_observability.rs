// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `NFR.OBS.3` — era detection per backend MUST be observable: which era, by
//! what evidence, and when re-probed
//! (`docs/requirements/RELEASE-4.0.0-requirements.md:292`).
//!
//! Written from the reviewed plan at
//! `docs/design/2026-09-04-nfr-obs-3-test-plan.md`, BEFORE the implementation.
//! Every case here fails now. That order is the point: a test written after the
//! code agrees with the code, and one written first agrees with the criterion.
//!
//! Two rules the plan fixes and this file obeys. Every evidence case drives the
//! real probe through a real stdio peer, because a case that builds an
//! observation and asserts its own fields cannot fail. Every read goes through
//! the `gateway_list_servers` response rather than an accessor, because the
//! serialisation gap is exactly what `NFR.OBS.1` and `NFR.OBS.2` were re-opened
//! for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use serde_json::{Value, json};
use tempfile::TempDir;
use tracing::field::{Field, Visit};
use tracing::subscriber::set_global_default;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::Registry;

// ---------------------------------------------------------------------------
// Captured events — the second observability surface
// ---------------------------------------------------------------------------

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
    static BUFFER: OnceLock<Mutex<Vec<Record>>> = OnceLock::new();
    BUFFER.get_or_init(|| Mutex::new(Vec::new()))
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
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

/// Serialises the cases: one global subscriber and one shared buffer mean two
/// concurrent cases would read each other's events.
async fn capture_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    static INSTALLED: OnceLock<()> = OnceLock::new();
    let guard = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    INSTALLED.get_or_init(|| {
        let subscriber = Registry::default()
            .with(Collector)
            .with(tracing::level_filters::LevelFilter::DEBUG);
        set_global_default(subscriber).expect("no other global subscriber in this test binary");
    });
    captured().lock().expect("buffer").clear();
    guard
}

/// Records the gateway emits about what it observed, newest last.
fn observed(name: &str) -> Vec<Record> {
    captured()
        .lock()
        .expect("buffer")
        .iter()
        .filter(|r| r.target == "mcp_gateway::observed" && r.fields.contains_key(name))
        .cloned()
        .collect()
}

/// The one record of its kind, or a failure naming what was actually captured.
fn only(kind: &str) -> Record {
    let found = observed(kind);
    assert_eq!(
        found.len(),
        1,
        "expected exactly one `{kind}` record on target `mcp_gateway::observed`, captured: {:?}",
        captured().lock().expect("buffer")
    );
    found.into_iter().next().expect("checked above")
}

// ---------------------------------------------------------------------------
// The peer — a recorder, not a participant
// ---------------------------------------------------------------------------

/// Logs every received line before answering it, so a frame that produced a
/// response is on disk by the time the caller sees that response. No era logic
/// lives here: the fixture answers the same canned frames whatever the gateway
/// believes, which is what keeps the classification under test.
const FIXTURE: &str = r#"LOG='__LOG__'
while IFS= read -r request; do
    printf '%s\n' "$request" >> "$LOG"
    id=$(printf '%s' "$request" | tr ',' '\n' | sed -n 's/^"id":\([0-9][0-9]*\).*/\1/p' | head -1)
    case "$request" in
        *'"method":"initialize"'*)
            printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"__VERSION__","capabilities":{},"serverInfo":{"name":"era-fixture","version":"1"}}}\n' "$id"
            ;;
        *'"method":"server/discover"'*)
            __DISCOVER_ARM__
            ;;
        *'"method":"tools/list"'*)
            printf '{"jsonrpc":"2.0","id":%s,__TOOLS__}\n' "$id"
            ;;
    esac
done
"#;

const MODERN_DISCOVER: &str =
    r#""result":{"capabilities":{},"supportedVersions":["2026-07-28","2025-11-25"]}"#;
/// A discovery document that answers, and names no revision we can speak
/// statelessly — the dual-era peer offering only 2025.
const NOT_MODERN_DISCOVER: &str =
    r#""result":{"capabilities":{},"supportedVersions":["2025-11-25"]}"#;
const METHOD_NOT_FOUND: &str = r#""error":{"code":-32601,"message":"Method not found"}"#;
/// `-32022`, which only a 2026-07-28 peer knows how to raise.
const UNSUPPORTED_VERSION: &str =
    r#""error":{"code":-32022,"message":"Unsupported protocol version"}"#;
/// An error carrying no era signal either way.
const OTHER_ERROR: &str = r#""error":{"code":-32000,"message":"Server error"}"#;
const EMPTY_TOOLS: &str = r#""result":{"tools":[]}"#;

struct Fixture {
    _dir: TempDir,
    command: String,
}

impl Fixture {
    /// `discover` is the JSON-RPC payload following the echoed `id` — either
    /// `"result":{...}` or `"error":{...}`.
    fn new(discover: &str) -> Self {
        let arm = format!(r#"printf '{{"jsonrpc":"2.0","id":%s,{discover}}}\n' "$id""#);
        Self::with_discover_arm(&arm)
    }

    /// A peer that completes `initialize` and then never answers the probe.
    ///
    /// `:` is the shell no-op: the request is still logged, and nothing is
    /// written back. This is the only honest route to `no_answer` — silence is
    /// produced by not answering, not by a canned "no answer" payload.
    fn silent() -> Self {
        Self::with_discover_arm(":")
    }

    /// A peer that answers the start probe one way and every later probe
    /// another, and whose ordinary responses carry `-32022` so the first real
    /// request contradicts a legacy verdict and triggers the re-probe.
    ///
    /// An empty `later` is silence, which is how the second transition reaches
    /// `no_answer` from a backend that had already answered once.
    fn reprobing(first: &str, later: &str) -> Self {
        let discover_arm = format!(
            "if [ -f \"$LOG.probed\" ]; then {}; else : > \"$LOG.probed\"; {}; fi",
            Self::arm(later),
            Self::arm(first)
        );
        Self::with_arms(&discover_arm, UNSUPPORTED_VERSION)
    }

    /// A discover arm answering `payload`, or the shell no-op for silence.
    fn arm(payload: &str) -> String {
        if payload.is_empty() {
            ":".to_string()
        } else {
            format!(r#"printf '{{"jsonrpc":"2.0","id":%s,{payload}}}\n' "$id""#)
        }
    }

    fn with_discover_arm(discover_arm: &str) -> Self {
        Self::with_arms(discover_arm, EMPTY_TOOLS)
    }

    fn with_arms(discover_arm: &str, tools: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("frames.log");
        let script = dir.path().join("peer.sh");
        let body = FIXTURE
            .replace("__LOG__", &log.display().to_string())
            .replace("__VERSION__", "2025-11-25")
            .replace("__DISCOVER_ARM__", discover_arm)
            .replace("__TOOLS__", tools);
        std::fs::write(&script, body).expect("write fixture");
        Self {
            _dir: dir,
            command: format!("sh {}", script.display()),
        }
    }

    fn backend(&self, name: &str) -> Backend {
        let config = BackendConfig {
            description: format!("era observability fixture: {name}"),
            enabled: true,
            transport: TransportConfig::Stdio {
                command: self.command.clone(),
                cwd: None,
                protocol_version: None,
            },
            // No reaper: an idle sweep mid-test would restart the peer and
            // re-probe it, moving the very fields under assertion.
            stop_when_idle_for: None,
            timeout: Duration::from_secs(30),
            env: HashMap::default(),
            headers: HashMap::default(),
            oauth: None,
            secrets: Vec::new(),
            passthrough: false,
            allow_cleartext_credentials: false,
            runtime_profile: None,
            identity_propagation: None,
        };
        Backend::new(
            name,
            config,
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        )
    }
}

// ---------------------------------------------------------------------------
// The read — through the router, never through an accessor
// ---------------------------------------------------------------------------

mod read {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
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

    fn state(backends: Arc<BackendRegistry>) -> Arc<AppState> {
        let mut config = Config::default();
        config.server.modern_protocol = true;
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

    /// The `servers` array of a `gateway_list_servers` call, as an operator
    /// sees it. Through the router, because an accessor would hide exactly the
    /// serialisation gap this criterion is about.
    pub async fn servers(backends: Arc<BackendRegistry>) -> Vec<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "gateway_list_servers",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        });
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            // The body names a revision, so the header must name the same one:
            // the gateway rejects a mismatch with HEADER_MISMATCH before any
            // handler runs, and that rejection is not what these cases observe.
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        let response = create_router(state(backends))
            .oneshot(request)
            .await
            .expect("router must answer");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body must read");
        let envelope: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let text = envelope["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("gateway_list_servers must answer with content: {envelope}"));
        let payload: Value =
            serde_json::from_str(text).unwrap_or_else(|_| panic!("content must be JSON: {text}"));
        payload["servers"]
            .as_array()
            .unwrap_or_else(|| panic!("response must carry a servers array: {payload}"))
            .clone()
    }
}

/// The entry for one backend, or a failure naming what the response did carry.
fn entry(servers: &[Value], name: &str) -> Value {
    servers
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no `{name}` entry in {servers:?}"))
        .clone()
}

/// The five operator-read fields, absences included, as one comparable value.
///
/// A whole snapshot rather than five assertions: an `era` from the latest probe
/// beside an `era_evidence` from the previous one is internally inconsistent,
/// and no per-field assertion sees that.
fn snapshot(entry: &Value) -> Value {
    let mut fields = serde_json::Map::new();
    for name in [
        "era",
        "era_source",
        "era_evidence",
        "era_probe_trigger",
        "era_probed_at",
    ] {
        if let Some(value) = entry.get(name) {
            fields.insert(name.to_string(), value.clone());
        }
    }
    Value::Object(fields)
}

/// Starts one backend against `fixture`, then reads it back off the wire.
async fn probe_and_read(fixture: &Fixture, name: &str) -> Value {
    let backends = Arc::new(BackendRegistry::new());
    let backend = Arc::new(fixture.backend(name));
    assert!(
        backends.register(Arc::clone(&backend)),
        "backend must register"
    );
    backend
        .ensure_started()
        .await
        .unwrap_or_else(|e| panic!("backend must start: {e}"));
    let servers = read::servers(backends).await;
    entry(&servers, name)
}

/// Rides every row of the matrix: the raw JSON-RPC code is an event field, and
/// a read that leaks it has widened the operator surface past what the design
/// fixed — which no positive assertion in the matrix would notice.
fn assert_no_error_code(entry: &Value) {
    assert!(
        entry.get("error_code").is_none(),
        "the operator read must not carry the raw error code: {entry}"
    );
}

// ---------------------------------------------------------------------------
// (a) The evidence matrix — one case per `EraEvidence` variant
// ---------------------------------------------------------------------------

/// A backend that has never been probed reads as an assumption, not a finding.
///
/// It observes a backend that was never probed rather than one whose
/// observation was reset: a reset reaches the same values by a path the
/// criterion does not describe.
#[tokio::test]
async fn never_probed_reads_as_an_assumed_legacy_era() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(MODERN_DISCOVER);
    let backends = Arc::new(BackendRegistry::new());
    assert!(
        backends.register(Arc::new(fixture.backend("unstarted"))),
        "backend must register"
    );

    // Deliberately not started: the probe runs on the start path.
    let servers = read::servers(backends).await;
    let entry = entry(&servers, "unstarted");

    assert_eq!(
        snapshot(&entry),
        json!({
            "era": "legacy",
            "era_source": "assumed",
            "era_evidence": "never_probed",
        }),
        "an unprobed backend reads as assumed, with no trigger and no time: {entry}"
    );
    assert_no_error_code(&entry);
}

/// A discovery document naming a revision we can speak statelessly.
#[tokio::test]
async fn a_modern_discovery_document_reads_as_discover_modern() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(MODERN_DISCOVER);
    let entry = probe_and_read(&fixture, "modern-doc").await;

    assert_eq!(entry["era"], "modern", "read: {entry}");
    assert_eq!(entry["era_source"], "probed", "read: {entry}");
    assert_eq!(entry["era_evidence"], "discover_modern", "read: {entry}");
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(
        entry.get("era_probed_at").is_some(),
        "a completed probe stamps a time: {entry}"
    );
    assert_no_error_code(&entry);
}

/// A discovery document that answers and names no speakable revision.
#[tokio::test]
async fn a_dual_era_discovery_document_reads_as_discover_not_modern() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(NOT_MODERN_DISCOVER);
    let entry = probe_and_read(&fixture, "not-modern-doc").await;

    assert_eq!(entry["era"], "legacy", "read: {entry}");
    assert_eq!(entry["era_source"], "probed", "read: {entry}");
    assert_eq!(
        entry["era_evidence"], "discover_not_modern",
        "read: {entry}"
    );
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(entry.get("era_probed_at").is_some(), "read: {entry}");
    assert_no_error_code(&entry);
}

/// `-32022` — an error only a modern peer knows how to raise.
///
/// Also the case that pins the design's "one enum, both readers" property: the
/// event's `evidence` is compared against the read's, not against a literal,
/// because two literals let the surfaces drift while both suites stay green.
#[tokio::test]
async fn a_modern_only_error_code_reads_as_modern_error_code() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(UNSUPPORTED_VERSION);
    let entry = probe_and_read(&fixture, "modern-error").await;

    assert_eq!(entry["era"], "modern", "read: {entry}");
    assert_eq!(entry["era_source"], "probed", "read: {entry}");
    assert_eq!(entry["era_evidence"], "modern_error_code", "read: {entry}");
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(entry.get("era_probed_at").is_some(), "read: {entry}");
    assert_no_error_code(&entry);

    let event = only("evidence");
    assert_eq!(
        Value::from(event.field("evidence")),
        entry["era_evidence"],
        "event and read must name the same evidence: {event:?} vs {entry}"
    );
    assert_eq!(
        event.field("error_code"),
        "-32022",
        "the raw code belongs on the event: {event:?}"
    );
}

/// `-32601` — the honest legacy answer to a method the peer does not implement.
#[tokio::test]
async fn method_not_found_reads_as_method_not_found() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(METHOD_NOT_FOUND);
    let entry = probe_and_read(&fixture, "method-not-found").await;

    assert_eq!(entry["era"], "legacy", "read: {entry}");
    assert_eq!(entry["era_source"], "probed", "read: {entry}");
    assert_eq!(entry["era_evidence"], "method_not_found", "read: {entry}");
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(entry.get("era_probed_at").is_some(), "read: {entry}");
    assert_no_error_code(&entry);

    let event = only("evidence");
    assert_eq!(
        Value::from(event.field("evidence")),
        entry["era_evidence"],
        "event and read must name the same evidence: {event:?} vs {entry}"
    );
}

/// An error carrying no era signal is not evidence of modernity.
#[tokio::test]
async fn an_unrelated_error_code_reads_as_other_error() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(OTHER_ERROR);
    let entry = probe_and_read(&fixture, "other-error").await;

    assert_eq!(entry["era"], "legacy", "read: {entry}");
    assert_eq!(entry["era_source"], "probed", "read: {entry}");
    assert_eq!(entry["era_evidence"], "other_error", "read: {entry}");
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(entry.get("era_probed_at").is_some(), "read: {entry}");
    assert_no_error_code(&entry);

    let event = only("evidence");
    assert_eq!(
        Value::from(event.field("evidence")),
        entry["era_evidence"],
        "event and read must name the same evidence: {event:?} vs {entry}"
    );
}

/// Silence — the regression row.
///
/// The only case where `era_source` is `assumed` while `era_probed_at` is set.
/// An implementation that marks the era `probed` whenever a probe *completes*
/// passes every other row in this matrix and fails only here.
#[tokio::test]
async fn a_probe_that_gets_no_answer_stays_assumed_while_stamping_a_time() {
    let _guard = capture_lock().await;
    let fixture = Fixture::silent();
    let entry = probe_and_read(&fixture, "silent").await;

    assert_eq!(entry["era"], "legacy", "read: {entry}");
    assert_eq!(
        entry["era_source"], "assumed",
        "silence is not a finding, so the era stays assumed: {entry}"
    );
    assert_eq!(entry["era_evidence"], "no_answer", "read: {entry}");
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(
        entry.get("era_probed_at").is_some(),
        "the probe ran, so its time is known even though its answer is not: {entry}"
    );
    assert_no_error_code(&entry);
}

/// RFC 3339, UTC, second precision, `Z` suffix — asserted once.
///
/// Once rather than per row: asserting it everywhere tests the fixture, and
/// asserting it nowhere leaves the design's stated format unenforced.
#[tokio::test]
async fn the_probe_time_is_rfc_3339_utc_at_second_precision() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(MODERN_DISCOVER);
    let entry = probe_and_read(&fixture, "timestamp").await;
    let stamp = entry["era_probed_at"]
        .as_str()
        .unwrap_or_else(|| panic!("era_probed_at must be a string: {entry}"));

    let parsed = chrono::DateTime::parse_from_rfc3339(stamp)
        .unwrap_or_else(|e| panic!("era_probed_at must be RFC 3339: {stamp} ({e})"));
    assert!(
        stamp.ends_with('Z'),
        "the time must be UTC with a `Z` suffix, not an offset: {stamp}"
    );
    assert_eq!(
        stamp,
        parsed
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "second precision, so two reads compare as times not formats: {stamp}"
    );
}

// ---------------------------------------------------------------------------
// (b) Transitions — change over time, which no single row can express
// ---------------------------------------------------------------------------

/// Polls the operator read until the re-probe has landed.
///
/// The contradiction re-probe is a detached task, so the read that follows the
/// contradicting request races it. Polling a value the test then asserts in
/// full is honest — a poll on `era_probe_trigger` alone would let every other
/// field settle afterwards.
async fn await_reprobe(backends: &Arc<BackendRegistry>, name: &str) -> Value {
    for _ in 0..250 {
        let entry = entry(&read::servers(Arc::clone(backends)).await, name);
        if entry["era_probe_trigger"] == "reprobe" {
            return entry;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "no re-probe was recorded within 5s: {}",
        entry(&read::servers(Arc::clone(backends)).await, name)
    );
}

/// A contradicted legacy verdict is re-probed, and the read moves with it.
///
/// Asserts the complete snapshot on both sides. A case pinning only the moving
/// fields passes while a stale `era_evidence` survives beside a correctly
/// updated `era` — an internally inconsistent read no per-field assertion sees.
#[tokio::test]
async fn a_contradiction_reprobes_and_the_whole_read_moves_with_it() {
    let _guard = capture_lock().await;
    let fixture = Fixture::reprobing(METHOD_NOT_FOUND, UNSUPPORTED_VERSION);
    let backends = Arc::new(BackendRegistry::new());
    let backend = Arc::new(fixture.backend("contradicted"));
    assert!(
        backends.register(Arc::clone(&backend)),
        "backend must register"
    );
    backend.ensure_started().await.expect("start");

    let before = entry(&read::servers(Arc::clone(&backends)).await, "contradicted");
    assert_eq!(
        snapshot(&before),
        json!({
            "era": "legacy",
            "era_source": "probed",
            "era_evidence": "method_not_found",
            "era_probe_trigger": "start",
            "era_probed_at": before["era_probed_at"],
        }),
        "before: {before}"
    );

    // The ordinary request whose error contradicts the legacy verdict.
    let _ = backend.request("tools/list", None).await;
    let after = await_reprobe(&backends, "contradicted").await;

    assert_eq!(
        snapshot(&after),
        json!({
            "era": "modern",
            "era_source": "probed",
            "era_evidence": "modern_error_code",
            "era_probe_trigger": "reprobe",
            "era_probed_at": after["era_probed_at"],
        }),
        "after: {after}"
    );
    // The plan's equality against a stepped clock needs a clock seam the
    // production path does not offer; ordering is what is assertable today.
    assert!(
        after["era_probed_at"].as_str() >= before["era_probed_at"].as_str(),
        "the re-probe's time cannot precede the start probe's: {before} -> {after}"
    );
    assert_no_error_code(&after);
}

/// A re-probe that gets no answer gives the era back, rather than keeping a
/// finding it can no longer support.
#[tokio::test]
async fn a_reprobe_that_gets_no_answer_returns_the_era_to_assumed() {
    let _guard = capture_lock().await;
    let fixture = Fixture::reprobing(NOT_MODERN_DISCOVER, "");
    let backends = Arc::new(BackendRegistry::new());
    let backend = Arc::new(fixture.backend("silenced"));
    assert!(
        backends.register(Arc::clone(&backend)),
        "backend must register"
    );
    backend.ensure_started().await.expect("start");

    let before = entry(&read::servers(Arc::clone(&backends)).await, "silenced");
    assert_eq!(
        snapshot(&before),
        json!({
            "era": "legacy",
            "era_source": "probed",
            "era_evidence": "discover_not_modern",
            "era_probe_trigger": "start",
            "era_probed_at": before["era_probed_at"],
        }),
        "before: {before}"
    );

    let _ = backend.request("tools/list", None).await;
    let after = await_reprobe(&backends, "silenced").await;

    assert_eq!(
        snapshot(&after),
        json!({
            "era": "legacy",
            "era_source": "assumed",
            "era_evidence": "no_answer",
            "era_probe_trigger": "reprobe",
            "era_probed_at": after["era_probed_at"],
        }),
        "after: {after}"
    );
    assert_no_error_code(&after);
}

// ---------------------------------------------------------------------------
// (d) The event contract — the other observability surface
// ---------------------------------------------------------------------------

/// The field names a record carries, sorted, so a set can be compared whole.
fn keys(record: &Record) -> Vec<&str> {
    let mut names: Vec<&str> = record.fields.keys().map(String::as_str).collect();
    names.sort_unstable();
    names
}

/// `era_probe` carries exactly the design's fields, and no `error_code` when
/// the probe did not fail.
///
/// Absences are asserted rather than assumed: a record carrying a field the
/// design did not give it has widened the surface as surely as a missing one
/// has narrowed it, and only a pinned set sees either.
#[tokio::test]
async fn the_era_probe_record_carries_exactly_its_designed_fields() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(MODERN_DISCOVER);
    probe_and_read(&fixture, "probe-record").await;

    let record = only("evidence");
    assert_eq!(
        keys(&record),
        vec!["backend", "duration_ms", "evidence", "outcome", "trigger"],
        "field set: {record:?}"
    );
    assert_eq!(record.field("backend"), "probe-record", "{record:?}");
    assert_eq!(record.field("evidence"), "discover_modern", "{record:?}");
    assert_eq!(record.field("trigger"), "start", "{record:?}");
    assert_eq!(record.field("outcome"), "modern", "{record:?}");
}

/// `era_cache` says `false` on the probe that resolves and `true` on the read
/// that follows it.
#[tokio::test]
async fn the_era_cache_record_reports_a_miss_then_a_hit() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(MODERN_DISCOVER);
    probe_and_read(&fixture, "cache-record").await;

    let records = observed("hit");
    let first = records
        .first()
        .expect("a cache record on the resolving probe");
    assert_eq!(keys(first), vec!["backend", "hit"], "field set: {first:?}");
    assert_eq!(first.field("backend"), "cache-record", "{first:?}");
    assert_eq!(
        first.field("hit"),
        "false",
        "the probe that resolves the era cannot have hit the cache: {first:?}"
    );
    assert!(
        records.iter().skip(1).any(|r| r.field("hit") == "true"),
        "the read after the probe must hit the cache: {records:?}"
    );
}

/// `era_invalidated` names why the era was thrown away.
#[tokio::test]
async fn the_era_invalidated_record_names_the_contradiction_as_its_reason() {
    let _guard = capture_lock().await;
    let fixture = Fixture::reprobing(METHOD_NOT_FOUND, UNSUPPORTED_VERSION);
    let backends = Arc::new(BackendRegistry::new());
    let backend = Arc::new(fixture.backend("invalidated"));
    assert!(
        backends.register(Arc::clone(&backend)),
        "backend must register"
    );
    backend.ensure_started().await.expect("start");
    let _ = backend.request("tools/list", None).await;
    await_reprobe(&backends, "invalidated").await;

    let record = only("reason");
    assert_eq!(
        keys(&record),
        vec!["backend", "reason"],
        "field set: {record:?}"
    );
    assert_eq!(record.field("backend"), "invalidated", "{record:?}");
    assert_eq!(record.field("reason"), "trigger", "{record:?}");
}

// ---------------------------------------------------------------------------
// (e) System — the read agrees with behaviour, and it is per backend
// ---------------------------------------------------------------------------

/// The `era` the operator reads agrees with how the peer actually behaves.
///
/// A case that reads the field and stops proves the field exists; it cannot
/// tell a read wired to the request path from one wired to a constant. So this
/// drives `server/discover` — a call only a modern peer serves — and asserts
/// the read and the observed behaviour say the same thing.
#[tokio::test]
async fn the_era_read_agrees_with_how_the_peer_answers_a_modern_only_call() {
    let _guard = capture_lock().await;
    let modern = Fixture::new(MODERN_DISCOVER);
    let legacy = Fixture::new(METHOD_NOT_FOUND);
    let backends = Arc::new(BackendRegistry::new());
    let modern_backend = Arc::new(modern.backend("speaks-modern"));
    let legacy_backend = Arc::new(legacy.backend("speaks-legacy"));
    assert!(
        backends.register(Arc::clone(&modern_backend)),
        "backend must register"
    );
    assert!(
        backends.register(Arc::clone(&legacy_backend)),
        "backend must register"
    );
    modern_backend.ensure_started().await.expect("start modern");
    legacy_backend.ensure_started().await.expect("start legacy");

    let modern_answer = modern_backend
        .request("server/discover", None)
        .await
        .expect("modern peer answers");
    let legacy_answer = legacy_backend
        .request("server/discover", None)
        .await
        .expect("legacy peer answers, with an error");
    assert!(
        modern_answer.error.is_none() && legacy_answer.error.is_some(),
        "the two peers must differ on the modern-only call, or this case proves \
         nothing: {modern_answer:?} vs {legacy_answer:?}"
    );

    let servers = read::servers(backends).await;
    assert_eq!(
        entry(&servers, "speaks-modern")["era"],
        "modern",
        "the peer that served the modern-only call must read modern: {servers:?}"
    );
    assert_eq!(
        entry(&servers, "speaks-legacy")["era"],
        "legacy",
        "the peer that refused it must read legacy: {servers:?}"
    );
}

/// Two backends in one response each carry their own era observation.
///
/// A shared cell, a cached first answer, or a fold over all backends renders
/// identically when only one backend is observed. This is the only case that
/// separates them.
#[tokio::test]
async fn each_backend_carries_its_own_era_observation() {
    let _guard = capture_lock().await;
    let probed = Fixture::new(MODERN_DISCOVER);
    let unprobed = Fixture::new(MODERN_DISCOVER);
    let backends = Arc::new(BackendRegistry::new());
    let started = Arc::new(probed.backend("probed-peer"));
    assert!(
        backends.register(Arc::clone(&started)),
        "backend must register"
    );
    assert!(
        backends.register(Arc::new(unprobed.backend("unprobed-peer"))),
        "backend must register"
    );
    started.ensure_started().await.expect("start");

    let servers = read::servers(backends).await;

    assert_eq!(
        snapshot(&entry(&servers, "unprobed-peer")),
        json!({
            "era": "legacy",
            "era_source": "assumed",
            "era_evidence": "never_probed",
        }),
        "the unprobed backend must not inherit its neighbour's finding: {servers:?}"
    );
    let probed_entry = entry(&servers, "probed-peer");
    assert_eq!(probed_entry["era"], "modern", "{servers:?}");
    assert_eq!(
        probed_entry["era_evidence"], "discover_modern",
        "{servers:?}"
    );
    assert!(probed_entry.get("era_probed_at").is_some(), "{servers:?}");
}
