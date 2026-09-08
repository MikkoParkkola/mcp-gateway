// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture for `signing_nonce_cache_admission`: a real backend, a gateway built
//! by the production builder, and the reading taken from the live objects.
//!
//! Split out of the test file only to keep every file under the 500-line cap.
//! Nothing here decides an outcome — the oracles live beside the tests.

use super::*;
use crate::gateway::server::serving_context::OwnedMetaMcp;
use crate::idempotency::admission::Snapshot;
use crate::idempotency::admission::observer::Observed;
use axum::body::Body;
use axum::http::Request;

pub(super) const API_KEY: &str = "signing-nonce-test-credential-0123456789";
pub(super) const BACKEND: &str = "nonce_backend";
pub(super) const TOOL: &str = "echo";
/// 45 bytes — above the 32-byte minimum `validate_secret` enforces.
const SIGNING_SECRET: &str = "a-signing-secret-that-is-at-least-32-bytes!!!!";
/// The admission owner's epoch is injected, so nothing here depends on
/// wall-clock time; retention windows sit far outside any test's lifetime.
pub(super) const CLOCK_EPOCH: u64 = 1_760_000_000;

// ── The real backend ─────────────────────────────────────────────────────────

pub(super) struct EchoBackend {
    pub(super) url: String,
    received: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl EchoBackend {
    pub(super) async fn start() -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let app_received = Arc::clone(&received);
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
                let received = Arc::clone(&app_received);
                async move {
                    received
                        .lock()
                        .expect("backend recorder")
                        .push(request.clone());
                    let id = request.get("id").cloned().unwrap_or(Value::Null);
                    let response = match request.get("method").and_then(Value::as_str) {
                        Some("initialize") => json!({"jsonrpc": "2.0", "id": id, "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": BACKEND, "version": "test"}
                        }}),
                        Some("tools/list") => json!({"jsonrpc": "2.0", "id": id, "result": {
                            "tools": [{
                                "name": TOOL,
                                "description": "returns the configured test result",
                                "inputSchema": {"type": "object"},
                                "annotations": {"readOnlyHint": true}
                            }]
                        }}),
                        Some("tools/call") => json!({"jsonrpc": "2.0", "id": id, "result": {
                            "content": [{"type": "text", "text": "echo-ok"}]
                        }}),
                        Some("notifications/initialized") => json!({}),
                        _ => json!({"jsonrpc": "2.0", "id": id, "error": {
                            "code": -32601, "message": "fixture method not found"
                        }}),
                    };
                    axum::Json(response)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let address = listener.local_addr().expect("backend address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve backend");
        });
        Self {
            url: format!("http://{address}/"),
            received,
            task,
        }
    }

    pub(super) fn tools_call_count(&self) -> usize {
        self.received
            .lock()
            .expect("backend recorder")
            .iter()
            .filter(|request| request["method"] == "tools/call")
            .count()
    }
}

impl Drop for EchoBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ── The gateway under test ───────────────────────────────────────────────────

pub(super) fn auth_config() -> AuthConfig {
    serde_json::from_value(json!({
        "enabled": true,
        "public_paths": ["/health"],
        "api_keys": [{
            "key": API_KEY,
            "name": "nonce-owner",
            "backends": [BACKEND]
        }]
    }))
    .expect("AuthConfig shape")
}

/// The operator configuration this checkpoint is about: modern protocol,
/// response cache on, message signing enforced with a required nonce, and one
/// real HTTP backend.
fn signing_config(backend_url: &str) -> crate::config::Config {
    let mut config = crate::config::Config::default();
    config.server.modern_protocol = true;
    config.auth = auth_config();
    config.cache.enabled = true;
    config.cache.default_ttl = Duration::from_secs(300);
    config.security.message_signing.enabled = true;
    config.security.message_signing.shared_secret = SIGNING_SECRET.to_string();
    config.security.message_signing.require_nonce = true;
    config.security.message_signing.replay_window = 300;
    config.security.message_signing.key_id = "nonce-checkpoint".to_string();
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            transport: crate::config::TransportConfig::Http {
                http_url: backend_url.to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            enabled: true,
            ..BackendConfig::default()
        },
    );
    config
}

/// What a caller may vary about the fixture without writing a second one.
///
/// Named fields rather than positional flags: a call site reads as what it
/// configures. `Default` is hand-written — a derived one would silently flip
/// `require_nonce` to `false` under the tests that depend on enforcement.
pub(super) struct FixtureOptions {
    /// `Some` → the production transparency logger is opened at this path and
    /// installed by the real builder, so the request-hash block actually runs.
    pub(super) transparency_path: Option<std::path::PathBuf>,
    /// Whether a nonce is mandatory. `false` is the operator's optional-nonce
    /// posture: an absent nonce signs, a malformed present one still refuses.
    pub(super) require_nonce: bool,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            transparency_path: None,
            require_nonce: true,
        }
    }
}

/// The production builder, not a hand-assembled `MetaMcp`: the controls in the
/// test file are worth something only if the cache and the admission owner are
/// the ones this configuration actually produces.
///
/// The owner is returned so the caller keeps it alive — dropping it aborts the
/// cleanup task the real server holds for the same reason.
pub(super) async fn gateway(backend_url: &str) -> (Arc<AppState>, OwnedMetaMcp) {
    gateway_with(backend_url, FixtureOptions::default()).await
}

/// The same fixture with the two knobs above applied to the SAME configuration
/// the builder already accepts — nothing else differs, so a reading taken here
/// is comparable with one taken through [`gateway`].
pub(super) async fn gateway_with(
    backend_url: &str,
    options: FixtureOptions,
) -> (Arc<AppState>, OwnedMetaMcp) {
    let mut config = signing_config(backend_url);
    config.security.message_signing.require_nonce = options.require_nonce;
    if let Some(path) = options.transparency_path {
        config.security.transparency_log.enabled = true;
        config.security.transparency_log.path = path.to_string_lossy().into_owned();
    }
    let owner =
        crate::gateway::server::build_meta_mcp_for_test(config.clone(), Arc::new(|| CLOCK_EPOCH))
            .await
            .expect("the production builder must accept this configuration");
    let meta = Arc::clone(owner.meta());
    let mut state = test_router_app_state_with(StreamingConfig::default(), config);
    {
        let inner = Arc::get_mut(&mut state).expect("unique AppState");
        // The registry the built handler routes through, not a second empty
        // one: a request answered by a different registry would never reach the
        // backend whose calls this fixture counts.
        inner.backends = Arc::clone(&meta.backends);
        inner.auth_config = Arc::new(ResolvedAuthConfig::from_config(&auth_config()));
        inner.meta_mcp = meta;
    }
    (state, owner)
}

// ── Requests ─────────────────────────────────────────────────────────────────

/// A large nested backend argument tree, built deterministically so two calls
/// that use it produce the same response-cache key.
///
/// Large enough that the work a refusal must not do is not lost in the noise of
/// a `{}` payload, and nested so a shallow copy would not stand in for a deep
/// one. NO allocation or clone-count claim is made here — that is row 40, and
/// this file measures neither.
pub(super) fn nested_arguments() -> Value {
    let leaf = json!({
        "note": "n".repeat(64),
        "flags": [true, false, true],
        "ids": (0..8).collect::<Vec<u32>>(),
    });
    let mut branch = serde_json::Map::new();
    for index in 0..12 {
        branch.insert(format!("field_{index:02}"), leaf.clone());
    }
    let branch = Value::Object(branch);
    json!({
        "label": "large-nested-backend-arguments",
        "filter": { "nested": { "deep": branch.clone() } },
        "batch": [branch.clone(), branch],
    })
}

/// A modern `gateway_invoke` carrying an explicit idempotency key, the large
/// nested arguments, and the protocol nonce exactly where a client puts it.
pub(super) fn invoke(id: &str, idempotency_key: &str, nonce: Option<Value>) -> Request<Body> {
    let mut arguments = json!({
        "server": BACKEND,
        "tool": TOOL,
        "arguments": nested_arguments(),
    });
    if let Some(nonce) = nonce {
        arguments
            .as_object_mut()
            .expect("arguments object")
            .insert("nonce".into(), nonce);
    }
    let payload = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": arguments,
            "_meta": {
                "io.mcp-gateway/idempotency-key": idempotency_key,
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(Body::from(serde_json::to_vec(&payload).expect("payload")))
        .expect("request")
}

pub(super) async fn send(state: &Arc<AppState>, request: Request<Body>) -> (StatusCode, Value) {
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("oneshot");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).expect("json-rpc"))
}

// ── What is observed ─────────────────────────────────────────────────────────

/// Everything a nonce refusal must leave alone, read from the live objects.
///
/// `hit_rate` is deliberately absent: it is an `f64` derived from the two
/// counters already here, and keeping it would cost the `Eq` that lets a whole
/// reading be compared in one assertion. Taking a reading performs no admission
/// work — a snapshot read is not counted as a lookup.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Reading {
    pub(super) cache_hits: u64,
    pub(super) cache_misses: u64,
    pub(super) cache_entries: usize,
    pub(super) admission: Snapshot,
    pub(super) observed: Observed,
    pub(super) backend_calls: usize,
}

pub(super) fn read(state: &Arc<AppState>, backend: &EchoBackend) -> Reading {
    let cache = state
        .meta_mcp
        .cache
        .as_ref()
        .expect("this configuration enables the response cache");
    let stats = cache.stats();
    Reading {
        cache_hits: stats.hits,
        cache_misses: stats.misses,
        cache_entries: stats.size,
        admission: state.meta_mcp.execution_admission().snapshot(),
        observed: state.meta_mcp.execution_admission().observed(),
        backend_calls: backend.tools_call_count(),
    }
}
