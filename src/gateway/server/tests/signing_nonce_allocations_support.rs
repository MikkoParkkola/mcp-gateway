// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture for the owned-stdio allocation checkpoint: a real backend, a
//! gateway built by the production builder, the prepared payloads, and the
//! child-process isolation.
//!
//! Nothing here decides an outcome — the oracles live in
//! `signing_nonce_allocations`. Nothing here allocates inside a measurement
//! scope either: every helper is called before the meter opens.
//!
//! The router's `signing_nonce_cache_admission_support` fixture is the pattern
//! this follows. It is deliberately NOT imported: it is router-local, it
//! assembles an `AppState` and an axum request this transport has no use for,
//! and widening its visibility to reach it would be a production visibility
//! change made for a test. The config shape is reproduced here at the minimum
//! this checkpoint needs.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::super::{Gateway, MetaMcp, MtlsPolicy, ToolPolicy};
use crate::config::{BackendConfig, Config, TransportConfig};

/// 45 bytes — above the 32-byte minimum `validate_secret` enforces.
const SIGNING_SECRET: &str = "a-signing-secret-that-is-at-least-32-bytes!!!!";
pub(super) const BACKEND: &str = "nonce_backend";
pub(super) const TOOL: &str = "echo";
pub(super) const SESSION: &str = "stdio-session";

/// Set in the re-executed child. Its presence is what tells a test body it is
/// the one that must actually measure.
const CHILD_ENV: &str = "MCPGW_ALLOC_METER_CHILD";

// ── Child-process isolation ──────────────────────────────────────────────────

/// Returns `true` in the PARENT, after running this one test in a child that
/// did the measuring. Returns `false` in the child, meaning "you are the
/// measurement, proceed".
///
/// Why a child at all: the totals are per-process-thread and the lib-test
/// binary runs many unrelated tests. A shared process would let another
/// test's allocations land in a total that claims to be one dispatch's.
///
/// `--exact` plus the assertion on `1 passed` is load-bearing. A child that
/// matched zero tests exits 0, and the parent would go green on a test that
/// never ran — a case that can never fail is not a test.
pub(super) fn isolate(test_path: &str) -> bool {
    if std::env::var_os(CHILD_ENV).is_some() {
        return false;
    }
    let exe = std::env::current_exe().expect("the running test binary must be locatable");
    let output = std::process::Command::new(exe)
        .args([test_path, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("re-executing the test binary must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "isolated child failed for {test_path}\n--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed"),
        "isolated child for {test_path} did not run exactly one test\n--- child stdout ---\n{stdout}"
    );
    true
}

/// One thread, so the meter's thread-local totals cover the whole dispatch.
pub(super) fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
}

// ── The real backend ─────────────────────────────────────────────────────────

pub(super) struct EchoBackend {
    pub(super) url: String,
    received: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl EchoBackend {
    async fn start() -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let app_received = Arc::clone(&received);
        let app = axum::Router::new()
            .route(
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
            )
            // This fixture receives the 3 MiB payload verbatim, and axum's `Json`
            // extractor caps a request body at 2 MiB by default — the valid
            // control would be refused by the TEST SERVER before the gateway could
            // be judged at all. Fixture-only: the gateway's own maximum-body
            // semantics are not touched, and every payload is prepared and bounded
            // outside the meter.
            .layer(axum::extract::DefaultBodyLimit::disable());
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

    /// How many `tools/call` requests actually reached the backend. A refusal
    /// must not move this.
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

fn signing_config(backend_url: &str, require_nonce: bool) -> Config {
    let mut config = Config::default();
    config.server.modern_protocol = true;
    config.security.message_signing.enabled = true;
    config.security.message_signing.shared_secret = SIGNING_SECRET.to_string();
    config.security.message_signing.require_nonce = require_nonce;
    config.security.message_signing.replay_window = 300;
    config.security.message_signing.key_id = "stdio-allocation-checkpoint".to_string();
    config.cache.enabled = true;
    config.cache.default_ttl = Duration::from_secs(300);
    // Stdio carries no authenticated identity, so an explicit idempotency key
    // cannot be admitted on this adapter at all: `admit_operation` demands a
    // verified principal for a keyed operation and refuses with
    // `-32003 A verified execution principal is required`. The supported
    // answer is the operator-configured exact read-only target, which takes
    // the unkeyed path (`SyncAdmission::Unprotected`). The echo fixture really
    // is read-only, and this is the existing API — no identity is manufactured,
    // no production policy is changed, and the backend's own `readOnlyHint`
    // annotation remains untrusted: only this exact server/tool pair counts.
    config.idempotency.read_only_tools = vec![crate::config::IdempotencyReadOnlyTool {
        server: BACKEND.to_string(),
        tool: TOOL.to_string(),
    }];
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            transport: TransportConfig::Http {
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

/// Exactly the three values `run_stdio` holds and hands to
/// `dispatch_single_with_sink`, obtained from the production builder rather
/// than assembled by hand.
///
/// `build_meta_mcp` is used directly, not `build_meta_mcp_for_test`, because
/// the tool policy and the mTLS policy are needed too and only the full
/// `BuiltMetaMcp` carries them. Both are private to `crate::gateway::server`
/// and this module is a descendant of it, so no visibility is widened.
///
/// NO clock is injected, and the docs say so rather than implying one still
/// is. An earlier shape of this fixture passed a fixed epoch through
/// `CleanupRuntime::with_clock`; that clock fed `ExecutionAdmission`, not the
/// `NonceStore`'s own monotonic clock, and the current production builder —
/// `build_meta_mcp()`, which takes no arguments — exposes no injection point
/// for it. The delta is bounded: every call these fixtures make is an
/// operator-configured read-only unkeyed stdio call, so no durable admission
/// record is published, none expires, and no test advances a clock. The
/// signing replay window, the nonce store and the expiry configuration in
/// `signing_config` are untouched, and nothing waits on wall-clock time.
pub(super) struct Fixture {
    pub(super) meta: Arc<MetaMcp>,
    pub(super) tool_policy: Arc<ToolPolicy>,
    pub(super) mtls_policy: Arc<MtlsPolicy>,
    pub(super) backend: EchoBackend,
}

impl Fixture {
    pub(super) async fn start(require_nonce: bool) -> Self {
        let backend = EchoBackend::start().await;
        let config = signing_config(&backend.url, require_nonce);
        let gateway = Gateway::new(config)
            .await
            .expect("the production constructor must accept this configuration");
        let built = gateway
            .build_meta_mcp()
            .await
            .expect("the production builder must accept this configuration");
        Self {
            meta: built.meta_mcp,
            tool_policy: built.tool_policy,
            mtls_policy: built.mtls_policy,
            backend,
        }
    }
}

// ── Prepared payloads ────────────────────────────────────────────────────────

pub(super) const ONE_MIB: usize = 1024 * 1024;
pub(super) const THREE_MIB: usize = 3 * 1024 * 1024;

/// A nested argument tree whose serialised form is at least `target_bytes`.
///
/// Nested rather than one long string so a shallow copy could not stand in for
/// a deep one, and deterministic so two requests built from it are identical.
/// Built ENTIRELY before any meter opens.
pub(super) fn nested_arguments(target_bytes: usize) -> Value {
    let leaf = json!({
        "note": "n".repeat(512),
        "flags": [true, false, true],
        "ids": (0..16).collect::<Vec<u32>>(),
    });
    let leaf_bytes = serde_json::to_vec(&leaf).expect("leaf serialises").len();
    let count = target_bytes / leaf_bytes + 1;
    let branch = Value::Array((0..count).map(|_| leaf.clone()).collect());
    let arguments = json!({
        "label": "stdio-allocation-checkpoint",
        "filter": { "nested": { "deep": { "batch": branch } } },
    });
    let actual = serde_json::to_vec(&arguments)
        .expect("arguments serialise")
        .len();
    assert!(
        actual >= target_bytes,
        "prepared payload is {actual} bytes, below the {target_bytes} this test claims to send"
    );
    arguments
}

/// A stdio `tools/call` for `gateway_invoke`, with the protocol nonce exactly
/// where a client puts it.
///
/// NO idempotency key travels here, and that is the supported shape for this
/// adapter rather than an omission. Two runs established it: without a key,
/// modern admission refused with `-32602 An explicit idempotency key is
/// required`; WITH one it refused harder, `-32003 A verified execution
/// principal is required`, because stdio carries no authenticated identity for
/// a keyed operation to belong to. The configured exact read-only target in
/// `signing_config` takes the unkeyed branch of `admit_operation` instead.
///
/// The replay test depends on an ORDER, so it is stated rather than left
/// implicit: `prepare_signing_invocation` runs before `admit_meta_sync`, so a
/// reused nonce is refused by the NONCE store — which is why the replay
/// assertion pins `-32001 Nonce replay detected` and not an admission error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the json! macro clones its inputs regardless, so borrowing here saves \
              nothing and only forces an & at every call site"
)]
pub(super) fn invoke(id: &str, nonce: Option<Value>, arguments: Value) -> Value {
    let mut invoke_arguments = json!({
        "server": BACKEND,
        "tool": TOOL,
        "arguments": arguments,
    });
    if let Some(nonce) = nonce {
        invoke_arguments
            .as_object_mut()
            .expect("arguments object")
            .insert("nonce".into(), nonce);
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": invoke_arguments,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    })
}

// ── Reading a response ───────────────────────────────────────────────────────

/// The error a refusal must carry, read from the response the dispatcher
/// returned. Formatting happens here, AFTER the meter closed.
pub(super) fn error_of(response: &Value) -> (i64, String) {
    assert!(
        response.get("result").is_none(),
        "a refused dispatch must carry no result: {response}"
    );
    let error = response
        .get("error")
        .unwrap_or_else(|| panic!("a refused dispatch must carry an error: {response}"));
    let code = error
        .get("code")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("error carries no numeric code: {response}"));
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    (code, message)
}
