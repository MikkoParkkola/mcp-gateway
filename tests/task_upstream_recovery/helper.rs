// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Owned fixtures for the upstream-recovery vertical: a bounded loopback peer
//! that speaks the pinned SEP-2663 vocabulary, and owned gateway children over
//! a temporary config directory and store.
//!
//! The peer here is a SYNTHETIC control and is named as one. The real pinned
//! `FastMCP` + Docket proof lives in `task_upstream_recovery_sdk.rs` and runs the
//! actual SDK; nothing in this file is offered as evidence about the SDK.

// One consumer: `tests/task_upstream_recovery.rs`. Scaffolding it does not
// drive yet is marked `expect(dead_code)` so the annotation self-deletes
// the moment a case starts using the item.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use mcp_gateway::config::{BackendConfig, Config, ToolContractConfig, TransportConfig};
use parking_lot::Mutex;
use serde_json::{Value, json};

pub const PROTOCOL_VERSION: &str = "2026-07-28";
pub const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";
pub const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
pub const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";
#[expect(
    dead_code,
    reason = "read only by tasks_get_attested, which no case in this target drives yet"
)]
pub const RECOVERY_META: &str = "io.mcp-gateway/recovery";

pub const BACKEND: &str = "upstream";
pub const TOOL: &str = "slow_echo";
pub const HANDLE: &str = "upstream-job-0001";
pub const MARKER: &str = "upstream-task-answered";

pub const READY_BOUND: Duration = Duration::from_secs(60);
pub const EXIT_BOUND: Duration = Duration::from_secs(90);
pub const POLL_GAP: Duration = Duration::from_millis(25);
pub const OBSERVE_BOUND: Duration = Duration::from_secs(30);

/// What the peer will answer the NEXT `tasks/get` with.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Upstream {
    Working,
    Unavailable,
    Completed,
    #[expect(
        dead_code,
        reason = "peer answer state; no case in this target drives the peer to a failed task"
    )]
    Failed,
}

/// A loopback peer speaking the pinned SEP-2663 vocabulary, counting exactly
/// what the criteria are about: submissions and queries.
pub struct Peer {
    submissions: AtomicUsize,
    queries: AtomicUsize,
    handles_asked: Mutex<Vec<String>>,
    /// Whether every `tools/call` carried the tasks-extension opt-in.
    optin_seen: AtomicUsize,
    state: Mutex<Upstream>,
    /// Body the peer returns for a completed job.
    payload: Mutex<Value>,
}

impl Peer {
    pub fn submissions(&self) -> usize {
        self.submissions.load(Ordering::SeqCst)
    }

    pub fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }

    pub fn optin_seen(&self) -> usize {
        self.optin_seen.load(Ordering::SeqCst)
    }

    pub fn handles_asked(&self) -> Vec<String> {
        self.handles_asked.lock().clone()
    }

    pub fn set(&self, next: Upstream) {
        *self.state.lock() = next;
    }

    #[expect(
        dead_code,
        reason = "peer payload override; no case in this target sets a custom payload yet"
    )]
    pub fn set_payload(&self, payload: Value) {
        *self.payload.lock() = payload;
    }

    pub async fn wait_for_queries(&self, at_least: usize) {
        let observe = async {
            loop {
                if self.queries() >= at_least {
                    return;
                }
                tokio::time::sleep(POLL_GAP).await;
            }
        };
        assert!(
            tokio::time::timeout(OBSERVE_BOUND, observe).await.is_ok(),
            "the peer saw {} tasks/get within {OBSERVE_BOUND:?}, expected at least {at_least}",
            self.queries()
        );
    }
}

fn declares_tasks(params: Option<&Value>) -> bool {
    params
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get(CLIENT_CAPABILITIES))
        .and_then(|caps| caps.get("extensions"))
        .and_then(|ext| ext.get(TASKS_EXTENSION))
        .is_some()
}

async fn peer_handler(State(peer): State<Arc<Peer>>, Json(body): Json<Value>) -> Response {
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let Some(id) = body.get("id").filter(|id| !id.is_null()).cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let params = body.get("params");

    let result = match method.as_str() {
        // The extension declaration this gateway negotiates against.
        "server/discover" => json!({
            "resultType": "complete",
            "supportedVersions": [PROTOCOL_VERSION],
            "capabilities": { "extensions": { TASKS_EXTENSION: {}, } },
        }),
        "tools/list" => json!({
            "resultType": "complete",
            // Deliberately NO `execution` field: the pinned SDK does not emit
            // one at 2026-07-28, so a fixture that did would let the gateway
            // depend on something the real peer never sends.
            "tools": [{
                "name": TOOL,
                "description": "Runs as an upstream task.",
                "inputSchema": { "type": "object", "properties": {} },
            }],
        }),
        "tools/call" => {
            peer.submissions.fetch_add(1, Ordering::SeqCst);
            if declares_tasks(params) {
                peer.optin_seen.fetch_add(1, Ordering::SeqCst);
            }
            json!({
                "resultType": "task",
                "taskId": HANDLE,
                "status": "working",
                "createdAt": "2026-09-08T00:00:00Z",
                "lastUpdatedAt": "2026-09-08T00:00:00Z",
                "ttlMs": 900_000,
                "pollIntervalMs": 5_000,
            })
        }
        "tasks/get" => {
            peer.queries.fetch_add(1, Ordering::SeqCst);
            let asked = params
                .and_then(|params| params.get("taskId"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            peer.handles_asked.lock().push(asked.clone());
            let state = *peer.state.lock();
            match state {
                Upstream::Unavailable => {
                    return Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32000, "message": "upstream unavailable" }
                    }))
                    .into_response();
                }
                Upstream::Working => json!({
                    "resultType": "complete", "taskId": asked, "status": "working",
                    "createdAt": "2026-09-08T00:00:00Z", "lastUpdatedAt": "2026-09-08T00:00:00Z",
                    "ttlMs": 900_000,
                }),
                Upstream::Completed => json!({
                    "resultType": "complete", "taskId": asked, "status": "completed",
                    "createdAt": "2026-09-08T00:00:00Z", "lastUpdatedAt": "2026-09-08T00:00:00Z",
                    "ttlMs": 900_000,
                    "result": peer.payload.lock().clone(),
                }),
                Upstream::Failed => json!({
                    "resultType": "complete", "taskId": asked, "status": "failed",
                    "createdAt": "2026-09-08T00:00:00Z", "lastUpdatedAt": "2026-09-08T00:00:00Z",
                    "ttlMs": 900_000,
                    "error": { "code": -32099, "message": "the upstream job failed" },
                }),
            }
        }
        _ => json!({ "resultType": "complete" }),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

pub struct PeerGuard {
    server: tokio::task::JoinHandle<()>,
    pub url: String,
    pub peer: Arc<Peer>,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        self.server.abort();
    }
}

pub async fn serve_peer(initial: Upstream) -> PeerGuard {
    let peer = Arc::new(Peer {
        submissions: AtomicUsize::new(0),
        queries: AtomicUsize::new(0),
        handles_asked: Mutex::new(Vec::new()),
        optin_seen: AtomicUsize::new(0),
        state: Mutex::new(initial),
        payload: Mutex::new(json!({
            "content": [{ "type": "text", "text": MARKER }],
            "structuredContent": { "marker": MARKER },
            "isError": false,
        })),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the synthetic peer binds an ephemeral loopback port");
    let addr = listener
        .local_addr()
        .expect("the bound listener reports its address");
    let app = Router::new()
        .route("/mcp", post(peer_handler))
        .with_state(Arc::clone(&peer));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    PeerGuard {
        server,
        url: format!("http://{addr}/mcp"),
        peer,
    }
}

/// Config knobs one test varies.
pub struct Fixture<'a> {
    /// Filename under the temp root. Named per fixture so a test that writes a
    /// second configuration is visibly writing a different file.
    pub name: &'a str,
    pub port: u16,
    pub backend_url: &'a str,
    /// Names written to `tasks.recovery_adapters`. Empty is the no-adapter
    /// control, whose behaviour must be unchanged.
    pub adapters: Vec<String>,
    /// A `response_contract` that blocks the recovered payload, when set.
    pub forbid_marker: bool,
}

pub fn write_config(root: &Path, fixture: &Fixture<'_>) -> PathBuf {
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = fixture.port;
    config.server.modern_protocol = true;
    config.auth.enabled = false;
    config.capabilities.enabled = false;
    // Counted effects only: a cached answer would make a second read prove
    // nothing about how many times the peer was actually asked.
    config.cache.enabled = false;

    config.tasks.store_dir = root.join("tasks").display().to_string();
    config.tasks.default_ttl_ms = 3_600_000;
    config.tasks.expiry_interval = Duration::from_secs(3_600);
    config.tasks.recovery_adapters.clone_from(&fixture.adapters);

    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: fixture.backend_url.to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
    );

    if fixture.forbid_marker {
        // The SAME configured output policy a live dispatch faces, set through
        // the gateway's own config type rather than appended YAML.
        config.security.response_contract.enabled = true;
        config.security.response_contract.action_mode = true;
        config.security.response_contract.fail_closed = false;
        config.security.response_contract.tools.insert(
            TOOL.to_string(),
            ToolContractConfig {
                max_bytes: None,
                forbidden_patterns: vec![MARKER.to_string()],
                action_mode: Some(true),
            },
        );
    }

    let yaml =
        serde_yaml::to_string(&config).expect("the gateway's own config type serializes to YAML");
    let path = root.join(fixture.name);
    std::fs::write(&path, yaml).expect("the config is written inside the test's own temp root");
    path
}

pub fn store_dir(root: &Path) -> PathBuf {
    root.join("tasks")
}

pub fn free_port() -> u16 {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port can be reserved");
    listener
        .local_addr()
        .expect("the reserved listener reports its address")
        .port()
}

/// Every durable record body, parsed. The store is the assertion surface for
/// the handle/marker/version table.
#[expect(
    dead_code,
    reason = "store assertion surface; no case in this target reads the records yet"
)]
pub fn durable_records(root: &Path) -> Vec<Value> {
    let Ok(entries) = std::fs::read_dir(store_dir(root)) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.starts_with("task-")
                    && Path::new(name)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            })
        })
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .filter_map(|body| serde_json::from_str::<Value>(&body).ok())
        .collect()
}

/// One task's durable record, found by the name the store derives from its id
/// (`store::record_name`) rather than by a pointer into the private snapshot:
/// the filename is a documented invariant, the snapshot's internal shape is not
/// this test's business.
pub fn durable_record(root: &Path, task_id: &str) -> Value {
    let path = store_dir(root).join(format!("{task_id}.json"));
    let body = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the durable record for {task_id} must exist at {}: {error}",
            path.display()
        )
    });
    serde_json::from_str(&body)
        .unwrap_or_else(|error| panic!("the durable record for {task_id} must parse: {error}"))
}

/// The committed status inside the private snapshot
/// (`TaskSnapshot { task: TaskWire { status, .. } }`, `camelCase`, `snake_case`
/// status values).
pub fn record_status(record: &Value) -> Option<&str> {
    record.pointer("/model/task/status").and_then(Value::as_str)
}

pub struct Gateway {
    child: tokio::process::Child,
    log: PathBuf,
    base: String,
}

impl Gateway {
    pub fn start(root: &Path, config: &Path, port: u16, log_name: &str) -> Self {
        Self::start_with_env(root, config, port, log_name, &[])
    }

    /// The same child with additional environment entries, applied AFTER the
    /// `MCP_GATEWAY_*` scrub so a fixture cannot be silently overridden. The
    /// real-SDK vertical uses it for a child-scoped trust anchor
    /// (`SSL_CERT_FILE`); `start` passes an empty slice, so that child is
    /// unchanged by construction.
    pub fn start_with_env(
        root: &Path,
        config: &Path,
        port: u16,
        log_name: &str,
        env: &[(&str, &str)],
    ) -> Self {
        let log = root.join(log_name);
        let out = std::fs::File::create(&log).expect("the child log opens under the temp root");
        let err = out.try_clone().expect("the child log handle clones");

        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
        // Operator config overrides must not replace this child's isolated fixture.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("MCP_GATEWAY_") {
                command.env_remove(key);
            }
        }
        command.env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"));
        for (key, value) in env {
            command.env(key, value);
        }
        let child = command
            .current_dir(root)
            .arg("--config")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .kill_on_drop(true)
            .spawn()
            .expect("the cargo-built mcp-gateway binary spawns");

        Self {
            child,
            log,
            base: format!("http://127.0.0.1:{port}"),
        }
    }

    pub fn logs(&self) -> String {
        let body =
            std::fs::read_to_string(&self.log).unwrap_or_else(|e| format!("<unreadable: {e}>"));
        format!("--- {} ---\n{body}", self.log.display())
    }

    pub async fn wait_until_ready(&mut self, client: &reqwest::Client) {
        let url = format!("{}/health", self.base);
        let ready = async {
            loop {
                if let Some(status) = self.child.try_wait().expect("owned child status") {
                    panic!(
                        "gateway exited before readiness ({status})\n{}",
                        self.logs()
                    );
                }
                if client.get(&url).send().await.is_ok() {
                    return;
                }
                tokio::time::sleep(POLL_GAP).await;
            }
        };
        assert!(
            tokio::time::timeout(READY_BOUND, ready).await.is_ok(),
            "the gateway never answered on {url} within {READY_BOUND:?}\n{}",
            self.logs()
        );
    }

    pub async fn post(&self, client: &reqwest::Client, body: &Value) -> Value {
        self.post_as(client, body, None).await
    }

    /// The same request under a caller's own credential. `None` presents no
    /// `Authorization` header at all — which is what `post` has always sent,
    /// so the auth-disabled synthetic control is unchanged.
    pub async fn post_as(
        &self,
        client: &reqwest::Client,
        body: &Value,
        bearer: Option<&str>,
    ) -> Value {
        let method = body["method"].as_str().unwrap_or_default().to_string();
        let mut request = client
            .post(format!("{}/mcp", self.base))
            .header("content-type", "application/json")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .header("mcp-method", &method);
        if let Some(field) = mcp_gateway::protocol::headers::mcp_name_body_field(&method)
            && let Some(name) = body
                .pointer(&format!("/params/{field}"))
                .and_then(Value::as_str)
        {
            request = request.header("mcp-name", name);
        }
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        let response = request.json(body).send().await.unwrap_or_else(|e| {
            panic!(
                "the gateway did not answer a {method} at all (transport failure: {e})\n{}",
                self.logs()
            )
        });
        let status = response.status();
        let text = response
            .text()
            .await
            .unwrap_or_else(|e| panic!("the answer body did not read: {e}\n{}", self.logs()));
        let mut parsed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("the answer is not JSON ({e}): {text}\n{}", self.logs()));
        parsed["_httpStatus"] = json!(status.as_u16());
        parsed
    }

    /// SIGKILL: the crash the recovery table is about. A graceful stop would
    /// drain the worker and settle the row, which is a different test.
    pub async fn kill(&mut self) {
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(EXIT_BOUND, self.child.wait()).await;
    }

    pub async fn terminate(&mut self) {
        if let Some(pid) = self.child.id() {
            let _ = tokio::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status()
                .await;
        }
        let _ = tokio::time::timeout(EXIT_BOUND, self.child.wait()).await;
    }
}

/// A modern request carrying the extension opt-in and, optionally, a fresh
/// recovery attestation token under the gateway's own namespace.
pub fn modern(id: i64, method: &str, params: Value) -> Value {
    let mut params = params;
    let existing = params.get("_meta").cloned();
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": { TASKS_EXTENSION: {} }
        },
        "io.modelcontextprotocol/clientInfo": { "name": "UpstreamRecoveryClient", "version": "1.0.0" }
    });
    if let Some(Value::Object(extra)) = existing {
        for (key, value) in extra {
            params["_meta"][key] = value;
        }
    }
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

pub fn task_invoke(id: i64, key: &str) -> Value {
    let mut body = modern(
        id,
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": TOOL, "arguments": {} },
            "task": {}
        }),
    );
    body["params"]["_meta"][IDEMPOTENCY_KEY_META] = json!(key);
    body
}

pub fn tasks_get(id: i64, task_id: &str) -> Value {
    modern(id, "tasks/get", json!({ "taskId": task_id }))
}

/// The same read, carrying a fresh attestation token in the namespaced field
/// the addendum defines. Never persisted, never reused.
#[expect(
    dead_code,
    reason = "attested-recovery read fixture; no case in this target drives it yet"
)]
pub fn tasks_get_attested(id: i64, task_id: &str, token: &str) -> Value {
    let mut body = tasks_get(id, task_id);
    body["params"]["_meta"][RECOVERY_META] = json!({ "attestation": token });
    body
}

pub fn task_id_of(created: &Value) -> String {
    created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("a task-augmented call must be answered with a handle: {created}")
        })
        .to_string()
}

pub fn status_of(body: &Value) -> Option<&str> {
    body.pointer("/result/status").and_then(Value::as_str)
}
