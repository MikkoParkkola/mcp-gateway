// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Bounded HTTP/backend fixtures and owned gateway child processes.

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
use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
use serde_json::{Value, json};

pub const READY_BOUND: Duration = Duration::from_secs(60);

pub const EXIT_BOUND: Duration = Duration::from_secs(90);

pub const COMPLETION_BOUND: Duration = Duration::from_secs(30);

pub const TTL_MS: u64 = 10_000;

pub const EXPIRY_INTERVAL: Duration = Duration::from_secs(1);

pub const EXPIRY_BOUND: Duration = Duration::from_millis(TTL_MS + 30_000);

pub const POLL_GAP: Duration = Duration::from_millis(25);

pub const BACKEND: &str = "mock";
pub const TOOL: &str = "echo";
pub const MARKER: &str = "task-expiry-backend-answered";

pub struct CountedBackend {
    calls: AtomicUsize,
}

impl CountedBackend {
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub async fn wait_for_calls(&self, expected: usize) {
        let observe = async {
            loop {
                if self.calls() >= expected {
                    return;
                }
                tokio::time::sleep(POLL_GAP).await;
            }
        };
        assert!(
            tokio::time::timeout(READY_BOUND, observe).await.is_ok(),
            "the backend saw {} dispatch(es) within {READY_BOUND:?}, expected {expected}",
            self.calls()
        );
        assert_eq!(
            self.calls(),
            expected,
            "the backend must be dispatched to exactly {expected} time(s)"
        );
    }

    fn result() -> Value {
        json!({
            "content": [{ "type": "text", "text": MARKER }],
            "structuredContent": { "marker": MARKER }
        })
    }
}

pub struct BackendGuard {
    server: tokio::task::JoinHandle<()>,
    pub url: String,
    pub backend: Arc<CountedBackend>,
}

impl Drop for BackendGuard {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn mcp_handler(
    State(backend): State<Arc<CountedBackend>>,
    Json(body): Json<Value>,
) -> Response {
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let Some(id) = body.get("id").filter(|id| !id.is_null()).cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };

    let result = match method.as_str() {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": BACKEND, "version": "0" }
        }),
        "tools/list" => json!({
            "tools": [{
                "name": TOOL,
                "description": "Returns a fixed marker; reads and mutates nothing.",
                "inputSchema": { "type": "object", "properties": {} },
                "annotations": {
                    "title": "Echo",
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                }
            }]
        }),
        "tools/call" => {
            backend.calls.fetch_add(1, Ordering::SeqCst);
            CountedBackend::result()
        }
        _ => json!({}),
    };

    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

pub async fn serve_backend() -> BackendGuard {
    let backend = Arc::new(CountedBackend {
        calls: AtomicUsize::new(0),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the mock backend binds an ephemeral loopback port");
    let addr = listener
        .local_addr()
        .expect("the bound listener reports its address");
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(Arc::clone(&backend));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    BackendGuard {
        server,
        url: format!("http://{addr}/mcp"),
        backend,
    }
}

pub fn write_config(root: &Path, port: u16, backend_url: &str) -> PathBuf {
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = port;
    config.server.modern_protocol = true;
    config.auth.enabled = false;
    config.capabilities.enabled = false;
    config.cache.enabled = false;

    config.tasks.store_dir = root.join("tasks").display().to_string();
    config.tasks.default_ttl_ms = TTL_MS;
    config.tasks.expiry_interval = EXPIRY_INTERVAL;

    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: backend_url.to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
    );

    let path = root.join("gateway.yaml");
    std::fs::write(
        &path,
        serde_yaml::to_string(&config).expect("the gateway's own config type serializes to YAML"),
    )
    .expect("the config is written inside the test's own temp root");
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

pub fn durable_records(root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(store_dir(root)) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| {
            name.starts_with("task-")
                && Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .collect()
}

pub struct Gateway {
    child: tokio::process::Child,
    log: PathBuf,
    base: String,
}

impl Gateway {
    pub fn start(root: &Path, config: &Path, port: u16, log_name: &str) -> Self {
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
        let child = command
            .current_dir(root)
            .arg("--config")
            .arg(config)
            .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
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

    fn pid(&self) -> u32 {
        self.child.id().unwrap_or_else(|| {
            panic!(
                "the child exited before it could be signalled\n{}",
                self.logs()
            )
        })
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
        let response = request.json(body).send().await.unwrap_or_else(|e| {
            panic!(
                "the gateway did not answer a {method} at all (transport failure: {e}) — \
                 this is a child that is not listening, NOT a task that is absent\n{}",
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

    pub async fn terminate(&mut self) -> std::process::ExitStatus {
        let pid = self.pid();
        let signalled = tokio::process::Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()
            .await
            .expect("kill(1) runs");
        assert!(
            signalled.success(),
            "SIGTERM was not delivered to the owned pid {pid}\n{}",
            self.logs()
        );

        match tokio::time::timeout(EXIT_BOUND, self.child.wait()).await {
            Ok(status) => status.expect("the owned child is waitable"),
            Err(elapsed) => panic!(
                "pid {pid} did not exit within {EXIT_BOUND:?} of SIGTERM ({elapsed}): the \
                 graceful shutdown never completed, so the store lease is still held\n{}",
                self.logs()
            ),
        }
    }
}

pub const PROTOCOL_VERSION: &str = "2026-07-28";
pub const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";
pub const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";

pub fn modern(id: i64, method: &str, params: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": { TASKS_EXTENSION: {} }
        },
        "io.modelcontextprotocol/clientInfo": { "name": "ExpiryLifecycleClient", "version": "1.0.0" }
    });
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
