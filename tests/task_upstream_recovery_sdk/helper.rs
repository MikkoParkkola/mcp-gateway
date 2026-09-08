// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Owned gateway children, temporary config, and durable-record helpers for
//! the real pinned-SDK upstream-recovery vertical.
//!
//! The peer is `peer.rs` (pinned FastMCP + Docket). Nothing here is a
//! synthetic upstream: process, config, store and JSON plumbing only,
//! copied from the proven synthetic-journey helper this target used to
//! import.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
use serde_json::{Value, json};

pub const PROTOCOL_VERSION: &str = "2026-07-28";
const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";
pub const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";

pub const BACKEND: &str = "upstream";

const READY_BOUND: Duration = Duration::from_secs(60);
const EXIT_BOUND: Duration = Duration::from_secs(90);
const POLL_GAP: Duration = Duration::from_millis(25);

/// Config knobs one test varies.
pub struct Fixture<'a> {
    /// Filename under the temp root. Named per fixture so a test that writes a
    /// second configuration is visibly writing a different file.
    pub name: &'a str,
    pub port: u16,
    pub backend_url: &'a str,
    /// Names written to `tasks.recovery_adapters`.
    pub adapters: Vec<String>,
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
    config.tasks.recovery_adapters = fixture.adapters.clone();

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
/// (`TaskSnapshot { task: TaskWire { status, .. } }`, camelCase, snake_case
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
    /// Spawn the cargo-built gateway child with additional environment entries,
    /// applied AFTER the `MCP_GATEWAY_*` scrub so a fixture cannot be silently
    /// overridden. The real-SDK vertical uses it for a child-scoped trust
    /// anchor (`SSL_CERT_FILE`).
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
        if tokio::time::timeout(READY_BOUND, ready).await.is_err() {
            panic!(
                "the gateway never answered on {url} within {READY_BOUND:?}\n{}",
                self.logs()
            );
        }
    }

    /// Request under a caller's own credential. `None` presents no
    /// `Authorization` header at all — the uncredentialed 401 this journey
    /// asserts before any owner speaks.
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

/// A modern request carrying the extension opt-in.
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

pub fn tasks_get(id: i64, task_id: &str) -> Value {
    modern(id, "tasks/get", json!({ "taskId": task_id }))
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
