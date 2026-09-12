// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real gateway/backend fixture shared by signing and response-firewall tests.
//!
//! No AppState or signer is installed by this fixture: the shipped binary reads
//! its isolated YAML and runs its production constructor.

use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

pub const BACKEND: &str = "signing_fixture";
pub const TOOL: &str = "echo";
pub const KEY: &str = "signing-test-current-key-0123456789abcdef";
const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub struct BackendFixture {
    pub url: String,
    received: Arc<Mutex<Vec<BackendRequest>>>,
    result: Arc<RwLock<Value>>,
    tools: Arc<RwLock<Value>>,
    task: JoinHandle<()>,
}

struct BackendRequest {
    body: Value,
}

impl BackendFixture {
    pub async fn start(result: Value) -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let result = Arc::new(RwLock::new(result));
        let tools = Arc::new(RwLock::new(json!({"tools": [{
            "name": TOOL,
            "description": "returns the configured test result",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": true}
        }]})));
        let app_received = Arc::clone(&received);
        let app_result = Arc::clone(&result);
        let app_tools = Arc::clone(&tools);
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
                let received = Arc::clone(&app_received);
                let result = Arc::clone(&app_result);
                let tools = Arc::clone(&app_tools);
                async move {
                    received
                        .lock()
                        .expect("backend recorder")
                        .push(BackendRequest {
                            body: request.clone(),
                        });
                    let id = request.get("id").cloned().unwrap_or(Value::Null);
                    let response = match request.get("method").and_then(Value::as_str) {
                        Some("initialize") => json!({"jsonrpc": "2.0", "id": id, "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": BACKEND, "version": "test"}
                        }}),
                        Some("tools/list") => json!({"jsonrpc": "2.0", "id": id,
                            "result": tools.read().expect("backend tools").clone()}),
                        Some("tools/call") => json!({"jsonrpc": "2.0", "id": id,
                            "result": result.read().expect("backend result").clone()}),
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
            result,
            tools,
            task,
        }
    }

    pub fn calls(&self) -> Vec<Value> {
        self.received
            .lock()
            .expect("backend recorder")
            .iter()
            .filter(|request| request.body["method"] == "tools/call")
            .map(|request| request.body.clone())
            .collect()
    }

    pub fn set_result(&self, result: Value) {
        *self.result.write().expect("backend result") = result;
    }

    pub fn set_tools(&self, tools: Value) {
        *self.tools.write().expect("backend tools") = tools;
    }
}

impl Drop for BackendFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn fixture_config(backend_url: &str) -> Value {
    json!({
        "server": {"host": "127.0.0.1", "modern_protocol": true},
        "cache": {"enabled": false},
        "backends": {(BACKEND): {"http_url": backend_url, "streamable_http": true}},
        "security": {
            "trust_configured_backends": true,
            "message_signing": {"enabled": true, "shared_secret": KEY,
                "key_id": "signing-test-current", "require_nonce": true, "replay_window": 300}
        }
    })
}

pub fn child_command(directory: &Path, config_path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
    command
        .env_clear()
        .env("HOME", directory)
        .env("XDG_CONFIG_HOME", directory.join(".config"))
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .current_dir(directory)
        .arg("--config")
        .arg(config_path)
        .arg("serve")
        .kill_on_drop(true);
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    command
}

pub struct HttpGateway {
    child: Child,
    directory: TempDir,
    pub url: String,
    pub client: reqwest::Client,
}

impl HttpGateway {
    pub async fn start(config: Value) -> Self {
        Self::start_with_env(config, &[]).await
    }

    /// Run the production CLI with explicit child-local fixture environment.
    /// Overrides follow env_clear; they never change the test runner's process.
    pub async fn start_with_env(config: Value, env: &[(&str, &std::ffi::OsStr)]) -> Self {
        let mut config = config;
        let directory = tempfile::tempdir().expect("gateway directory");
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve port");
        let port = reservation.local_addr().expect("reserved address").port();
        config["server"]["port"] = json!(port);
        let config_path = directory.path().join("gateway.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config YAML"),
        )
        .expect("write gateway config");
        let log = std::fs::File::create(directory.path().join("gateway.log")).expect("gateway log");
        let mut command = child_command(directory.path(), &config_path);
        command.envs(env.iter().copied());
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("clone gateway log")))
            .stderr(Stdio::from(log));
        drop(reservation);
        let child = command.spawn().expect("spawn real HTTP gateway");
        let mut gateway = Self {
            child,
            directory,
            url: format!("http://127.0.0.1:{port}"),
            client: reqwest::Client::builder()
                .timeout(IO_TIMEOUT)
                .build()
                .expect("HTTP client"),
        };
        let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
        loop {
            if let Some(status) = gateway.child.try_wait().expect("gateway process status") {
                panic!(
                    "gateway startup fixture exited {status}: {}",
                    gateway.logs()
                );
            }
            if gateway
                .client
                .get(format!("{}/health", gateway.url))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "gateway readiness fixture timed out: {}",
                gateway.logs()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        gateway
    }

    pub fn logs(&self) -> String {
        std::fs::read_to_string(self.directory.path().join("gateway.log")).unwrap_or_default()
    }

    pub async fn initialize(&self) -> String {
        let response = self
            .client
            .post(format!("{}/mcp", self.url))
            .json(&json!({
                "jsonrpc": "2.0", "id": "fixture-initialize", "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "signing-fixture", "version": "test"}
                }
            }))
            .send()
            .await
            .expect("initialize HTTP");
        let session = response
            .headers()
            .get("mcp-session-id")
            .expect("legacy session header")
            .to_str()
            .expect("session header text")
            .to_owned();
        let body: Value = response.json().await.expect("initialize JSON");
        assert!(
            body.get("result").is_some(),
            "initialize fixture refused: {body}"
        );
        session
    }

    pub async fn call(&self, session: &str, request: &Value) -> Value {
        let response = self
            .client
            .post(format!("{}/mcp", self.url))
            .header("mcp-session-id", session)
            .json(request)
            .send()
            .await
            .expect("gateway HTTP response");
        let status = response.status();
        let body = response.text().await.expect("gateway response body");
        serde_json::from_str(&body).unwrap_or_else(|error| {
            panic!(
                "gateway JSON response ({status}): {error}; body={body}; logs={}",
                self.logs()
            )
        })
    }
}

pub fn invoke(id: Value, nonce: Value, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": "gateway_invoke", "arguments": {
            "server": BACKEND, "tool": TOOL, "arguments": arguments, "nonce": nonce
        }
    }})
}
