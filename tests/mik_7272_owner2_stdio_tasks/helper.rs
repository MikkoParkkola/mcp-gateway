// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Owned fixtures for MIK-7272.OWNER.2 (I4): a counting backend, the shipped
//! binary over stdio and over HTTP, and the modern task vocabulary.
//!
//! Test plan: `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md` (I4).
//! Every row drives the binary through its config and JSON-RPC, never a
//! crate item, so the red commit compiles before the fix exists.

#![allow(
    dead_code,
    reason = "shared by two test targets that each use a subset"
)]

#[path = "../common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Json;
use mcp_gateway::config::{ApiKeyConfig, ApiKeyKind, BackendConfig, Config, TransportConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::watch;

pub const BACKEND: &str = "fixture";
/// Answers at once with [`MARKER`].
pub const ECHO: &str = "echo";
/// Reports arrival, then waits until the test opens the barrier.
pub const HELD: &str = "held";
/// Answers `input_required` once, then [`ANSWERED`] once the round is answered.
pub const ASK: &str = "ask";
pub const MARKER: &str = "owner2-marker";
pub const ANSWERED: &str = "owner2-answered";
pub const PROTOCOL_VERSION: &str = "2026-07-28";
pub const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";
pub const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";
pub const API_KEY: &str = "owner2-test-key-0123456789abcdef";
/// Every wait for a frame, an exit or readiness.
pub const BOUND: Duration = Duration::from_secs(10);
const POLL_GAP: Duration = Duration::from_millis(50);
const STALL_SLACK: Duration = Duration::from_secs(3);
const TICK: Duration = Duration::from_millis(250);

/// `fut`'s output, or `None` once it has had [`BOUND`] of unstalled time.
pub async fn bound<F: std::future::Future>(fut: F) -> Option<F::Output> {
    tokio::pin!(fut);
    let mut left = BOUND;
    let mut last = tokio::time::Instant::now();
    loop {
        tokio::select! {
            biased;
            () = tokio::time::sleep(TICK) => {
                // A gap between two looks far longer than a look takes means
                // the whole machine stood still (a paused VM, a starved
                // runner): the clock ran, the gateway could not, and that gap
                // is not charged (MIK-7808). A slow answer is charged in full.
                let gap = last.elapsed();
                last = tokio::time::Instant::now();
                if gap <= TICK + STALL_SLACK {
                    left = left.saturating_sub(gap);
                }
                if left.is_zero() {
                    return None;
                }
            }
            out = &mut fut => return Some(out),
        }
    }
}

/// The fixture backend, served in the test process so its counters and the
/// `held` barrier are directly observable.
pub struct Backend {
    pub url: String,
    /// `tools/call` rounds received, of any tool.
    pub rounds: Arc<AtomicUsize>,
    /// Bumped when a `held` call arrives.
    arrived: watch::Receiver<usize>,
    release: watch::Sender<bool>,
}

impl Backend {
    pub async fn start() -> Self {
        let rounds = Arc::new(AtomicUsize::new(0));
        let (arrived_tx, arrived) = watch::channel(0_usize);
        let (release, release_rx) = watch::channel(false);
        let arrived_tx = Arc::new(arrived_tx);
        let app = {
            let rounds = Arc::clone(&rounds);
            axum::Router::new().route(
                "/",
                axum::routing::post(move |Json(request): Json<Value>| {
                    let rounds = Arc::clone(&rounds);
                    let arrived = Arc::clone(&arrived_tx);
                    let mut release = release_rx.clone();
                    async move { Json(answer(&request, &rounds, &arrived, &mut release).await) }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture backend");
        let address = listener.local_addr().expect("fixture address");
        tokio::spawn(async move { drop(axum::serve(listener, app).await) });
        Self {
            url: format!("http://{address}/"),
            rounds,
            arrived,
            release,
        }
    }

    pub fn rounds(&self) -> usize {
        self.rounds.load(Ordering::SeqCst)
    }

    /// Wait until `count` `held` calls have arrived.
    pub async fn wait_arrivals(&mut self, count: usize) {
        bound(self.arrived.wait_for(|seen| *seen >= count))
            .await
            .expect("the held call reaches the backend within the bound")
            .expect("the fixture is alive");
    }

    pub fn open_barrier(&self) {
        self.release.send_modify(|open| *open = true);
    }
}

async fn answer(
    request: &Value,
    rounds: &AtomicUsize,
    arrived: &watch::Sender<usize>,
    release: &mut watch::Receiver<bool>,
) -> Value {
    let tool = request.pointer("/params/name").and_then(Value::as_str);
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": BACKEND, "version": "0"},
        }),
        Some("tools/list") => {
            let tools: Vec<Value> = [ECHO, HELD, ASK]
                .into_iter()
                .map(|name| {
                    json!({
                        "name": name,
                        "description": "owner2 fixture tool",
                        "inputSchema": {"type": "object"},
                    })
                })
                .collect();
            json!({ "tools": tools })
        }
        Some("tools/call") => {
            rounds.fetch_add(1, Ordering::SeqCst);
            match tool {
                Some(HELD) => {
                    arrived.send_modify(|seen| *seen += 1);
                    drop(release.wait_for(|open| *open).await);
                    done(MARKER)
                }
                Some(ASK) if request.pointer("/params/inputResponses").is_some() => done(ANSWERED),
                Some(ASK) => json!({
                    "resultType": "input_required",
                    "inputRequests": {"confirm": {
                        "method": "elicitation/create",
                        "params": {"mode": "form", "message": "Go on?",
                            "requestedSchema": {"type": "object", "properties": {}}},
                    }},
                    "requestState": "owner2-state",
                }),
                _ => done(MARKER),
            }
        }
        _ => json!({}),
    };
    json!({"jsonrpc": "2.0", "id": request.get("id").cloned(), "result": result})
}

fn done(marker: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": marker}],
        "structuredContent": {"marker": marker},
        "isError": false,
    })
}

/// How a config's HTTP side authenticates.
#[derive(Clone, Copy)]
pub enum Auth {
    Off,
    /// One shared API key, [`API_KEY`].
    Key,
}

/// Write `<root>/<name>` for one gateway: port 0, modern on, the response
/// cache off (counted effects only), and `tasks.store_dir` = `store_dir`.
pub fn write_config(
    root: &Path,
    name: &str,
    store_dir: &Path,
    backend: &str,
    auth: Auth,
) -> PathBuf {
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = 0;
    config.server.modern_protocol = true;
    config.capabilities.enabled = false;
    config.cache.enabled = false;
    config.tasks.store_dir = store_dir.display().to_string();
    config.tasks.default_ttl_ms = 3_600_000;
    config.tasks.expiry_interval = Duration::from_secs(3_600);
    config.auth.enabled = matches!(auth, Auth::Key);
    if matches!(auth, Auth::Key) {
        // Auth on requires an audit log (UPGRADING-4.0 item 43), and the
        // readiness probe reads `/health` without a credential.
        config.auth.public_paths = vec!["/health".to_string()];
        config.security.transparency_log.enabled = true;
        config.security.transparency_log.path = root
            .join(format!("audit-{name}"))
            .join("log.jsonl")
            .to_string_lossy()
            .into_owned();
        config.auth.api_keys.push(ApiKeyConfig {
            key: None,
            key_sha256: Some(mcp_gateway::config::api_key_digest_spec(API_KEY.as_bytes())),
            expires_at: None,
            name: "owner2".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: ApiKeyKind::Shared,
        });
    }
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: backend.to_string(),
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout: Duration::from_secs(30),
            ..BackendConfig::default()
        },
    );
    let yaml = serde_yaml::to_string(&config).expect("config serializes");
    let path = root.join(name);
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    path
}

/// A modern request: the era and the client's capabilities ride in `_meta`.
/// `tasks` decides whether the client declares the Tasks extension.
pub fn modern(id: Value, method: &str, mut params: Value, tasks: bool) -> Value {
    let extensions = if tasks {
        json!({TASKS_EXTENSION: {}})
    } else {
        json!({})
    };
    let carried = params.get("_meta").cloned();
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {"extensions": extensions, "elicitation": {}},
        "io.modelcontextprotocol/clientInfo": {"name": "owner2", "version": "1.0.0"},
    });
    if let Some(Value::Object(extra)) = carried {
        for (key, value) in extra {
            params["_meta"][key] = value;
        }
    }
    let mut request = json!({"jsonrpc": "2.0", "method": method, "params": params});
    request["id"] = id;
    request
}

/// The modern handshake, declaring the Tasks extension.
pub fn initialize(id: Value) -> Value {
    modern(
        id,
        "initialize",
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "clientInfo": {"name": "owner2", "version": "1.0.0"},
            "capabilities": {},
        }),
        true,
    )
}

/// A task-augmented `gateway_invoke` of `tool`, keyed `key` when set.
pub fn task_call(id: Value, tool: &str, key: Option<&str>) -> Value {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": tool, "arguments": {}},
        "task": {},
    });
    if let Some(key) = key {
        params["_meta"] = json!({IDEMPOTENCY_KEY_META: key});
    }
    modern(id, "tools/call", params, true)
}

/// The same call without the `task` member: the synchronous path.
pub fn sync_call(id: Value, tool: &str, key: &str) -> Value {
    modern(
        id,
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": tool, "arguments": {}},
            "_meta": {IDEMPOTENCY_KEY_META: key},
        }),
        true,
    )
}

pub fn tasks_get(id: Value, task: &str) -> Value {
    modern(id, "tasks/get", json!({"taskId": task}), true)
}

pub fn tasks_cancel(id: Value, task: &str) -> Value {
    modern(id, "tasks/cancel", json!({"taskId": task}), true)
}

pub fn tasks_update(id: Value, task: &str) -> Value {
    modern(
        id,
        "tasks/update",
        json!({"taskId": task, "inputResponses": {"confirm": {"action": "accept", "content": {}}}}),
        true,
    )
}

pub fn discover(id: Value) -> Value {
    let mut request = json!({"jsonrpc": "2.0", "method": "server/discover", "params": {}});
    request["id"] = id;
    request
}

/// The `taskId` of a create-task answer, or a failed assertion naming what
/// came back instead.
pub fn task_id(created: &Value) -> String {
    assert_eq!(
        created
            .pointer("/result/resultType")
            .and_then(Value::as_str),
        Some("task"),
        "a task-augmented call is answered with a task handle: {created}"
    );
    created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .expect("the handle carries a taskId")
        .to_owned()
}

pub fn status(task: &Value) -> Option<&str> {
    task.pointer("/result/status").and_then(Value::as_str)
}

pub fn error_code(answer: &Value) -> Option<i64> {
    answer.pointer("/error/code").and_then(Value::as_i64)
}

/// Whether an answer (initialize or discover) declares the Tasks extension
/// under `capabilities.extensions`, read structurally.
pub fn declares_tasks(answer: &Value) -> bool {
    answer
        .pointer("/result/capabilities/extensions")
        .and_then(Value::as_object)
        .is_some_and(|extensions| extensions.contains_key(TASKS_EXTENSION))
}

/// The shipped binary over stdio, with an explicit config.
pub struct StdioGateway {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
    log: PathBuf,
}

impl StdioGateway {
    pub fn spawn(root: &Path, config: &Path, log_name: &str) -> Self {
        let log = root.join(log_name);
        let err = std::fs::File::create(&log).expect("stdio child log");
        let mut command = tokio::process::Command::from(gateway_bin::command(
            root,
            gateway_bin::Inherit::Environment,
        ));
        let mut child = command
            .current_dir(root)
            .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
            .arg("--config")
            .arg(config)
            .arg("serve")
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(err))
            .kill_on_drop(true)
            .spawn()
            .expect("spawn the gateway over stdio");
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().expect("child stdout")).lines();
        Self {
            child,
            stdin,
            stdout,
            log,
        }
    }

    pub fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    pub async fn send(&mut self, request: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        stdin
            .write_all(format!("{request}\n").as_bytes())
            .await
            .expect("write to the gateway");
        stdin.flush().await.expect("flush");
    }

    /// The next response (not a request or notification) answering `id`, or
    /// `None` if none arrives within [`BOUND`] of unstalled time.
    pub async fn try_answer(&mut self, id: &Value) -> Option<Value> {
        let stdout = &mut self.stdout;
        bound(async {
            loop {
                let line = stdout.next_line().await.ok()??;
                let Ok(frame) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if frame.get("method").is_none() && frame.get("id") == Some(id) {
                    return Some(frame);
                }
            }
        })
        .await
        .flatten()
    }

    pub async fn request(&mut self, request: &Value) -> Value {
        self.send(request).await;
        let id = request["id"].clone();
        self.try_answer(&id)
            .await
            .unwrap_or_else(|| panic!("no answer to {request} within {BOUND:?}\n{}", self.logs()))
    }

    /// `tasks/get` until the task is terminal.
    pub async fn terminal(&mut self, task: &str) -> Value {
        let polled = bound(async {
            let mut n = 0;
            loop {
                n += 1;
                let got = self
                    .request(&tasks_get(json!(format!("poll-{n}")), task))
                    .await;
                if matches!(status(&got), Some("completed" | "failed" | "cancelled")) {
                    return got;
                }
                tokio::time::sleep(POLL_GAP).await;
            }
        })
        .await;
        polled.unwrap_or_else(|| panic!("task {task} is not terminal within {BOUND:?}"))
    }

    /// Close stdin and wait for a clean exit.
    pub async fn close(mut self) {
        drop(self.stdin.take());
        let status = bound(self.child.wait())
            .await
            .expect("the stdio gateway exits after EOF within the bound")
            .expect("child status");
        assert!(
            status.success(),
            "clean exit after EOF ({status})\n{}",
            self.logs()
        );
    }

    /// SIGKILL: no drain, no store close.
    pub async fn kill(mut self) {
        self.child.kill().await.expect("kill the stdio gateway");
    }
}

/// The shipped binary over HTTP. Start pattern copied from
/// `tests/task_upstream_recovery/helper.rs` (`Gateway::start`), not shared.
pub struct HttpGateway {
    child: Child,
    log: PathBuf,
    base: String,
}

impl HttpGateway {
    pub fn spawn(root: &Path, config: &Path, log_name: &str) -> Self {
        let log = root.join(log_name);
        let out = std::fs::File::create(&log).expect("http child log");
        let err = out.try_clone().expect("log handle clones");
        let mut command = tokio::process::Command::from(gateway_bin::command(
            root,
            gateway_bin::Inherit::Environment,
        ));
        command.env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state-http"));
        let child = command
            .current_dir(root)
            .arg("--config")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .kill_on_drop(true)
            .spawn()
            .expect("spawn the gateway over HTTP");
        Self {
            child,
            log,
            base: String::new(),
        }
    }

    pub fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Start and wait for `/health`, or panic with the child's log.
    pub async fn start(root: &Path, config: &Path, log_name: &str) -> Self {
        let mut gateway = Self::spawn(root, config, log_name);
        let client = reqwest::Client::new();
        let ready = bound(async {
            loop {
                if let Some(status) = gateway.child.try_wait().expect("child status") {
                    panic!(
                        "HTTP gateway exited before readiness ({status})\n{}",
                        gateway.logs()
                    );
                }
                if gateway.base.is_empty()
                    && let Some(port) = bound_port(&gateway.logs())
                {
                    gateway.base = format!("http://127.0.0.1:{port}");
                }
                if !gateway.base.is_empty()
                    && let Ok(response) =
                        client.get(format!("{}/health", gateway.base)).send().await
                    && let Ok(body) = response.json::<Value>().await
                    && body["version"] == env!("CARGO_PKG_VERSION")
                {
                    return;
                }
                tokio::time::sleep(POLL_GAP).await;
            }
        })
        .await;
        assert!(
            ready.is_some(),
            "HTTP gateway not ready within {BOUND:?}\n{}",
            gateway.logs()
        );
        gateway
    }

    /// Whether the child exits on its own within [`BOUND`] instead of
    /// serving, with its log either way.
    pub async fn exits_instead_of_serving(mut self) -> (Option<std::process::ExitStatus>, String) {
        let status = bound(self.child.wait())
            .await
            .map(|status| status.expect("child status"));
        (status, self.logs())
    }

    pub async fn post(&self, body: &Value, bearer: Option<&str>) -> Value {
        let method = body["method"].as_str().unwrap_or_default().to_string();
        let mut request = reqwest::Client::new()
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
        if let Some(key) = bearer {
            request = request.header("authorization", format!("Bearer {key}"));
        }
        let response = request.json(body).send().await.expect("POST /mcp");
        response.json::<Value>().await.unwrap_or(Value::Null)
    }

    pub async fn stop(mut self) {
        self.child.kill().await.expect("stop the HTTP gateway");
    }
}

/// The port from the last complete `Listening` banner line.
fn bound_port(log: &str) -> Option<u16> {
    let complete = &log[..=log.rfind('\n')?];
    complete.lines().rev().find_map(|line| {
        let plain: String = strip_ansi(line);
        let (_, fields) = plain.split_once("server::support: Listening ")?;
        fields
            .split_whitespace()
            .find_map(|field| field.strip_prefix("port=")?.parse().ok())
    })
}

fn strip_ansi(line: &str) -> String {
    let mut plain = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
}

/// The `task-*.json` record names directly under `dir`.
pub fn record_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| {
            name.starts_with("task-")
                && Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .collect();
    names.sort();
    names
}
