// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shipped binary under an events config, restartable on one store.

#[path = "../common/gateway_bin.rs"]
pub(crate) mod gateway_bin;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::process::{Child, Command};

const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// API keys: alice and carol may reach the capability backend `hooks`, bob may not.
pub const ALICE: &str = "events-test-alice-key-0123456789abcdef";
pub const BOB: &str = "events-test-bob-key-0123456789abcdef00";
pub const CAROL: &str = "events-test-carol-key-0123456789abcdef";
/// An API key with admin standing (the dead-letter routes) and no backend a
/// subscription could use.
pub const ADMIN: &str = "events-test-admin-key-0123456789abcdef0";
pub const EVENT: &str = "webhook.github.push.received";

/// A webhook-only capability whose `push` route opts into an MCP event.
pub const GITHUB_CAPABILITY: &str = r#"
name: github
description: GitHub push webhooks
schema:
  input: { type: object, properties: {} }
  output: { type: object }
providers: {}
webhooks:
  push:
    path: /github/push
    method: POST
    transform:
      event_type: "github.{action}"
      data: { repo: "{repository.full_name}", ref: "{ref}" }
    event:
      description: "A push to a repository the gateway receives webhooks for."
      filters: [repo, ref]
      delivery_id_header: X-GitHub-Delivery
"#;

fn key(name: &str, key: &str, backends: &[&str]) -> Value {
    json!({
        "name": name,
        "key_sha256": mcp_gateway::config::api_key_digest_spec(key.as_bytes()),
        "backends": backends,
    })
}

fn admin_key(name: &str, key_text: &str, backends: &[&str]) -> Value {
    let mut admin = key(name, key_text, backends);
    admin["admin"] = json!(true);
    admin
}

/// A config with auth on, the `github` capability under backend `hooks`, and
/// `events` merged over the supplied object.
pub fn config(root: &Path, events: &Value) -> Value {
    let caps = root.join("caps");
    std::fs::create_dir_all(&caps).expect("capability dir");
    std::fs::write(caps.join("github.yaml"), GITHUB_CAPABILITY).expect("capability file");
    let mut events_section = json!({
        "enabled": true,
        "store_dir": root.join("events").to_string_lossy(),
    });
    if let Some(extra) = events.as_object() {
        for (k, v) in extra {
            events_section[k] = v.clone();
        }
    }
    json!({
        "server": {"host": "127.0.0.1", "modern_protocol": true, "port": 0},
        "cache": {"enabled": false},
        "tasks": {"store_dir": "tasks"},
        "auth": {"enabled": true, "api_keys": [
            key("alice", ALICE, &["hooks"]),
            key("bob", BOB, &["other"]),
            key("carol", CAROL, &["hooks"]),
            admin_key("admin", ADMIN, &["admin-only"]),
        ]},
        "capabilities": {"enabled": true, "name": "hooks",
            "directories": [caps.to_string_lossy()]},
        "webhooks": {"enabled": true, "require_signature": false},
        // Auth on requires an audit log (UPGRADING-4.0 §43).
        "security": {"transparency_log": {"enabled": true, "path": "audit.jsonl"}},
        "events": events_section,
    })
}

/// One gateway child. `restart` keeps the directory, so the store survives.
pub struct Gateway {
    child: Option<Child>,
    root: PathBuf,
    config: Value,
    env: Vec<(String, String)>,
    runs: u32,
    pub url: String,
    pub client: reqwest::Client,
}

/// Under coverage, end the child with SIGTERM and give it 10 s to drain, so an
/// instrumented build writes its profile at exit; a SIGKILL would lose it.
/// `kill_on_drop` stays the backstop. `stop` and `restart` keep their SIGKILL:
/// rows use them to simulate a crash.
// ponytail: this blocks the test's runtime for up to 10 s, so on a
// current-thread runtime an in-process mock cannot answer the draining child;
// that child is then SIGKILLed and its profile lost. Coverage-only, and the
// measured startup row clears its floor anyway; move rows that hold mocks to a
// multi-thread runtime if a profile proves to matter.
#[cfg(unix)]
impl Drop for Gateway {
    fn drop(&mut self) {
        if std::env::var_os("LLVM_PROFILE_FILE").is_none() {
            return;
        }
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let Some(pid) = child.id() else {
            return;
        };
        let Some(pid) = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        else {
            return;
        };
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Gateway {
    pub async fn start(root: &Path, config: Value) -> Self {
        Self::start_with_env(root, config, &[]).await
    }

    pub async fn start_with_env(root: &Path, config: Value, env: &[(&str, &str)]) -> Self {
        let mut gateway = Self {
            child: None,
            root: root.to_path_buf(),
            config,
            env: env
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            runs: 0,
            url: String::new(),
            client: reqwest::Client::builder()
                .timeout(IO_TIMEOUT)
                .build()
                .expect("HTTP client"),
        };
        gateway.spawn().await;
        gateway
    }

    fn log_path(&self) -> PathBuf {
        self.root.join(format!("gateway-{}.log", self.runs))
    }

    pub fn logs(&self) -> String {
        std::fs::read_to_string(self.log_path()).unwrap_or_default()
    }

    /// What a row that missed its deadline prints: every gateway log line, so
    /// a stall names its cause (MIK-7891).
    pub fn stall_report(&self) -> String {
        use std::fmt::Write as _;
        (1..=self.runs).fold(String::new(), |mut out, n| {
            let log = std::fs::read_to_string(self.root.join(format!("gateway-{n}.log")))
                .unwrap_or_default();
            let _ = write!(out, "--- gateway run {n} ---\n{log}");
            out
        })
    }

    /// Every log line this directory's children wrote, across restarts.
    pub fn all_logs(&self) -> String {
        (1..=self.runs)
            .map(|n| {
                std::fs::read_to_string(self.root.join(format!("gateway-{n}.log")))
                    .unwrap_or_default()
            })
            .collect()
    }

    async fn spawn(&mut self) {
        self.runs += 1;
        let config_path = self.root.join("gateway.yaml");
        mcp_gateway::gateway::test_helpers::write_owner_only(
            &config_path,
            serde_yaml::to_string(&self.config).expect("config YAML"),
        )
        .expect("write gateway config");
        let log = std::fs::File::create(self.log_path()).expect("gateway log");
        let mut command = Command::from(gateway_bin::command(
            &self.root,
            gateway_bin::Inherit::Nothing,
        ));
        command
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .envs(gateway_bin::checked_env(
                self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            ))
            .current_dir(&self.root)
            .arg("--config")
            .arg(&config_path)
            .arg("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .kill_on_drop(true);
        self.child = Some(command.spawn().expect("spawn gateway"));
        self.url.clear();
        let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
        loop {
            let child = self.child.as_mut().expect("child");
            if let Some(status) = child.try_wait().expect("child status") {
                panic!("gateway exited {status}: {}", self.logs());
            }
            if self.url.is_empty()
                && let Some(port) = bound_port(&self.logs())
            {
                self.url = format!("http://127.0.0.1:{port}");
            }
            if !self.url.is_empty()
                && self
                    .client
                    .get(format!("{}/health", self.url))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "gateway readiness timed out: {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Stop the child and wait for it to exit; the directory and store stay.
    /// `restart` then starts a new one.
    pub async fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
    }

    /// Stop the child and start a new one on the same directory and store.
    pub async fn restart(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
        self.spawn().await;
    }

    /// The directory the child runs in (store, logs, `audit.jsonl`).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The config the child was started with.
    pub fn config(&self) -> &Value {
        &self.config
    }

    /// Rewrite `gateway.yaml` in place, for the live config watcher to pick
    /// up; the next `restart` also uses it.
    pub fn rewrite_config(&mut self, config: Value) {
        self.config = config;
        mcp_gateway::gateway::test_helpers::write_owner_only(
            self.root.join("gateway.yaml"),
            serde_yaml::to_string(&self.config).expect("config YAML"),
        )
        .expect("rewrite gateway config");
    }

    /// POST `body` to the inbound webhook route `/webhooks/github/push` with
    /// `X-GitHub-Delivery: delivery_id`; the HTTP status.
    pub async fn webhook(&self, delivery_id: &str, body: &Value) -> u16 {
        self.webhook_at(
            "/webhooks/github/push",
            Some(delivery_id),
            &body.to_string(),
        )
        .await
    }

    /// POST the raw `body` bytes to any inbound webhook `path`, optionally
    /// with a delivery id.
    pub async fn webhook_at(&self, path: &str, delivery_id: Option<&str>, body: &str) -> u16 {
        let mut request = self
            .client
            .post(format!("{}{path}", self.url))
            .header("content-type", "application/json")
            .body(body.to_owned());
        if let Some(id) = delivery_id {
            request = request.header("X-GitHub-Delivery", id);
        }
        request
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {path}: {e}; logs={}", self.logs()))
            .status()
            .as_u16()
    }

    /// A modern `/mcp` request as `api_key` (none = no credential).
    pub async fn rpc(&self, api_key: Option<&str>, method: &str, params: Value) -> Value {
        let mut params = params;
        let name = (method == "tools/call")
            .then(|| params["name"].as_str().map(str::to_owned))
            .flatten();
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "events-test", "version": "1"}
        });
        let body = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
        let mut request = self
            .client
            .post(format!("{}/mcp", self.url))
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method)
            .json(&body);
        if let Some(name) = name {
            request = request.header("mcp-name", name);
        }
        if let Some(key) = api_key {
            request = request.bearer_auth(key);
        }
        let response = request
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST /mcp: {e}; logs={}", self.logs()));
        let text = response.text().await.expect("body");
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("non-JSON answer {e}: {text}"))
    }

    /// One request to the admin HTTP API as `api_key`: the status and the JSON
    /// body (the raw text when it is not JSON).
    pub async fn admin(&self, api_key: Option<&str>, method: &str, path: &str) -> (u16, Value) {
        let method = reqwest::Method::from_bytes(method.as_bytes()).expect("HTTP method");
        let mut request = self.client.request(method, format!("{}{path}", self.url));
        if let Some(key) = api_key {
            request = request.bearer_auth(key);
        }
        let response = request
            .send()
            .await
            .unwrap_or_else(|e| panic!("{path}: {e}; logs={}", self.logs()));
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    /// `tools/call` of meta-tool `tool` as `api_key`: the document the tool
    /// put in its content text.
    pub async fn tool_call(&self, api_key: &str, tool: &str, arguments: Value) -> Value {
        let answer = self
            .rpc(
                Some(api_key),
                "tools/call",
                json!({"name": tool, "arguments": arguments}),
            )
            .await;
        let text = answer["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{tool} answers content text: {answer}"));
        serde_json::from_str(text).unwrap_or_else(|e| panic!("{tool} document {e}: {text}"))
    }

    /// `events/list` names visible to `api_key`, polled until `want` shows up
    /// or 10 s pass (capabilities load in the background).
    pub async fn event_names(&self, api_key: Option<&str>, want: Option<&str>) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let answer = self.rpc(api_key, "events/list", json!({})).await;
            let names: Vec<String> = answer["result"]["events"]
                .as_array()
                .map(|events| {
                    events
                        .iter()
                        .filter_map(|e| e["name"].as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let done = want.is_none_or(|w| names.iter().any(|n| n == w));
            if done || tokio::time::Instant::now() >= deadline {
                return names;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// The error object of an answer, or a panic naming the answer.
pub fn error(answer: &Value) -> &Value {
    answer
        .get("error")
        .unwrap_or_else(|| panic!("expected a JSON-RPC error, got {answer}"))
}

fn bound_port(log: &str) -> Option<u16> {
    let complete = &log[..=log.rfind('\n')?];
    complete.lines().rev().find_map(|line| {
        let plain = without_ansi(line);
        let (_, fields) = plain.split_once("server::support: Listening ")?;
        fields
            .split_whitespace()
            .find_map(|field| field.strip_prefix("port=")?.parse().ok())
    })
}

fn without_ansi(line: &str) -> String {
    let mut plain = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
}
