// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The first-run harness the end-to-end journeys share: an empty project
//! directory with its own HOME and state dir, the built binary run in it, a
//! gateway started on an OS-chosen port, an MCP client session over its HTTP
//! endpoint, and a local stdio peer with one tool. Moved here unchanged from
//! e2e_first_run_journey.rs (MIK-8044 SURF.7).

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

pub const BACKEND: &str = "tidebook";
pub const TOOL: &str = "tide_table";
pub const MARKER: &str = "tidebook-answered";
pub const READY_BOUND: Duration = Duration::from_secs(60);
pub const SEARCH_BOUND: Duration = Duration::from_secs(30);
pub const POLL_GAP: Duration = Duration::from_millis(100);
pub const REQUEST_BOUND: Duration = Duration::from_secs(30);

/// A stdio MCP server with one tool. Any other request with an id gets an
/// empty result, so warm-start probes and pings are answered.
pub const PEER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  [ -z "$id" ] && continue
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"tidebook","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"tide_table","description":"Look up the tide table for a harbour.","inputSchema":{"type":"object","properties":{"harbour":{"type":"string"}}}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"tidebook-answered"}]}}\n' "$id" ;;
    *)
      printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id" ;;
  esac
done
"#;

pub struct Workspace {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
}

impl Workspace {
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().expect("a temp root");
        let root = tmp.path().to_path_buf();
        for dir in ["home", "empty-path"] {
            std::fs::create_dir(root.join(dir)).expect("a temp subdir");
        }
        Self { _tmp: tmp, root }
    }

    /// The binary as a user in an empty project directory runs it: own HOME,
    /// own state dir, no inherited `MCP_GATEWAY_*` override.
    pub fn command(&self) -> Command {
        let mut command = super::gateway_bin::command(
            &self.root.join("home"),
            super::gateway_bin::Inherit::Environment,
        );
        command
            .current_dir(&self.root)
            .env("MCP_GATEWAY_CONFIG_DIR", self.root.join("gateway-state"))
            .stdin(Stdio::null());
        command
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().expect("the binary runs")
    }

    pub fn run_ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "`{}` failed\n{}",
            args.join(" "),
            show(&out)
        );
        String::from_utf8(out.stdout).expect("stdout is UTF-8")
    }
}

pub fn show(out: &Output) -> String {
    format!(
        "exit: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Every HTTP wait is bounded, and loopback never goes through an inherited
/// proxy.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_BOUND)
        .no_proxy()
        .build()
        .expect("an HTTP client")
}

/// One MCP client session over the gateway's HTTP endpoint.
pub struct Session {
    http: reqwest::Client,
    url: String,
    token: Option<String>,
    id: Option<String>,
    next: i64,
}

impl Session {
    pub async fn open(url: &str, token: Option<String>) -> Self {
        let mut session = Self {
            http: http_client(),
            url: url.to_string(),
            token,
            id: None,
            next: 1,
        };
        let init = session
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "first-run-journey", "version": "1" }
                }),
            )
            .await;
        assert_eq!(
            init["result"]["serverInfo"]["name"], "mcp-gateway",
            "initialize: {init}"
        );
        session
            .send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .await;
        session
    }

    pub async fn send(&mut self, body: &Value) -> reqwest::Response {
        let mut request = self
            .http
            .post(&self.url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .json(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(id) = &self.id {
            request = request.header("mcp-session-id", id);
        }
        let response = request.send().await.expect("the gateway answers");
        if let Some(id) = response.headers().get("mcp-session-id") {
            self.id = Some(id.to_str().expect("ASCII session id").to_string());
        }
        response
    }

    pub async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response = self.send(&body).await;
        let status = response.status();
        let text = response.text().await.expect("a body");
        assert_eq!(status, reqwest::StatusCode::OK, "{method}: {text}");
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{method}: not JSON ({e}): {text}"))
    }

    pub async fn tool_names(&mut self) -> Vec<String> {
        let list = self.request("tools/list", json!({})).await;
        list["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list: {list}"))
            .iter()
            .map(|t| t["name"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    pub async fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
        .await
    }
}

/// The text payload of a `tools/call` answer, parsed as JSON.
pub fn payload(answer: &Value) -> Value {
    let text = answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content: {answer}"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("payload not JSON ({e}): {text}"))
}

pub struct Gateway {
    pub child: tokio::process::Child,
    pub log: PathBuf,
    pub url: String,
}

impl Gateway {
    pub async fn start(ws: &Workspace) -> Self {
        let log = ws.root.join("serve.log");
        let out = std::fs::File::create(&log).expect("serve log");
        let err = out.try_clone().expect("log handle");
        let mut command = tokio::process::Command::from(ws.command());
        let child = command
            .args(["-c", "gateway.yaml", "-p", "0", "serve"])
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .kill_on_drop(true)
            .spawn()
            .expect("serve spawns");
        let mut gateway = Self {
            child,
            log,
            url: String::new(),
        };
        gateway.wait_ready().await;
        gateway
    }

    pub fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Read the port the child bound (`-p 0`) from its log, then wait for
    /// `/health` on it.
    pub async fn wait_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + READY_BOUND;
        let http = http_client();
        loop {
            if let Some(status) = self.child.try_wait().expect("child status") {
                panic!("serve exited before ready ({status})\n{}", self.logs());
            }
            if self.url.is_empty()
                && let Some(port) = super::gateway_bin::logged_port(&self.log)
            {
                self.url = format!("http://127.0.0.1:{port}");
            }
            if !self.url.is_empty()
                && http
                    .get(format!("{}/health", self.url))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "serve not ready within {READY_BOUND:?}\n{}",
                self.logs()
            );
            tokio::time::sleep(POLL_GAP).await;
        }
    }
}
