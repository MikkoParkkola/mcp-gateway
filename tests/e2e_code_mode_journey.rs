// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Code Mode through the built binary: `code_mode.enabled: true`, then over
//! HTTP list the two tools, find a backend tool with `gateway_search`, run it
//! with `gateway_execute`, and read the errors a user meets: a tool the
//! backend does not have, a server that does not exist, a bare tool name, and
//! a backend whose process will not start.
//!
//! Local only: one stdio peer that answers, one whose command exits at once.

#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};

const BACKEND: &str = "tidebook";
const DOWN: &str = "downbook";
const MARKER: &str = "tidebook-answered";
const READY_BOUND: Duration = Duration::from_secs(60);
const SEARCH_BOUND: Duration = Duration::from_secs(30);
const REQUEST_BOUND: Duration = Duration::from_secs(30);

/// Every HTTP wait is bounded, and loopback never goes through an inherited
/// proxy.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_BOUND)
        .no_proxy()
        .build()
        .expect("an HTTP client")
}

/// A stdio MCP server with one tool; any other request gets an empty result.
const PEER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  [ -z "$id" ] && continue
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"tidebook","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"tide_table","description":"Look up the tide table for a harbour.","inputSchema":{"type":"object","properties":{"harbour":{"type":"string"}}}},{"name":"tide_secret","description":"Read the harbour master secret log.","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"tidebook-answered"}]}}\n' "$id" ;;
    *)
      printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id" ;;
  esac
done
"#;

struct Gateway {
    _tmp: tempfile::TempDir,
    child: tokio::process::Child,
    log: PathBuf,
    url: String,
}

impl Gateway {
    async fn start() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("temp root");
        let root = tmp.path().to_path_buf();
        let peer = root.join("tidebook.sh");
        std::fs::write(&peer, PEER).expect("peer");
        let config = root.join("gateway.yaml");
        std::fs::write(
            &config,
            format!(
                "server:\n  host: 127.0.0.1\ncode_mode:\n  enabled: true\n\
                 security:\n  tool_policy:\n    deny: [tide_secret]\nbackends:\n  \
                 {BACKEND}:\n    command: /bin/sh {peer}\n  \
                 {DOWN}:\n    command: /bin/sh -c \"exit 3\"\n",
                peer = peer.display()
            ),
        )
        .expect("config");
        // The gateway refuses a config other users can read.
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600");

        let log = root.join("serve.log");
        let out = std::fs::File::create(&log).expect("serve log");
        let err = out.try_clone().expect("log handle");
        let mut command = tokio::process::Command::from(gateway_bin::command(
            &root,
            gateway_bin::Inherit::Environment,
        ));
        let child = command
            .current_dir(&root)
            .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
            .args(["-c", "gateway.yaml", "-p", "0", "serve"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .kill_on_drop(true)
            .spawn()
            .expect("serve spawns");
        let mut gateway = Self {
            _tmp: tmp,
            child,
            log,
            // Learned from the child's `Listening` line in `wait_ready`.
            url: String::new(),
        };
        gateway.wait_ready().await;
        gateway
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    async fn wait_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + READY_BOUND;
        let http = http_client();
        loop {
            if let Some(status) = self.child.try_wait().expect("child status") {
                panic!("serve exited before ready ({status})\n{}", self.logs());
            }
            if self.url.is_empty()
                && let Some(port) = gateway_bin::logged_port(&self.log)
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
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// One MCP client session over the gateway's HTTP endpoint.
struct Session {
    http: reqwest::Client,
    url: String,
    id: Option<String>,
    next: i64,
}

impl Session {
    async fn open(gateway: &Gateway) -> Self {
        let mut session = Self {
            http: http_client(),
            url: format!("{}/mcp", gateway.url),
            id: None,
            next: 1,
        };
        let init = session
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "code-mode-journey", "version": "1" }
                }),
            )
            .await;
        assert_eq!(
            init["result"]["serverInfo"]["name"], "mcp-gateway",
            "{init}"
        );
        session
            .send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .await;
        session
    }

    async fn send(&mut self, body: &Value) -> reqwest::Response {
        let mut request = self
            .http
            .post(&self.url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .json(body);
        if let Some(id) = &self.id {
            request = request.header("mcp-session-id", id);
        }
        let response = request.send().await.expect("the gateway answers");
        if let Some(id) = response.headers().get("mcp-session-id") {
            self.id = Some(id.to_str().expect("ASCII session id").to_string());
        }
        response
    }

    /// The JSON-RPC answer, with its HTTP status recorded as `_httpStatus`.
    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response = self.send(&body).await;
        let status = response.status().as_u16();
        let text = response.text().await.expect("a body");
        let mut parsed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{method}: not JSON ({e}): {text}"));
        parsed["_httpStatus"] = json!(status);
        parsed
    }

    async fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
        .await
    }

    /// `gateway_execute` of one tool; returns its parsed text payload.
    async fn execute(&mut self, tool: &str, arguments: Value) -> Value {
        let answer = self
            .call(
                "gateway_execute",
                json!({ "tool": tool, "arguments": arguments }),
            )
            .await;
        payload(&answer)
    }
}

/// The text payload of a `tools/call` answer, parsed as JSON.
fn payload(answer: &Value) -> Value {
    let text = answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content: {answer}"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("payload not JSON ({e}): {text}"))
}

/// The first text block of an executed tool's payload.
fn text_of(payload: &Value) -> &str {
    payload["content"][0]["text"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn code_mode_lists_two_tools_searches_executes_and_reports_errors() {
    let gateway = Gateway::start().await;
    let mut mcp = Session::open(&gateway).await;

    // Exactly the two Code Mode tools, nothing else (README, "Code Mode").
    let list = mcp.request("tools/list", json!({})).await;
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list: {list}"))
        .iter()
        .map(|t| t["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, ["gateway_search", "gateway_execute"], "{list}");

    // gateway_search finds the backend tool as `server:tool` once warmed.
    let deadline = tokio::time::Instant::now() + SEARCH_BOUND;
    loop {
        let found = payload(
            &mcp.call("gateway_search", json!({ "query": "tide harbour" }))
                .await,
        );
        if found["matches"]
            .as_array()
            .is_some_and(|m| m.iter().any(|m| m["tool"] == "tidebook:tide_table"))
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "search never found tidebook:tide_table: {found}\n{}",
            gateway.logs()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // gateway_execute runs it and returns the backend's answer.
    let ran = mcp
        .execute("tidebook:tide_table", json!({ "harbour": "Oslo" }))
        .await;
    assert_eq!(text_of(&ran), MARKER, "{ran}\n{}", gateway.logs());
    assert_ne!(ran["isError"], true, "{ran}");
    assert!(
        ran["trace_id"].as_str().is_some_and(|t| !t.is_empty()),
        "{ran}"
    );

    // The gateway is still serving after every error, chains included.
    let step = json!({ "tool": "tidebook:tide_table", "arguments": { "harbour": "Bergen" } });
    let chain = payload(
        &mcp.call("gateway_execute", json!({ "chain": [step.clone(), step] }))
            .await,
    );
    assert_eq!(chain["steps"], 2, "{chain}\n{}", gateway.logs());
    assert_eq!(
        chain["results"].as_array().map(Vec::len),
        Some(2),
        "{chain}"
    );
    for (i, result) in chain["results"]
        .as_array()
        .expect("results")
        .iter()
        .enumerate()
    {
        assert_eq!(result["step"], i, "{chain}");
        assert_eq!(text_of(&result["result"]), MARKER, "{chain}");
    }

    assert_error_answers(&mut mcp).await;
    assert_invoke_matches_execute(&mut mcp).await;
}

/// The errors a Code Mode user meets, each as the guide documents it.
async fn assert_error_answers(mcp: &mut Session) {
    // A tool the backend does not list.
    let missing = mcp.execute("tidebook:no_such_tool", json!({})).await;
    assert_eq!(missing["isError"], true, "{missing}");
    assert!(text_of(&missing).contains("no_such_tool"), "{missing}");

    // A server that is not configured.
    let nowhere = mcp.execute("nosuch:tool", json!({})).await;
    assert_eq!(nowhere["isError"], true, "{nowhere}");
    assert!(
        text_of(&nowhere).contains("Backend not found: nosuch")
            && nowhere["recovery"]["error_code"] == "TOOL_NOT_FOUND",
        "{nowhere}"
    );

    // A bare name is refused with the format to use.
    let bare = mcp
        .call(
            "gateway_execute",
            json!({ "tool": "tide_table", "arguments": {} }),
        )
        .await;
    assert_eq!(bare["error"]["code"], -32602, "{bare}");
    assert!(
        bare["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("server:tool_name")),
        "{bare}"
    );

    // A backend whose process exits at start: an error, not a hang or a crash.
    let down = mcp.execute(&format!("{DOWN}:tide_table"), json!({})).await;
    assert_eq!(down["isError"], true, "{down}");
    assert!(
        text_of(&down).contains("exited before initialize"),
        "{down}"
    );
    assert_eq!(down["recovery"]["error_code"], "BACKEND_ERROR", "{down}");
    assert_eq!(down["recovery"]["retry"], true, "{down}");
}

async fn assert_invoke_matches_execute(mcp: &mut Session) {
    // Existing clients that call gateway_invoke by name keep working, and pass
    // the same grant check as gateway_execute: a policy-denied tool is
    // refused with the same answer on both paths.
    let invoked = payload(
        &mcp.call(
            "gateway_invoke",
            json!({ "server": BACKEND, "tool": "tide_table", "arguments": {} }),
        )
        .await,
    );
    assert_eq!(text_of(&invoked), MARKER, "{invoked}");
    let denied_execute = mcp
        .call(
            "gateway_execute",
            json!({ "tool": "tidebook:tide_secret", "arguments": {} }),
        )
        .await;
    let denied_invoke = mcp
        .call(
            "gateway_invoke",
            json!({ "server": BACKEND, "tool": "tide_secret", "arguments": {} }),
        )
        .await;
    assert!(
        denied_execute["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("blocked by security policy")),
        "{denied_execute}"
    );
    assert_eq!(denied_execute["_httpStatus"], 403, "{denied_execute}");
    assert_eq!(denied_execute["error"]["code"], -32600, "{denied_execute}");
    assert_eq!(denied_invoke["_httpStatus"], 403, "{denied_invoke}");
    assert_eq!(
        denied_invoke["error"], denied_execute["error"],
        "{denied_invoke}"
    );
}
