// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7967: with authentication on, an API-key caller can create a task and
//! read it back, through the built binary. A second API key cannot see it,
//! and a caller with no credential is still refused.
//!
//! The task is owned by the caller's credential (`credential:<principal>`,
//! the owner `route_task_owner` resolves). Before the fix the create was
//! refused because the caller had no OIDC identity, which is every API-key
//! caller.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const ALPHA: &str = "key-alpha-0123456789abcdef";
const BRAVO: &str = "key-bravo-0123456789abcdef";
const MARKER: &str = "tidebook-answered";
const PROTOCOL: &str = "2026-07-28";
const READY_BOUND: Duration = Duration::from_secs(60);
const COMPLETION_BOUND: Duration = Duration::from_secs(30);

/// A stdio MCP server with one tool; any other request gets an empty result.
const PEER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  [ -z "$id" ] && continue
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"tidebook","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"tide_table","description":"Look up the tide table.","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"tidebook-answered"}]}}\n' "$id" ;;
    *)
      printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id" ;;
  esac
done
"#;

fn key_hash(key: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(key.as_bytes())))
}

struct Gateway {
    _tmp: tempfile::TempDir,
    child: tokio::process::Child,
    log: PathBuf,
    url: String,
    http: reqwest::Client,
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
                "server:\n  host: 127.0.0.1\n\
                 auth:\n  enabled: true\n  public_paths: [\"/health\", \"/mcp\"]\n  api_keys:\n\
                 \x20   - name: alpha\n      key_sha256: \"{alpha}\"\n      backends: [\"*\"]\n\
                 \x20   - name: bravo\n      key_sha256: \"{bravo}\"\n      backends: [\"*\"]\n\
                 security:\n  transparency_log:\n    enabled: true\n\
                 backends:\n  tidebook:\n    command: /bin/sh {peer}\n",
                alpha = key_hash(ALPHA),
                bravo = key_hash(BRAVO),
                peer = peer.display()
            ),
        )
        .expect("config");
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600");

        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("a loopback port")
            .local_addr()
            .expect("its address")
            .port();
        let log = root.join("serve.log");
        let out = std::fs::File::create(&log).expect("serve log");
        let err = out.try_clone().expect("log handle");
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("MCP_GATEWAY_") {
                command.env_remove(key);
            }
        }
        let child = command
            .current_dir(&root)
            .env("HOME", &root)
            .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
            .args(["-c", "gateway.yaml", "-p", &port.to_string(), "serve"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .kill_on_drop(true)
            .spawn()
            .expect("serve spawns");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .build()
            .expect("an HTTP client");
        let mut gateway = Self {
            _tmp: tmp,
            child,
            log,
            url: format!("http://127.0.0.1:{port}"),
            http,
        };
        gateway.wait_ready().await;
        gateway
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    async fn wait_ready(&mut self) {
        let health = format!("{}/health", self.url);
        let deadline = tokio::time::Instant::now() + READY_BOUND;
        loop {
            if let Some(status) = self.child.try_wait().expect("child status") {
                panic!("serve exited before ready ({status})\n{}", self.logs());
            }
            if self
                .http
                .get(&health)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "serve not ready\n{}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Gateway {
    /// One modern (stateless) request as `key`'s holder, or with no
    /// credential when `key` is `None`.
    async fn post(&self, key: Option<&str>, id: i64, method: &str, mut params: Value) -> Value {
        params["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!(PROTOCOL);
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
            json!({ "extensions": { "io.modelcontextprotocol/tasks": {} } });
        params["_meta"]["io.modelcontextprotocol/clientInfo"] =
            json!({ "name": "task-owner-journey", "version": "1" });
        let mut request = self
            .http
            .post(format!("{}/mcp", self.url))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("mcp-protocol-version", PROTOCOL)
            .header("mcp-method", method)
            .json(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        if method == "tools/call" {
            request = request.header("mcp-name", "gateway_invoke");
        }
        if let Some(key) = key {
            request = request.bearer_auth(key);
        }
        let text = request
            .send()
            .await
            .expect("the gateway answers")
            .text()
            .await
            .expect("a body");
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{method}: not JSON ({e}): {text}"))
    }

    async fn create_task(&self, key: Option<&str>, id: i64, idempotency: &str) -> Value {
        self.post(
            key,
            id,
            "tools/call",
            json!({
                "name": "gateway_invoke",
                "arguments": { "server": "tidebook", "tool": "tide_table", "arguments": {} },
                "task": {},
                "_meta": { "io.mcp-gateway/idempotency-key": idempotency }
            }),
        )
        .await
    }
}

#[tokio::test]
async fn an_api_key_caller_owns_its_task_and_no_one_else_sees_it() {
    let gateway = Gateway::start().await;

    // MIK-7967.CREATE.1: the API-key caller is answered with a task handle.
    let created = gateway.create_task(Some(ALPHA), 1, "alpha-1").await;
    assert_eq!(
        created.pointer("/result/resultType"),
        Some(&json!("task")),
        "an API-key caller must be able to create a task: {created}\n{}",
        gateway.logs()
    );
    let task_id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no taskId: {created}"))
        .to_string();

    // ...and reads it back to completion with the backend's answer.
    let deadline = tokio::time::Instant::now() + COMPLETION_BOUND;
    let done = loop {
        let got = gateway
            .post(Some(ALPHA), 2, "tasks/get", json!({ "taskId": task_id }))
            .await;
        if got.pointer("/result/status") == Some(&json!("completed")) {
            break got;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "task never completed: {got}\n{}",
            gateway.logs()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(
        done.pointer("/result/result/content/0/text")
            .and_then(Value::as_str)
            .map(|t| t.contains(MARKER)),
        Some(true),
        "the completed task carries the backend's answer: {done}"
    );

    // MIK-7967.ISOLATE.1: another key is told the task does not exist.
    // Pinned by comparison: key A's task must be indistinguishable, to key B,
    // from a task that does not exist (`missing_task_error`). The made-up id
    // keeps the real one's shape, so only existence differs.
    let other = gateway
        .post(Some(BRAVO), 3, "tasks/get", json!({ "taskId": task_id }))
        .await;
    let made_up = {
        let mut id = task_id.clone();
        let last = id.pop().expect("a non-empty task id");
        id.push(if last == '0' { '1' } else { '0' });
        id
    };
    let missing = gateway
        .post(Some(BRAVO), 3, "tasks/get", json!({ "taskId": made_up }))
        .await;
    assert!(
        other.get("result").is_none() && other.get("error").is_some(),
        "a second API key must not see the first key's task: {other}"
    );
    assert_eq!(
        other.get("error"),
        missing.get("error"),
        "another key's task must answer exactly like a missing one"
    );

    // MIK-7967.ANON.1: a caller with no credential still cannot create one.
    // It is answered as a missing task (the unattributed gate, which names
    // nothing), the code TASKS.md documents.
    let anonymous = gateway.create_task(None, 4, "anon-1").await;
    assert_eq!(
        anonymous.pointer("/error/code"),
        Some(&json!(-32602)),
        "a caller with no credential must be refused as a missing task: {anonymous}"
    );
    assert!(
        anonymous.get("result").is_none(),
        "a refused create carries no result: {anonymous}"
    );
}
