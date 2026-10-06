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
//!
//! A proven subject outranks the credential, as it does for sessions: two
//! people a trusted proxy names behind one shared key own separate tasks, and
//! a subject header with no credential still owns nothing.
//!
//! MIK-7986: the other owner-scoped verbs, `tasks/cancel` and `tasks/update`,
//! answer another key exactly as a missing task and leave the running task
//! alone.

#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const ALPHA: &str = "key-alpha-0123456789abcdef";
const BRAVO: &str = "key-bravo-0123456789abcdef";
const MARKER: &str = "tidebook-answered";
const PROTOCOL: &str = "2026-07-28";
/// The header a trusted proxy names the end user with (`caller_identity`).
const SUBJECT_HEADER: &str = "x-gateway-identity-subject";
const READY_BOUND: Duration = Duration::from_secs(60);
const COMPLETION_BOUND: Duration = Duration::from_secs(30);

/// A stdio MCP server with two tools; any other request gets an empty result.
/// `slow_tide` answers after 20 s from a background subshell, so its task
/// stays `working` while the test acts on it and the loop keeps serving; the
/// bound stays under the backend's 30 s request timeout.
const PEER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  [ -z "$id" ] && continue
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"tidebook","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"tide_table","description":"Look up the tide table.","inputSchema":{"type":"object"}},{"name":"slow_tide","description":"Look up the tide table, slowly.","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"name":"slow_tide"'*)
      ( sleep 20; printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"tidebook-answered"}]}}\n' "$id" ) & ;;
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
                 \x20 caller_identity:\n    mode: trusted_proxy\n\
                 \x20   trusted_proxies: [\"127.0.0.1\"]\n    authority: corp-sso\n\
                 backends:\n  tidebook:\n    command: /bin/sh {peer}\n",
                alpha = key_hash(ALPHA),
                bravo = key_hash(BRAVO),
                peer = peer.display()
            ),
        )
        .expect("config");
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
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .build()
            .expect("an HTTP client");
        let mut gateway = Self {
            _tmp: tmp,
            child,
            log,
            url: String::new(),
            http,
        };
        gateway.wait_ready().await;
        gateway
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Read the port the child bound (`-p 0`) from its log, then wait for
    /// `/health` on it (MIK-7984).
    async fn wait_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + READY_BOUND;
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
                && self
                    .http
                    .get(format!("{}/health", self.url))
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
    async fn post(&self, key: Option<&str>, id: i64, method: &str, params: Value) -> Value {
        self.post_as(key, None, id, method, params).await
    }

    /// As [`Self::post`], with `subject` forwarded as the trusted proxy's
    /// identity header.
    async fn post_as(
        &self,
        key: Option<&str>,
        subject: Option<&str>,
        id: i64,
        method: &str,
        mut params: Value,
    ) -> Value {
        params["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!(PROTOCOL);
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
            json!({ "extensions": { "io.modelcontextprotocol/tasks": {} } });
        params["_meta"]["io.modelcontextprotocol/clientInfo"] =
            json!({ "name": "task-owner-journey", "version": "1" });
        // `Mcp-Name` must repeat the body's name: the tool for a call, the
        // task id for a task method (`protocol::headers`).
        let name = match method {
            "tools/call" => params["name"].as_str().map(str::to_owned),
            "tasks/get" | "tasks/update" | "tasks/cancel" => {
                params["taskId"].as_str().map(str::to_owned)
            }
            _ => None,
        };
        let mut request = self
            .http
            .post(format!("{}/mcp", self.url))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("mcp-protocol-version", PROTOCOL)
            .header("mcp-method", method)
            .json(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        if let Some(name) = name {
            request = request.header("mcp-name", name);
        }
        if let Some(key) = key {
            request = request.bearer_auth(key);
        }
        if let Some(subject) = subject {
            request = request.header(SUBJECT_HEADER, subject);
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
        self.create_task_as(key, None, id, idempotency, "tide_table")
            .await
    }

    async fn create_task_as(
        &self,
        key: Option<&str>,
        subject: Option<&str>,
        id: i64,
        idempotency: &str,
        tool: &str,
    ) -> Value {
        self.post_as(
            key,
            subject,
            id,
            "tools/call",
            json!({
                "name": "gateway_invoke",
                "arguments": { "server": "tidebook", "tool": tool, "arguments": {} },
                "task": {},
                "_meta": { "io.mcp-gateway/idempotency-key": idempotency }
            }),
        )
        .await
    }
}

/// A task id of the real one's shape that names no task: only existence
/// differs, so comparing the two answers pins non-disclosure.
fn made_up(task_id: &str) -> String {
    let mut id = task_id.to_owned();
    let last = id.pop().expect("a non-empty task id");
    id.push(if last == '0' { '1' } else { '0' });
    id
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
    let missing = gateway
        .post(
            Some(BRAVO),
            3,
            "tasks/get",
            json!({ "taskId": made_up(&task_id) }),
        )
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
    assert_eq!(
        anonymous.get("error"),
        missing.get("error"),
        "the refusal names nothing: it is the missing-task answer"
    );
    assert!(
        anonymous.get("result").is_none(),
        "a refused create carries no result: {anonymous}"
    );
}

#[tokio::test]
async fn two_subjects_behind_one_key_own_separate_tasks() {
    let gateway = Gateway::start().await;

    // MIK-7967.SUBJECT.1: alice, named by the trusted proxy, creates a task
    // with the key she shares with bob.
    let created = gateway
        .create_task_as(Some(ALPHA), Some("alice"), 1, "alice-1", "tide_table")
        .await;
    let task_id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "alice could not create a task: {created}\n{}",
                gateway.logs()
            )
        })
        .to_string();
    // Alice reads her own task, so a fix that refuses everyone cannot pass.
    let own = gateway
        .post_as(
            Some(ALPHA),
            Some("alice"),
            2,
            "tasks/get",
            json!({ "taskId": task_id }),
        )
        .await;
    assert!(
        own.pointer("/result/taskId").is_some(),
        "alice must read her own task: {own}\n{}",
        gateway.logs()
    );

    // Bob holds the same key but is a different person: alice's task must
    // answer him exactly as a task that does not exist.
    let bobs_view = gateway
        .post_as(
            Some(ALPHA),
            Some("bob"),
            3,
            "tasks/get",
            json!({ "taskId": task_id }),
        )
        .await;
    let missing = gateway
        .post_as(
            Some(ALPHA),
            Some("bob"),
            4,
            "tasks/get",
            json!({ "taskId": made_up(&task_id) }),
        )
        .await;
    assert!(
        bobs_view.get("result").is_none(),
        "bob shares alice's key but must not see her task: {bobs_view}"
    );
    assert_eq!(
        bobs_view.get("error"),
        missing.get("error"),
        "alice's task must answer bob exactly like a missing one"
    );

    // MIK-7967.SUBJECT.2: a subject header is not a credential. Without a
    // key the caller is still refused as a missing task.
    let headless = gateway
        .create_task_as(None, Some("alice"), 5, "alice-anon", "tide_table")
        .await;
    assert_eq!(
        headless.pointer("/error/code"),
        Some(&json!(-32602)),
        "a subject with no credential must be refused: {headless}"
    );
    assert!(headless.get("result").is_none(), "{headless}");
}

/// One owner-scoped task call: `tasks/cancel`, or `tasks/update` with the
/// given `inputResponses` (empty is acknowledged; non-empty asks for a round).
fn verb(method: &'static str, task_id: &str, answers: Option<Value>) -> (&'static str, Value) {
    let mut params = json!({ "taskId": task_id });
    if let Some(answers) = answers {
        params["inputResponses"] = answers;
    }
    (method, params)
}

fn mutating_verbs(task_id: &str) -> [(&'static str, Value); 3] {
    [
        verb("tasks/cancel", task_id, None),
        verb("tasks/update", task_id, Some(json!({}))),
        verb(
            "tasks/update",
            task_id,
            Some(json!({ "tide": { "ok": true } })),
        ),
    ]
}

#[tokio::test]
async fn another_key_cannot_cancel_or_update_a_running_task() {
    let gateway = Gateway::start().await;
    let created = gateway
        .create_task_as(Some(ALPHA), None, 1, "alpha-slow", "slow_tide")
        .await;
    let task_id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no taskId: {created}\n{}", gateway.logs()))
        .to_string();
    let status = |got: &Value| got.pointer("/result/status").cloned();
    let read = || gateway.post(Some(ALPHA), 2, "tasks/get", json!({ "taskId": task_id }));
    // The checks below mean something only while the task is still running.
    assert_eq!(
        status(&read().await),
        Some(json!("working")),
        "the slow task must still be running\n{}",
        gateway.logs()
    );

    // MIK-7986.XKEY.1 / XKEY.2: key B's cancel and updates on A's task each
    // answer exactly as the same call on a task that does not exist.
    let fake = made_up(&task_id);
    for ((method, params), (_, missing_params)) in mutating_verbs(&task_id)
        .into_iter()
        .zip(mutating_verbs(&fake))
    {
        let other = gateway.post(Some(BRAVO), 3, method, params.clone()).await;
        let missing = gateway.post(Some(BRAVO), 4, method, missing_params).await;
        assert!(
            other.get("result").is_none() && other.get("error").is_some(),
            "{method} {params}: key B must not act on key A's task: {other}"
        );
        assert_eq!(
            other.get("error"),
            missing.get("error"),
            "{method} {params}: key A's task must answer key B like a missing one"
        );
    }

    // MIK-7986.XKEY.3: A's task is untouched, and each update from A answers
    // differently from A's same update on a made-up id, so the comparisons
    // above have teeth. Cancel's own control is A's cancel below.
    assert_eq!(
        status(&read().await),
        Some(json!("working")),
        "key B's attempts must leave key A's task running"
    );
    for ((method, params), (_, missing_params)) in mutating_verbs(&task_id)
        .into_iter()
        .zip(mutating_verbs(&fake))
        .skip(1)
    {
        let missing = gateway.post(Some(ALPHA), 5, method, missing_params).await;
        let own = gateway.post(Some(ALPHA), 6, method, params.clone()).await;
        assert_ne!(
            own.get("error"),
            missing.get("error"),
            "{method} {params}: key A must reach its own task: {own}"
        );
    }
    let cancelled = gateway
        .post(Some(ALPHA), 7, "tasks/cancel", json!({ "taskId": task_id }))
        .await;
    assert!(
        cancelled.get("error").is_none() && cancelled.get("result").is_some(),
        "key A must cancel its own task: {cancelled}"
    );
    assert_eq!(status(&read().await), Some(json!("cancelled")));
}
