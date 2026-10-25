// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8895 STOP.1: a stop sent to the gateway's whole process group (what
//! `tini -g` does in the `-full` image, and a terminal's ^C) must not reach
//! the stdio backends before the gateway drains. The call in flight when the
//! signal lands is answered, then the gateway exits.
//!
//! Red before MIK-8895: the backend shared the gateway's process group, so it
//! died with the same signal and the drained call had nothing to wait for.
#![cfg(unix)]

use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
use serde_json::{Value, json};

const PROTOCOL_VERSION: &str = "2025-11-25";
const BACKEND: &str = "slow";
const TOOL: &str = "slow_answer";
const ANSWER: &str = "answered-after-the-stop";
const READY_BOUND: Duration = Duration::from_secs(60);
const EXIT_BOUND: Duration = Duration::from_secs(60);

/// A stdio MCP server in Python: it answers `initialize`, `ping` and
/// `tools/list`, and answers `tools/call` two seconds after marking the call
/// started, so a stop can land while the call is in flight. A TERM that
/// reaches it ends it before it answers.
const BACKEND_SCRIPT: &str = r#"import json, sys, time
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {"tools": {}},
                  "serverInfo": {"name": "slow", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "TOOL", "inputSchema": {"type": "object"},
                             "annotations": {"readOnlyHint": True}}]}
    elif method == "tools/call":
        open("called", "w").close()
        time.sleep(2)
        result = {"content": [{"type": "text", "text": "ANSWER"}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
"#;

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    listener.local_addr().expect("its address").port()
}

fn write_config(root: &Path, port: u16) -> std::path::PathBuf {
    let script = BACKEND_SCRIPT
        .replace("TOOL", TOOL)
        .replace("ANSWER", ANSWER);
    std::fs::write(root.join("backend.py"), script).expect("write backend");
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = port;
    config.server.shutdown_timeout = Duration::from_secs(20);
    config.auth.enabled = false;
    config.capabilities.enabled = false;
    config.cache.enabled = false;
    config.tasks.store_dir = root.join("tasks").display().to_string();
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Stdio {
                command: "python3 -u backend.py".to_string(),
                cwd: Some(root.display().to_string()),
                protocol_version: None,
            },
            timeout: Duration::from_secs(30),
            ..BackendConfig::default()
        },
    );
    let path = root.join("gateway.yaml");
    std::fs::write(&path, serde_yaml::to_string(&config).expect("config yaml")).expect("write");
    path
}

fn invoke(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": TOOL, "arguments": {} }
        }
    })
}

/// One POST on the session (`None` before `initialize`): the body and the
/// session id the gateway named, if any.
async fn post(
    client: &reqwest::Client,
    base: &str,
    session: Option<&str>,
    body: &Value,
) -> Result<(String, Option<String>), String> {
    let mut request = client
        .post(format!("{base}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("mcp-protocol-version", PROTOCOL_VERSION);
    if let Some(id) = session {
        request = request.header("mcp-session-id", id);
    }
    let response = request
        .json(body)
        .send()
        .await
        .map_err(|e| format!("transport failure: {e}"))?;
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let text = response.text().await.map_err(|e| format!("body: {e}"))?;
    Ok((text, session))
}

/// `initialize` then `notifications/initialized`: the session id.
async fn open_session(client: &reqwest::Client, base: &str, root: &Path) -> String {
    let init = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "StopDrainTest", "version": "1.0.0" }
        }
    });
    let (body, session) = post(client, base, None, &init)
        .await
        .unwrap_or_else(|e| panic!("initialize failed: {e}\n{}", logs(root)));
    let session = session.unwrap_or_else(|| panic!("no session id: {body}\n{}", logs(root)));
    let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    post(client, base, Some(&session), &initialized)
        .await
        .unwrap_or_else(|e| panic!("initialized failed: {e}\n{}", logs(root)));
    session
}

fn logs(root: &Path) -> String {
    std::fs::read_to_string(root.join("gateway.log")).unwrap_or_default()
}

#[tokio::test]
async fn a_stop_to_the_gateways_group_drains_the_backend_call() {
    let root = tempfile::tempdir().expect("temp root");
    let root = root.path();
    let port = free_port();
    let config = write_config(root, port);
    let log = std::fs::File::create(root.join("gateway.log")).expect("log");

    // The gateway leads its own group, as the entrypoint does under tini, so
    // the group signal below reaches it and its children but not this test.
    let mut gateway = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MCP_GATEWAY_") {
            gateway.env_remove(key);
        }
    }
    let mut gateway = gateway
        .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
        .current_dir(root)
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().expect("log handle")))
        .stderr(Stdio::from(log))
        .process_group(0)
        .spawn()
        .expect("the gateway binary spawns");
    let pgid = gateway.id();
    let _cleanup = KillGroup(pgid);

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");
    let ready_by = tokio::time::Instant::now() + READY_BOUND;
    while client.get(format!("{base}/health")).send().await.is_err() {
        assert!(
            tokio::time::Instant::now() < ready_by,
            "the gateway never became ready\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let session = open_session(&client, &base, root).await;
    let mut call = tokio::spawn({
        let client = client.clone();
        let base = base.clone();
        async move {
            post(&client, &base, Some(&session), &invoke(1))
                .await
                .map(|(body, _)| body)
        }
    });
    let called = root.join("called");
    let started_by = tokio::time::Instant::now() + READY_BOUND;
    while !called.exists() {
        assert!(
            tokio::time::Instant::now() < started_by,
            "the backend call never started\n{}",
            logs(root)
        );
        if let Ok(early) = tokio::time::timeout(Duration::from_millis(20), &mut call).await {
            panic!(
                "the call answered before reaching the backend: {early:?}\n{}",
                logs(root)
            );
        }
    }

    // What `tini -g` sends on `docker stop`: SIGTERM to the whole group.
    let signalled = std::process::Command::new("kill")
        .args(["-TERM", "--", &format!("-{pgid}")])
        .status()
        .expect("kill runs");
    assert!(signalled.success(), "the group signal was delivered");

    let answer = tokio::time::timeout(EXIT_BOUND, call)
        .await
        .expect("the drained call answers within the bound")
        .expect("the call task completes");
    let exited = tokio::time::timeout(
        EXIT_BOUND,
        tokio::task::spawn_blocking(move || gateway.wait()),
    )
    .await;
    let body = answer.unwrap_or_else(|e| panic!("the call failed: {e}\n{}", logs(root)));
    assert!(
        body.contains(ANSWER),
        "the call in flight at the stop was not answered by its backend: {body}\n{}",
        logs(root)
    );
    assert!(
        matches!(exited, Ok(Ok(Ok(_)))),
        "the gateway exits after the drain\n{}",
        logs(root)
    );
}

/// SIGKILLs the gateway's group when the row ends, so a red run leaks no
/// gateway and no backend.
struct KillGroup(u32);

impl Drop for KillGroup {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", self.0)])
            .stderr(Stdio::null())
            .status();
    }
}
