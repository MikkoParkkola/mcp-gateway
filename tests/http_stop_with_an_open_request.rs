// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An HTTP gateway stopped while a request is still open finishes its whole
//! stop inside a supervisor's grace: the listener's grace, the in-flight and
//! task drains and the backend stage all fit `server.shutdown_timeout`, one
//! total from the signal, so a grace of that total plus a second (the shipped
//! templates' rule) is never cut short.
//!
//! The row plays a supervisor with a 20 s stop grace and the gateway at 19 s:
//! SIGTERM, then SIGKILL at 20 s if the gateway is still running. A request
//! whose backend never answers holds its connection. The stop must end in a
//! clean exit, with the shutdown saves and the backend stage logged and the
//! backend's stdin closed. This is the case of the outside report against
//! 3.5.x, where the listener waited for that request without limit.
#![cfg(unix)]

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
use serde_json::{Value, json};

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/yaml.rs"]
mod yaml;

const PROTOCOL_VERSION: &str = "2025-11-25";
const BACKEND: &str = "silent";
const TOOL: &str = "never_answers";
const READY_BOUND: Duration = Duration::from_secs(60);
/// The gateway's stop total: a 20 s supervisor grace less the templates' 1 s.
const STOP_TOTAL: Duration = Duration::from_secs(19);
/// The supervisor's grace: after it, the row sends SIGKILL, as docker does.
const GRACE: Duration = Duration::from_secs(20);
/// The shutdown saves the stop must write, in the gateway's data dir.
const SAVE_FILES: [&str; 2] = ["usage.json", "transitions.json"];

/// A stdio MCP server in Python that never answers `tools/call`: it marks the
/// call started and goes on reading. Its stdin closing is the gateway's
/// backend stage reaching it; it then writes `stopped` and lingers, so only a
/// stage that waits for it (and then ends it) sees the mark while the gateway
/// still runs. A gateway that exits without the stage closes the pipe only by
/// exiting, so the mark would come after.
const BACKEND_SCRIPT: &str = r#"import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "tools/call":
        open("called", "w").close()
        continue
    if method == "initialize":
        result = {"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {"tools": {}},
                  "serverInfo": {"name": "silent", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "TOOL", "inputSchema": {"type": "object"},
                             "annotations": {"readOnlyHint": True}}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
open("stopped", "w").close()
import time
time.sleep(15)
"#;

fn write_config(root: &Path) -> std::path::PathBuf {
    std::fs::write(
        root.join("backend.py"),
        BACKEND_SCRIPT.replace("TOOL", TOOL),
    )
    .expect("write backend");
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = gateway_bin::ANY_PORT;
    config.server.shutdown_timeout = STOP_TOTAL;
    config.auth.enabled = false;
    config.capabilities.enabled = false;
    // The response cache is always on; a zero TTL keeps the call live.
    config.cache.default_ttl = Duration::ZERO;
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
            timeout: Duration::from_secs(600),
            ..BackendConfig::default()
        },
    );
    let path = root.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        yaml::to_string(&config).expect("config yaml"),
    )
    .expect("write");
    path
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

fn logs(root: &Path) -> String {
    std::fs::read_to_string(root.join("gateway.log")).unwrap_or_default()
}

/// The port the gateway reported binding, once it answers `/health` there.
async fn ready_port(client: &reqwest::Client, root: &Path) -> u16 {
    let ready_by = tokio::time::Instant::now() + READY_BOUND;
    loop {
        if let Some(port) = gateway_bin::logged_port(&root.join("gateway.log"))
            && client
                .get(format!("http://127.0.0.1:{port}/health"))
                .timeout(READY_BOUND)
                .send()
                .await
                .is_ok()
        {
            return port;
        }
        assert!(
            tokio::time::Instant::now() < ready_by,
            "the gateway never became ready\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Opens an MCP session (`initialize`, then `notifications/initialized`) and
/// returns its id.
async fn open_session(client: &reqwest::Client, base: &str, root: &Path) -> String {
    let init = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "OpenRequestStopTest", "version": "1.0.0" }
        }
    });
    let (body, session) = post(client, base, None, &init)
        .await
        .unwrap_or_else(|e| panic!("initialize failed: {e}\n{}", logs(root)));
    let session = session.unwrap_or_else(|| panic!("no session id: {body}\n{}", logs(root)));
    post(
        client,
        base,
        Some(&session),
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await
    .unwrap_or_else(|e| panic!("initialized failed: {e}\n{}", logs(root)));
    session
}

#[tokio::test]
async fn a_stop_with_an_open_request_finishes_inside_the_supervisors_grace() {
    let root = tempfile::tempdir().expect("temp root");
    let root = root.path();
    let config = write_config(root);
    let log = std::fs::File::create(root.join("gateway.log")).expect("log");
    let mut command = tokio::process::Command::from(gateway_bin::command(
        &root.join("home"),
        gateway_bin::Inherit::Environment,
    ));
    // Reaped kills a gateway still running when the row ends, so a red run
    // leaks nothing.
    let mut gateway = gateway_bin::Reaped::new(
        command
            .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
            .current_dir(root)
            .arg("--config")
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("log handle")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("the gateway binary spawns"),
    );
    let pid = gateway.child_mut().id().expect("the gateway's pid");

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", ready_port(&client, root).await);
    let session = tokio::time::timeout(READY_BOUND, open_session(&client, &base, root))
        .await
        .unwrap_or_else(|_| panic!("the session setup hung\n{}", logs(root)));

    // The request the stop finds open: its backend never answers.
    let call = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": TOOL, "arguments": {} }
        }
    });
    let open = tokio::spawn({
        let client = client.clone();
        let base = base.clone();
        async move { post(&client, &base, Some(&session), &call).await }
    });
    let called = root.join("called");
    let started_by = tokio::time::Instant::now() + READY_BOUND;
    while !called.exists() {
        assert!(
            tokio::time::Instant::now() < started_by,
            "the backend call never started\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Before the signal: the request is still open, and neither save file
    // exists yet, so the ones found after the stop were written by it.
    assert!(
        !open.is_finished(),
        "the request ended before the stop\n{}",
        logs(root)
    );
    let state = root.join("gateway-state");
    for file in SAVE_FILES {
        assert!(!state.join(file).exists(), "{file} existed before the stop");
    }
    let log_before = logs(root).len();

    // The supervisor: SIGTERM, then SIGKILL once the grace is over. The
    // gateway passes only if it exits by itself first.
    let signalled = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("kill runs");
    assert!(signalled.success(), "the signal was delivered");
    let (exited, marked_while_running) =
        wait_for_exit(gateway.child_mut(), &root.join("stopped")).await;
    if exited.is_err() {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    assert!(
        matches!(&exited, Ok(Ok(status)) if status.success()),
        "with a request open, the stop did not end cleanly inside the {GRACE:?} grace \
         (total {STOP_TOTAL:?}): {exited:?}\n{}",
        logs(root)
    );
    assert_teardown(root, log_before, marked_while_running);
}

type Exited = Result<std::io::Result<std::process::ExitStatus>, tokio::time::error::Elapsed>;

/// Waits up to [`GRACE`] for the gateway to exit, noting whether the backend's
/// mark appeared while the gateway was still running: a mark counts only when
/// the gateway is confirmed still running right after it is seen.
async fn wait_for_exit(child: &mut tokio::process::Child, mark: &Path) -> (Exited, bool) {
    let mut marked_while_running = false;
    let exited = tokio::time::timeout(GRACE, async {
        loop {
            tokio::select! {
                biased;
                status = child.wait() => break status,
                () = tokio::time::sleep(Duration::from_millis(20)) => {
                    // A mark counts only if the gateway is still running after it
                    // is seen: then it was written before the exit could close
                    // the pipe. `try_wait` asks the OS, not the runtime's notice.
                    if !marked_while_running && mark.exists() {
                        match child.try_wait() {
                            Ok(None) => marked_while_running = true,
                            Ok(Some(status)) => break Ok(status),
                            Err(e) => break Err(e),
                        }
                    }
                }
            }
        }
    })
    .await;
    (exited, marked_while_running)
}

/// What the stop must have done by the time the gateway has exited.
fn assert_teardown(root: &Path, log_before: usize, marked_while_running: bool) {
    // The backend's mark, seen while the gateway still ran: only its backend
    // stage closes the backend's stdin before the gateway exits.
    assert!(
        marked_while_running,
        "the backend's stdin was not closed by the backend stage while the gateway ran\n{}",
        logs(root)
    );
    // Only what the stop logged: lines from before the signal do not count.
    let log_text = logs(root);
    let after = &log_text[log_before..];
    for line in [
        "Saved search ranking usage data",
        "Saved transition tracking data",
        "Shutting down backends",
    ] {
        assert!(after.contains(line), "the stop skipped {line:?}\n{after}");
    }
    let state = root.join("gateway-state");
    for file in SAVE_FILES {
        let text = std::fs::read_to_string(state.join(file))
            .unwrap_or_else(|e| panic!("the stop did not write {file}: {e}\n{after}"));
        serde_json::from_str::<Value>(&text)
            .unwrap_or_else(|e| panic!("{file} is not whole JSON: {e}: {text:?}"));
        // The held call was admitted, and admission records the tool's use: a
        // usage save that wrote nothing it held fails. (A transition needs two
        // calls in a session, so transitions.json holds none here.)
        if file == "usage.json" {
            let rows: Vec<Value> = serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("{file} is not a list of rows: {e}: {text:?}"));
            assert!(
                rows.iter().any(|row| row["server"] == BACKEND
                    && row["tool"] == TOOL
                    && row["count"].as_u64() >= Some(1)),
                "{file} holds no use of {BACKEND}:{TOOL}: {text:?}"
            );
        }
    }
}
