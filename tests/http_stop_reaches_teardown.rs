// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A SIGTERM reaches the teardown while an HTTP request is still open (#5043),
//! and the whole stop fits `shutdown_timeout`.
//!
//! The listener used to wait without limit for every accepted connection to
//! close, so a request that never ends (a streaming response, a call whose
//! backend never answers) held the stop there: `stop_all` and the saves never
//! ran, and the supervisor's grace ended in SIGKILL. Red on the base: the
//! gateway is still running when the hang guard passes.
//!
//! A bound alone is not enough. Red on a bound that leaves the request's
//! handler running and gives each wait a fresh timeout:
//! - the in-flight drain then waits out a second full timeout for that handler,
//!   so the stop takes about twice the setting (it takes once here);
//! - the saves run while the handler can still change what they write (here
//!   the held request is dropped first, so the drain sees every request end,
//!   and the saves come after it).
#![cfg(unix)]

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
use serde_json::{Value, json};

const PROTOCOL_VERSION: &str = "2025-11-25";
const BACKEND: &str = "silent";
const TOOL: &str = "never_answers";
const READY_BOUND: Duration = Duration::from_secs(60);
/// The stop's total. Large enough that one total (about 6 s) and two or three
/// in series (12 s or more) cannot be confused on a loaded host.
const STOP_TOTAL: Duration = Duration::from_secs(6);
/// What the stop may take past its total: the saves and the backend stage,
/// which run after the last wait, with room for a loaded host. Under the 6 s a
/// second full timeout would add.
const STOP_MARGIN: Duration = Duration::from_secs(4);
/// The hang guard: a stop that never ends (the unbounded listener) fails here.
const STOP_BOUND: Duration = Duration::from_secs(60);

/// A stdio MCP server in Python that never answers `tools/call`: it marks the
/// call started and goes on reading.
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
"#;

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    listener.local_addr().expect("its address").port()
}

fn write_config(root: &Path, port: u16) -> std::path::PathBuf {
    std::fs::write(
        root.join("backend.py"),
        BACKEND_SCRIPT.replace("TOOL", TOOL),
    )
    .expect("write backend");
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = port;
    config.server.shutdown_timeout = STOP_TOTAL;
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
            timeout: Duration::from_secs(600),
            ..BackendConfig::default()
        },
    );
    let path = root.join("gateway.yaml");
    std::fs::write(&path, serde_yaml::to_string(&config).expect("config yaml")).expect("write");
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

/// The gateway's log as plain text: the file carries the terminal colour codes
/// the logger puts around field names (`backend=silent` is split by them).
fn logs(root: &Path) -> String {
    let raw = std::fs::read_to_string(root.join("gateway.log")).unwrap_or_default();
    let mut plain = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // An SGR sequence, ESC [ ... m: skip through its final `m`.
            for d in chars.by_ref() {
                if d == 'm' {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
}

#[tokio::test]
async fn a_sigterm_reaches_stop_all_while_a_request_is_still_open() {
    let root = tempfile::tempdir().expect("temp root");
    let root = root.path();
    let port = free_port();
    let config = write_config(root, port);
    let log = std::fs::File::create(root.join("gateway.log")).expect("log");

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
        .spawn()
        .expect("the gateway binary spawns");
    let _cleanup = KillPid(gateway.id());

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

    let init = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "HttpStopBoundTest", "version": "1.0.0" }
        }
    });
    let (body, session) = post(&client, &base, None, &init)
        .await
        .unwrap_or_else(|e| panic!("initialize failed: {e}\n{}", logs(root)));
    let session = session.unwrap_or_else(|| panic!("no session id: {body}\n{}", logs(root)));
    post(
        &client,
        &base,
        Some(&session),
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await
    .unwrap_or_else(|e| panic!("initialized failed: {e}\n{}", logs(root)));

    // The request the stop finds open: its backend never answers, so it holds
    // its connection for as long as the gateway lets it.
    let call = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": TOOL, "arguments": {} }
        }
    });
    let _open = tokio::spawn({
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

    // What a supervisor sends: SIGTERM to the gateway only, so the backend
    // can only learn of the stop from the gateway's `stop_all`.
    let signalled = std::process::Command::new("kill")
        .args(["-TERM", &gateway.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(signalled.success(), "the signal was delivered");
    let signalled_at = std::time::Instant::now();

    let exited = tokio::time::timeout(
        STOP_BOUND,
        tokio::task::spawn_blocking(move || gateway.wait()),
    )
    .await;
    let took = signalled_at.elapsed();
    assert!(
        matches!(&exited, Ok(Ok(Ok(status))) if status.success()),
        "with a request still open, the gateway did not finish its stop: {exited:?}\n{}",
        logs(root)
    );
    // One total for the whole stop: a second fresh timeout for the in-flight
    // drain would add another STOP_TOTAL here.
    assert!(
        took < STOP_TOTAL + STOP_MARGIN,
        "the stop took {took:?}, past its total {STOP_TOTAL:?} plus {STOP_MARGIN:?}\n{}",
        logs(root)
    );
    // The gateway's own record, complete once the process has exited: the held
    // request was dropped, so the in-flight drain saw every request end; the
    // saves came after that drain; and the backend stage ran and reached this
    // backend.
    let log_text = logs(root);
    let at = |line: &str| {
        log_text
            .find(line)
            .unwrap_or_else(|| panic!("the stop never logged {line:?}\n{log_text}"))
    };
    let drained = at("All in-flight requests completed");
    let saved = at("Saved search ranking usage data");
    assert!(
        drained < saved,
        "the saves ran before the in-flight drain ended\n{log_text}"
    );
    at("Shutting down backends");
    at(&format!("Stopping backend backend={BACKEND}"));
}

/// SIGKILLs a pid when the row ends, so a red run leaks no gateway.
struct KillPid(u32);

impl Drop for KillPid {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &self.0.to_string()])
            .stderr(Stdio::null())
            .status();
    }
}
