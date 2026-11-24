// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7268: the shipped binary does not report ready before its capability
//! catalogue has loaded.
//!
//! Startup installs the capability backend empty and scans the directories in
//! the background, after a deliberate pause that lets the listener bind first.
//! A readiness probe that answered 200 in that window routed traffic to a
//! gateway whose every capability call failed.
//!
//! The scan is held until the test has seen the loading answer (a debug-build
//! gate file, `MCP_GATEWAY_TEST_HOLD_CAPABILITY_SCAN`, #2376), so that answer
//! does not depend on the load being slower than the first probe.
//!
//! The same held scan pins the status tools: `gateway_list_servers` and
//! `gateway_get_stats` must not call a half-loaded catalogue's count known.

#[path = "common/yaml.rs"]
mod yaml;

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::process::{Child, Command};

const CAPABILITIES: usize = 1000;
const TOKEN: &str = "mik-7268-admin";
const DEADLINE: Duration = Duration::from_secs(60);
const HOLD_WINDOW: Duration = Duration::from_secs(2);
const HOLD_SCAN_ENV: &str = "MCP_GATEWAY_TEST_HOLD_CAPABILITY_SCAN";

fn write_capabilities(dir: &Path) {
    std::fs::create_dir_all(dir).expect("capability dir");
    for i in 0..CAPABILITIES {
        let body = format!(
            "name: cap_{i:04}\ndescription: Readiness fixture {i}\nproviders:\n  primary:\n    \
             service: rest\n    config:\n      base_url: https://example.com\n      path: /r{i}\n"
        );
        std::fs::write(dir.join(format!("cap_{i:04}.yaml")), body).expect("write capability");
    }
}

fn spawn(directory: &Path, scan_gate: &Path) -> Child {
    let caps = directory.join("caps");
    let config = json!({
        "server": {"host": "127.0.0.1", "port": gateway_bin::ANY_PORT},
        "auth": {"enabled": true, "bearer_token": TOKEN, "public_paths": ["/health"]},
        // Relative to the child's cwd: HOME cannot isolate the store on Windows.
        "tasks": {"store_dir": "tasks"},
        // Auth on requires an audit log (UPGRADING-4.0 item 43).
        "security": {"transparency_log": {
            "enabled": true, "path": directory.join("audit").join("log.jsonl")
        }},
        "capabilities": {"enabled": true, "directories": [caps.to_string_lossy()]},
    });
    let config_path = directory.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config_path,
        yaml::to_string(&config).expect("config YAML"),
    )
    .expect("write gateway config");
    let log = std::fs::File::create(directory.join("gateway.log")).expect("gateway log");
    Command::from(gateway_bin::command(
        directory,
        gateway_bin::Inherit::Nothing,
    ))
    .env(HOLD_SCAN_ENV, scan_gate)
    .env("XDG_CONFIG_HOME", directory.join(".config"))
    .env("PATH", std::env::var_os("PATH").unwrap_or_default())
    .current_dir(directory)
    .arg("--config")
    .arg(&config_path)
    .arg("serve")
    .stdin(Stdio::null())
    .stdout(Stdio::from(log.try_clone().expect("clone log")))
    .stderr(Stdio::from(log))
    .kill_on_drop(true)
    .spawn()
    .expect("spawn gateway")
}

/// Poll `/readyz` unauthenticated until it answers 200, returning the base URL
/// and every answer seen before it. The child binds [`gateway_bin::ANY_PORT`],
/// so the port is read from its log first; refusals before that are skipped.
/// The scan stays held for `HOLD_WINDOW` after the first "capabilities loading"
/// answer, and a 200 inside that window fails the test: without the hold the
/// 1000-file load finishes well inside it, so a removed or ignored hook fails
/// every run rather than passing on the natural race.
async fn readyz_until_ready(
    client: &reqwest::Client,
    child: &mut Child,
    directory: &Path,
    scan_gate: &Path,
) -> (String, Vec<(u16, String)>) {
    let log = directory.join("gateway.log");
    let logs = || std::fs::read_to_string(&log).unwrap_or_default();
    let start = tokio::time::Instant::now();
    let mut seen = Vec::new();
    let mut held_since: Option<tokio::time::Instant> = None;
    let mut url = None;
    loop {
        if let Some(status) = child.try_wait().expect("gateway status") {
            panic!("gateway exited {status}: {}", logs());
        }
        if url.is_none() {
            url = gateway_bin::logged_port(&log).map(|port| format!("http://127.0.0.1:{port}"));
        }
        if let Some(url) = &url
            && let Ok(response) = client.get(format!("{url}/readyz")).send().await
        {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            if status == 503 && body == "capabilities loading" {
                held_since.get_or_insert_with(tokio::time::Instant::now);
            }
            seen.push((status, body));
            if status == 200 {
                assert!(
                    scan_gate.exists(),
                    "the scan finished before its gate was released"
                );
                return (url.clone(), seen);
            }
        }
        if held_since.is_some_and(|since| since.elapsed() >= HOLD_WINDOW) && !scan_gate.exists() {
            std::fs::write(scan_gate, "release").expect("release the scan gate");
        }
        assert!(
            start.elapsed() < DEADLINE,
            "never ready; seen {seen:?}: {}",
            logs()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Poll `/readyz` until it answers 503 "capabilities loading", returning the
/// base URL. Never releases the gate, so the scan is still held on return.
async fn url_while_loading(
    client: &reqwest::Client,
    child: &mut Child,
    directory: &Path,
) -> String {
    let log = directory.join("gateway.log");
    let logs = || std::fs::read_to_string(&log).unwrap_or_default();
    let start = tokio::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("gateway status") {
            panic!("gateway exited {status}: {}", logs());
        }
        if let Some(port) = gateway_bin::logged_port(&log) {
            let url = format!("http://127.0.0.1:{port}");
            if let Ok(response) = client.get(format!("{url}/readyz")).send().await {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if status == 503 && body == "capabilities loading" {
                    return url;
                }
                assert_ne!(status, 200, "ready while the scan is held: {}", logs());
            }
        }
        assert!(
            start.elapsed() < DEADLINE,
            "never reported loading: {}",
            logs()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// One meta-tool call over `/mcp` with the admin token, in a fresh session;
/// returns the tool's own JSON answer.
async fn call_tool(client: &reqwest::Client, url: &str, name: &str) -> Value {
    let post = |sid: Option<String>, body: Value| {
        let mut request = client
            .post(format!("{url}/mcp"))
            .bearer_auth(TOKEN)
            .header("accept", "application/json")
            .json(&body);
        if let Some(sid) = sid {
            request = request.header("mcp-session-id", sid);
        }
        request.send()
    };
    let init = post(
        None,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "readiness-status", "version": "1"}}}),
    )
    .await
    .expect("initialize");
    let sid = init
        .headers()
        .get("mcp-session-id")
        .map(|v| v.to_str().expect("ASCII").to_owned());
    post(
        sid.clone(),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await
    .expect("initialized");
    let answer: Value = post(
        sid,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": name, "arguments": {}}}),
    )
    .await
    .expect("tools/call")
    .json()
    .await
    .expect("a JSON answer");
    let text = answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} answered without text content: {answer}"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{name} answer is not JSON ({e}): {text}"))
}

/// The capability backend's row of a `gateway_list_servers` answer.
fn capability_row(servers: &Value) -> Value {
    servers["servers"]
        .as_array()
        .expect("servers is an array")
        .iter()
        .find(|s| s["transport"] == "capability")
        .cloned()
        .unwrap_or_else(|| panic!("the capability backend is listed: {servers}"))
}

/// Stop the gateway the way an operator would, so a coverage build writes
/// its profile on exit; `kill_on_drop` stays as the backstop.
async fn stop(child: Child) {
    #[cfg(unix)]
    {
        let mut child = child;
        let pid = child.id().expect("the gateway is still running");
        let signalled = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .expect("run kill");
        assert!(signalled.success(), "SIGTERM was not delivered");
        tokio::time::timeout(Duration::from_secs(60), child.wait())
            .await
            .expect("the gateway exits after SIGTERM")
            .expect("wait on the gateway");
    }
    #[cfg(not(unix))]
    drop(child);
}

#[tokio::test]
async fn readyz_is_not_ready_until_every_capability_has_loaded() {
    let directory = tempfile::tempdir().expect("gateway directory");
    write_capabilities(&directory.path().join("caps"));
    std::fs::create_dir_all(directory.path().join("audit")).expect("audit dir");
    let scan_gate = directory.path().join("scan-gate");
    let mut child = spawn(directory.path(), &scan_gate);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    let (url, seen) = readyz_until_ready(&client, &mut child, directory.path(), &scan_gate).await;
    assert!(
        seen.iter()
            .any(|(status, body)| *status == 503 && body == "capabilities loading"),
        "/readyz answered 200 without first reporting the catalogue as loading: {seen:?}"
    );

    let admin: Value = client
        .get(format!("{url}/health"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("admin /health")
        .json()
        .await
        .expect("admin /health JSON");
    let backend = &admin["capability_backend"];
    assert_eq!(
        backend["capabilities_count"], CAPABILITIES,
        "ready with a partial catalogue: {admin}"
    );
    assert_eq!(backend["loaded"], true, "{admin}");

    stop(child).await;
}

/// The status tools on the same held scan. While it is held,
/// `gateway_list_servers` lists the capability backend with `tools_count` null
/// and `tools_known` false, and `gateway_get_stats` says `tools_known` false
/// with its total a number: the floor of what is loaded, nothing yet. Once the
/// scan completes both say known, with the whole catalogue counted. One
/// gateway, both states, over `/mcp`.
#[tokio::test]
async fn the_status_tools_withhold_the_capability_count_until_the_scan_completes() {
    let directory = tempfile::tempdir().expect("gateway directory");
    write_capabilities(&directory.path().join("caps"));
    std::fs::create_dir_all(directory.path().join("audit")).expect("audit dir");
    let scan_gate = directory.path().join("scan-gate");
    let mut child = spawn(directory.path(), &scan_gate);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    let url = url_while_loading(&client, &mut child, directory.path()).await;
    let during = capability_row(&call_tool(&client, &url, "gateway_list_servers").await);
    assert_eq!(
        during.get("tools_count"),
        Some(&Value::Null),
        "mid-scan the capability count is not known: null, never a number: {during}"
    );
    assert_eq!(during["tools_known"], false, "mid-scan: {during}");
    let stats = call_tool(&client, &url, "gateway_get_stats").await;
    assert_eq!(
        stats["tools_known"], false,
        "mid-scan the total is not final: {stats}"
    );
    assert_eq!(
        stats["tools_available"], 0,
        "mid-scan the total is the floor of what is loaded (the scan has read nothing): {stats}"
    );
    assert!(
        !scan_gate.exists(),
        "premise: every answer above came while the scan was held"
    );

    std::fs::write(&scan_gate, "release").expect("release the scan gate");
    let (url, _) = readyz_until_ready(&client, &mut child, directory.path(), &scan_gate).await;
    let after = capability_row(&call_tool(&client, &url, "gateway_list_servers").await);
    assert_eq!(
        after["tools_count"], CAPABILITIES,
        "after the scan the whole catalogue is counted: {after}"
    );
    assert_eq!(after["tools_known"], true, "after the scan: {after}");
    let stats = call_tool(&client, &url, "gateway_get_stats").await;
    assert_eq!(stats["tools_known"], true, "after the scan: {stats}");
    assert_eq!(
        stats["tools_available"], CAPABILITIES,
        "after the scan the total is the whole catalogue: {stats}"
    );

    stop(child).await;
}
