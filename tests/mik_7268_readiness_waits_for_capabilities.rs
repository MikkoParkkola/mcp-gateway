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
        serde_yaml::to_string(&config).expect("config YAML"),
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
}
