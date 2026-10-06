// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.REPLICA.1 — the built binary refuses per-process state under
//! `server.replicas: 2`, and a config that never names `server.replicas`
//! still starts.
//!
//! The pure refusal is pinned in `src/gateway/server/replica_state_tests.rs`.
//! These prove the start path asks it: a gateway that skipped the call would
//! bind and serve, and the wait below would time out on a running process.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

/// Starts the binary on `yaml` (appended after the `server:` host and an
/// OS-chosen port, with a temp task store) and returns the child and its log path.
fn spawn(dir: &Path, yaml: &str) -> (Child, std::path::PathBuf) {
    let config = dir.join("gateway.yaml");
    let log = dir.join("gateway.log");
    let text = format!(
        "server:\n  host: 127.0.0.1\n  port: {}\n{yaml}tasks:\n  store_dir: {}\n",
        gateway_bin::ANY_PORT,
        dir.join("tasks").display()
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, text).expect("write config");
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log handle");
    let mut command = gateway_bin::command(dir, gateway_bin::Inherit::Environment);
    let child = command
        .env("MCP_GATEWAY_CONFIG_DIR", dir.join("state"))
        .current_dir(dir)
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("the built mcp-gateway binary spawns");
    (child, log)
}

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// The gateway must exit non-zero within a minute, naming `reason`.
fn assert_refused(yaml: &str, reason: &str) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, log) = spawn(dir.path(), yaml);
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait on the gateway") {
            break status;
        }
        if Instant::now() > deadline {
            stop(child);
            let logs = std::fs::read_to_string(&log).unwrap_or_default();
            panic!("the gateway kept running at replicas: 2:\n{logs}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let logs = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(!status.success(), "the gateway exited 0:\n{logs}");
    assert!(
        logs.contains(reason),
        "the refusal must name {reason}:\n{logs}"
    );
}

#[test]
fn startup_refuses_key_server_with_two_replicas() {
    assert_refused(
        "  replicas: 2\n  modern_protocol: false\nauth:\n  enabled: false\nkey_server:\n  enabled: true\n",
        "InMemoryTokenStore",
    );
}

/// F7: the stock config serves the modern protocol, and so the task store.
#[test]
fn startup_refuses_stock_config_with_two_replicas() {
    assert_refused("  replicas: 2\nauth:\n  enabled: false\n", "task store");
}

/// A 3.x-shaped config names no `server.replicas`: it loads as 1 and serves.
#[test]
fn config_without_replicas_starts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, log) = spawn(dir.path(), "auth:\n  enabled: false\n");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait().expect("wait on the gateway") {
            let logs = std::fs::read_to_string(&log).unwrap_or_default();
            panic!("a config without server.replicas exited {status}:\n{logs}");
        }
        if gateway_bin::logged_port(&log).is_some_and(gateway_bin::answers_livez) {
            break;
        }
        if Instant::now() > deadline {
            stop(child);
            let logs = std::fs::read_to_string(&log).unwrap_or_default();
            panic!("a config without server.replicas never answered /livez:\n{logs}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    stop(child);
}
