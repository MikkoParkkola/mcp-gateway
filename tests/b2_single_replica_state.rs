// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.REPLICA.1 — the built binary refuses per-process state under
//! `server.replicas: 2`, and a config that never names `server.replicas`
//! still starts.
//!
//! The pure refusal is pinned in `src/gateway/server/replica_state_tests.rs`.
//! These prove the start path asks it: a gateway that skipped the call would
//! bind and serve, and the wait below would time out on a running process.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("a free loopback port")
}

/// Starts the binary on `yaml` (appended after the `server:` host and port,
/// with a temp task store) and returns the child and its log path.
fn spawn(dir: &Path, port: u16, yaml: &str) -> (Child, std::path::PathBuf) {
    let config = dir.join("gateway.yaml");
    let log = dir.join("gateway.log");
    let text = format!(
        "server:\n  host: 127.0.0.1\n  port: {port}\n{yaml}tasks:\n  store_dir: {}\n",
        dir.join("tasks").display()
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, text).expect("write config");
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log handle");
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MCP_GATEWAY_") {
            command.env_remove(key);
        }
    }
    let child = command
        .env("HOME", dir)
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
    let (mut child, log) = spawn(dir.path(), free_port(), yaml);
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
    let port = free_port();
    let (mut child, log) = spawn(dir.path(), port, "auth:\n  enabled: false\n");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait().expect("wait on the gateway") {
            let logs = std::fs::read_to_string(&log).unwrap_or_default();
            panic!("a config without server.replicas exited {status}:\n{logs}");
        }
        if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let request = format!(
                "GET /livez HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            );
            let mut answer = String::new();
            if stream.write_all(request.as_bytes()).is_ok()
                && stream.read_to_string(&mut answer).is_ok()
                && answer.starts_with("HTTP/1.1 200")
            {
                break;
            }
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
