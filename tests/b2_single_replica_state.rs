// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.REPLICA.1 — the built binary refuses to serve the key server under
//! `server.replicas: 2`.
//!
//! The pure refusal is pinned in `src/gateway/server/replica_state_tests.rs`.
//! This proves the start path asks it: a gateway that skipped the call would
//! bind and serve, and the wait below would time out on a running process.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("a free loopback port")
}

#[test]
fn startup_refuses_key_server_with_two_replicas() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    let log = dir.path().join("gateway.log");
    let yaml = format!(
        "server:\n  host: 127.0.0.1\n  port: {port}\n  replicas: 2\n  modern_protocol: false\n\
         auth:\n  enabled: false\n\
         key_server:\n  enabled: true\n\
         tasks:\n  store_dir: {tasks}\n",
        port = free_port(),
        tasks = dir.path().join("tasks").display(),
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, yaml).expect("write config");

    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log handle");
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MCP_GATEWAY_") {
            command.env_remove(key);
        }
    }
    let mut child = command
        .env("HOME", dir.path())
        .env("MCP_GATEWAY_CONFIG_DIR", dir.path().join("state"))
        .current_dir(dir.path())
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("the built mcp-gateway binary spawns");

    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait on the gateway") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            let logs = std::fs::read_to_string(&log).unwrap_or_default();
            panic!("the gateway kept running with key_server at replicas: 2:\n{logs}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let logs = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(!status.success(), "the gateway exited 0:\n{logs}");
    assert!(
        logs.contains("InMemoryTokenStore"),
        "the refusal must name the per-process token store:\n{logs}"
    );
}
