// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8364: SIGTERM ends the shipped stdio gateway through its graceful
//! path, and its final save holds every request it observed.
//!
//! The real binary, in its own process, so the saved window holds only this
//! process's observations and the count is exact. Before MIK-8364 stdio had
//! no signal handler: SIGTERM killed it, and only the per-request save (now
//! gone, it cost ~7-18 ms per request) kept the counts.
#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use serde_json::{Value, json};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Requests sent before the signal.
const PINGS: u64 = 10;
/// Bound on each wait for something that must happen.
const ARRIVAL: Duration = Duration::from_secs(60);

#[tokio::test]
async fn sigterm_ends_stdio_gracefully_and_saves_every_observed_request() {
    let temp = tempfile::tempdir().expect("isolated home");
    let config = temp.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, String::new())
        .expect("write config");
    let mut command = tokio::process::Command::from(gateway_bin::command(
        temp.path(),
        gateway_bin::Inherit::Environment,
    ));
    command
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "serve",
            "--stdio",
        ])
        .current_dir(temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("spawn shipped binary");
    // Held open to the end: only the signal may stop this session.
    let mut stdin = child.stdin.take().expect("stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();

    let mut frames = vec![
        json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "mik8364-sigterm", "version": "0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ];
    frames.extend((1..=PINGS).map(|id| json!({"jsonrpc": "2.0", "id": id, "method": "ping"})));
    for frame in &frames {
        stdin
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("stdin accepts the frame");
    }
    tokio::time::timeout(ARRIVAL, async {
        loop {
            let line = lines
                .next_line()
                .await
                .expect("stdout reads")
                .expect("stdout stays open until the last ping is answered");
            if serde_json::from_str::<Value>(&line).is_ok_and(|frame| frame["id"] == json!(PINGS)) {
                return;
            }
        }
    })
    .await
    .expect("the last ping is answered");

    let pid = child.id().expect("the child is running").to_string();
    let sent = std::process::Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("run kill");
    assert!(sent.success(), "kill -TERM {pid} failed");

    let status = tokio::time::timeout(ARRIVAL, child.wait())
        .await
        .expect("stdio ends after SIGTERM")
        .expect("reap child");
    assert!(
        status.success(),
        "SIGTERM must end stdio through its graceful path, not kill it: {status}"
    );
    drop(stdin);

    // Read as raw JSON, like tests/u1_v1_window_grade.rs: the window loader
    // is crate-private since the v2 window (MIK-7211).
    let path = mcp_gateway::protocol_revision_telemetry::durable_window_path(
        &temp.path().join(".mcp-gateway"),
    );
    let saved: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the window file reads"))
            .expect("the window file is JSON");
    let saved = &saved["stdio"];
    let saved_stdio = saved["by_transport"]["stdio"].as_u64().unwrap_or(0);
    assert!(
        saved_stdio > PINGS,
        "the window saved after SIGTERM holds {saved_stdio} stdio requests; {} were observed: {saved:?}",
        PINGS + 2
    );
}
