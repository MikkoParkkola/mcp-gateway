// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U1 v2 design row 19: an HTTP `serve` with `--protocol-revision-window
//! record` (the hidden flag that replaced the config key, MIK-8783) that
//! serves a request and is then killed (`SIGKILL`) leaves its segment in
//! the window, unclean, so the window blocks. It never leaves no segment: the
//! segment is opened before the listener serves, not at the first periodic
//! save, so a crash cannot hide a process that served traffic.
//!
//! The real binary, so the kill is a real process death. The binary has no
//! knob to stop its periodic save (every 5 s), so the row kills it (`SIGKILL`) at once
//! after the first response and asserts the kill landed inside 5 s of the
//! spawn: before any periodic save could have created the file, so only the
//! open-before-serving can explain a segment. A slower run fails rather than
//! passing for that wrong reason. The ordering itself is pinned in-crate
//! (`the_segment_is_open_before_serving_and_sealed_on_the_broadcast`).
#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::process::Stdio;
use std::time::{Duration, Instant};

/// Bound on each wait for something that must happen.
const ARRIVAL: Duration = Duration::from_secs(60);
/// The shipped window save interval (`WINDOW_SAVE_INTERVAL`); the kill must
/// land before the first periodic save could.
const FIRST_PERIODIC_SAVE: Duration = Duration::from_secs(5);

#[test]
fn a_record_gateway_killed_after_serving_leaves_an_unclean_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let config = dir.path().join("gateway.yaml");
    let log = dir.path().join("gateway.log");
    let text = format!(
        "server:\n  host: 127.0.0.1\n  port: {}\nauth:\n  enabled: false\ntasks:\n  store_dir: {}\n",
        gateway_bin::ANY_PORT,
        dir.path().join("tasks").display()
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, text).expect("write config");
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log handle");
    let mut child = gateway_bin::command(dir.path(), gateway_bin::Inherit::Environment)
        .env("MCP_GATEWAY_CONFIG_DIR", &state)
        .current_dir(dir.path())
        .arg("--config")
        .arg(&config)
        .args(["--protocol-revision-window", "record"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("the built mcp-gateway binary spawns");

    let spawned = Instant::now();
    let start = spawned;
    let port = loop {
        if let Some(port) =
            gateway_bin::logged_port(&log).filter(|p| gateway_bin::answers_livez(*p))
        {
            break port;
        }
        if start.elapsed() > ARRIVAL || child.try_wait().expect("wait").is_some() {
            let _ = child.kill();
            panic!(
                "the gateway never served:\n{}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        post_initialize(port).starts_with("HTTP/1.1 200"),
        "the request was not served"
    );

    child.kill().expect("SIGKILL");
    let killed_after = spawned.elapsed();
    let _ = child.wait();
    // timing-oracle: vs WINDOW_SAVE_INTERVAL (MIK-7211)
    assert!(
        killed_after < FIRST_PERIODIC_SAVE,
        "inconclusive: the kill landed {killed_after:?} after spawn, when a periodic save may \
         already have written the file; rerun on a less loaded host"
    );

    let path = state
        .join("protocol-revision-telemetry")
        .join("window.json");
    let window: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("a served process left its window file"),
    )
    .expect("window.json is JSON");
    let segments = window["http_segments"].as_array().expect("http_segments");
    assert_eq!(segments.len(), 1, "{window:#}");
    assert_eq!(segments[0]["closed_cleanly"], false, "{window:#}");
    assert!(segments[0]["sealed_at_ms"].is_null(), "{window:#}");
}

fn post_initialize(port: u16) -> String {
    use std::io::{Read as _, Write as _};
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "row19", "version": "1"}}
    })
    .to_string();
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(ARRIVAL)).expect("timeout");
    write!(
        stream,
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("send");
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
}
