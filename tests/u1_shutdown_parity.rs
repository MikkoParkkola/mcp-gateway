// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U1 shutdown parity (MIK-7211.PARENT.5, #2469), against the built binary.
//!
//! A POST is held in its body read (headers and half the body sent) while the
//! gateway receives SIGTERM; the rest of the body follows after the shutdown
//! broadcast. With `server.protocol_revision_window: off` (the default) the
//! request is served as in 3.5.x. With `record`, the segment sealed on the
//! broadcast, so the request reaches counting after the seal and is refused
//! with 503, unserved.
// Unix-only: the case stops the gateway with SIGTERM, which Windows has no equivalent of.
#![cfg(unix)]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("a free loopback port")
}

fn spawn(dir: &Path, port: u16, window: &str) -> (Child, std::path::PathBuf) {
    let config = dir.join("gateway.yaml");
    let log = dir.join("gateway.log");
    let text = format!(
        "server:\n  host: 127.0.0.1\n  port: {port}\n  protocol_revision_window: {window}\n\
         auth:\n  enabled: false\ntasks:\n  store_dir: {}\n",
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

fn answers_livez(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let request =
        format!("GET /livez HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let mut answer = String::new();
    stream.write_all(request.as_bytes()).is_ok()
        && stream.read_to_string(&mut answer).is_ok()
        && answer.starts_with("HTTP/1.1 200")
}

/// Hold a request in its body read across SIGTERM; return the raw response.
fn request_held_across_sigterm(window: &str) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let (mut child, log) = spawn(dir.path(), port, window);
    let logs = || std::fs::read_to_string(&log).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !answers_livez(port) {
        if let Some(status) = child.try_wait().expect("wait on the gateway") {
            panic!("the gateway exited {status} before serving:\n{}", logs());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the gateway never answered /livez:\n{}", logs());
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let body = r#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"parity","version":"0"}}}"#;
    let (head, tail) = body.split_at(body.len() / 2);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Accept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{head}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .expect("send headers and half the body");
    // Let the handler reach its body read before the signal.
    std::thread::sleep(Duration::from_millis(300));

    let signalled = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("run kill");
    assert!(signalled.success(), "SIGTERM was not delivered");
    // Past the shutdown broadcast, so a `record` gateway has sealed.
    std::thread::sleep(Duration::from_millis(500));
    stream
        .write_all(tail.as_bytes())
        .expect("send the rest of the body");
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);

    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("wait on the gateway").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the gateway did not exit after SIGTERM:\n{}", logs());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    (answer, logs())
}

#[test]
fn window_off_serves_a_request_in_its_body_read_across_sigterm() {
    let (answer, logs) = request_held_across_sigterm("off");
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "with the window off, shutdown must serve the request as 3.5.x did: {answer}\n{logs}"
    );
    assert!(!answer.contains("U1 window sealed"), "{answer}");
}

#[test]
fn window_record_refuses_a_request_counted_after_the_seal() {
    let (answer, logs) = request_held_across_sigterm("record");
    assert!(
        answer.starts_with("HTTP/1.1 503"),
        "with the window recording, a request counted after the seal is refused: {answer}\n{logs}"
    );
    assert!(answer.contains("U1 window sealed"), "{answer}");
    assert!(
        answer.contains("\"id\":7"),
        "the refusal carries the request's id: {answer}"
    );
}
