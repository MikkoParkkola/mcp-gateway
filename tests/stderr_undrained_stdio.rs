// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! L1j: the shipped stdio gateway, logging at trace, with a stderr nobody
//! reads still answers every request and exits once stdin closes (L1j-a).
//! With stderr drained, the same session logs more than a pipe holds, so the
//! undrained run is a real test, and its last line reaches stderr (L1j-b).
#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use serde_json::{Value, json};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Pings in a session: at trace, well over 1 MiB of log lines.
const PINGS: u64 = 20_000;
/// Pings in flight at once, under the gateway's cap of 64.
const WINDOW: u64 = 32;
/// Past this the child is taken to have stalled on its stderr.
const KILL_TIMER: Duration = Duration::from_secs(60);
/// The last line the stdio path logs before the process exits.
const LAST_LINE: &str = "stdio: shutdown complete";

/// What the test does with the child's stderr.
#[derive(Clone, Copy)]
enum Stderr {
    /// Held open and never read.
    Unread,
    /// Read to the end and returned.
    Drained,
}

/// Write `frames` to the child's stdin, one per line.
async fn send(stdin: &mut tokio::process::ChildStdin, frames: &[Value]) {
    for frame in frames {
        stdin
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("stdin accepts the frame");
    }
}

/// One session: initialize, `PINGS` pings, then stdin closes. Asserts every
/// request is answered and the child exits cleanly within the kill timer;
/// returns the child's stderr when it is drained.
async fn session(stderr: Stderr) -> Vec<u8> {
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
        .env("RUST_LOG", "trace")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("spawn shipped binary");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let err = child.stderr.take().expect("stderr");
    let (held, drained) = match stderr {
        Stderr::Unread => (Some(err), None),
        Stderr::Drained => {
            let mut err = err;
            let reader = tokio::spawn(async move {
                let mut bytes = Vec::new();
                err.read_to_end(&mut bytes).await.expect("stderr reads");
                bytes
            });
            (None, Some(reader))
        }
    };

    // Sent in windows under the gateway's in-flight cap (64), each answered
    // before the next is sent: past the cap the gateway refuses as busy, and
    // the test is about stderr, not about that refusal.
    let run = async {
        let mut lines = BufReader::new(stdout).lines();
        let mut answered = 0_u64;
        let mut replies = 0_u64;
        send(
            &mut stdin,
            &[
                json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "l1j-stderr", "version": "0"}}}),
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            ],
        )
        .await;
        let mut sent = 1_u64;
        let mut next = 1_u64;
        loop {
            while replies < sent {
                let line = lines
                    .next_line()
                    .await
                    .expect("stdout reads")
                    .expect("stdout stays open while requests are outstanding");
                let Ok(frame) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if frame.get("id").is_some() {
                    replies += 1;
                    answered += u64::from(frame.get("result").is_some());
                }
            }
            if next > PINGS {
                break;
            }
            let end = (next + WINDOW - 1).min(PINGS);
            let window: Vec<Value> = (next..=end)
                .map(|id| json!({"jsonrpc": "2.0", "id": id, "method": "ping"}))
                .collect();
            send(&mut stdin, &window).await;
            sent += end - next + 1;
            next = end + 1;
        }
        drop(stdin);
        while lines.next_line().await.expect("stdout reads").is_some() {}
        let status = child.wait().await.expect("reap child");
        (answered, status)
    };
    let Ok((answered, status)) = tokio::time::timeout(KILL_TIMER, run).await else {
        panic!(
            "the kill timer fired: the child stalled before answering every request and exiting"
        );
    };
    assert_eq!(answered, PINGS + 1, "every request is answered");
    assert!(
        status.success(),
        "the child exits cleanly once stdin closes: {status}"
    );
    drop(held);
    match drained {
        Some(reader) => reader.await.expect("the stderr reader"),
        None => Vec::new(),
    }
}

/// L1j-a: a stderr nobody reads holds up neither the requests nor the exit.
#[tokio::test]
async fn l1j_a_an_unread_stderr_stalls_neither_requests_nor_exit() {
    session(Stderr::Unread).await;
}

/// L1j-b: with stderr drained, the session logs more than a pipe can hold
/// (so L1j-a's stall would be real), and the last line before exit arrives.
#[tokio::test]
async fn l1j_b_a_drained_stderr_gets_the_whole_session_and_its_last_line() {
    let err = session(Stderr::Drained).await;
    assert!(
        err.len() > 1 << 20,
        "the session must log more than 1 MiB for L1j-a to mean anything: {} bytes",
        err.len()
    );
    let text = String::from_utf8_lossy(&err);
    let tail: String = text
        .chars()
        .rev()
        .take(2000)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    assert!(
        text.contains(LAST_LINE),
        "the line logged just before exit is flushed: ...{tail}"
    );
}
