// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! L1j: the shipped stdio gateway, logging at trace, with a stderr nobody
//! reads still answers every request and exits once stdin closes (L1j-a).
//! With stderr first left unread and then drained once stdin closes, the
//! writer has dropped lines (so the pipe filled, and L1j-a is a real test),
//! and the line logged just before exit still arrives: the exit flush waits
//! for the backlog to drain (L1j-b).
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
    /// Held unread through the session, then read to the end from the moment
    /// stdin closes, and returned.
    DrainedAtExit,
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

/// The shipped binary on `serve --stdio`, logging at trace, every stream piped.
fn spawn(home: &std::path::Path) -> tokio::process::Child {
    let config = home.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, String::new())
        .expect("write config");
    let mut command = tokio::process::Command::from(gateway_bin::command(
        home,
        gateway_bin::Inherit::Environment,
    ));
    command
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "serve",
            "--stdio",
        ])
        .current_dir(home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("RUST_LOG", "trace")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command.spawn().expect("spawn shipped binary")
}

/// One session: initialize, `PINGS` pings, then stdin closes. Asserts every
/// request is answered and the child exits cleanly within the kill timer;
/// returns the child's stderr when it is drained.
async fn session(stderr: Stderr) -> Vec<u8> {
    let temp = tempfile::tempdir().expect("isolated home");
    let mut child = spawn(temp.path());
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let err = child.stderr.take().expect("stderr");
    let mut held = Some(err);
    let mut drained = None;

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
        if matches!(stderr, Stderr::DrainedAtExit) {
            let mut err = held.take().expect("stderr is held until now");
            drained = Some(tokio::spawn(async move {
                let mut bytes = Vec::new();
                err.read_to_end(&mut bytes).await.expect("stderr reads");
                bytes
            }));
        }
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

/// L1j-b: stderr is full when stdin closes, so lines were dropped, and the
/// line logged just before exit still arrives once stderr drains.
#[tokio::test]
async fn l1j_b_the_last_line_survives_a_full_stderr_at_exit() {
    let err = session(Stderr::DrainedAtExit).await;
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
        text.contains("log lines while stderr was not draining"),
        "stderr filled during the session, so lines were dropped: ...{tail}"
    );
    assert!(
        text.contains(LAST_LINE),
        "the line logged just before exit is flushed: ...{tail}"
    );
}

/// L1j-c (structural): the exit flush guard is bound before the runtime runs
/// and held through it. A guard dropped early flushes at startup and not at
/// exit, which a process test cannot tell apart while stderr keeps up.
#[test]
fn l1j_c_the_flush_guard_outlives_the_runtime() {
    let main = include_str!("../src/main.rs");
    let bound = main
        .find("let _flush_logs = match setup_tracing(")
        .expect("main binds the flush guard");
    let runs = main[bound..]
        .find("runtime::block_on(")
        .map(|at| bound + at)
        .expect("the runtime runs after the guard is bound");
    assert!(
        !main[bound..runs].contains("drop(_flush_logs"),
        "the flush guard is dropped before the runtime runs"
    );
}
