// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7683: the stdio process exits even when its client never reads stdout.
//!
//! Production stdout writes run on Tokio's blocking pool. A client that stops
//! reading leaves one of them stuck in `write(2)`; `run_stdio_on` still
//! returns (its drain and teardown are bounded), but dropping the runtime used
//! to wait on that pool thread for ever. Driven through the shipped binary.
#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Requests whose answers together exceed any OS pipe buffer: each answer
/// echoes a 200-byte id, so 4000 of them are about 1 MiB, past the largest
/// pipe a Linux or macOS host gives by default.
const PINGS: usize = 4000;
/// Drain (30 s) + teardown (10 s) + runtime shutdown (10 s), plus margin.
const EXIT_BOUND: Duration = Duration::from_secs(65);
/// The reading control's outstanding-request window, below the stdio
/// in-flight cap, so no answer is a busy refusal.
const WINDOW: usize = 500;

/// The id of ping `k`: 200 bytes, so the answers fill a pipe quickly.
fn id(k: usize) -> String {
    format!("p{k:0>199}")
}

fn ping(k: usize) -> String {
    serde_json::json!({"jsonrpc": "2.0", "id": id(k), "method": "ping"}).to_string()
}

fn initialize() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": "init", "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mik7683", "version": "0"},
        },
    })
    .to_string()
}

fn command(dir: &tempfile::TempDir) -> tokio::process::Command {
    let path = dir.path().join("gateway.yaml");
    let yaml = format!(
        "backends: {{}}\ntasks:\n  store_dir: {}\n",
        serde_json::to_string(&dir.path().join("tasks").display().to_string())
            .expect("a JSON string")
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
    command
        .args(["--config", path.to_str().unwrap(), "serve", "--stdio"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("MCP_GATEWAY_TEST_HOME_DIR", dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("MCP_GATEWAY_") && name != "MCP_GATEWAY_TEST_HOME_DIR"
        {
            command.env_remove(name);
        }
    }
    command
}

/// AC2. stdout is never read, stdin closes after the requests: the process
/// exits within the stated bound instead of hanging in the runtime drop.
#[tokio::test]
async fn the_process_exits_when_stdout_is_never_read() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = command(&dir).spawn().expect("spawn shipped binary");
    let mut stdin = child.stdin.take().expect("stdin");
    // Held, never read, until after the child is reaped: a read or a closed
    // pipe would end the stuck write.
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let stderr_text = tokio::spawn(async move {
        let mut text = String::new();
        drop(tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut text).await);
        text
    });
    let mut script = vec![initialize()];
    script.extend((0..PINGS).map(ping));
    stdin
        .write_all((script.join("\n") + "\n").as_bytes())
        .await
        .expect("write the requests");
    drop(stdin);
    let status = tokio::time::timeout(EXIT_BOUND, child.wait()).await;
    let exited = matches!(status, Ok(Ok(_)));
    if !exited {
        drop(child.kill().await);
    }
    drop(stdout);
    let stderr = stderr_text.await.unwrap_or_default();
    assert!(
        exited,
        "the process must exit within {EXIT_BOUND:?} of EOF with stdout unread; stderr:\n{stderr}"
    );
}

/// Positive control: a client that reads gets every answer and a clean exit.
/// Requests go in windows below the in-flight cap, and the last window is
/// still being answered when stdin closes, so the shutdown path runs while
/// frames are pending.
#[tokio::test]
async fn a_reading_client_gets_every_answer_before_exit() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = command(&dir).spawn().expect("spawn shipped binary");
    let mut stdin = Some(child.stdin.take().expect("stdin"));
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let mut stderr = child.stderr.take().expect("stderr");
    let stderr_text = tokio::spawn(async move {
        let mut text = String::new();
        drop(tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut text).await);
        text
    });
    let mut seen = std::collections::BTreeMap::<String, usize>::new();
    let read_one = async |lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
                          seen: &mut std::collections::BTreeMap<String, usize>|
           -> bool {
        match tokio::time::timeout(EXIT_BOUND, lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                let frame: serde_json::Value = serde_json::from_str(&line).expect("one JSON frame");
                if let Some(id) = frame["id"].as_str() {
                    *seen.entry(id.to_string()).or_default() += 1;
                }
                true
            }
            _ => false,
        }
    };
    let write = async |stdin: &mut tokio::process::ChildStdin, text: String| {
        stdin
            .write_all(text.as_bytes())
            .await
            .expect("write requests");
    };
    write(stdin.as_mut().unwrap(), initialize() + "\n").await;
    for start in (0..PINGS).step_by(WINDOW) {
        let end = (start + WINDOW).min(PINGS);
        let chunk: Vec<String> = (start..end).map(ping).collect();
        write(stdin.as_mut().unwrap(), chunk.join("\n") + "\n").await;
        if end == PINGS {
            // The last window is closed behind while its answers are pending.
            drop(stdin.take());
            break;
        }
        while seen.len() < end + 1 {
            assert!(
                read_one(&mut lines, &mut seen).await,
                "answers stopped early"
            );
        }
    }
    while read_one(&mut lines, &mut seen).await {}
    let status = tokio::time::timeout(EXIT_BOUND, child.wait())
        .await
        .expect("a reading client's gateway exits")
        .expect("reap child");
    let stderr = stderr_text.await.unwrap_or_default();
    assert!(status.success(), "{status}; stderr:\n{stderr}");
    let mut expected: std::collections::BTreeMap<String, usize> =
        (0..PINGS).map(|k| (id(k), 1)).collect();
    expected.insert("init".to_string(), 1);
    assert_eq!(seen, expected, "every request is answered exactly once");
}
