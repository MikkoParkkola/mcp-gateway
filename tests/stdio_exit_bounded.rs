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

/// Requests whose answers together exceed any OS pipe buffer.
const PINGS: usize = 4000;
/// Drain (30 s) + teardown (10 s) + runtime shutdown (10 s), plus margin.
const EXIT_BOUND: Duration = Duration::from_secs(65);

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

/// The handshake, then `PINGS` pings, one per line.
fn script() -> String {
    let mut lines = vec![
        serde_json::json!({
            "jsonrpc": "2.0", "id": "init", "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mik7683", "version": "0"},
            },
        })
        .to_string(),
    ];
    lines.extend(
        (0..PINGS)
            .map(|k| serde_json::json!({"jsonrpc": "2.0", "id": k, "method": "ping"}).to_string()),
    );
    lines.join("\n") + "\n"
}

/// AC2. stdout is never read, stdin closes after the requests: the process
/// exits within the stated bound instead of hanging in the runtime drop.
#[tokio::test]
async fn the_process_exits_when_stdout_is_never_read() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = command(&dir).spawn().expect("spawn shipped binary");
    let mut stdin = child.stdin.take().expect("stdin");
    // Held, never read: a closed pipe would end the stuck write with EPIPE.
    let _stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let stderr_text = tokio::spawn(async move {
        let mut text = String::new();
        drop(tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut text).await);
        text
    });
    stdin
        .write_all(script().as_bytes())
        .await
        .expect("write the requests");
    drop(stdin);
    let status = tokio::time::timeout(EXIT_BOUND, child.wait()).await;
    let exited = matches!(status, Ok(Ok(_)));
    if !exited {
        drop(child.kill().await);
    }
    let stderr = stderr_text.await.unwrap_or_default();
    assert!(
        exited,
        "the process must exit within {EXIT_BOUND:?} of EOF with stdout unread; stderr:\n{stderr}"
    );
}

/// Positive control: a client that reads gets every answer, and the process
/// exits cleanly. The bound does not cost a reading client a frame.
#[tokio::test]
async fn a_reading_client_gets_every_answer_before_exit() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = command(&dir).spawn().expect("spawn shipped binary");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let reader = tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        let mut ids = std::collections::BTreeSet::new();
        while let Ok(Some(line)) = lines.next_line().await {
            let frame: serde_json::Value = serde_json::from_str(&line).expect("one JSON frame");
            if let Some(id) = frame["id"].as_u64() {
                ids.insert(id);
            }
        }
        ids
    });
    stdin
        .write_all(script().as_bytes())
        .await
        .expect("write the requests");
    drop(stdin);
    let status = tokio::time::timeout(EXIT_BOUND, child.wait())
        .await
        .expect("a reading client's gateway exits")
        .expect("reap child");
    assert!(status.success(), "{status}");
    let ids = reader.await.expect("reader task");
    let expected: std::collections::BTreeSet<u64> = (0..PINGS as u64).collect();
    assert_eq!(ids, expected, "every ping is answered exactly once");
}
