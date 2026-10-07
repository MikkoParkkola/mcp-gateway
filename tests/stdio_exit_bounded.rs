// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7683: the stdio process exits even when its client never reads stdout.
//!
//! Production stdout writes run on Tokio's blocking pool. A client that stops
//! reading leaves one of them stuck in `write(2)`; `run_stdio_on` still
//! returns (its drain and teardown are bounded), but dropping the runtime used
//! to wait on that pool thread for ever. Driven through the shipped binary.
#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Requests whose answers together exceed any OS pipe buffer: each answer
/// echoes a 200-byte id, so 4000 of them are about 1 MiB, past the largest
/// pipe a Linux or macOS host gives by default.
const PINGS: usize = 4000;
/// The sum of `STDIO_DRAIN_TIMEOUT` (30 s), `STDIO_TEARDOWN_TIMEOUT` (10 s, a
/// maximum) and the runtime shutdown bound (10 s), plus margin. They are
/// private constants of the binary, so restated here; a change there must
/// move this.
const EXIT_BOUND: Duration = Duration::from_secs(65);
/// Writing the requests, bounded apart from the exit.
const WRITE_BOUND: Duration = Duration::from_secs(30);
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
    let yaml = format!(
        "backends: {{}}\ntasks:\n  store_dir: {}\n",
        serde_json::to_string(&dir.path().join("tasks").display().to_string())
            .expect("a JSON string")
    );
    command_with(dir, &yaml)
}

/// `serve --stdio` under the config `yaml`, written into `dir`.
fn command_with(dir: &tempfile::TempDir, yaml: &str) -> tokio::process::Command {
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let mut command = tokio::process::Command::from(gateway_bin::command(
        dir.path(),
        gateway_bin::Inherit::Environment,
    ));
    command
        .args([
            "--config",
            path.to_str().unwrap(),
            "--log-level",
            "info",
            "serve",
            "--stdio",
        ])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
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
    // Bounded on its own: a child that stopped reading stdin must fail the
    // test, not hang it.
    tokio::time::timeout(
        WRITE_BOUND,
        stdin.write_all((script.join("\n") + "\n").as_bytes()),
    )
    .await
    .expect("the gateway keeps reading stdin")
    .expect("write the requests");
    drop(stdin);
    let status = tokio::time::timeout(EXIT_BOUND, child.wait()).await;
    let exited = matches!(&status, Ok(Ok(status)) if status.success());
    if status.is_err() {
        drop(child.kill().await);
    }
    drop(stdout);
    let stderr = stderr_text.await.unwrap_or_default();
    assert!(
        exited,
        "the process must exit cleanly within {EXIT_BOUND:?} of EOF with stdout unread \
         ({status:?}); stderr:\n{stderr}"
    );
    // The hang being bounded is the one after the serve loop: it read EOF.
    assert!(stderr.contains("EOF reached"), "stderr:\n{stderr}");
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
        tokio::time::timeout(WRITE_BOUND, stdin.write_all(text.as_bytes()))
            .await
            .expect("the gateway keeps reading stdin")
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

/// An in-process MCP backend with one tool, `echo`.
async fn spawn_backend() -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(|axum::Json(request): axum::Json<serde_json::Value>| async move {
            let result = match request["method"].as_str().unwrap_or("") {
                "initialize" => serde_json::json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fixture", "version": "0"},
                }),
                "tools/list" => serde_json::json!({"tools": [
                    {"name": "echo", "description": "echoes", "inputSchema": {"type": "object"}},
                ]}),
                "tools/call" => serde_json::json!({"content": [{"type": "text", "text": "echoed"}]}),
                _ => serde_json::json!({}),
            };
            axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    format!("http://{address}/")
}

/// The bound cuts only the stdio runtime's blocking work, never an audit
/// write: a call answered just before EOF has its invocation record on disk
/// once the process has exited.
#[tokio::test]
async fn the_last_audit_record_is_on_disk_after_exit() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit").join("transparency.jsonl");
    let yaml = format!(
        "backends:\n  fixture:\n    http_url: \"{}\"\n    streamable_http: true\n\
         tasks:\n  store_dir: {}\n\
         security:\n  transparency_log:\n    enabled: true\n    path: {}\n",
        spawn_backend().await,
        serde_json::to_string(&dir.path().join("tasks").display().to_string())
            .expect("a JSON string"),
        serde_json::to_string(&audit.display().to_string()).expect("a JSON string"),
    );
    let mut child = command_with(&dir, &yaml)
        .spawn()
        .expect("spawn shipped binary");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let mut stderr = child.stderr.take().expect("stderr");
    let stderr_text = tokio::spawn(async move {
        let mut text = String::new();
        drop(tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut text).await);
        text
    });
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": "call-1", "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": "fixture", "tool": "echo", "arguments": {},
        }},
    });
    stdin
        .write_all(format!("{}\n{call}\n", initialize()).as_bytes())
        .await
        .expect("write the requests");
    let answered = tokio::time::timeout(WRITE_BOUND, async {
        while let Ok(Some(line)) = lines.next_line().await {
            let frame: serde_json::Value = serde_json::from_str(&line).expect("one JSON frame");
            if frame["id"] == "call-1" {
                return Some(frame);
            }
        }
        None
    })
    .await
    .expect("the call is answered")
    .expect("stdout stays open until the answer");
    assert!(answered.get("result").is_some(), "{answered}");
    drop(stdin);
    while let Ok(Some(_)) = lines.next_line().await {}
    let status = tokio::time::timeout(EXIT_BOUND, child.wait())
        .await
        .expect("the gateway exits")
        .expect("reap child");
    let stderr = stderr_text.await.unwrap_or_default();
    assert!(status.success(), "{status}; stderr:\n{stderr}");
    let log = std::fs::read_to_string(&audit).expect("the audit log exists");
    assert!(
        log.lines()
            .any(|line| line.contains("request_hash") && line.contains("\"echo\"")),
        "the call's invocation record is on disk:\n{log}"
    );
}
