// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The real binary, one capability MCP child, then the gateway's stop: SIGTERM
//! for the HTTP gateway, the end of its stdin for the stdio one. Once the
//! gateway has exited, the child and its process group must be gone, and the
//! child must have been stopped the MCP way (its stdin closed first), not only
//! killed.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use mcp_gateway::config::{Config, ProcessCommand};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/yaml.rs"]
mod yaml;

const PROTOCOL_VERSION: &str = "2025-11-25";
/// The name the gateway lists its capabilities under.
const CAPS: &str = "caps";
const CAPABILITY: &str = "stop_probe";
const READY_BOUND: Duration = Duration::from_secs(60);
/// The gateway's whole stop, at the 13 s floor below which an HTTP start is
/// refused; the row waits a little longer for the exit.
const STOP_TOTAL: Duration = Duration::from_secs(13);
const EXIT_BOUND: Duration = Duration::from_secs(30);

fn fixture() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/fake_mcp.py")
        .display()
        .to_string()
}

/// One operation, `say`, mapped to the fixture's `echo`, which reports the
/// child's pid. The mark file's name reaches the child through `env:`.
fn capability_yaml(script: &str) -> String {
    format!(
        r#"name: {CAPABILITY}
description: An MCP capability whose child must end with the gateway.
schema:
  input:
    type: object
    properties:
      operation:
        type: string
      text:
        type: string
providers:
  primary:
    service: mcp
    timeout: 20
    config:
      command: python3
      args: ['{script}']
      transport: stdio
      env: [CAP_EXEC_TEST_EOF_MARK]
      tool_selector:
        param: operation
        tools:
          say: {{ tool: echo, arguments: {{ message: "{{text}}" }} }}
"#
    )
}

/// The capability file, pinned, and a config that lets it run its process.
fn write_config(root: &Path) -> PathBuf {
    let script = fixture();
    let caps = root.join("capabilities");
    std::fs::create_dir_all(&caps).expect("capability dir");
    let file = caps.join(format!("{CAPABILITY}.yaml"));
    std::fs::write(&file, capability_yaml(&script)).expect("capability file");
    mcp_gateway::capability::pin_file(&file).expect("the capability pins");

    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = gateway_bin::ANY_PORT;
    config.server.shutdown_timeout = STOP_TOTAL;
    config.auth.enabled = false;
    config.cache.default_ttl = Duration::ZERO;
    config.tasks.store_dir = root.join("tasks").display().to_string();
    config.capabilities.enabled = true;
    config.capabilities.name = CAPS.to_string();
    config.capabilities.directories = vec![caps.display().to_string()];
    config.capabilities.process_commands = Some(vec![ProcessCommand {
        command: "python3".to_string(),
        args_prefix: vec![script],
    }]);
    let path = root.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        yaml::to_string(&config).expect("config yaml"),
    )
    .expect("write config");
    path
}

fn logs(root: &Path) -> String {
    std::fs::read_to_string(root.join("gateway.log")).unwrap_or_default()
}

/// One JSON-RPC POST on `/mcp`: the response body and the session id it named.
async fn post(
    client: &reqwest::Client,
    base: &str,
    session: Option<&str>,
    body: &Value,
) -> (String, Option<String>) {
    let mut request = client
        .post(format!("{base}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("mcp-protocol-version", PROTOCOL_VERSION);
    if let Some(id) = session {
        request = request.header("mcp-session-id", id);
    }
    let response = request
        .json(body)
        .send()
        .await
        .expect("the POST is answered");
    let named = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (response.text().await.expect("a body"), named)
}

/// The port the gateway logged, once `/health` answers there.
async fn ready_port(client: &reqwest::Client, root: &Path) -> u16 {
    let give_up = tokio::time::Instant::now() + READY_BOUND;
    loop {
        if let Some(port) = gateway_bin::logged_port(&root.join("gateway.log"))
            && client
                .get(format!("http://127.0.0.1:{port}/health"))
                .send()
                .await
                .is_ok_and(|reply| reply.status().is_success())
        {
            return port;
        }
        assert!(
            tokio::time::Instant::now() < give_up,
            "the gateway never became ready\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The first number after `"pid"` in `body`, however deeply the capability's
/// answer was quoted on its way out.
fn pid_in(body: &str) -> Option<u32> {
    let after = &body[body.find("pid")? + 3..];
    let digits: String = after
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// `kill -0` on a pid, or on a process group when given as `-PGID`.
fn answers(target: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", "--", target])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// True once nothing answers to `target`, checked every 100 ms for `limit`.
async fn gone_within(target: &str, limit: Duration) -> bool {
    let give_up = tokio::time::Instant::now() + limit;
    while answers(target) {
        if tokio::time::Instant::now() >= give_up {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}

/// The group `pid` leads or sits in, unless it is this test's own group:
/// a leftover kill sent there would take the test runner down too.
fn foreign_group(pid: u32) -> Option<i32> {
    use rustix::process::{Pid, getpgid, getpgrp};
    let group = getpgid(Some(Pid::from_raw(i32::try_from(pid).ok()?)?)).ok()?;
    (group != getpgrp()).then(|| group.as_raw_nonzero().get())
}

/// SIGKILL for whatever a red run left behind; errors mean it is gone.
fn kill_leftover(target: &str) {
    let _ = std::process::Command::new("kill")
        .args(["-9", "--", target])
        .stderr(Stdio::null())
        .status();
}

#[tokio::test]
async fn sigterm_ends_an_idle_capability_child_by_closing_its_stdin() {
    let dir = tempfile::tempdir().expect("a temp root");
    let root = dir.path().to_path_buf();
    let home = root.join("home");
    std::fs::create_dir_all(&home).expect("a home dir");
    let config = write_config(&root);
    let mark = root.join("child-read-eof");
    let log = std::fs::File::create(root.join("gateway.log")).expect("a log file");

    let mut command = gateway_bin::command(&home, gateway_bin::Inherit::Environment);
    command
        .arg("--config")
        .arg(&config)
        .envs(gateway_bin::checked_env([(
            "CAP_EXEC_TEST_EOF_MARK",
            mark.as_os_str(),
        )]))
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("a second log handle"))
        .stderr(log);
    let mut gateway = gateway_bin::Reaped::new(
        tokio::process::Command::from(command)
            .spawn()
            .expect("the gateway binary starts"),
    );
    gateway.owning(dir);

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", ready_port(&client, &root).await);
    let hello = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "capability-stop-row", "version": "1" }
        }
    });
    let (_, session) = post(&client, &base, None, &hello).await;
    let session = session.expect("initialize names a session");
    let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    post(&client, &base, Some(&session), &initialized).await;
    let call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {
                "server": CAPS,
                "tool": CAPABILITY,
                "arguments": { "operation": "say", "text": "before the stop" }
            }
        }
    });
    let (answer, _) = post(&client, &base, Some(&session), &call).await;
    let pid = pid_in(&answer)
        .unwrap_or_else(|| panic!("the call named no child pid: {answer}\n{}", logs(&root)));
    let group = foreign_group(pid);

    // The child now sits idle; SIGTERM the gateway and wait for its exit.
    gateway.reap_within(EXIT_BOUND).await;

    let child_gone = gone_within(&pid.to_string(), Duration::from_secs(1)).await;
    let group_gone = match group {
        Some(g) => gone_within(&format!("-{g}"), Duration::from_secs(1)).await,
        None => true,
    };
    let read_eof = mark.exists();
    if !child_gone {
        kill_leftover(&pid.to_string());
    }
    if let Some(g) = group.filter(|_| !group_gone) {
        kill_leftover(&format!("-{g}"));
    }
    assert!(
        child_gone && group_gone && read_eof,
        "after the gateway exited: child {pid} gone {child_gone}, its group {group:?} gone \
         {group_gone}, child saw its stdin end {read_eof}\n{}",
        logs(&root)
    );
    gateway.stop().await;
}

/// Initialize the stdio gateway, invoke the capability once, and return the
/// answer to that call (other lines, the initialize answer among them, are
/// skipped). Both pipes are borrowed: the row keeps its read end open until
/// the gateway exits, so the end of the gateway's stdin is the only stop.
async fn call_over_stdio(
    stdin: &mut tokio::process::ChildStdin,
    stdout: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    root: &Path,
) -> String {
    let messages = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "capability-stop-row", "version": "1" }
            }
        }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "gateway_invoke",
                "arguments": {
                    "server": CAPS,
                    "tool": CAPABILITY,
                    "arguments": { "operation": "say", "text": "before the stop" }
                }
            }
        }),
    ];
    for message in &messages {
        stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("the gateway reads its stdin");
    }
    stdin.flush().await.expect("stdin flushes");
    tokio::time::timeout(READY_BOUND, async {
        loop {
            let line = stdout
                .next_line()
                .await
                .expect("stdout reads")
                .unwrap_or_else(|| panic!("the gateway closed stdout\n{}", logs(root)));
            if serde_json::from_str::<Value>(&line).is_ok_and(|value| value["id"] == json!(2)) {
                break line;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the call was never answered\n{}", logs(root)))
}

/// The same child under the stdio gateway, stopped the way its client stops
/// it: the gateway's own stdin ends, and it exits by itself.
#[tokio::test]
async fn closing_stdin_ends_an_idle_capability_child_by_closing_its_stdin() {
    let dir = tempfile::tempdir().expect("a temp root");
    let root = dir.path().to_path_buf();
    let home = root.join("home");
    std::fs::create_dir_all(&home).expect("a home dir");
    let config = write_config(&root);
    let mark = root.join("child-read-eof");
    let log = std::fs::File::create(root.join("gateway.log")).expect("a log file");

    let mut command = gateway_bin::command(&home, gateway_bin::Inherit::Environment);
    command
        .arg("--config")
        .arg(&config)
        .arg("serve")
        .arg("--stdio")
        .envs(gateway_bin::checked_env([(
            "CAP_EXEC_TEST_EOF_MARK",
            mark.as_os_str(),
        )]))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(log);
    let mut gateway = gateway_bin::Reaped::new(
        tokio::process::Command::from(command)
            .spawn()
            .expect("the gateway binary starts"),
    );
    let mut stdin = gateway.child_mut().stdin.take().expect("its stdin");
    let mut stdout = BufReader::new(gateway.child_mut().stdout.take().expect("its stdout")).lines();
    let answer = call_over_stdio(&mut stdin, &mut stdout, &root).await;
    let pid = pid_in(&answer)
        .unwrap_or_else(|| panic!("the call named no child pid: {answer}\n{}", logs(&root)));
    let group = foreign_group(pid);

    // The child now sits idle; end the gateway's input and wait for its exit.
    drop(stdin);
    let exited = tokio::time::timeout(EXIT_BOUND, gateway.child_mut().wait()).await;

    let child_gone = gone_within(&pid.to_string(), Duration::from_secs(1)).await;
    let group_gone = match group {
        Some(g) => gone_within(&format!("-{g}"), Duration::from_secs(1)).await,
        None => true,
    };
    let read_eof = mark.exists();
    if !child_gone {
        kill_leftover(&pid.to_string());
    }
    if let Some(g) = group.filter(|_| !group_gone) {
        kill_leftover(&format!("-{g}"));
    }
    assert!(
        exited.is_ok(),
        "the stdio gateway did not exit within {EXIT_BOUND:?} of its stdin ending\n{}",
        logs(&root)
    );
    assert!(
        child_gone && group_gone && read_eof,
        "after the gateway exited: child {pid} gone {child_gone}, its group {group:?} gone \
         {group_gone}, child saw its stdin end {read_eof}\n{}",
        logs(&root)
    );
    gateway.stop().await;
    drop(dir);
}
