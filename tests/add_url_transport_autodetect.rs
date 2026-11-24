// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway add --url` must produce a backend that works against both
//! HTTP server shapes the MCP spec allows, driven through the shipped binary.
//!
//! The spec's backwards-compatibility rule: POST `initialize` first (Streamable
//! HTTP) and fall back to the legacy SSE `GET` only when that POST is refused
//! with a 4xx. A streamable-only server answers `GET` with 405, so a config
//! that always opens with `GET` fails on its first call. An explicit flag
//! that the server refuses with such a 4xx gets one try of the other transport.

use stdio_session::gateway_bin;

#[path = "common/mcp_http_servers.rs"]
#[allow(dead_code, reason = "shared fixtures; each binary uses a subset")]
mod mcp_http_servers;
#[path = "common/stdio_session.rs"]
mod stdio_session;

use std::path::Path;

use axum::http::Method;
use mcp_http_servers::{Hits, sse_server, streamable_server};
use serde_json::{Value, json};
use stdio_session::StdioSession;

const BACKEND: &str = "fx";

fn add(home: &Path, url: &str) {
    let output = gateway_bin::command(home, gateway_bin::Inherit::Environment)
        .args(["add", "--url", url, BACKEND, "--config"])
        .arg(home.join("gateway.yaml"))
        .output()
        .expect("run mcp-gateway add");
    assert!(
        output.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Drive one `gateway_invoke` of the fixture's `ping` through `serve --stdio`.
async fn invoke_ping(home: &Path) -> Value {
    let mut session = StdioSession::spawn(home);
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "add-url-autodetect", "version": "0"},
            }}),
        )
        .await;
    let (_, init) = session.read_until_id(1).await;
    assert!(init.is_some(), "the gateway never answered initialize");
    session
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "gateway_invoke",
                "arguments": {"server": BACKEND, "tool": "ping", "arguments": {}},
            }}),
        )
        .await;
    let (lines, reply) = session.read_until_id(2).await;
    session.shutdown().await;
    reply.unwrap_or_else(|| panic!("no reply to the invoke; saw: {lines:?}"))
}

#[tokio::test]
async fn add_url_reaches_a_streamable_only_server() {
    let hits = Hits::default();
    let url = streamable_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    add(home.path(), &url);

    let reply = invoke_ping(home.path()).await;
    assert!(
        reply.to_string().contains("pong-streamable"),
        "a streamable-only server must work after `add --url`; reply: {reply}"
    );
}

#[tokio::test]
async fn add_url_still_reaches_a_legacy_sse_server() {
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    add(home.path(), &url);

    let reply = invoke_ping(home.path()).await;
    assert!(
        reply.to_string().contains("pong-sse"),
        "a legacy SSE server must still work after `add --url`; reply: {reply}"
    );
}

#[tokio::test]
async fn add_url_leaves_the_transport_to_detection() {
    let home = tempfile::tempdir().expect("home");
    add(home.path(), "https://mcp.example.test/mcp");
    let yaml = std::fs::read_to_string(home.path().join("gateway.yaml")).expect("gateway.yaml");
    assert!(
        !yaml.contains("streamable_http"),
        "`add --url` must not pin a transport the server was never asked about:\n{yaml}"
    );
}

fn write_explicit(home: &Path, url: &str, streamable: bool) {
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"{url}\"\n    streamable_http: {streamable}\n"
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(home.join("gateway.yaml"), yaml)
        .expect("write gateway.yaml");
}

/// An explicit `streamable_http: false` that the server accepts is used as
/// written: the gateway opens with the SSE `GET` and never probes with a `POST`.
#[tokio::test]
async fn explicit_streamable_false_is_honoured() {
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    write_explicit(home.path(), &url, false);

    let reply = invoke_ping(home.path()).await;
    assert!(reply.to_string().contains("pong-sse"), "reply: {reply}");
    let posts_to_sse = hits
        .lock()
        .expect("hits")
        .iter()
        .filter(|(method, path)| *method == Method::POST && path == "/sse")
        .count();
    assert_eq!(posts_to_sse, 0, "explicit `false` must not probe with POST");
}

/// The config the old `add --url` wrote: an explicit `false` naming a server
/// that speaks only Streamable HTTP. The refused `GET` costs one request, not
/// the backend.
#[tokio::test]
async fn an_old_add_config_reaches_a_streamable_only_server() {
    let hits = Hits::default();
    let url = streamable_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    write_explicit(home.path(), &url, false);

    let reply = invoke_ping(home.path()).await;
    assert!(
        reply.to_string().contains("pong-streamable"),
        "reply: {reply}"
    );
}

/// The mirror case: an explicit `true` naming a legacy SSE server.
#[tokio::test]
async fn explicit_streamable_true_still_reaches_a_legacy_sse_server() {
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    write_explicit(home.path(), &url, true);

    let reply = invoke_ping(home.path()).await;
    assert!(reply.to_string().contains("pong-sse"), "reply: {reply}");
}

/// A gateway that exits before it is ready ends the first read's wait for its
/// ready line: the read sees stdout end, where a wait that missed the exit
/// would panic at its cap. `Ok(None)` (stdout ended) rather than an expired
/// bound is also the premise: the config really stopped the start.
#[tokio::test]
async fn a_gateway_that_cannot_start_ends_the_wait_for_ready() {
    let home = tempfile::tempdir().expect("home");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.path().join("gateway.yaml"),
        "backends: [unclosed\n",
    )
    .expect("write gateway.yaml");
    let mut session = StdioSession::spawn(home.path());
    let ended = session.next_line(stdio_session::READ_TIMEOUT).await;
    assert!(
        matches!(ended, Ok(None)),
        "a gateway that cannot start must end its stdout; got {ended:?}"
    );
}

/// How long the slow launcher holds the gateway's start: past the read bound.
#[cfg(unix)]
const SLOW_START_SECS: u64 = 12;

/// A start slower than the read bound still gets its answer, because the
/// first read waits for the ready line before its own bound starts. A read
/// bound that started at spawn timed out here (train 56a's Windows failure).
#[cfg(unix)]
#[tokio::test]
async fn a_start_slower_than_the_read_bound_still_gets_its_answer() {
    assert!(
        std::time::Duration::from_secs(SLOW_START_SECS) > stdio_session::READ_TIMEOUT,
        "the premise: the launcher holds the start past the read bound"
    );
    let home = tempfile::tempdir().expect("home");
    let launcher = format!("sleep {SLOW_START_SECS}; exec \"$0\" \"$@\"");
    let mut session = StdioSession::spawn_through(&["sh", "-c", &launcher], home.path());
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "add-url-autodetect", "version": "0"},
            }}),
        )
        .await;
    let (lines, init) = session.read_until_id(1).await;
    session.shutdown().await;
    assert!(
        init.is_some(),
        "the gateway never answered initialize; saw: {lines:?}"
    );
}

/// A start that never finishes is reported as not ready, so every read
/// fails "never became ready" at its cap rather than hanging. The launcher
/// sleeps in the gateway's place, so no ready line ever comes; the 3 s window
/// only has to pass without one, which no load can make fail.
#[cfg(unix)]
#[tokio::test]
async fn a_start_that_never_finishes_is_reported_not_ready() {
    let home = tempfile::tempdir().expect("home");
    let mut session = StdioSession::spawn_through(&["sh", "-c", "exec sleep 600"], home.path());
    assert!(
        !session
            .wait_ready_for(std::time::Duration::from_secs(3))
            .await,
        "a launcher that never starts the gateway was reported ready"
    );
}

/// A gateway that exits before it is ready ends the wait even while a process
/// it started (a backend, say) still holds its stderr open, so the pipe never
/// closes: the wait watches the child's exit, not only the pipe.
#[cfg(unix)]
#[tokio::test]
async fn an_exit_before_ready_ends_the_wait_while_a_grandchild_holds_stderr() {
    let home = tempfile::tempdir().expect("home");
    let mut session = StdioSession::spawn_through(&["sh", "-c", "sleep 30 & exit 3"], home.path());
    assert!(
        session.wait_ready_for(stdio_session::READ_TIMEOUT).await,
        "the launcher exited at once, yet the wait for ready did not end"
    );
}

/// A capture ends while a process the launcher left behind still holds the
/// gateway's stderr open after the gateway is killed: `finish_capturing` joins the
/// stderr drain for a bounded time and keeps what arrived. With that join
/// unbounded the call would wait for the sleeper; the outer bound turns that
/// into a failure. The sleeper's pid is written down and it is killed at the end.
#[cfg(unix)]
#[tokio::test]
async fn a_capture_ends_while_a_grandchild_holds_stderr() {
    let home = tempfile::tempdir().expect("home");
    let pid_file = home.path().join("sleeper.pid");
    let launcher = format!(
        "sleep 120 & echo $! > '{}'; exec \"$0\" \"$@\"",
        pid_file.display()
    );
    let (session, captured) =
        StdioSession::spawn_capturing_through(&["sh", "-c", &launcher], home.path());
    let lines = tokio::time::timeout(
        std::time::Duration::from_secs(50),
        session.finish_capturing(captured),
    )
    .await;
    if let Ok(pid) = std::fs::read_to_string(&pid_file) {
        let _ = std::process::Command::new("kill").arg(pid.trim()).status();
    }
    let lines = lines.expect("finish_capturing waited on a grandchild holding stderr open");
    assert!(
        lines.iter().any(|l| l.contains(stdio_session::READY_LINE)),
        "the capture lost the gateway's own lines: {lines:?}"
    );
}

/// The line the session waits for is the one the gateway logs, at info, from
/// the module whose target `gateway_bin` keeps visible: a changed wording or a
/// moved module fails here by name, not as every stdio row's 120 s "never
/// became ready".
#[test]
fn the_ready_line_is_the_one_the_gateway_logs() {
    // One literal for both checks: `include_str!` takes no runtime string.
    macro_rules! ready_source {
        () => {
            "src/gateway/server/stdio_loop.rs"
        };
    }
    let source = include_str!(concat!("../", ready_source!()));
    let logged = format!("info!(\"{}\")", stdio_session::READY_LINE);
    assert!(
        source.contains(&logged),
        "{} no longer logs {logged}",
        ready_source!()
    );
    // A plain `info!` logs under its module path.
    let module = ready_source!()
        .strip_prefix("src/")
        .and_then(|path| path.strip_suffix(".rs"))
        .expect("a src/*.rs path")
        .replace('/', "::");
    assert_eq!(
        gateway_bin::STDIO_READY_TARGET,
        format!("mcp_gateway::{module}"),
        "gateway_bin keeps a target visible that does not log the ready line"
    );
}
