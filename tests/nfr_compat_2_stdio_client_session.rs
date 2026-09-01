//! NFR.COMPAT.2 — demonstration half.
//!
//! Criterion: "A client that worked against 3.5.0 MUST work against 4.0.0 with
//! no configuration change." Verification method is "T, D". The T half is
//! `tests/mik_7217_acs.rs::ac_discover_3_initialize_result_is_unchanged`, which
//! pins the initialize result against a golden fixture by calling the handler
//! in-process. Nothing exercised a real client over a real transport, and
//! `tests/stdio_tests.rs` says so in its own header: it tests "the *components*
//! of stdio dispatch in isolation (no process spawning required)".
//!
//! This file spawns the shipped `mcp-gateway` binary and drives a full session
//! over its stdio transport the way a 3.5.0-era client would:
//! initialize -> notifications/initialized -> tools/list -> tools/call.
//!
//! "No configuration change" is staged as a client that ships no gateway config
//! at all: the child runs in an empty directory with `HOME` pointed at it and
//! every `MCP_GATEWAY_*` variable removed, so `Config::fallback_config_path`
//! finds nothing and the gateway boots on defaults alone.

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

/// A hung child must fail the test rather than block the suite forever.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The protocol version a 3.5.0-era client sends. Matches the versions the
/// T-half golden pins; omitting the field would stage 2024-11-05 instead.
const CLIENT_PROTOCOL_VERSION: &str = "2025-06-18";

/// Meta tool used for the `tools/call` leg: zero arguments, no backend needed.
const META_TOOL: &str = "gateway_list_servers";

struct StdioSession {
    child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
}

impl StdioSession {
    /// Spawns the shipped binary with no configuration reachable from anywhere.
    fn spawn(home: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
            .arg("serve")
            .arg("--stdio")
            .current_dir(home)
            .env("HOME", home)
            .env_remove("MCP_GATEWAY_CONFIG")
            .env_remove("MCP_GATEWAY_CONFIG_DIR")
            .env_remove("MCP_GATEWAY_CAPABILITIES")
            .env_remove("MCP_GATEWAY_PORT")
            .env_remove("MCP_GATEWAY_HOST")
            .env_remove("MCP_GATEWAY_LOG_LEVEL")
            .env_remove("MCP_GATEWAY_LOG_FORMAT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Inherited, not piped: an undrained pipe deadlocks the child at
            // ~64KB, and the startup log is part of the demonstration.
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn mcp-gateway serve --stdio");

        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout")).lines();
        Self {
            child,
            stdin,
            stdout,
        }
    }

    async fn send(&mut self, message: &Value) {
        let line = format!("{message}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write request to child stdin");
        self.stdin.flush().await.expect("flush child stdin");
    }

    /// Reads until the response carrying `id` arrives. Any other line (a log
    /// escaping onto stdout, a notification) is skipped rather than parsed as
    /// the answer.
    async fn read_response(&mut self, id: i64) -> Value {
        loop {
            let line = timeout(READ_TIMEOUT, self.stdout.next_line())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for response to id {id}"))
                .expect("read child stdout")
                .unwrap_or_else(|| panic!("child closed stdout before answering id {id}"));

            let Ok(value) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if value.get("id").and_then(Value::as_i64) == Some(id) {
                return value;
            }
        }
    }

    async fn shutdown(mut self) {
        drop(self.stdin);
        let _ = self.child.kill().await;
    }
}

/// Asserts a JSON-RPC envelope carries a result. A JSON-RPC error uses the same
/// envelope, so the absence of `error` is the load-bearing half.
fn expect_result<'a>(response: &'a Value, what: &str) -> &'a Value {
    assert!(
        response.get("error").is_none(),
        "{what} returned a JSON-RPC error: {response}"
    );
    response
        .get("result")
        .unwrap_or_else(|| panic!("{what} carried no result: {response}"))
}

#[tokio::test]
async fn nfr_compat_2_a_3_5_0_client_completes_a_session_against_4_0_0() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut session = StdioSession::spawn(home.path());

    // 1. initialize — the handshake a 3.5.0 client opens with.
    session
        .send(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": CLIENT_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "nfr-compat-2-client", "version": "3.5.0" }
            }
        }))
        .await;
    let initialize = session.read_response(1).await;
    let result = expect_result(&initialize, "initialize");
    assert!(
        result.get("protocolVersion").is_some(),
        "initialize result carried no protocolVersion: {result}"
    );
    assert!(
        result.get("capabilities").is_some(),
        "initialize result carried no capabilities: {result}"
    );
    assert!(
        result.get("serverInfo").is_some(),
        "initialize result carried no serverInfo: {result}"
    );

    // 2. notifications/initialized — no id, so no response is expected.
    session
        .send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await;

    // 3. tools/list — the client must be able to see the surface.
    session
        .send(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
        .await;
    let list = session.read_response(2).await;
    let tools = expect_result(&list, "tools/list")
        .get("tools")
        .and_then(Value::as_array)
        .expect("tools/list result carried no tools array")
        .clone();
    assert!(!tools.is_empty(), "tools/list returned an empty surface");
    assert!(
        tools
            .iter()
            .any(|t| t.get("name").and_then(Value::as_str) == Some(META_TOOL)),
        "tools/list did not surface {META_TOOL}: {tools:?}"
    );

    // 4. tools/call — the client must be able to use the surface.
    session
        .send(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": META_TOOL, "arguments": {} }
        }))
        .await;
    let call = session.read_response(3).await;
    let call_result = expect_result(&call, "tools/call");
    assert!(
        call_result.get("isError").and_then(Value::as_bool) != Some(true),
        "tools/call reported a tool-level error: {call_result}"
    );
    let content = call_result
        .get("content")
        .and_then(Value::as_array)
        .expect("tools/call result carried no content array");
    assert!(!content.is_empty(), "tools/call returned empty content");

    session.shutdown().await;
}
