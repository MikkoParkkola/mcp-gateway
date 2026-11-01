// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend that echoes a credential its configuration gave it, through
//! `env:` or `headers:` rather than a `secrets:` rule: the value is loaded
//! the way the gateway loads it, so the row sees what config load marks.

use axum::body::to_bytes;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_backend;
use crate::backend::Backend;
use crate::config::{Config, FailsafeConfig};

/// The credential the env file holds; long enough that no rule treats it
/// as too short to redact.
const SECRET: &str = "config-env-secret-5b81d0c4e9a2";

/// The marker the shared redactor writes in place of a value.
const MARKER: &str = "[redacted]";

/// A stdio MCP child whose `echo` tool answers with its `ECHO_TOKEN`.
#[cfg(unix)]
const STDIO_ENV_ECHO: &str = r#"import json, os, sys
for line in sys.stdin:
    req = json.loads(line)
    if "id" not in req:
        continue
    method = req.get("method")
    if method == "initialize":
        body = {"result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                           "serverInfo": {"name": "echoes", "version": "0"}}}
    elif method == "tools/list":
        body = {"result": {"tools": [{"name": "echo", "description": "fixture",
                                      "inputSchema": {"type": "object"}}]}}
    elif method == "tools/call":
        token = os.environ.get("ECHO_TOKEN", "")
        body = {"result": {"content": [{"type": "text", "text": "environment " + token}]}}
    else:
        body = {"result": {}}
    print(json.dumps({"jsonrpc": "2.0", "id": req["id"], **body}), flush=True)
"#;

fn write_0600(path: &Path, body: &str) {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).expect("open");
    file.write_all(body.as_bytes()).expect("write");
}

/// A gateway config whose one backend, `echoes`, is described by
/// `backend` (YAML lines indented under it), and an env file holding
/// `env_body`.
fn config(dir: &Path, backend: &str, env_body: &str) -> PathBuf {
    let env = dir.join("gateway.env");
    write_0600(&env, env_body);
    let path = dir.join("gateway.yaml");
    write_0600(
        &path,
        &format!(
            "env_files:\n  - \"{}\"\nbackends:\n  echoes:\n    timeout: 10s\n{backend}",
            env.display()
        ),
    );
    path
}

/// A stdio backend running the env-echo child, with `env_line` under `env:`.
#[cfg(unix)]
fn stdio_backend(dir: &Path, env_line: &str) -> String {
    let script = dir.join("echo.py");
    std::fs::write(&script, STDIO_ENV_ECHO).expect("write the child script");
    format!(
        "    command: \"python3 {}\"\n    env:\n      {env_line}\n",
        script.display()
    )
}

/// The `echoes` backend as the loaded config describes it.
fn loaded_backend(path: &Path) -> Arc<Backend> {
    let loaded = Config::load_evaluated(Some(path)).expect("the config loads");
    let config = loaded
        .config
        .backends
        .get("echoes")
        .expect("the backend is configured")
        .clone();
    Arc::new(Backend::new(
        "echoes",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(30),
    ))
}

/// Loads `path`, registers its `echoes` backend and calls its `echo` tool
/// on the meta route; the client's answer.
async fn invoke_echo(path: &Path) -> Value {
    let (state, _store) = test_router_app_state_with_backend(loaded_backend(path)).await;
    let router = create_router(state);
    post(
        &router,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "gateway_invoke",
            "arguments": {"server": "echoes", "tool": "echo", "arguments": {}}
        }}),
    )
    .await
}

async fn post(router: &axum::Router, body: Value) -> Value {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// CRED.1: a stdio backend whose `env:` holds a credential written as an
/// `env:` reference, and that echoes it in a tool result, does not get it
/// into the client's answer.
#[cfg(unix)]
#[tokio::test]
async fn a_stdio_env_credential_echo_is_redacted() {
    let dir = tempfile::tempdir().expect("config directory");
    let backend = stdio_backend(dir.path(), "ECHO_TOKEN: \"env:MIK_9105_ECHO_TOKEN\"");
    let path = config(
        dir.path(),
        &backend,
        &format!("MIK_9105_ECHO_TOKEN={SECRET}\n"),
    );
    let body = invoke_echo(&path).await;
    let text = body.to_string();
    assert!(
        text.contains("environment"),
        "premise: the child answered: {body}"
    );
    assert!(
        !text.contains(SECRET),
        "the env credential reached the client: {body}"
    );
    assert!(
        text.contains(MARKER),
        "the env credential was dropped, not redacted: {body}"
    );
}

/// CRED.3: an HTTP backend whose `headers:` value is an `env:` reference,
/// and that echoes the header it received, does not get it into the
/// client's answer.
#[tokio::test]
async fn an_http_header_credential_echo_is_redacted() {
    use super::secret_echo_tests::{Calls, Reply, echo_server};
    let calls = Calls::default();
    let url = echo_server(Arc::clone(&calls), Reply::EchoHeader).await;
    let dir = tempfile::tempdir().expect("config directory");
    let backend = format!(
        "    http_url: \"{url}\"\n    streamable_http: true\n    headers:\n      \
         X-Api-Key: \"env:MIK_9105_HEADER\"\n"
    );
    let path = config(dir.path(), &backend, &format!("MIK_9105_HEADER={SECRET}\n"));
    let body = invoke_echo(&path).await;
    let text = body.to_string();
    assert!(
        !calls.lock().is_empty(),
        "premise: the backend was called: {body}"
    );
    assert!(
        !text.contains(SECRET),
        "the header credential reached the client: {body}"
    );
    assert!(
        text.contains(MARKER),
        "the header echo was dropped, not redacted: {body}"
    );
}

/// CRED.3: a WebSocket backend that echoes its upgrade request's headers
/// does not get a configured header credential into the client's answer.
#[tokio::test]
async fn a_websocket_upgrade_header_credential_echo_is_redacted() {
    use crate::transport::websocket_test_server::{Behaviour, WsPeer};
    let peer = WsPeer::start(Behaviour::EchoUpgradeHeaders).await;
    let dir = tempfile::tempdir().expect("config directory");
    let backend = format!(
        "    ws_url: \"{}\"\n    headers:\n      Authorization: \"Bearer ${{MIK_9105_WS}}\"\n",
        peer.url
    );
    let path = config(dir.path(), &backend, &format!("MIK_9105_WS={SECRET}\n"));
    let body = invoke_echo(&path).await;
    let text = body.to_string();
    assert_eq!(
        peer.seen.calls.lock().len(),
        1,
        "premise: the peer was called: {body}"
    );
    assert!(
        text.contains("authorization"),
        "premise: the headers were echoed: {body}"
    );
    assert!(
        !text.contains(SECRET),
        "the upgrade header credential reached the client: {body}"
    );
    assert!(
        text.contains(MARKER),
        "the upgrade header echo was dropped, not redacted: {body}"
    );
}

/// CRED.4: a value the config does not mark secret passes unchanged: a
/// literal, and an inferred `${VAR}` too short to treat as a secret.
#[cfg(unix)]
#[tokio::test]
async fn a_value_not_marked_secret_passes_unchanged() {
    for (env_line, env_body, expected) in [
        ("ECHO_TOKEN: \"debug\"", String::new(), "environment debug"),
        (
            "ECHO_TOKEN: \"${MIK_9105_DEBUG}\"",
            "MIK_9105_DEBUG=1\n".to_owned(),
            "environment 1",
        ),
    ] {
        let dir = tempfile::tempdir().expect("config directory");
        let backend = stdio_backend(dir.path(), env_line);
        let path = config(dir.path(), &backend, &env_body);
        let body = invoke_echo(&path).await;
        let text = body.to_string();
        assert!(text.contains(expected), "{env_line}: changed: {body}");
        assert!(!text.contains(MARKER), "{env_line}: redacted: {body}");
    }
}
