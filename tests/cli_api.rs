// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway api METHOD PATH` against the shipped gateway binary: the
//! answer printed as JSON, the exit code per outcome, and the credential read
//! from `MCP_GATEWAY_TOKEN` only (rows A1-A5 and A8-A10 of the CLI design).
//!
//! The gateway and the CLI are both the built binary, so every row goes
//! through the real router, auth middleware and HTTP client.
#![cfg(all(unix, feature = "webui"))]

#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;

use gateway::{Gateway, gateway_bin};
use serde_json::{Value, json};

const ADMIN: &str = "cli-api-test-admin-key-0123456789abcdef";
const STANDARD: &str = "cli-api-test-standard-key-0123456789abc";

/// Auth on, one admin and one standard key, and the audit log auth needs.
fn config() -> Value {
    let key = |name: &str, secret: &str, admin: bool| {
        json!({
            "name": name,
            "key_sha256": mcp_gateway::config::api_key_digest_spec(secret.as_bytes()),
            "backends": ["*"],
            "admin": admin,
        })
    };
    json!({
        "server": {"host": "127.0.0.1", "port": 0},
        "auth": {"enabled": true, "api_keys": [
            key("admin", ADMIN, true),
            key("standard", STANDARD, false),
        ]},
        "security": {"transparency_log": {"enabled": true, "path": "audit.jsonl"}},
    })
}

/// What one `mcp-gateway api` run printed and exited with.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run `mcp-gateway api <args>` with `token` as `MCP_GATEWAY_TOKEN` (unset when
/// `None`), against `gw`.
fn api(gw: &Gateway, token: Option<&str>, args: &[&str]) -> Run {
    let home = tempfile::tempdir().expect("home");
    let mut cmd = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment);
    cmd.arg("api").args(args).args(["--url", &gw.url]);
    if let Some(token) = token {
        cmd.env("MCP_GATEWAY_TOKEN", token);
    }
    let out = cmd.output().expect("the CLI runs");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The same request sent directly as `ADMIN`: its parsed JSON body.
async fn direct_get(gw: &Gateway, path: &str) -> Value {
    gw.client
        .get(format!("{}{path}", gw.url))
        .bearer_auth(ADMIN)
        .send()
        .await
        .expect("direct GET")
        .json()
        .await
        .expect("JSON body")
}

async fn started() -> (tempfile::TempDir, Gateway) {
    let root = tempfile::tempdir().expect("root");
    let gw = Gateway::start(root.path(), config()).await;
    (root, gw)
}

/// A1: a GET prints the route's JSON, pretty, and exits 0.
#[tokio::test(flavor = "multi_thread")]
async fn a1_api_get_prints_json_and_exits_0() {
    let (_root, gw) = started().await;
    let run = api(&gw, Some(ADMIN), &["GET", "/ui/api/keys"]);
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    let printed: Value = serde_json::from_str(&run.stdout).expect("stdout is JSON");
    assert_eq!(printed, direct_get(&gw, "/ui/api/keys").await);
    assert!(
        run.stdout.contains("\n  \""),
        "pretty-printed: {}",
        run.stdout
    );
    assert!(run.stderr.is_empty(), "stderr: {}", run.stderr);
}

/// A2: `--data` reaches the handler. The same POST without a body is refused
/// as a bad body (422); with a body naming a taken key it reaches the name
/// check (409 `name_taken`, `keys_create.rs` checks the name before the
/// revision), so the two answers differ only because the body arrived.
#[tokio::test(flavor = "multi_thread")]
async fn a2_api_post_with_data_reaches_the_handler() {
    let (_root, gw) = started().await;
    let bare = api(&gw, Some(ADMIN), &["POST", "/ui/api/keys"]);
    assert_eq!(bare.code, Some(1), "stderr: {}", bare.stderr);
    assert!(bare.stderr.contains("422"), "stderr: {}", bare.stderr);
    let body = r#"{"name":"admin","backends":["*"],"revision":"x"}"#;
    let run = api(&gw, Some(ADMIN), &["POST", "/ui/api/keys", "--data", body]);
    assert_eq!(run.code, Some(1), "stderr: {}", run.stderr);
    let printed: Value = serde_json::from_str(&run.stdout).expect("stdout is JSON");
    assert_eq!(printed["error"], "name_taken", "{printed}");
    assert!(run.stderr.contains("409"), "stderr: {}", run.stderr);
}

/// A3: an HTTP error exits 1 with the gateway's JSON body on stdout. A backend
/// that does not exist, given an `env` edit, answers 404: only an `env` edit
/// reads the config expecting the backend (`slotting.rs:258-260`), and the
/// not-found answer is `slotting.rs:132-136`.
#[tokio::test(flavor = "multi_thread")]
async fn a3_api_http_error_exits_1_with_the_body() {
    let (_root, gw) = started().await;
    let run = api(
        &gw,
        Some(ADMIN),
        &[
            "PATCH",
            "/ui/api/backends/nope",
            "--data",
            r#"{"env":{"A":"b"}}"#,
        ],
    );
    assert_eq!(run.code, Some(1), "stderr: {}", run.stderr);
    let printed: Value = serde_json::from_str(&run.stdout).expect("stdout is JSON");
    assert!(printed.to_string().contains("not found"), "{printed}");
    assert!(run.stderr.contains("404"), "stderr: {}", run.stderr);
}

/// A4: a refused credential exits 4, names `login` and the variable, and
/// never echoes the token.
#[tokio::test(flavor = "multi_thread")]
async fn a4_api_401_names_login() {
    let (_root, gw) = started().await;
    let wrong = "cli-api-test-wrong-key-0123456789abcdef";
    let run = api(&gw, Some(wrong), &["GET", "/ui/api/keys"]);
    assert_eq!(run.code, Some(4), "stderr: {}", run.stderr);
    assert!(run.stderr.contains("mcp-gateway login"), "{}", run.stderr);
    assert!(run.stderr.contains("MCP_GATEWAY_TOKEN"), "{}", run.stderr);
    assert!(!run.stdout.contains(wrong) && !run.stderr.contains(wrong));
}

/// A5: a valid key without the route's standing exits 4, says so, and does
/// not send the user to `login`.
#[tokio::test(flavor = "multi_thread")]
async fn a5_api_403_for_a_standard_key() {
    let (_root, gw) = started().await;
    let run = api(&gw, Some(STANDARD), &["GET", "/ui/api/keys"]);
    assert_eq!(run.code, Some(4), "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("may not use this route"),
        "{}",
        run.stderr
    );
    assert!(!run.stderr.contains("login"), "{}", run.stderr);
}

/// A8: the token from `MCP_GATEWAY_TOKEN` appears in no output, on success or
/// on an error answer.
#[tokio::test(flavor = "multi_thread")]
async fn a8_the_token_is_never_echoed() {
    let (_root, gw) = started().await;
    for path in ["/ui/api/keys", "/ui/api/backends/nope"] {
        let run = api(&gw, Some(ADMIN), &["GET", path]);
        assert!(!run.stdout.contains(ADMIN), "{path}: {}", run.stdout);
        assert!(!run.stderr.contains(ADMIN), "{path}: {}", run.stderr);
    }
}

/// A9: with no credential the command names the variable and exits 4.
#[tokio::test(flavor = "multi_thread")]
async fn a9_no_credential_names_the_variable() {
    let (_root, gw) = started().await;
    let run = api(&gw, None, &["GET", "/ui/api/keys"]);
    assert_eq!(run.code, Some(4), "stderr: {}", run.stderr);
    assert!(run.stderr.contains("MCP_GATEWAY_TOKEN"), "{}", run.stderr);
}

/// A10: the method is one of five, in any case; anything else is a usage
/// error (exit 2) from argument parsing, before any request.
#[tokio::test(flavor = "multi_thread")]
async fn a10_the_method_is_one_of_five() {
    let (_root, gw) = started().await;
    let run = api(&gw, Some(ADMIN), &["TRACE", "/ui/api/keys"]);
    assert_eq!(run.code, Some(2), "stderr: {}", run.stderr);
    for method in ["get", "post", "put", "patch", "delete"] {
        let run = api(&gw, Some(ADMIN), &[method, "/ui/api/keys"]);
        assert_ne!(run.code, Some(2), "{method} parses: {}", run.stderr);
    }
}
