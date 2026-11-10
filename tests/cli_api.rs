// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway api METHOD PATH` against the shipped gateway binary: the
//! answer printed as JSON, the exit code per outcome, and the credential read
//! from `MCP_GATEWAY_TOKEN` only (rows A1-A5 and A8-A10 of the CLI design).
//!
//! Gateway rows use the real router, auth middleware and HTTP client. A
//! controlled listener also counts pre-dispatch refusals and method sends.
#![cfg(all(unix, feature = "webui"))]

#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;

use std::sync::{Arc, Mutex};

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
    api_at(&gw.url, token, args)
}

fn api_at(url: &str, token: Option<&str>, args: &[&str]) -> Run {
    let home = tempfile::tempdir().expect("home");
    let mut cmd = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment);
    cmd.arg("api").args(args).args(["--url", url]);
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

fn in_mode<'a>(args: &[&'a str], json_mode: bool) -> Vec<&'a str> {
    let mut args = args.to_vec();
    if json_mode {
        args.push("--json");
    }
    args
}

fn assert_error(
    run: &Run,
    json_mode: bool,
    code: i32,
    kind: &str,
    message: &str,
    remedy: &str,
    http_status: Option<u16>,
) {
    assert_eq!(run.code, Some(code), "stderr: {}", run.stderr);
    assert!(run.stdout.is_empty(), "stdout: {}", run.stdout);
    if json_mode {
        let error: Value = serde_json::from_str(&run.stderr).expect("one JSON stderr object");
        assert_eq!(
            error,
            json!({
                "schema_version": 1,
                "error": {
                    "kind": kind,
                    "message": message,
                    "remedy": remedy,
                    "http_status": http_status,
                    "request_id": null,
                },
            })
        );
    } else {
        assert_eq!(run.stderr, format!("error: {message}\n{remedy}\n"));
    }
}

fn body_file(root: &std::path::Path, body: &str) -> String {
    let path = root.join("request-body.json");
    std::fs::write(&path, body).expect("request body file");
    format!("@{}", path.display())
}

/// A controlled handler records every request that reached its exact route.
struct Probe {
    url: String,
    methods: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Probe {
    async fn start() -> Self {
        let methods = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&methods);
        let router = axum::Router::new().route(
            "/ui/api/probe",
            axum::routing::any(move |method: axum::http::Method| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.lock().expect("methods").push(method.to_string());
                    axum::Json(json!({"method": method.as_str()}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("probe server");
        });
        Self { url, methods, task }
    }

    fn requests(&self) -> Vec<String> {
        self.methods.lock().expect("methods").clone()
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.task.abort();
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

/// `value` with every `last_used` removed, each one asserted a string first.
fn without_last_used(mut value: Value) -> Value {
    match &mut value {
        Value::Object(map) => {
            if let Some(at) = map.remove("last_used") {
                assert!(at.is_string() || at.is_null(), "last_used is a timestamp: {at}");
            }
            map.values_mut()
                .for_each(|v| *v = without_last_used(v.take()));
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|v| *v = without_last_used(v.take())),
        _ => {}
    }
    value
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
    // `last_used` moves with the clock, so the two reads can straddle a
    // second boundary: it must be a timestamp or null, and the rest must match.
    assert_eq!(
        without_last_used(printed),
        without_last_used(direct_get(&gw, "/ui/api/keys").await)
    );
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
    let (root, gw) = started().await;
    let body = body_file(
        root.path(),
        r#"{"name":"admin","backends":["*"],"revision":"x"}"#,
    );
    for json_mode in [false, true] {
        let bare = api(
            &gw,
            Some(ADMIN),
            &in_mode(&["POST", "/ui/api/keys"], json_mode),
        );
        assert_error(
            &bare,
            json_mode,
            6,
            "Gateway",
            "the body must be {\"name\", \"backends\", \"revision\"} and the optional allowed_tools, denied_tools, admin, rate_limit and expires_at, and nothing else",
            "Correct the request body using the gateway's validation details. Gateway reason: invalid_body.",
            Some(422),
        );
        let run = api(
            &gw,
            Some(ADMIN),
            &in_mode(&["POST", "/ui/api/keys", "--data", &body], json_mode),
        );
        assert_error(
            &run,
            json_mode,
            6,
            "Gateway",
            "name_taken",
            "Choose an unused key name, then retry.",
            Some(409),
        );
    }
}

/// A3: a missing backend exits 4 with the error only on stderr. A backend
/// that does not exist, given an `env` edit, answers 404: only an `env` edit
/// reads the config expecting the backend (`slotting.rs:258-260`), and the
/// not-found answer is `slotting.rs:132-136`.
#[tokio::test(flavor = "multi_thread")]
async fn a3_api_http_error_exits_4_with_stderr_only() {
    let (root, gw) = started().await;
    let body = body_file(root.path(), r#"{"env":{"A":"b"}}"#);
    for json_mode in [false, true] {
        let run = api(
            &gw,
            Some(ADMIN),
            &in_mode(
                &["PATCH", "/ui/api/backends/nope", "--data", &body],
                json_mode,
            ),
        );
        assert_error(
            &run,
            json_mode,
            4,
            "NotFound",
            "Backend 'nope' not found",
            "List gateway backends and choose an existing name before retrying.",
            Some(404),
        );
    }
}

/// A4: a refused credential exits 3, names `login` and the gateway origin, and
/// never echoes the token.
#[tokio::test(flavor = "multi_thread")]
async fn a4_api_401_names_login() {
    let (_root, gw) = started().await;
    let wrong = "cli-api-test-wrong-key-0123456789abcdef";
    let remedy = format!(
        "Run mcp-gateway login --gateway {}, then retry. Gateway reason: -32000.",
        gw.url
    );
    for json_mode in [false, true] {
        let run = api(
            &gw,
            Some(wrong),
            &in_mode(&["GET", "/ui/api/keys"], json_mode),
        );
        assert_error(
            &run,
            json_mode,
            3,
            "AuthRefused",
            "Invalid token",
            &remedy,
            Some(401),
        );
        assert!(!run.stdout.contains(wrong) && !run.stderr.contains(wrong));
    }
}

/// A5: a valid key without the route's standing exits 3 and asks for an
/// entitled credential, without promising that login adds privileges.
#[tokio::test(flavor = "multi_thread")]
async fn a5_api_403_for_a_standard_key() {
    let (_root, gw) = started().await;
    let remedy = format!(
        "Use an entitled credential; run mcp-gateway login --gateway {} with an account permitted to perform this operation, then retry.",
        gw.url
    );
    for json_mode in [false, true] {
        let run = api(
            &gw,
            Some(STANDARD),
            &in_mode(&["GET", "/ui/api/keys"], json_mode),
        );
        assert_error(
            &run,
            json_mode,
            3,
            "AuthRefused",
            "Authentication required",
            &remedy,
            Some(403),
        );
    }
}

/// A8: the token from `MCP_GATEWAY_TOKEN` appears in no output, on success or
/// on an error answer.
#[tokio::test(flavor = "multi_thread")]
async fn a8_the_token_is_never_echoed() {
    let (root, gw) = started().await;
    let body = body_file(root.path(), r#"{"env":{"A":"b"}}"#);
    for json_mode in [false, true] {
        let success = api(
            &gw,
            Some(ADMIN),
            &in_mode(&["GET", "/ui/api/keys"], json_mode),
        );
        assert_eq!(success.code, Some(0), "{}", success.stderr);
        assert!(!success.stdout.contains(ADMIN), "{}", success.stdout);
        assert!(success.stderr.is_empty(), "{}", success.stderr);
        let run = api(
            &gw,
            Some(ADMIN),
            &in_mode(
                &["PATCH", "/ui/api/backends/nope", "--data", &body],
                json_mode,
            ),
        );
        assert_error(
            &run,
            json_mode,
            4,
            "NotFound",
            "Backend 'nope' not found",
            "List gateway backends and choose an existing name before retrying.",
            Some(404),
        );
        assert!(!run.stdout.contains(ADMIN), "{}", run.stdout);
        assert!(!run.stderr.contains(ADMIN), "{}", run.stderr);
    }
}

/// A9: missing credentials exit 3 with login advice before any request.
#[tokio::test(flavor = "multi_thread")]
async fn a9_no_credential_names_login_and_sends_nothing() {
    let probe = Probe::start().await;
    let remedy = format!("Run mcp-gateway login --gateway {}, then retry.", probe.url);
    for json_mode in [false, true] {
        let run = api_at(
            &probe.url,
            None,
            &in_mode(&["GET", "/ui/api/probe"], json_mode),
        );
        assert_error(
            &run,
            json_mode,
            3,
            "AuthRefused",
            "No gateway credential is available.",
            &remedy,
            None,
        );
        assert!(
            probe.requests().is_empty(),
            "no credential must send nothing"
        );
    }
}

/// Explicitly empty and whitespace-only credentials are invalid settings,
/// never an absent credential or a reason to fall back to another source.
#[tokio::test(flavor = "multi_thread")]
async fn blank_credentials_exit_2_and_send_nothing() {
    let probe = Probe::start().await;
    for token in ["", "   "] {
        for json_mode in [false, true] {
            let run = api_at(
                &probe.url,
                Some(token),
                &in_mode(&["GET", "/ui/api/probe"], json_mode),
            );
            assert_error(
                &run,
                json_mode,
                2,
                "Usage",
                "MCP_GATEWAY_TOKEN is empty.",
                "Unset or replace MCP_GATEWAY_TOKEN, then retry.",
                None,
            );
            assert!(
                probe.requests().is_empty(),
                "blank credential must send nothing"
            );
        }
    }
}

/// A10: the method is one of five, in any case; anything else is a usage
/// error (exit 2), before any request. Every supported method reaches its
/// exact handler and returns the method the handler actually received.
#[tokio::test(flavor = "multi_thread")]
async fn a10_the_method_is_one_of_five() {
    let probe = Probe::start().await;
    for json_mode in [false, true] {
        let run = api_at(
            &probe.url,
            Some(ADMIN),
            &in_mode(&["TRACE", "/ui/api/probe"], json_mode),
        );
        assert_error(
            &run,
            json_mode,
            2,
            "Usage",
            "Unsupported API method \"TRACE\".",
            "Use GET, POST, PUT, PATCH or DELETE.",
            None,
        );
        assert!(probe.requests().is_empty(), "TRACE must send nothing");
    }
    for (method, expected) in [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("patch", "PATCH"),
        ("delete", "DELETE"),
    ] {
        let run = api_at(&probe.url, Some(ADMIN), &[method, "/ui/api/probe"]);
        assert_eq!(run.code, Some(0), "{method}: {}", run.stderr);
        assert!(run.stderr.is_empty(), "{method}: {}", run.stderr);
        let printed: Value = serde_json::from_str(&run.stdout).expect("handler JSON");
        assert_eq!(printed, json!({"method": expected}));
    }
    assert_eq!(probe.requests(), ["GET", "POST", "PUT", "PATCH", "DELETE"]);
}

/// Expiry and revocation share the same wire refusal. Both cases must stop
/// accepting a credential that was valid, without inferring a provider cause.
#[tokio::test(flavor = "multi_thread")]
async fn expired_and_revoked_credentials_are_both_refused() {
    const DEPARTING: &str = "cli-api-test-departing-key-0123456789abcdef";
    for expired in [true, false] {
        let root = tempfile::tempdir().expect("root");
        let mut settings = config();
        settings["auth"]["api_keys"]
            .as_array_mut()
            .expect("keys")
            .push(json!({
                "name": "departing",
                "key_sha256": mcp_gateway::config::api_key_digest_spec(DEPARTING.as_bytes()),
                "backends": ["*"],
                "admin": true,
            }));
        let mut gw = Gateway::start(root.path(), settings.clone()).await;
        let accepted = api(&gw, Some(DEPARTING), &["GET", "/ui/api/keys"]);
        assert_eq!(accepted.code, Some(0), "{}", accepted.stderr);
        if expired {
            settings["auth"]["api_keys"][2]["expires_at"] = json!("2001-01-01T00:00:00Z");
        } else {
            let revoked = settings["auth"]["api_keys"]
                .as_array_mut()
                .expect("keys")
                .pop()
                .expect("departing key");
            assert_eq!(revoked["name"], "departing");
        }
        gw.rewrite_config(settings);
        gw.restart().await;
        let remedy = format!(
            "Run mcp-gateway login --gateway {}, then retry. Gateway reason: -32000.",
            gw.url
        );
        for json_mode in [false, true] {
            let run = api(
                &gw,
                Some(DEPARTING),
                &in_mode(&["GET", "/ui/api/keys"], json_mode),
            );
            assert_error(
                &run,
                json_mode,
                3,
                "AuthRefused",
                "Invalid token",
                &remedy,
                Some(401),
            );
            assert!(!run.stderr.contains(DEPARTING), "{}", run.stderr);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_bearer_bypasses_environment_proxies() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let gateway_hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&gateway_hits);
    let gateway_app = axum::Router::new().route(
        "/ui/api/status",
        axum::routing::get(move |headers: axum::http::HeaderMap| {
            let seen = Arc::clone(&seen);
            async move {
                assert_eq!(headers["authorization"], format!("Bearer {ADMIN}"));
                seen.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({"ok":true}))
            }
        }),
    );
    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gateway");
    let gateway_url = format!("http://{}", gateway_listener.local_addr().expect("address"));
    let gateway_task = tokio::spawn(async move {
        axum::serve(gateway_listener, gateway_app)
            .await
            .expect("serve");
    });
    let proxy_hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&proxy_hits);
    let proxy_app = axum::Router::new().fallback(move || {
        let seen = Arc::clone(&seen);
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            axum::http::StatusCode::BAD_GATEWAY
        }
    });
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("proxy");
    let proxy_url = format!("http://{}", proxy_listener.local_addr().expect("address"));
    let proxy_task =
        tokio::spawn(async move { axum::serve(proxy_listener, proxy_app).await.expect("serve") });
    let out = tokio::task::spawn_blocking(move || {
        let home = tempfile::tempdir().expect("home");
        let mut cmd = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment);
        cmd.args(["api", "GET", "/ui/api/status", "--url", &gateway_url])
            .env("MCP_GATEWAY_TOKEN", ADMIN)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy");
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            cmd.env(name, &proxy_url);
        }
        cmd.output().expect("CLI")
    })
    .await
    .expect("join");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(proxy_hits.load(Ordering::SeqCst), 0);
    assert_eq!(gateway_hits.load(Ordering::SeqCst), 1);
    assert!(!String::from_utf8_lossy(&out.stdout).contains(ADMIN));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(ADMIN));
    gateway_task.abort();
    proxy_task.abort();
}
