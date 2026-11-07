// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The admin command refuses unsafe input before invoking its transport, and
//! keeps the response and the older body-less callers' wire contract intact.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use mcp_gateway::cli::api::{ApiArgs, ApiMethod};
use mcp_gateway::cli::dashboard_link::DashboardLinkTls;
use mcp_gateway::cli::events::{DeadLetterAction, DeadLettersArgs};
use serde_json::json;

use super::api::{ApiExit, ApiOutcome, ApiRequest, run_api_with};
use super::dashboard_link::{
    AdminResponse, LinkTls, TOKEN_ENV, admin_call, admin_call_url, dead_letters_request, fetch_link,
};

const TOKEN: &str = "api-unit-credential";

fn args(path: &str) -> ApiArgs {
    ApiArgs {
        method: ApiMethod::Get,
        path: path.to_string(),
        data: None,
        url: None,
        tls: DashboardLinkTls::default(),
    }
}

fn credential(name: &str) -> Option<String> {
    (name == TOKEN_ENV).then(|| TOKEN.to_string())
}

fn no_stdin() -> Result<String, String> {
    panic!("stdin must only be read for --data -")
}

async fn send(request: ApiRequest) -> Result<AdminResponse, String> {
    admin_call_url(
        request.method,
        request.url,
        &request.token,
        &request.tls,
        request.body.as_ref(),
    )
    .await
}

struct Seen {
    method: axum::http::Method,
    path: String,
    authorization: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

struct Stand {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Stand {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn stand_in(status: StatusCode, content_type: &'static str, body: &'static str) -> Stand {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |request: Request<Body>| {
        let requests = Arc::clone(&requests);
        async move {
            let (parts, incoming) = request.into_parts();
            let incoming = to_bytes(incoming, 1024 * 1024).await.expect("request body");
            requests.lock().expect("requests").push(Seen {
                method: parts.method,
                path: parts.uri.to_string(),
                authorization: parts.headers["authorization"]
                    .to_str()
                    .expect("bearer")
                    .to_string(),
                content_type: parts
                    .headers
                    .get("content-type")
                    .map(|v| v.to_str().expect("type").to_string()),
                body: incoming.to_vec(),
            });
            (status, [("content-type", content_type)], body)
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    Stand { base, seen, server }
}

async fn refused(base: &str, path: &str, expected: ApiExit) -> ApiOutcome {
    let calls = AtomicUsize::new(0);
    let out = run_api_with(
        &args(path),
        base,
        &LinkTls::default(),
        credential,
        no_stdin,
        |request| {
            calls.fetch_add(1, Ordering::SeqCst);
            send(request)
        },
    )
    .await;
    assert_eq!(out.exit.code(), expected.code(), "{}", out.stderr);
    assert!(out.stdout.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0, "refusal must precede send");
    out
}

#[tokio::test]
async fn a6_api_path_outside_ui_api_is_refused_and_nothing_sent() {
    let base = stand_in(StatusCode::OK, "application/json", "{}").await;
    let other = stand_in(StatusCode::OK, "application/json", "{}").await;
    let authority = other.base.strip_prefix("http:").expect("authority");
    for path in [
        "/mcp",
        "/dashboard",
        "/auth",
        "/ui/api",
        "/ui/api/../mcp",
        r"/ui/api/..\mcp",
        "/ui/api/%2e%2e/mcp",
        "/ui/api/%2E./mcp",
        "/ui/api/x%2Fy",
        "/ui/api/x%5cy",
        "//evil/ui/api/x",
        r"/ui/api/\..\..\mcp",
        "/ui/api/./keys",
        "/ui/api/keys#fragment",
    ] {
        refused(&base.base, path, ApiExit::Usage).await;
    }
    for path in [
        format!("{authority}/ui/api/x"),
        format!("{}/ui/api/x", other.base),
    ] {
        refused(&base.base, &path, ApiExit::Usage).await;
    }
    assert!(base.seen.lock().expect("requests").is_empty());
    assert!(
        other.seen.lock().expect("requests").is_empty(),
        "the named authority received no request"
    );
}

#[tokio::test]
async fn a7_api_cleartext_off_loopback_is_refused_and_nothing_sent() {
    let out = refused("http://192.0.2.1:9", "/ui/api/keys", ApiExit::Transport).await;
    assert!(out.stderr.contains("https") || out.stderr.contains("loopback"));
}

#[tokio::test]
async fn unsupported_scheme_is_a_refused_target_before_sending() {
    for base in ["file:///", "ftp://127.0.0.1/", "custom://127.0.0.1/"] {
        let out = refused(base, "/ui/api/status", ApiExit::Transport).await;
        assert!(out.stderr.contains("unsupported scheme"), "{}", out.stderr);
    }
}

#[tokio::test]
async fn a13_a_base_with_a_path_or_query_is_refused() {
    let listener = stand_in(StatusCode::OK, "application/json", "{}").await;
    let https = listener.base.replacen("http:", "https:", 1);
    for suffix in ["/mcp?x=", "/ui/api#f", "/mcp", "/?x=", "/#f"] {
        refused(&format!("{https}{suffix}"), "/ui/api/keys", ApiExit::Usage).await;
    }
    assert!(listener.seen.lock().expect("requests").is_empty());
}

#[tokio::test]
async fn a11_non_json_2xx_body_printed_raw() {
    let raw = "gateway text\nwithout a final newline";
    let listener = stand_in(StatusCode::OK, "text/plain", raw).await;
    let out = run_api_with(
        &args("/ui/api/status"),
        &listener.base,
        &LinkTls::default(),
        credential,
        no_stdin,
        send,
    )
    .await;
    assert_eq!(out.exit.code(), 0, "{}", out.stderr);
    assert_eq!(out.stdout, raw.as_bytes());
    assert!(out.stderr.contains("non-JSON"), "{}", out.stderr);
    let seen = listener.seen.lock().expect("requests");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].authorization, format!("Bearer {TOKEN}"));
}

#[tokio::test]
async fn a12_existing_admin_call_callers_unchanged() {
    let raw = r#"{"link":"http://127.0.0.1/dashboard?bootstrap=abc","items":[]}"#;
    let listener = stand_in(StatusCode::OK, "application/json", raw).await;
    let tls = LinkTls::default();
    let list = DeadLettersArgs {
        action: DeadLetterAction::List,
        id: None,
        all: false,
        subscription: Some("orders & returns".to_string()),
        reason: None,
        url: None,
        tls: DashboardLinkTls::default(),
    };
    let (method, path) = dead_letters_request(&list).expect("list");
    let body = admin_call(method, &listener.base, &path, TOKEN, &tls)
        .await
        .expect("list body");
    assert_eq!(
        body,
        serde_json::from_str::<serde_json::Value>(raw).expect("fixture")
    );
    assert_eq!(
        serde_json::to_string_pretty(&body).expect("printed body"),
        "{\n  \"items\": [],\n  \"link\": \"http://127.0.0.1/dashboard?bootstrap=abc\"\n}"
    );
    assert_eq!(
        fetch_link(&listener.base, TOKEN, &tls).await.expect("link"),
        "http://127.0.0.1/dashboard?bootstrap=abc"
    );
    let seen = listener.seen.lock().expect("requests");
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].method, reqwest::Method::GET);
    assert_eq!(
        seen[0].path,
        "/ui/api/events/dead-letters?subscription=orders+%26+returns"
    );
    assert_eq!(seen[1].method, reqwest::Method::POST);
    assert_eq!(seen[1].path, "/ui/api/dashboard-link");
    for request in seen.iter() {
        assert_eq!(request.authorization, format!("Bearer {TOKEN}"));
        assert!(request.body.is_empty(), "existing callers remain body-less");
        assert!(request.content_type.is_none());
    }
}

#[tokio::test]
async fn a12_existing_admin_call_errors_keep_their_wording() {
    for (status, body, expected) in [
        (
            StatusCode::FORBIDDEN,
            r#"{"reason":"no standing","error":"ignored"}"#,
            "the gateway answered 403 Forbidden: no standing",
        ),
        (
            StatusCode::NOT_FOUND,
            r#"{"error":"missing"}"#,
            "the gateway answered 404 Not Found: missing",
        ),
        (
            StatusCode::BAD_GATEWAY,
            "plain",
            "the gateway answered 502 Bad Gateway: no reason given",
        ),
        (
            StatusCode::OK,
            "plain",
            "the gateway answered 200 OK with no JSON body",
        ),
        (
            StatusCode::OK,
            "null",
            "the gateway answered 200 OK with no JSON body",
        ),
    ] {
        let listener = stand_in(status, "application/json", body).await;
        let error = admin_call(
            reqwest::Method::GET,
            &listener.base,
            "/ui/api/events/dead-letters",
            TOKEN,
            &LinkTls::default(),
        )
        .await
        .expect_err("legacy error");
        assert_eq!(error, expected);
    }
}

#[tokio::test]
async fn data_sources_and_query_are_sent_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("body.json");
    std::fs::write(&path, r#"{"source":"file"}"#).expect("JSON file");
    for (data, expected, reads_stdin) in [
        (
            r#"{"source":"inline"}"#.to_string(),
            json!({"source":"inline"}),
            false,
        ),
        (
            format!("@{}", path.display()),
            json!({"source":"file"}),
            false,
        ),
        ("-".to_string(), json!({"source":"stdin"}), true),
    ] {
        let mut args = args("/ui/api/keys?name=a%20b&kind=cli");
        args.method = ApiMethod::Post;
        args.data = Some(data);
        let listener = stand_in(StatusCode::OK, "application/json", "{}").await;
        let stdin_calls = AtomicUsize::new(0);
        let out = run_api_with(
            &args,
            &listener.base,
            &LinkTls::default(),
            credential,
            || {
                stdin_calls.fetch_add(1, Ordering::SeqCst);
                Ok(r#"{"source":"stdin"}"#.to_string())
            },
            send,
        )
        .await;
        assert_eq!(out.exit.code(), 0, "{}", out.stderr);
        assert_eq!(stdin_calls.load(Ordering::SeqCst), usize::from(reads_stdin));
        let seen = listener.seen.lock().expect("requests");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, args.path);
        assert_eq!(seen[0].method, reqwest::Method::POST);
        assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&seen[0].body).expect("JSON sent"),
            expected
        );
    }
}

#[tokio::test]
async fn missing_or_blank_credential_never_sends() {
    for value in [None, Some(""), Some(" \n\t")] {
        let calls = AtomicUsize::new(0);
        let out = run_api_with(
            &args("/ui/api/keys"),
            "http://127.0.0.1:1",
            &LinkTls::default(),
            |_| value.map(ToString::to_string),
            no_stdin,
            |request| {
                calls.fetch_add(1, Ordering::SeqCst);
                send(request)
            },
        )
        .await;
        assert_eq!(out.exit.code(), 4);
        assert!(out.stdout.is_empty());
        assert!(out.stderr.contains("set MCP_GATEWAY_TOKEN, or run `mcp-gateway login` once it ships in this release's second part"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn credential_errors_keep_the_exact_advice_and_hide_the_token() {
    for (status, advice) in [
        (
            StatusCode::UNAUTHORIZED,
            "the credential was refused (not recognised, revoked or expired): run `mcp-gateway login` or set MCP_GATEWAY_TOKEN",
        ),
        (
            StatusCode::FORBIDDEN,
            "the credential is valid but may not use this route",
        ),
    ] {
        let out = run_api_with(
            &args("/ui/api/keys"),
            "http://127.0.0.1:1",
            &LinkTls::default(),
            credential,
            no_stdin,
            |_| async move {
                Ok(AdminResponse {
                    status,
                    body: serde_json::to_vec(&json!({"reason": format!("refused {TOKEN}")}))
                        .expect("body"),
                })
            },
        )
        .await;
        assert_eq!(out.exit.code(), 4);
        assert!(
            out.stderr
                .contains(&format!("api: the gateway answered {status}: refused ")),
            "{}",
            out.stderr
        );
        assert!(out.stderr.contains(advice), "{}", out.stderr);
        assert!(!out.stderr.contains(TOKEN));
        let stdout = String::from_utf8(out.stdout).expect("JSON output");
        assert!(!stdout.contains(TOKEN));
        serde_json::from_str::<serde_json::Value>(&stdout).expect("error body remains JSON");
        if status == StatusCode::FORBIDDEN {
            assert!(!out.stderr.contains("login"));
        }
    }
}

#[tokio::test]
async fn echoed_json_credentials_are_redacted_without_corrupting_json() {
    for token in ["abc\"def", r"abc\def", "null"] {
        let out = run_api_with(
            &args("/ui/api/keys"),
            "http://127.0.0.1:1",
            &LinkTls::default(),
            |_| Some(token.to_string()),
            no_stdin,
            |_| async move {
                Ok(AdminResponse {
                    status: StatusCode::OK,
                    body: serde_json::to_vec(&json!({
                        "echo": token, "nested": [token], "literal": null,
                        (token): "an echoed key",
                    }))
                    .expect("body"),
                })
            },
        )
        .await;
        assert_eq!(out.exit.code(), 0);
        assert!(out.stderr.is_empty());
        let printed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
        assert_eq!(printed["echo"], "[REDACTED]");
        assert_eq!(printed["nested"][0], "[REDACTED]");
        assert!(printed["literal"].is_null());
        assert!(printed.get(token).is_none());
        assert_eq!(printed["[REDACTED]"], "an echoed key");
    }
}

#[tokio::test]
async fn invalid_data_is_a_usage_error_before_sending() {
    let dir = tempfile::tempdir().expect("tempdir");
    for data in [
        "not JSON".to_string(),
        format!("@{}", dir.path().join("absent.json").display()),
        "-".to_string(),
    ] {
        let mut args = args("/ui/api/keys");
        args.data = Some(data);
        let calls = AtomicUsize::new(0);
        let out = run_api_with(
            &args,
            "http://127.0.0.1:1",
            &LinkTls::default(),
            credential,
            || Err("unreadable stdin".to_string()),
            |request| {
                calls.fetch_add(1, Ordering::SeqCst);
                send(request)
            },
        )
        .await;
        assert_eq!(out.exit.code(), 2, "{}", out.stderr);
        assert!(out.stdout.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
