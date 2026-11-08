// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The admin command refuses unsafe input before invoking its transport, and
//! keeps the response and the older body-less callers' wire contract intact.

use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use mcp_gateway::cli::api::{ApiArgs, ApiMethod};
use mcp_gateway::cli::dashboard_link::DashboardLinkTls;
use mcp_gateway::cli::events::{DeadLetterAction, DeadLettersArgs};
use serde_json::json;

use super::api::{ApiExit, ApiOutcome, ApiRequest, run_api_with, write_outcome};
use super::dashboard_link::{
    AdminCallError, AdminFailureKind, AdminResponse, LinkTls, TOKEN_ENV, admin_call,
    admin_call_url, dead_letters_request, fetch_link,
};

const TOKEN: &str = "api-unit-credential";

fn args(path: &str) -> ApiArgs {
    ApiArgs {
        method: ApiMethod::Get,
        path: path.to_string(),
        data: None,
        json: false,
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

async fn send(request: ApiRequest) -> Result<AdminResponse, AdminCallError> {
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
    stand_in_with_headers(status, content_type, body, &[]).await
}

async fn stand_in_with_headers(
    status: StatusCode,
    content_type: &'static str,
    body: &'static str,
    extra_headers: &[(&'static str, &'static str)],
) -> Stand {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "content-type",
        reqwest::header::HeaderValue::from_static(content_type),
    );
    for &(name, value) in extra_headers {
        headers.insert(name, reqwest::header::HeaderValue::from_static(value));
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |request: Request<Body>| {
        let requests = Arc::clone(&requests);
        let headers = headers.clone();
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
            (status, headers, body)
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    Stand { base, seen, server }
}

#[allow(
    clippy::too_many_arguments,
    reason = "fixtures pin every error field independently"
)]
fn assert_error(
    out: &ApiOutcome,
    json_output: bool,
    code: u8,
    kind: &str,
    message: &str,
    remedy: &str,
    status: Option<u16>,
    request_id: Option<&str>,
) {
    assert_eq!(out.exit.code(), code, "{}", out.stderr);
    assert!(out.stdout.is_empty(), "errors must never reach stdout");
    if json_output {
        let printed: serde_json::Value = serde_json::from_str(&out.stderr).expect("one JSON error");
        assert_eq!(
            printed,
            json!({
                "schema_version": 1,
                "error": {
                    "kind": kind,
                    "message": message,
                    "remedy": remedy,
                    "http_status": status,
                    "request_id": request_id,
                },
            })
        );
    } else {
        assert_eq!(out.stderr, format!("error: {message}\n{remedy}\n"));
    }
    assert!(!out.stderr.contains(TOKEN));
}

async fn refused(base: &str, path: &str, message: &str, remedy: &str) {
    for json_output in [false, true] {
        let mut args = args(path);
        args.json = json_output;
        let calls = AtomicUsize::new(0);
        let out = run_api_with(
            &args,
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
        assert_error(&out, json_output, 2, "Usage", message, remedy, None, None);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "refusal must precede send");
    }
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
        refused(
            &base.base,
            path,
            "API path is outside the unchanged /ui/api/ boundary.",
            "Use an unchanged relative path beginning /ui/api/.",
        )
        .await;
    }
    for path in [
        format!("{authority}/ui/api/x"),
        format!("{}/ui/api/x", other.base),
    ] {
        refused(
            &base.base,
            &path,
            "API path is outside the unchanged /ui/api/ boundary.",
            "Use an unchanged relative path beginning /ui/api/.",
        )
        .await;
    }
    assert!(base.seen.lock().expect("requests").is_empty());
    assert!(
        other.seen.lock().expect("requests").is_empty(),
        "the named authority received no request"
    );
}

#[tokio::test]
async fn a7_api_cleartext_off_loopback_is_refused_and_nothing_sent() {
    refused(
        "http://192.0.2.1:9",
        "/ui/api/keys",
        "Gateway URL must use HTTPS or loopback HTTP.",
        "Use an HTTPS gateway URL or a loopback HTTP URL.",
    )
    .await;
}

#[tokio::test]
async fn unsupported_scheme_is_a_refused_target_before_sending() {
    for base in ["file:///", "ftp://127.0.0.1/", "custom://127.0.0.1/"] {
        refused(
            base,
            "/ui/api/status",
            "Gateway URL must use HTTPS or loopback HTTP.",
            "Use an HTTPS gateway URL or a loopback HTTP URL.",
        )
        .await;
    }
}

#[tokio::test]
async fn a13_a_base_with_a_path_or_query_is_refused() {
    let listener = stand_in(StatusCode::OK, "application/json", "{}").await;
    let https = listener.base.replacen("http:", "https:", 1);
    for suffix in ["/mcp?x=", "/ui/api#f", "/mcp", "/?x=", "/#f"] {
        refused(
            &format!("{https}{suffix}"),
            "/ui/api/keys",
            "API path is outside the unchanged /ui/api/ boundary.",
            "Use an unchanged relative path beginning /ui/api/.",
        )
        .await;
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
            "the gateway answered 403 Forbidden: ignored",
        ),
        (
            StatusCode::FORBIDDEN,
            r#"{"reason":"no standing"}"#,
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
    for (value, code, kind, message, remedy) in [
        (
            None,
            3,
            "AuthRefused",
            "No gateway credential is available.",
            "Run mcp-gateway login --gateway http://127.0.0.1:1, then retry.",
        ),
        (
            Some(""),
            2,
            "Usage",
            "MCP_GATEWAY_TOKEN is empty.",
            "Unset or replace MCP_GATEWAY_TOKEN, then retry.",
        ),
        (
            Some(" \n\t"),
            2,
            "Usage",
            "MCP_GATEWAY_TOKEN is empty.",
            "Unset or replace MCP_GATEWAY_TOKEN, then retry.",
        ),
    ] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys");
            args.json = json_output;
            let calls = AtomicUsize::new(0);
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1/",
                &LinkTls::default(),
                |_| value.map(ToString::to_string),
                no_stdin,
                |request| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    send(request)
                },
            )
            .await;
            assert_error(&out, json_output, code, kind, message, remedy, None, None);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn credential_errors_keep_the_exact_advice_and_hide_the_token() {
    for (status, remedy) in [
        (
            StatusCode::UNAUTHORIZED,
            "Run mcp-gateway login --gateway http://127.0.0.1:1, then retry.",
        ),
        (
            StatusCode::FORBIDDEN,
            "Use an entitled credential; run mcp-gateway login --gateway http://127.0.0.1:1 with an account permitted to perform this operation, then retry.",
        ),
    ] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys");
            args.json = json_output;
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1/",
                &LinkTls::default(),
                credential,
                no_stdin,
                |_| async move {
                    Ok(AdminResponse {
                        status,
                        headers: reqwest::header::HeaderMap::new(),
                        body: serde_json::to_vec(&json!({"reason": format!("refused {TOKEN}")}))
                            .expect("body"),
                    })
                },
            )
            .await;
            assert_error(
                &out,
                json_output,
                3,
                "AuthRefused",
                "refused [REDACTED]",
                remedy,
                Some(status.as_u16()),
                None,
            );
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
                    headers: reqwest::header::HeaderMap::new(),
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
    let absent = dir.path().join("absent.json");
    for (data, code, kind, message, remedy) in [
        (
            "not JSON".to_string(),
            2,
            "Usage",
            "Request body is not valid JSON.".to_string(),
            "Correct the JSON or select the body's actual Content-Type.".to_string(),
        ),
        (
            format!("@{}", absent.display()),
            1,
            "LocalFailure",
            format!("Could not read request body from {}.", absent.display()),
            format!("Make {} readable, then retry.", absent.display()),
        ),
        (
            "-".to_string(),
            1,
            "LocalFailure",
            "Could not read request body from stdin.".to_string(),
            "Supply readable request bytes on stdin, then retry.".to_string(),
        ),
    ] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys");
            args.data = Some(data.clone());
            args.json = json_output;
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
            assert_error(&out, json_output, code, kind, &message, &remedy, None, None);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn exit_table_e_uses_the_approved_numeric_values() {
    for (exit, code) in [
        (ApiExit::Ok, 0),
        (ApiExit::LocalFailure, 1),
        (ApiExit::Usage, 2),
        (ApiExit::AuthRefused, 3),
        (ApiExit::NotFound, 4),
        (ApiExit::Network, 5),
        (ApiExit::Gateway, 6),
        (ApiExit::Declined, 7),
        (ApiExit::UncertainOutcome, 8),
        (ApiExit::Interrupted, 130),
    ] {
        assert_eq!(exit.code(), code);
    }
}

#[tokio::test]
async fn unsupported_method_is_a_usage_error_before_sending() {
    for json_output in [false, true] {
        let mut args = args("/ui/api/status");
        args.method = ApiMethod::Unsupported("TRACE".to_string());
        args.json = json_output;
        let calls = AtomicUsize::new(0);
        let out = run_api_with(
            &args,
            "http://127.0.0.1:1",
            &LinkTls::default(),
            credential,
            no_stdin,
            |request| {
                calls.fetch_add(1, Ordering::SeqCst);
                send(request)
            },
        )
        .await;
        assert_error(
            &out,
            json_output,
            2,
            "Usage",
            "Unsupported API method \"TRACE\".",
            "Use GET, POST, PUT, PATCH or DELETE.",
            None,
            None,
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn gateway_status_reasons_use_the_exact_message_and_remedy() {
    for (status, body, code, kind, message, remedy) in [
        (
            StatusCode::UNAUTHORIZED,
            r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"Invalid token"},"id":null}"#,
            3,
            "AuthRefused",
            "Invalid token",
            "Run mcp-gateway login --gateway http://127.0.0.1:1, then retry. Gateway reason: -32000.",
        ),
        (
            StatusCode::UNAUTHORIZED,
            "",
            3,
            "AuthRefused",
            "The gateway rejected this credential.",
            "Run mcp-gateway login --gateway http://127.0.0.1:1, then retry.",
        ),
        (
            StatusCode::FORBIDDEN,
            r#"{"error":"admin_required"}"#,
            3,
            "AuthRefused",
            "admin_required",
            "Use an entitled credential; run mcp-gateway login --gateway http://127.0.0.1:1 with an account permitted to perform this operation, then retry.",
        ),
        (
            StatusCode::FORBIDDEN,
            "",
            3,
            "AuthRefused",
            "This credential is not permitted to perform this operation.",
            "Use an entitled credential; run mcp-gateway login --gateway http://127.0.0.1:1 with an account permitted to perform this operation, then retry.",
        ),
        (
            StatusCode::NOT_FOUND,
            r#"{"error":"Backend 'nope' not found"}"#,
            4,
            "NotFound",
            "Backend 'nope' not found",
            "List gateway backends and choose an existing name before retrying.",
        ),
        (
            StatusCode::CONFLICT,
            r#"{"error":"name_taken"}"#,
            6,
            "Gateway",
            "name_taken",
            "Choose an unused key name, then retry.",
        ),
        (
            StatusCode::CONFLICT,
            r#"{"error":"stale","message":"Capability 'x' changed on disk since it was loaded; reload it"}"#,
            6,
            "Gateway",
            "Capability 'x' changed on disk since it was loaded; reload it",
            "Read capability \"x\" again and reapply the edit using its current revision. Gateway reason: stale.",
        ),
        (
            StatusCode::PRECONDITION_REQUIRED,
            r#"{"error":"precondition_required","message":"Send If-Match with the ETag (the sha256) of the file you loaded"}"#,
            6,
            "Gateway",
            "Send If-Match with the ETag (the sha256) of the file you loaded",
            "Send the request with If-Match set to the current revision. Gateway reason: precondition_required.",
        ),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            r#"{"error":"invalid_body"}"#,
            6,
            "Gateway",
            "invalid_body",
            "Correct the request body using the gateway's validation details.",
        ),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            r#"{"error":"invalid_body","message":"the body must be {\"name\", \"backends\", \"revision\"} and the optional allowed_tools, denied_tools, admin, rate_limit and expires_at, and nothing else"}"#,
            6,
            "Gateway",
            "the body must be {\"name\", \"backends\", \"revision\"} and the optional allowed_tools, denied_tools, admin, rate_limit and expires_at, and nothing else",
            "Correct the request body using the gateway's validation details. Gateway reason: invalid_body.",
        ),
    ] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/capabilities/x");
            args.method = ApiMethod::Patch;
            args.data = Some("-".to_string());
            args.json = json_output;
            let calls = AtomicUsize::new(0);
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1/",
                &LinkTls::default(),
                credential,
                || Ok("{}".to_string()),
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok(AdminResponse {
                            status,
                            headers: reqwest::header::HeaderMap::new(),
                            body: body.as_bytes().to_vec(),
                        })
                    }
                },
            )
            .await;
            assert_error(
                &out,
                json_output,
                code,
                kind,
                message,
                remedy,
                Some(status.as_u16()),
                None,
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn rate_limit_jsonrpc_preserves_retry_after_and_does_not_retry() {
    for json_output in [false, true] {
        let listener = stand_in_with_headers(
            StatusCode::TOO_MANY_REQUESTS,
            "application/json",
            r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"Rate limit exceeded for client 'cli-a'. Try again later."},"id":null}"#,
            &[("retry-after", "60")],
        ).await;
        let mut args = args("/ui/api/keys");
        args.method = ApiMethod::Post;
        args.data = Some("-".to_string());
        args.json = json_output;
        let out = run_api_with(
            &args,
            &listener.base,
            &LinkTls::default(),
            credential,
            || Ok("{}".to_string()),
            send,
        )
        .await;
        assert_error(
            &out,
            json_output,
            6,
            "Gateway",
            "Rate limit exceeded for client 'cli-a'. Try again later.",
            "Wait for the gateway's Retry-After interval (60 s) before retrying. Gateway reason: -32000.",
            Some(429),
            None,
        );
        assert_eq!(
            listener.seen.lock().expect("requests").len(),
            1,
            "429 must make exactly one upstream request"
        );
    }
}

#[tokio::test]
async fn reason_reader_precedence_is_shared_with_admin_call() {
    for (body, expected, suffix) in [
        (
            r#"{"message":"first","error":{"message":"second"},"reason":"fourth"}"#,
            "first",
            "",
        ),
        (
            r#"{"message":null,"error":{"message":"second"},"reason":"fourth"}"#,
            "second",
            "",
        ),
        (
            r#"{"message":false,"error":"third","reason":"fourth"}"#,
            "third",
            "",
        ),
        (r#"{"error":null,"reason":"fourth"}"#, "fourth", ""),
        (
            r#"{"message":"first","error":"third","reason":"fourth"}"#,
            "first",
            " Gateway reason: third.",
        ),
    ] {
        let listener = stand_in(StatusCode::FORBIDDEN, "application/json", body).await;
        let error = admin_call(
            reqwest::Method::GET,
            &listener.base,
            "/ui/api/keys",
            TOKEN,
            &LinkTls::default(),
        )
        .await
        .expect_err("admin refusal");
        assert_eq!(
            error,
            format!("the gateway answered 403 Forbidden: {expected}")
        );
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys");
            args.json = json_output;
            let out = run_api_with(
                &args,
                &listener.base,
                &LinkTls::default(),
                credential,
                no_stdin,
                send,
            )
            .await;
            let remedy = format!(
                "Use an entitled credential; run mcp-gateway login --gateway {} with an account permitted to perform this operation, then retry.{suffix}",
                listener.base
            );
            assert_error(
                &out,
                json_output,
                3,
                "AuthRefused",
                expected,
                &remedy,
                Some(403),
                None,
            );
        }
    }
}

#[tokio::test]
async fn request_id_prefers_body_then_header_then_null() {
    for (body, header, expected) in [
        (
            json!({"error":"name_taken", "request_id":"body-id"}),
            Some("header-id"),
            Some("body-id"),
        ),
        (
            json!({"error":"name_taken", "request_id":null}),
            Some("header-id"),
            None,
        ),
        (
            json!({"error":"name_taken"}),
            Some("header-id"),
            Some("header-id"),
        ),
        (json!({"error":"name_taken"}), None, None),
    ] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys");
            args.json = json_output;
            let mut headers = reqwest::header::HeaderMap::new();
            if let Some(header) = header {
                headers.insert(
                    "x-request-id",
                    reqwest::header::HeaderValue::from_static(header),
                );
            }
            let body = serde_json::to_vec(&body).expect("fixture");
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1",
                &LinkTls::default(),
                credential,
                no_stdin,
                |_| async move {
                    Ok(AdminResponse {
                        status: StatusCode::CONFLICT,
                        headers,
                        body,
                    })
                },
            )
            .await;
            assert_error(
                &out,
                json_output,
                6,
                "Gateway",
                "name_taken",
                "Choose an unused key name, then retry.",
                Some(409),
                expected,
            );
        }
    }
}

#[tokio::test]
async fn only_the_exact_503_middleware_envelope_is_known_not_run() {
    for (status, body, code, message, remedy) in [
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"jsonrpc":"2.0","error":{"code":-32003,"message":"Client 'cli-a' circuit breaker is open. Try again later."},"id":null}"#,
            6,
            "Client 'cli-a' circuit breaker is open. Try again later.",
            "Resolve the gateway error, then retry. Gateway reason: -32003.",
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"jsonrpc":"2.0","error":{"code":-32003,"message":"Client 'cli-a' circuit breaker is open. Try again later."},"id":null}"#,
            8,
            "The gateway may have applied this change.",
            "Inspect the gateway state before retrying; this command did not retry.",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "",
            8,
            "The gateway may have applied this change.",
            "Inspect the gateway state before retrying; this command did not retry.",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":{"code":-32003},"id":null}"#,
            8,
            "The gateway may have applied this change.",
            "Inspect the gateway state before retrying; this command did not retry.",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"jsonrpc":"1.0","error":{"code":-32003},"id":null}"#,
            8,
            "The gateway may have applied this change.",
            "Inspect the gateway state before retrying; this command did not retry.",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"jsonrpc":"2.0","error":{"code":-32003},"id":1}"#,
            8,
            "The gateway may have applied this change.",
            "Inspect the gateway state before retrying; this command did not retry.",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"jsonrpc":"2.0","error":{"code":-32003}}"#,
            8,
            "The gateway may have applied this change.",
            "Inspect the gateway state before retrying; this command did not retry.",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"jsonrpc":"2.0","error":{"code":-32000},"id":null}"#,
            8,
            "The gateway may have applied this change.",
            "Inspect the gateway state before retrying; this command did not retry.",
        ),
    ] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys");
            args.method = ApiMethod::Post;
            args.data = Some("-".to_string());
            args.json = json_output;
            let calls = AtomicUsize::new(0);
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1",
                &LinkTls::default(),
                credential,
                || Ok("{}".to_string()),
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok(AdminResponse {
                            status,
                            headers: reqwest::header::HeaderMap::new(),
                            body: body.as_bytes().to_vec(),
                        })
                    }
                },
            )
            .await;
            let kind = if code == 6 {
                "Gateway"
            } else {
                "UncertainOutcome"
            };
            assert_error(
                &out,
                json_output,
                code,
                kind,
                message,
                remedy,
                Some(status.as_u16()),
                None,
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn uncertain_codes_and_disposition_override_http_mapping() {
    for (status, body, message, suffix) in [
        (
            StatusCode::CONFLICT,
            json!({"error":"state_uncertain"}),
            "state_uncertain",
            "",
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":"may_have_run"}),
            "may_have_run",
            "",
        ),
        (
            StatusCode::FORBIDDEN,
            json!({"error":"state_uncertain","disposition":"may_have_run"}),
            "state_uncertain",
            " Disposition: may_have_run.",
        ),
        (
            StatusCode::OK,
            json!({"error":"state_uncertain","disposition":"may_have_run","receipt":{"name":"cli-a","revoked":true,"revision":"R2"}}),
            "state_uncertain",
            " Disposition: may_have_run. Receipt: {\"name\":\"cli-a\",\"revoked\":true,\"revision\":\"R2\"}.",
        ),
    ] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys/cli-a");
            args.method = ApiMethod::Delete;
            args.json = json_output;
            let body = serde_json::to_vec(&body).expect("fixture");
            let calls = AtomicUsize::new(0);
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1",
                &LinkTls::default(),
                credential,
                no_stdin,
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok(AdminResponse {
                            status,
                            headers: reqwest::header::HeaderMap::new(),
                            body,
                        })
                    }
                },
            )
            .await;
            let remedy = format!(
                "Inspect the gateway state before retrying; this command did not retry.{suffix}"
            );
            assert_error(
                &out,
                json_output,
                8,
                "UncertainOutcome",
                message,
                &remedy,
                Some(status.as_u16()),
                None,
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn transport_failure_preserves_send_phase_and_never_replays() {
    for (kind, method, code, error_kind, message, remedy) in [
        (
            AdminFailureKind::Dns,
            ApiMethod::Post,
            5,
            "Network",
            "Gateway host could not be resolved.",
            "Check the gateway hostname and DNS settings, then retry.",
        ),
        (
            AdminFailureKind::Connect,
            ApiMethod::Post,
            5,
            "Network",
            "Could not connect to the gateway.",
            "Check the gateway address and listener, then retry.",
        ),
        (
            AdminFailureKind::Tls,
            ApiMethod::Post,
            5,
            "Network",
            "Gateway TLS verification failed.",
            "Check the gateway hostname, CA and client identity files, then retry.",
        ),
        (
            AdminFailureKind::ResponseLost,
            ApiMethod::Get,
            5,
            "Network",
            "Gateway response was interrupted.",
            "Repeat the read request.",
        ),
        (
            AdminFailureKind::ResponseLost,
            ApiMethod::Post,
            8,
            "UncertainOutcome",
            "The gateway may have applied this change.",
            "Inspect the gateway state before retrying; this command did not retry.",
        ),
    ] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys");
            args.method = method.clone();
            args.json = json_output;
            let calls = AtomicUsize::new(0);
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1",
                &LinkTls::default(),
                credential,
                no_stdin,
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Err(AdminCallError {
                            kind,
                            detail: format!("private transport details {TOKEN}"),
                            status: None,
                            request_id: None,
                        })
                    }
                },
            )
            .await;
            assert_error(
                &out,
                json_output,
                code,
                error_kind,
                message,
                remedy,
                None,
                None,
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}

struct FailedOutput {
    failure: Option<io::ErrorKind>,
    written: Vec<u8>,
    attempts: Vec<Vec<u8>>,
}

impl FailedOutput {
    fn new(failure: io::ErrorKind) -> Self {
        Self {
            failure: Some(failure),
            written: Vec::new(),
            attempts: Vec::new(),
        }
    }
}

impl Write for FailedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.attempts.push(bytes.to_vec());
        if let Some(failure) = self.failure.take() {
            return Err(io::Error::from(failure));
        }
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_io_is_local_failure_and_an_ordinary_broken_pipe_succeeds() {
    for json_output in [false, true] {
        for (failure, code) in [
            (io::ErrorKind::BrokenPipe, 0),
            (io::ErrorKind::PermissionDenied, 1),
        ] {
            let out = ApiOutcome {
                stdout: b"data\n".to_vec(),
                stderr: String::new(),
                exit: ApiExit::Ok,
            };
            let mut stdout = FailedOutput::new(failure);
            let mut stderr = Vec::new();
            let exit = write_outcome(out, json_output, TOKEN, &mut stdout, &mut stderr);
            assert!(
                stdout.written.is_empty(),
                "output errors never reach stdout"
            );
            assert_eq!(exit.code(), code);
            if code == 0 {
                assert!(stderr.is_empty());
            } else {
                let captured = ApiOutcome {
                    stdout: Vec::new(),
                    stderr: String::from_utf8(stderr).expect("stderr"),
                    exit,
                };
                assert_error(
                    &captured,
                    json_output,
                    1,
                    "LocalFailure",
                    "Could not write command output.",
                    "Check the output destination before repeating the command.",
                    None,
                    None,
                );
            }
        }
    }
}

#[tokio::test]
async fn known_not_run_protocol_and_version_failures_use_gateway_exit() {
    for (status, body, message, remedy) in [
        (
            StatusCode::OK,
            r#"{"disposition":"not_run"}"#,
            "The gateway failed before running the operation.",
            "Resolve the gateway error, then retry.",
        ),
        (
            StatusCode::OK,
            r#"{"error":"unsupported_version"}"#,
            "The gateway API version is unsupported.",
            "Use a CLI and gateway that support the same UI API version. Gateway reason: unsupported_version.",
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"disposition":"not_run"}"#,
            "The gateway failed before running the operation.",
            "Resolve the gateway error, then retry.",
        ),
        (
            StatusCode::BAD_REQUEST,
            "not a reviewed response",
            "The gateway returned an invalid response.",
            "Check the gateway response against UI API 1.",
        ),
        (
            StatusCode::TEMPORARY_REDIRECT,
            "",
            "The gateway returned an invalid response.",
            "Check the gateway response against UI API 1.",
        ),
        (
            StatusCode::BAD_REQUEST,
            r#"{"error":"unsupported_version"}"#,
            "The gateway API version is unsupported.",
            "Use a CLI and gateway that support the same UI API version. Gateway reason: unsupported_version.",
        ),
    ] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys");
            args.method = ApiMethod::Post;
            args.json = json_output;
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1",
                &LinkTls::default(),
                credential,
                no_stdin,
                |_| async move {
                    Ok(AdminResponse {
                        status,
                        headers: reqwest::header::HeaderMap::new(),
                        body: body.as_bytes().to_vec(),
                    })
                },
            )
            .await;
            assert_error(
                &out,
                json_output,
                6,
                "Gateway",
                message,
                remedy,
                Some(status.as_u16()),
                None,
            );
        }
    }
}

#[tokio::test]
async fn login_remedy_uses_the_normalised_resolved_origin() {
    for json_output in [false, true] {
        let mut args = args("/ui/api/keys");
        args.json = json_output;
        let out = run_api_with(
            &args,
            "https://GATEWAY.example:443/",
            &LinkTls::default(),
            credential,
            no_stdin,
            |_| async {
                Ok(AdminResponse {
                    status: StatusCode::UNAUTHORIZED,
                    headers: reqwest::header::HeaderMap::new(),
                    body: Vec::new(),
                })
            },
        )
        .await;
        assert_error(
            &out,
            json_output,
            3,
            "AuthRefused",
            "The gateway rejected this credential.",
            "Run mcp-gateway login --gateway https://gateway.example, then retry.",
            Some(401),
            None,
        );
    }
}

#[test]
fn output_failure_does_not_redact_json_syntax_as_credential_bytes() {
    let out = ApiOutcome {
        stdout: b"data\n".to_vec(),
        stderr: String::new(),
        exit: ApiExit::Ok,
    };
    let mut stdout = FailedOutput::new(io::ErrorKind::PermissionDenied);
    let mut stderr = Vec::new();
    let exit = write_outcome(out, true, "null", &mut stdout, &mut stderr);
    assert!(
        stdout.written.is_empty(),
        "output errors never reach stdout"
    );
    let captured = ApiOutcome {
        stdout: Vec::new(),
        stderr: String::from_utf8(stderr).expect("stderr"),
        exit,
    };
    assert_error(
        &captured,
        true,
        1,
        "LocalFailure",
        "Could not write command output.",
        "Check the output destination before repeating the command.",
        None,
        None,
    );
}

#[tokio::test]
async fn unsupported_methods_redact_credentials_before_quoting() {
    for token in ["abc\"def", r"abc\def"] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/status");
            args.method = ApiMethod::Unsupported(token.to_string());
            args.json = json_output;
            let calls = AtomicUsize::new(0);
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1",
                &LinkTls::default(),
                |_| Some(token.to_string()),
                no_stdin,
                |request| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    send(request)
                },
            )
            .await;
            assert_error(
                &out,
                json_output,
                2,
                "Usage",
                "Unsupported API method \"[REDACTED]\".",
                "Use GET, POST, PUT, PATCH or DELETE.",
                None,
                None,
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn stderr_output_failure_is_local_io_without_stdout_fallback() {
    for json_output in [false, true] {
        let mut args = args("/ui/api/keys");
        args.json = json_output;
        let out = run_api_with(
            &args,
            "http://127.0.0.1:1",
            &LinkTls::default(),
            |_| None,
            no_stdin,
            send,
        )
        .await;
        assert_error(
            &out,
            json_output,
            3,
            "AuthRefused",
            "No gateway credential is available.",
            "Run mcp-gateway login --gateway http://127.0.0.1:1, then retry.",
            None,
            None,
        );
        let attempted = out.stderr.as_bytes().to_vec();
        let mut stdout = Vec::new();
        let mut stderr = FailedOutput::new(io::ErrorKind::PermissionDenied);
        let exit = write_outcome(out, json_output, TOKEN, &mut stdout, &mut stderr);
        assert_eq!(exit.code(), 1);
        assert!(stdout.is_empty());
        assert!(stderr.written.is_empty());
        assert_eq!(stderr.attempts, vec![attempted]);
    }
}

struct TruncatedStand {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for TruncatedStand {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn truncated_response_stand() -> TruncatedStand {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&requests);
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).await.expect("request headers");
                assert_ne!(count, 0, "request ended before its headers");
                request.extend_from_slice(&buffer[..count]);
                assert!(request.len() <= 16384, "bounded request headers");
            }
            observed
                .lock()
                .expect("requests")
                .push(String::from_utf8(request).expect("request text"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 64\r\nX-Request-ID: interrupted-123\r\nConnection: close\r\n\r\n{}").await.expect("truncated response");
            stream.shutdown().await.expect("close response");
        }
    });
    TruncatedStand {
        base,
        requests,
        server,
    }
}

#[tokio::test]
async fn truncated_http_response_preserves_phase_and_request_metadata() {
    for (method, request_line, code, kind, message, remedy) in [
        (
            ApiMethod::Get,
            "GET /ui/api/keys HTTP/1.1",
            5,
            "Network",
            "Gateway response was interrupted.",
            "Repeat the read request.",
        ),
        (
            ApiMethod::Post,
            "POST /ui/api/keys HTTP/1.1",
            8,
            "UncertainOutcome",
            "The gateway may have applied this change.",
            "Inspect the gateway state before retrying; this command did not retry.",
        ),
    ] {
        for json_output in [false, true] {
            let listener = truncated_response_stand().await;
            let mut args = args("/ui/api/keys");
            args.method = method.clone();
            args.json = json_output;
            let out = run_api_with(
                &args,
                &listener.base,
                &LinkTls::default(),
                credential,
                no_stdin,
                send,
            )
            .await;
            assert_error(
                &out,
                json_output,
                code,
                kind,
                message,
                remedy,
                Some(200),
                Some("interrupted-123"),
            );
            let requests = listener.requests.lock().expect("requests");
            assert_eq!(
                requests.len(),
                1,
                "response loss must not replay the request"
            );
            assert!(requests[0].starts_with(request_line));
            assert!(requests[0].contains(&format!("Bearer {TOKEN}")));
        }
    }
}
