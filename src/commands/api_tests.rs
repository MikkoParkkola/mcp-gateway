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

use super::api::{ApiRequest, run_api_with};
use super::cli_exit::emit_to;
use super::cli_exit::{CliExit, CliOutcome};

use super::dashboard_link::{
    AdminCallError, AdminFailureKind, AdminResponse, LinkTls, Remedies, TOKEN_ENV, admin_call_url,
    dead_letters_request,
};

const TOKEN: &str = "api-unit-credential";

fn args(path: &str) -> ApiArgs {
    ApiArgs {
        method: ApiMethod::Get,
        path: path.to_string(),
        data: None,
        if_match: None,
        limit: None,
        json: false,
        gateway: mcp_gateway::cli::dashboard_link::GatewayArg::default(),
        tls: DashboardLinkTls::default(),
    }
}

/// The commands' `admin_call` as a read, its error as it prints for a run holding `token`.
async fn admin_call(
    method: reqwest::Method,
    base: &str,
    path: &str,
    token: &str,
    tls: &LinkTls,
) -> Result<serde_json::Value, String> {
    super::dashboard_link::admin_call(
        method,
        base,
        path,
        token,
        tls,
        super::cli_exit::Request::Read,
        &Remedies::read(base),
    )
    .await
    .map_err(|error| error.outcome(false, &[token]).stderr().to_string())
}

/// `fetch_link`, its error as it prints for a run holding `token`.
async fn fetch_link(base: &str, token: &str, tls: &LinkTls) -> Result<String, String> {
    super::dashboard_link::fetch_link(base, token, tls)
        .await
        .map_err(|error| error.outcome(false, &[token]).stderr().to_string())
}

fn credential(name: &str) -> Option<String> {
    (name == TOKEN_ENV).then(|| TOKEN.to_string())
}

fn no_stdin() -> Result<Vec<u8>, String> {
    panic!("stdin must only be read for --data -")
}

async fn send(request: ApiRequest) -> Result<AdminResponse, AdminCallError> {
    admin_call_url(
        request.method,
        request.url,
        &request.token,
        &request.tls,
        request.body.as_ref(),
        request.if_match.as_ref(),
    )
    .await
}

struct Seen {
    method: axum::http::Method,
    path: String,
    authorization: String,
    content_type: Option<String>,
    if_match: Option<String>,
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
            let incoming = to_bytes(incoming, 17 * 1024 * 1024)
                .await
                .expect("request body");
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
                if_match: parts
                    .headers
                    .get("if-match")
                    .map(|v| v.to_str().expect("if-match").to_string()),
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
    out: &CliOutcome,
    json_output: bool,
    code: u8,
    kind: &str,
    message: &str,
    remedy: &str,
    status: Option<u16>,
    request_id: Option<&str>,
) {
    assert_eq!(out.exit().code(), code, "{}", out.stderr());
    assert!(out.stdout().is_empty(), "errors must never reach stdout");
    if json_output {
        let printed: serde_json::Value =
            serde_json::from_str(out.stderr()).expect("one JSON error");
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
        assert_eq!(out.stderr(), format!("error: {message}\n{remedy}\n"));
    }
    assert!(!out.stderr().contains(TOKEN));
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
            "Gateway URL must have no path, query or fragment.",
            "Use the gateway's origin only, for example https://gateway.example:8443.",
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
    assert_eq!(out.exit().code(), 0, "{}", out.stderr());
    assert_eq!(out.stdout(), raw.as_bytes());
    assert!(out.stderr().contains("non-JSON"), "{}", out.stderr());
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
        gateway: mcp_gateway::cli::dashboard_link::GatewayArg::default(),
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
async fn a12_admin_call_errors_use_the_shared_shape() {
    for (status, body, expected) in [
        (
            StatusCode::FORBIDDEN,
            r#"{"reason":"no standing","error":"ignored"}"#,
            "The gateway answered HTTP 403: ignored\nUse a token permitted to perform this operation for {base}, then retry.",
        ),
        (
            StatusCode::FORBIDDEN,
            r#"{"reason":"no standing"}"#,
            "The gateway answered HTTP 403: no standing\nUse a token permitted to perform this operation for {base}, then retry.",
        ),
        (
            StatusCode::NOT_FOUND,
            r#"{"error":"missing"}"#,
            "The gateway answered HTTP 404: missing\nCheck that the gateway supports this command (update the gateway or the CLI), then retry.",
        ),
        (
            StatusCode::BAD_GATEWAY,
            "plain",
            "The gateway answered HTTP 502: its error body is not JSON\nResolve the gateway error, then retry.",
        ),
        (
            StatusCode::OK,
            "plain",
            "The gateway returned an invalid response.\nCheck the gateway response against UI API 1.",
        ),
        (
            StatusCode::OK,
            "null",
            "The gateway returned an invalid response.\nCheck the gateway response against UI API 1.",
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
        .expect_err("an error");
        let expected = format!("error: {}\n", expected.replace("{base}", &listener.base));
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
                Ok(br#"{"source":"stdin"}"#.to_vec())
            },
            send,
        )
        .await;
        assert_eq!(out.exit().code(), 0, "{}", out.stderr());
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
            "Set MCP_GATEWAY_TOKEN to a valid token for http://127.0.0.1:1, then retry.",
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
            "Set MCP_GATEWAY_TOKEN to a valid token for http://127.0.0.1:1, then retry.",
        ),
        (
            StatusCode::FORBIDDEN,
            "Use a token permitted to perform this operation for http://127.0.0.1:1, then retry.",
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
            assert_eq!(out.exit(), CliExit::AuthRefused);
            assert!(out.stdout().is_empty());
            assert!(!out.stderr().contains(TOKEN));
            if json_output {
                let printed: serde_json::Value =
                    serde_json::from_str(out.stderr()).expect("valid JSON error");
                assert_eq!(printed["error"]["remedy"], remedy);
                assert_eq!(printed["error"]["http_status"], status.as_u16());
            } else {
                assert!(out.stderr().contains(remedy));
            }
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
        assert_eq!(out.exit().code(), 0);
        assert!(out.stderr().is_empty());
        let printed: serde_json::Value = serde_json::from_slice(out.stdout()).expect("valid JSON");
        assert!(!printed["echo"].as_str().expect("string").contains(token));
        assert!(
            !printed["nested"][0]
                .as_str()
                .expect("string")
                .contains(token)
        );
        if token == "null" {
            assert!(!printed["literal"].is_null());
        } else {
            assert!(printed["literal"].is_null());
        }
        assert!(printed.get(token).is_none());
        assert!(
            printed
                .as_object()
                .expect("object")
                .values()
                .any(|value| value == "an echoed key")
        );
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

async fn echoed_body(token: &str, body: Vec<u8>) -> CliOutcome {
    run_api_with(
        &args("/ui/api/status"),
        "http://127.0.0.1:1",
        &LinkTls::default(),
        |_| Some(token.to_string()),
        no_stdin,
        |_| async move {
            Ok(AdminResponse {
                status: StatusCode::OK,
                headers: reqwest::header::HeaderMap::new(),
                body,
            })
        },
    )
    .await
}

/// A gateway answer with `status` and `body` to a GET, in human or JSON mode.
async fn answered(token: &str, status: StatusCode, body: &str, json_output: bool) -> CliOutcome {
    let mut a = args("/ui/api/status");
    a.json = json_output;
    let body = body.as_bytes().to_vec();
    run_api_with(
        &a,
        "http://127.0.0.1:1",
        &LinkTls::default(),
        |_| Some(token.to_string()),
        no_stdin,
        |_| async move {
            Ok(AdminResponse {
                status,
                headers: reqwest::header::HeaderMap::new(),
                body,
            })
        },
    )
    .await
}

#[path = "api_errors_tests.rs"]
mod errors;

#[path = "api_transport_tests.rs"]
mod transport;

#[path = "api_redaction_tests.rs"]
mod redaction;

#[path = "api_matrix_tests.rs"]
mod matrix;

#[path = "api_yaml_tests.rs"]
mod yaml;

#[path = "api_revision_tests.rs"]
mod revision;
