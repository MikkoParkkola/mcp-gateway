// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `mcp-gateway api` rows, part errors: the shared fixtures live in the parent module.

use super::*;

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
#[expect(
    clippy::too_many_lines,
    reason = "one table of gateway status fixtures, each pinning its exact message, remedy and exit; splitting it would scatter the table"
)]
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
                || Ok(b"{}".to_vec()),
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
            || Ok(b"{}".to_vec()),
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
#[expect(
    clippy::too_many_lines,
    reason = "one table of near-miss envelopes around the not-run exception; each case differs from the real middleware body in one field"
)]
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
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"jsonrpc":"2.0","error":{"code":-32003},"id":null}"#,
            8,
            "The gateway may have applied this change.",
            "Inspect the gateway state before retrying; this command did not retry.",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"jsonrpc":"2.0","error":{"code":-32003,"message":42},"id":null}"#,
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
                || Ok(b"{}".to_vec()),
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
        (
            StatusCode::OK,
            json!({"disposition":"may_have_run"}),
            "may_have_run",
            " Disposition: may_have_run.",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"disposition":"not_run","error":"state_uncertain"}),
            "state_uncertain",
            "",
        ),
        (
            StatusCode::CONFLICT,
            json!({"error":"state_uncertain","recovery":"Inspect api-unit-credential."}),
            "state_uncertain",
            " Inspect api-unit-credential.",
        ),
        (
            StatusCode::CONFLICT,
            json!({"error":"state_uncertain","recovery":"unsafe\nrecovery"}),
            "state_uncertain",
            "",
        ),
    ] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys/cli-a");
            args.method = ApiMethod::Post;
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
            let remedy = mcp_gateway::cli::redact::text(&remedy, &[TOKEN.to_string()]);
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
            let exit = write_outcome(&out, json_output, TOKEN, &mut stdout, &mut stderr);
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
