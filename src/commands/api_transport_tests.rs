// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `mcp-gateway api` rows, part transport: the shared fixtures live in the parent module.

use super::*;

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
fn output_failure_with_a_token_inside_json_null_prints_the_fixed_sentence() {
    let out = ApiOutcome {
        stdout: b"data\n".to_vec(),
        stderr: String::new(),
        exit: ApiExit::Ok,
    };
    let mut stdout = FailedOutput::new(io::ErrorKind::PermissionDenied);
    let mut stderr = Vec::new();
    let exit = write_outcome(&out, true, "null", &mut stdout, &mut stderr);
    assert!(
        stdout.written.is_empty(),
        "output errors never reach stdout"
    );
    let captured = ApiOutcome {
        stdout: Vec::new(),
        stderr: String::from_utf8(stderr).expect("stderr"),
        exit,
    };
    assert_eq!(captured.exit, ApiExit::LocalFailure);
    // The token is "null", which JSON's own null fields contain: the report
    // becomes the fixed sentence instead.
    assert_eq!(
        captured.stderr,
        "error: The error report could not be printed without exposing the credential.\n"
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
            assert_eq!(out.exit, ApiExit::Usage);
            assert!(out.stdout.is_empty());
            assert!(!out.stderr.contains(token));
            if json_output {
                let printed: serde_json::Value =
                    serde_json::from_str(&out.stderr).expect("valid JSON error");
                assert!(
                    !printed["error"]["message"]
                        .as_str()
                        .expect("message")
                        .contains(token)
                );
            }
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
        let exit = write_outcome(&out, json_output, TOKEN, &mut stdout, &mut stderr);
        assert_eq!(exit.code(), 1);
        assert!(stdout.is_empty());
        assert!(stderr.written.is_empty());
        assert_eq!(stderr.attempts, vec![attempted]);
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

#[tokio::test]
async fn the_raw_2xx_body_is_redacted() {
    let stand = stand_in(StatusCode::OK, "text/plain", "echo api-unit-credential").await;
    let out = run_api_with(
        &args("/ui/api/status"),
        &stand.base,
        &LinkTls::default(),
        credential,
        no_stdin,
        send,
    )
    .await;
    assert_eq!(out.exit.code(), 0);
    let expected = mcp_gateway::cli::redact::text("echo api-unit-credential", &[TOKEN.to_string()]);
    assert_eq!(String::from_utf8(out.stdout).expect("text"), expected);
    assert!(!out.stderr.contains(TOKEN));
}

#[tokio::test]
async fn read_500_and_path_404_keep_their_error_mapping() {
    for (status, body, code, kind, message, remedy) in [
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "{}",
            6,
            "Gateway",
            "The gateway returned an invalid response.",
            "Check the gateway response against UI API 1.",
        ),
        (
            StatusCode::NOT_FOUND,
            "{}",
            4,
            "NotFound",
            "API path was not found.",
            "Check the path against docs/api/stable-ui-routes.md.",
        ),
        (
            StatusCode::NOT_FOUND,
            r#"{"error":"Backend 'nope' not found"}"#,
            4,
            "NotFound",
            "Backend 'nope' not found",
            "List gateway backends and choose an existing name before retrying.",
        ),
    ] {
        let stand = stand_in(status, "application/json", body).await;
        for json_output in [false, true] {
            let mut args = args("/ui/api/missing");
            args.json = json_output;
            let out = run_api_with(
                &args,
                &stand.base,
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
                Some(status.as_u16()),
                None,
            );
        }
    }
}

#[tokio::test]
async fn refused_connection_is_network_through_real_transport() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    drop(listener);
    for json_output in [false, true] {
        let mut args = args("/ui/api/keys");
        args.method = ApiMethod::Post;
        args.json = json_output;
        let out = run_api_with(
            &args,
            &base,
            &LinkTls::default(),
            credential,
            no_stdin,
            send,
        )
        .await;
        assert_error(
            &out,
            json_output,
            5,
            "Network",
            "Could not connect to the gateway.",
            "Check the gateway address and listener, then retry.",
            None,
            None,
        );
    }
}

#[tokio::test]
async fn if_match_controls_capability_delete() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let app = axum::Router::new().route(
        "/ui/api/capabilities/x",
        axum::routing::delete(|headers: axum::http::HeaderMap| async move {
            if headers
                .get("if-match")
                .and_then(|value| value.to_str().ok())
                == Some("\"E1\"")
            {
                (StatusCode::OK, axum::Json(json!({"deleted":true})))
            } else {
                (
                    StatusCode::PRECONDITION_REQUIRED,
                    axum::Json(json!({"message":"If-Match is required."})),
                )
            }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    for json_output in [false, true] {
        for if_match in [None, Some("\"E1\"".to_string())] {
            let mut args = args("/ui/api/capabilities/x");
            args.method = ApiMethod::Delete;
            args.json = json_output;
            args.if_match = if_match;
            let out = run_api_with(
                &args,
                &base,
                &LinkTls::default(),
                credential,
                no_stdin,
                send,
            )
            .await;
            if args.if_match.is_some() {
                assert_eq!(out.exit.code(), 0);
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("JSON"),
                    json!({"deleted":true})
                );
            } else {
                assert_error(
                    &out,
                    json_output,
                    6,
                    "Gateway",
                    "If-Match is required.",
                    "Send the request with If-Match set to the current revision.",
                    Some(428),
                    None,
                );
            }
        }
    }
    server.abort();
}

#[tokio::test]
async fn control_characters_in_if_match_are_refused_before_send() {
    for value in ["E1\r", "E1\n", "E1\t", "E1\0", "E1\u{7f}"] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/capabilities/x");
            args.method = ApiMethod::Delete;
            args.if_match = Some(value.to_string());
            args.json = json_output;
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1",
                &LinkTls::default(),
                credential,
                no_stdin,
                |_| async { panic!("invalid header must not send") },
            )
            .await;
            assert_error(
                &out,
                json_output,
                2,
                "Usage",
                "If-Match value is not a valid header value.",
                "Pass the ETag exactly as the gateway returned it.",
                None,
                None,
            );
        }
    }
}

#[tokio::test]
async fn oversized_request_sources_are_usage_errors() {
    let mut file = tempfile::NamedTempFile::new().expect("file");
    let body = " ".repeat(16 * 1024 * 1024 + 1);
    file.write_all(body.as_bytes()).expect("body");
    for data in [format!("@{}", file.path().display()), "-".to_string()] {
        for json_output in [false, true] {
            let mut args = args("/ui/api/keys");
            args.method = ApiMethod::Post;
            args.data = Some(data.clone());
            args.json = json_output;
            let out = run_api_with(
                &args,
                "http://127.0.0.1:1",
                &LinkTls::default(),
                credential,
                || Ok(body.as_bytes().to_vec()),
                |_| async { panic!("oversized body must not send") },
            )
            .await;
            assert_error(
                &out,
                json_output,
                2,
                "Usage",
                "Request body exceeds 16 MiB.",
                "Send a smaller body.",
                None,
                None,
            );
        }
    }
}

#[tokio::test]
async fn decoded_response_limit_preserves_mutation_uncertainty() {
    for size in [16 * 1024 * 1024, 16 * 1024 * 1024 + 1] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let app = axum::Router::new().fallback(move || async move { vec![b'x'; size] });
        let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        for (method, code, kind) in [
            (ApiMethod::Get, 5, "Network"),
            (ApiMethod::Post, 8, "UncertainOutcome"),
        ] {
            for json_output in [false, true] {
                let mut args = args("/ui/api/keys");
                args.method = method.clone();
                args.json = json_output;
                let out = run_api_with(
                    &args,
                    &base,
                    &LinkTls::default(),
                    credential,
                    no_stdin,
                    send,
                )
                .await;
                if size == 16 * 1024 * 1024 {
                    assert_eq!(out.exit.code(), 0);
                    assert_eq!(out.stdout.len(), size);
                } else {
                    assert_error(
                        &out,
                        json_output,
                        code,
                        kind,
                        "Gateway response exceeded 16 MiB.",
                        "Narrow the request or read the data in smaller pages.",
                        Some(200),
                        None,
                    );
                }
            }
        }
        server.abort();
    }
}

#[tokio::test]
async fn lost_response_request_ids_use_safe_text() {
    for (id, retained) in [
        ("request-api-unit-credential", true),
        ("bad\tvalue", false),
        ("", false),
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
                |_| async {
                    Err(AdminCallError {
                        kind: AdminFailureKind::ResponseLost,
                        detail: String::new(),
                        status: Some(StatusCode::OK),
                        request_id: Some(id.to_string()),
                    })
                },
            )
            .await;
            assert_eq!(out.exit, ApiExit::UncertainOutcome);
            assert!(out.stdout.is_empty());
            assert!(!out.stderr.contains(TOKEN));
            if json_output {
                let printed: serde_json::Value =
                    serde_json::from_str(&out.stderr).expect("valid JSON error");
                let id = &printed["error"]["request_id"];
                if retained {
                    assert!(!id.as_str().expect("request id").contains(TOKEN));
                } else {
                    assert!(id.is_null());
                }
            }
        }
    }
}

#[tokio::test]
async fn request_sources_accept_exactly_sixteen_mib() {
    let mut body = vec![b' '; 16 * 1024 * 1024];
    body[..2].copy_from_slice(b"{}");
    let mut file = tempfile::NamedTempFile::new().expect("file");
    file.write_all(&body).expect("body");
    for data in [format!("@{}", file.path().display()), "-".to_string()] {
        let mut args = args("/ui/api/keys");
        args.method = ApiMethod::Post;
        args.data = Some(data);
        let out = run_api_with(
            &args,
            "http://127.0.0.1:1",
            &LinkTls::default(),
            credential,
            || Ok(body.clone()),
            |request| async move {
                assert_eq!(request.body, Some(json!({})));
                Ok(AdminResponse {
                    status: StatusCode::OK,
                    headers: reqwest::header::HeaderMap::new(),
                    body: b"{}".to_vec(),
                })
            },
        )
        .await;
        assert_eq!(out.exit.code(), 0, "{}", out.stderr);
    }
}

#[tokio::test]
async fn a_token_echoed_as_a_json_number_is_redacted() {
    let token = "1234567890123456";
    let out = echoed_body(token, br#"{"echo":1234567890123456}"#.to_vec()).await;
    assert_eq!(out.exit, ApiExit::Ok);
    assert!(!String::from_utf8_lossy(&out.stdout).contains(token));
    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("valid JSON");
}

#[tokio::test]
async fn a_key_collision_keeps_every_field() {
    let marker = mcp_gateway::cli::redact::text(TOKEN, &[TOKEN.to_string()]);
    let body = json!({(TOKEN): "renamed", (marker.clone()): "original", "other": 42});
    let out = echoed_body(TOKEN, serde_json::to_vec(&body).expect("body")).await;
    assert_eq!(out.exit, ApiExit::Ok);
    assert!(!String::from_utf8_lossy(&out.stdout).contains(TOKEN));
    let printed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let fields = printed.as_object().expect("object");
    assert_eq!(fields.len(), 3);
    assert_eq!(printed[&marker], "original");
    assert_eq!(printed["other"], 42);
    assert!(fields.values().any(|value| value == "renamed"));
}

#[tokio::test]
async fn a_token_inside_the_marker_is_not_copied_back() {
    let token = "redacted";
    let out = echoed_body(token, br#"{"echo":"redacted"}"#.to_vec()).await;
    assert_eq!(out.exit, ApiExit::Ok);
    assert!(!String::from_utf8_lossy(&out.stdout).contains(token));
    let printed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    // The facade's marker-rotation row checks this value with contains_marker.
    assert_eq!(
        printed["echo"],
        mcp_gateway::cli::redact::text(token, &[token.to_string()])
    );
}

#[tokio::test]
async fn invalid_utf8_is_preserved_only_without_token_bytes() {
    let clean = vec![0xff, 0xfe];
    let out = echoed_body(TOKEN, clean.clone()).await;
    assert_eq!(out.exit, ApiExit::Ok);
    assert_eq!(out.stdout, clean);

    let mut unsafe_body = vec![0xff];
    unsafe_body.extend_from_slice(TOKEN.as_bytes());
    let out = echoed_body(TOKEN, unsafe_body).await;
    assert_error(
        &out,
        false,
        1,
        "LocalFailure",
        "The response could not be printed safely.",
        "The response was received but could not be printed safely; inspect the gateway state before sending the request again.",
        None,
        None,
    );
}

#[tokio::test]
async fn dropped_object_entries_refuse_the_entire_success_body() {
    // `[redacted]` is the shared redactor's first marker
    // (`src/security/secret_redaction.rs:124`): renaming the key `#` to it
    // collides with the existing key, and every suffix contains the token.
    for body in [
        json!({"#":"first","[redacted]":"second"}),
        json!({"nested":[{"#":"first","[redacted]":"second"}]}),
    ] {
        let out = echoed_body("#", serde_json::to_vec(&body).expect("body")).await;
        assert_error(
            &out,
            false,
            1,
            "LocalFailure",
            "The response could not be printed safely.",
            "The response was received but could not be printed safely; inspect the gateway state before sending the request again.",
            None,
            None,
        );
        assert!(!out.stderr.contains('#'));
    }
}

#[tokio::test]
async fn a_token_inside_a_fixed_key_or_number_replaces_the_json_report() {
    for token in ["1", "error"] {
        let mut args = args("/ui/api/status");
        args.json = true;
        let out = run_api_with(
            &args,
            "http://127.0.0.1:1",
            &LinkTls::default(),
            |_| Some(token.to_string()),
            no_stdin,
            |_| async move {
                Ok(AdminResponse {
                    status: StatusCode::UNAUTHORIZED,
                    headers: reqwest::header::HeaderMap::new(),
                    body: serde_json::to_vec(&json!({
                        "message": format!("rejected {token}"),
                        "request_id": format!("request-{token}"),
                    }))
                    .expect("body"),
                })
            },
        )
        .await;
        // "1" is the schema version and "error" a fixed key, so the JSON report
        // would carry the token: it becomes the fixed sentence, or nothing when
        // the sentence itself contains the token ("error").
        assert_eq!(out.exit.code(), 3, "{token}");
        assert!(out.stdout.is_empty(), "{token}: stdout");
        let expected = if token == "error" {
            ""
        } else {
            "error: The error report could not be printed without exposing the credential.\n"
        };
        assert_eq!(out.stderr, expected, "{token}");
    }
}
