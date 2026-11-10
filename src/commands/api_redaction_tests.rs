// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `mcp-gateway api` rows, part redaction: the shared fixtures live in the parent module.

use super::*;

#[tokio::test]
async fn tls_connect_timeout_is_network_even_for_a_mutation() {
    use super::super::dashboard_link::{AdminClientOptions, admin_call_url_with_options};
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("https://{}", listener.local_addr().expect("address"));
    let (hello_sent, hello_received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut byte = [0];
        socket.read_exact(&mut byte).await.expect("TLS ClientHello");
        assert_eq!(byte[0], 0x16, "TLS handshake record");
        hello_sent.send(()).expect("notify");
        std::future::pending::<()>().await;
        drop(socket);
    });
    let mut args = args("/ui/api/keys");
    args.method = ApiMethod::Post;
    let out = run_api_with(
        &args,
        &base,
        &LinkTls::default(),
        credential,
        no_stdin,
        |request| async move {
            admin_call_url_with_options(
                request.method,
                request.url,
                &request.token,
                &request.tls,
                request.body.as_ref(),
                request.if_match.as_ref(),
                &AdminClientOptions {
                    // The listener never answers its ClientHello, so this timer
                    // must fire; a slower firing under load still gives Network.
                    // timing: lower-bound
                    connect_timeout: std::time::Duration::from_millis(300),
                },
            )
            .await
        },
    )
    .await;
    server.abort();
    hello_received.await.expect("listener received ClientHello");
    assert_error(
        &out,
        false,
        5,
        "Network",
        "Could not connect to the gateway.",
        "Check the gateway address and listener, then retry.",
        None,
        None,
    );
}

#[tokio::test]
async fn legacy_admin_calls_refuse_oversized_bodies() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let app = axum::Router::new().fallback(|| async { vec![b'x'; 16 * 1024 * 1024 + 1] });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    for path in ["/ui/api/dashboard-link", "/ui/api/events/dead-letters"] {
        let error = admin_call(
            reqwest::Method::POST,
            &base,
            path,
            TOKEN,
            &LinkTls::default(),
        )
        .await
        .expect_err("body cap");
        assert_eq!(error, "the gateway answer exceeded 16 MiB");
    }
    server.abort();
}

#[tokio::test]
async fn gzip_response_is_capped_after_decompression() {
    // Gzip of 16 MiB + 1 ASCII x bytes, smaller than the wire-size cap.
    let compressed = include_bytes!("../../tests/fixtures/api-response-over-limit.txt.gz");
    assert!(compressed.len() < 16 * 1024 * 1024);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let app = axum::Router::new()
        .fallback(move || async move { ([("content-encoding", "gzip")], compressed.as_slice()) });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    let out = run_api_with(
        &args("/ui/api/status"),
        &base,
        &LinkTls::default(),
        credential,
        no_stdin,
        send,
    )
    .await;
    server.abort();
    assert_error(
        &out,
        false,
        5,
        "Network",
        "Gateway response exceeded 16 MiB.",
        "Narrow the request or read the data in smaller pages.",
        Some(200),
        None,
    );
}

/// A token equal to a fixed field of the JSON error (its `http_status`, its
/// `schema_version`, or text inside its kind) never reaches stderr: the report
/// becomes one fixed token-free sentence.
#[tokio::test]
async fn a_token_equal_to_a_fixed_error_field_never_reaches_stderr() {
    for (token, status) in [
        ("404", StatusCode::NOT_FOUND),
        ("1", StatusCode::NOT_FOUND),
        ("Found", StatusCode::NOT_FOUND),
        ("Refused", StatusCode::UNAUTHORIZED),
    ] {
        let out = answered(token, status, "{}", true).await;
        assert!(out.stdout.is_empty(), "{token}: stdout");
        assert!(!out.stderr.contains(token), "{token}: {}", out.stderr);
        assert!(!out.stderr.is_empty(), "{token}: something is reported");
    }
}

/// Independent of the shared redactor: the raw token string is absent from
/// every stream, on success and on error, in both output modes.
#[tokio::test]
async fn the_token_is_absent_from_every_stream_whatever_the_redactor_says() {
    let token = "independent-canary-0123456789abcdef";
    let echo = format!(r#"{{"echo":"{token}","message":"{token}"}}"#);
    for (status, json_output) in [
        (StatusCode::OK, false),
        (StatusCode::OK, true),
        (StatusCode::BAD_REQUEST, false),
        (StatusCode::BAD_REQUEST, true),
    ] {
        let out = answered(token, status, &echo, json_output).await;
        assert!(!String::from_utf8_lossy(&out.stdout).contains(token));
        assert!(!out.stderr.contains(token));
    }
}

/// The dropped-entry refusal in JSON mode: stdout empty and one structured
/// `LocalFailure` object on stderr.
#[tokio::test]
async fn dropped_entry_refusal_in_json_mode_is_one_local_failure_object() {
    let out = answered(
        "#",
        StatusCode::OK,
        r##"{"#":"first","[redacted]":"second"}"##,
        true,
    )
    .await;
    assert!(out.stdout.is_empty(), "nothing printed on stdout");
    let printed: serde_json::Value = serde_json::from_str(&out.stderr).expect("one JSON error");
    assert_eq!(printed["error"]["kind"], "LocalFailure");
    assert_eq!(
        printed["error"]["message"],
        "The response could not be printed safely."
    );
}
