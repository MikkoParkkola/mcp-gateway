// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Error classification: backend error detail to recovery category.

use super::classify_from_detail;
use crate::gateway::recovery::{ErrorCategory, RecoveryContext, recovery_for};

/// A typed 429 never reaches the prose classifier at all.
///
/// `classify_dispatch_error` dispatches on the error VARIANT and only sends
/// `Protocol` through `classify_from_detail`. GH475.RL.10 made a capability
/// 429 an `Error::Http`, and although its `Display` still happens to say
/// "429" nothing reads that text -- it fell through to `BackendError`, and
/// the client was told to retry at once instead of backing off. The
/// listener answers one request and is the only way to obtain a real
/// `reqwest::Error` carrying a status.
#[tokio::test]
async fn a_typed_429_is_still_rate_limited() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut scratch = [0u8; 1024];
        let _ = socket.read(&mut scratch).await;
        let _ = socket
            .write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n")
            .await;
    });

    let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
    let error = crate::Error::Http(response.error_for_status().unwrap_err().without_url());
    let (category, _) = super::classify_dispatch_error(&error);
    assert_eq!(
        category,
        ErrorCategory::RateLimited,
        "a typed 429 must keep the backoff hint the prose one earned"
    );
}

#[test]
fn rate_limit_429_classified_as_rate_limited() {
    // The exact shape returned by archive.org through the REST provider.
    let detail = "Protocol error: API returned 429 Too Many Requests: \
                  <html><body><h1>429 Too Many Requests</h1></body></html>";
    let cat = classify_from_detail(Some(detail));
    assert!(matches!(cat, ErrorCategory::RateLimited));

    // And the resulting hint must be RATE_LIMITED + retryable, NOT
    // INVALID_PARAM with a "fix your params" suggestion.
    let hint = recovery_for(cat, RecoveryContext::default());
    assert_eq!(hint.error_code, "RATE_LIMITED");
    assert!(hint.retry, "rate-limited calls are retryable after backoff");
}

#[test]
fn rate_limit_phrasings_all_match() {
    for s in [
        "rate limit exceeded",
        "Rate-Limit hit",
        "ratelimit reached",
        "request throttled by upstream",
        "HTTP 429",
    ] {
        assert!(
            matches!(classify_from_detail(Some(s)), ErrorCategory::RateLimited),
            "expected RateLimited for {s:?}"
        );
    }
}

#[test]
fn timeout_signals_classified_as_timeout() {
    for s in [
        "request timeout",
        "connection timed out",
        "HTTP 504",
        "504 Gateway Timeout",
    ] {
        assert!(
            matches!(classify_from_detail(Some(s)), ErrorCategory::Timeout),
            "expected Timeout for {s:?}"
        );
    }
}

#[test]
fn server_errors_classified_as_backend_error() {
    for s in [
        "500 Internal Server Error",
        "502 Bad Gateway",
        "503 Service Unavailable",
    ] {
        assert!(
            matches!(classify_from_detail(Some(s)), ErrorCategory::BackendError),
            "expected BackendError for {s:?}"
        );
    }
}

/// Row 16c - the client-facing category must not move when a status-carried
/// refusal starts arriving as `Error::JsonRpc` instead of `Error::Transport`.
/// Both already map to `BackendError`; this pins that, because the transport
/// rows cannot reach this classifier.
#[test]
fn row_16c_a_json_rpc_refusal_and_a_transport_fault_share_one_category() {
    use super::classify_dispatch_error;
    use crate::Error;

    for error in [
        Error::json_rpc(-32601, "Method not found: server/discover"),
        Error::Transport("HTTP 404".to_string()),
    ] {
        assert!(
            matches!(
                classify_dispatch_error(&error).0,
                ErrorCategory::BackendError
            ),
            "expected BackendError for {error:?}"
        );
    }
}

#[test]
fn genuine_validation_errors_default_to_validation() {
    // Schema/param errors must keep the prior behaviour.
    for s in [
        "missing required field 'url'",
        "invalid enum value for 'output'",
        "expected string, got integer",
    ] {
        assert!(
            matches!(classify_from_detail(Some(s)), ErrorCategory::Validation),
            "expected Validation for {s:?}"
        );
    }
    // No detail at all also defaults to Validation.
    assert!(matches!(
        classify_from_detail(None),
        ErrorCategory::Validation
    ));
}
