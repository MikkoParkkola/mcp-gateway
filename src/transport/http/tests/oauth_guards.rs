// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Bearer header value and the OAuth cleartext-transmission guard.

use super::*;

// =========================================================================
// bearer_header_value — invalid-byte token must not panic (MIK-6909, AC.5)
// =========================================================================

#[test]
fn bearer_header_value_accepts_a_well_formed_token() {
    // GIVEN a token containing only header-legal bytes
    // WHEN we build the Authorization value
    // THEN it succeeds and carries the Bearer prefix.
    let value = bearer_header_value("abc123.DEF-456").expect("valid token must produce a header");
    assert_eq!(value.to_str().unwrap(), "Bearer abc123.DEF-456");
}

#[test]
fn bearer_header_value_rejects_invalid_bytes_without_panicking() {
    // GIVEN a token with bytes illegal in an HTTP header value (newline, NUL, CR)
    // WHEN we build the Authorization value
    // THEN it returns a clean OAuth error rather than panicking, and the error
    //      never echoes the token (credential hygiene, CWE-532).
    for bad in ["tok\nen", "tok\0en", "tok\ren"] {
        let err = bearer_header_value(bad).expect_err("invalid token must be rejected");
        assert!(
            matches!(err, Error::OAuth(_)),
            "expected a clean OAuth error, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(bad),
            "error must not leak the raw token"
        );
    }
}

/// One canary, every redaction helper. Each site was found by a reviewer AFTER a
/// previous round claimed the class was closed — five in round one, three more in
/// round two, including two session-ID logs and a config line that was the twin
/// of one already fixed. A per-site fix does not generalise; a sweep does.
#[test]
fn no_diagnostic_helper_passes_a_canary_through() {
    const CANARY: &str = "SENTINEL_TRANSPORT_9f3c";

    // URL redaction: the secret in each position a URL can hide one.
    for raw in [
        format!("https://user:{CANARY}@svc.example.com/mcp"),
        format!("https://svc.example.com/services/{CANARY}"),
        format!("https://svc.example.com/mcp?token={CANARY}"),
        format!("https://svc.example.com/mcp#{CANARY}"),
    ] {
        let out = sanitize_url_for_diagnostics(&raw);
        assert!(!out.contains(CANARY), "URL redaction leaked: {out}");
        assert!(
            out.starts_with("https://svc.example.com"),
            "origin lost: {out}"
        );
    }

    // Unparseable input must not be echoed — the failure path is where a
    // redaction usually gets undone.
    let bad = sanitize_url_for_diagnostics(&format!(":://not a url {CANARY}"));
    assert!(!bad.contains(CANARY), "invalid-URL path leaked: {bad}");

    // A backend error body is untrusted and may quote our own credentials back.
    for body in [
        format!("{{\"error\":\"{CANARY}\"}}"),
        format!("{{\"code\":-32015,\"message\":\"Session not found {CANARY}\"}}"),
    ] {
        let err = safe_http_status_error(reqwest::StatusCode::BAD_REQUEST, &body);
        assert!(
            !err.to_string().contains(CANARY),
            "status error leaked: {err}"
        );
    }

    // The expiry marker still survives that redaction, or session recovery breaks.
    let expired = safe_http_status_error(
        reqwest::StatusCode::BAD_REQUEST,
        &format!("{{\"code\":-32015,\"message\":\"Session not found {CANARY}\"}}"),
    );
    assert!(
        is_session_expired_error(&expired),
        "expiry lost to redaction: {expired}"
    );

    // A cross-origin redirect rejection names both URLs; neither may carry one.
    let base = Url::parse("https://svc.example.com/mcp").expect("base");
    let target = Url::parse(&format!("https://evil.example.com/x?t={CANARY}")).expect("target");
    if let RedirectDecision::Reject(reason) = evaluate_redirect(&base, &target, 0) {
        assert!(
            !reason.contains(CANARY),
            "redirect rejection leaked: {reason}"
        );
    } else {
        panic!("a cross-origin redirect must be rejected");
    }
}

/// The SSE body may carry a server-to-client *request* rather than the answer
/// to the call in flight. Handing that back to the caller as its response is
/// the defect this guards.
#[tokio::test]
async fn sse_decode_rejects_inbound_request_frame() {
    // GIVEN: an SSE body whose first data line is a request, not a response
    let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"sampling/createMessage\",\"params\":{}}\n\n";

    // WHEN: the transport decodes it
    let outcome = sse_decoder::decode_sse_exchange(sse_stream(body)).await;

    // THEN: it is refused, never returned as an empty successful response
    assert!(
        outcome.is_err(),
        "a frame carrying `method` must not decode as a response, got {outcome:?}"
    );
}

/// Guard the extraction: a genuine response still decodes.
#[tokio::test]
async fn sse_decode_accepts_response_frame() {
    let body = "data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"tools\":[]}}\n";
    let response = sse_decoder::decode_sse_exchange(sse_stream(body))
        .await
        .expect("valid response must decode");
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

// =========================================================================
// OAuth cleartext-transmission guard (CodeQL rust/cleartext-transmission
// alerts #90/#91, CWE-319). An OAuth bearer token must never leave the
// process over plaintext `http://` unless the peer is loopback.
//
// Test plan — one row per acceptance criterion:
//   1  https + non-loopback + oauth      -> ALLOW  (guard must not over-refuse)
//   2  http  + non-loopback + oauth      -> REFUSE (the alert itself; RED today)
//   3  http://localhost + oauth          -> ALLOW  (operator-ruled exemption)
//   4  http://127.0.0.2 + oauth          -> ALLOW  (127.0.0.0/8, not one address)
//   5  http://[::1] + oauth              -> ALLOW  (v6 loopback)
//   6  http://localhost.evil.com + oauth -> REFUSE (kills a substring host check)
//   7  http://127.0.0.1.evil.com + oauth -> REFUSE (kills a prefix host check)
//   8  http://[::ffff:127.0.0.1] + oauth -> REFUSE (mapped v4 is not loopback here)
//   9  ftp://localhost + oauth           -> REFUSE (only http/https are transports)
//  10  http + non-loopback, NO oauth     -> ALLOW  (no credential, no change)
//  11  request time: message endpoint downgraded -> get_oauth_token refuses
//  12  request time: no oauth configured -> Ok(None) even over cleartext
// =========================================================================

#[test]
fn oauth_over_tls_is_allowed() {
    assert!(
        transport_with_oauth("https://backend.example/mcp").is_ok(),
        "row 1: TLS is the normal case and must keep working"
    );
}

#[test]
fn oauth_over_cleartext_non_loopback_is_refused() {
    let Err(err) = transport_with_oauth("http://backend.example/mcp") else {
        panic!("row 2: a bearer token must not travel in cleartext to a remote host");
    };
    assert!(
        err.to_string().contains("cleartext"),
        "the refusal must name the reason, got: {err}"
    );
    // Permanent, not transient: warm-start retries a plain `Transport` error
    // forever at debug level, so a misclassification hides the refusal from the
    // operator entirely.
    assert!(
        matches!(err, Error::TransportPermanent(_)),
        "a cleartext origin never becomes secure by waiting, got: {err}"
    );
}

#[test]
fn oauth_over_cleartext_loopback_is_allowed() {
    // Rows 3-5: local MCP backends legitimately bind loopback without TLS.
    for url in [
        "http://localhost:8080/mcp",
        "http://127.0.0.1:8080/mcp",
        "http://127.0.0.2:9000/mcp",
        "http://[::1]:8080/mcp",
    ] {
        assert!(
            transport_with_oauth(url).is_ok(),
            "{url} is loopback and must stay allowed"
        );
    }
}

#[test]
fn oauth_over_cleartext_loopback_lookalikes_are_refused() {
    // Rows 6-9: hosts that a substring/prefix check would wave through, plus a
    // scheme that is not an HTTP transport at all.
    for url in [
        "http://localhost.evil.com/mcp",
        "http://127.0.0.1.evil.com/mcp",
        "http://[::ffff:127.0.0.1]/mcp",
        "ftp://localhost/mcp",
    ] {
        assert!(
            transport_with_oauth(url).is_err(),
            "{url} must not be treated as a loopback HTTP peer"
        );
    }
}

#[test]
fn cleartext_without_oauth_is_unchanged() {
    // Row 10: no credential is attached, so the guard must not fire.
    assert!(
        HttpTransport::new(
            "http://backend.example/mcp",
            HashMap::new(),
            Duration::from_secs(5),
            true,
        )
        .is_ok(),
        "transports without OAuth keep working over plaintext"
    );
}

#[tokio::test]
async fn get_oauth_token_refuses_a_downgraded_message_endpoint() {
    // Row 11: the request-time barrier, independent of construction. The
    // message endpoint is the URL the token is actually posted to.
    let t = transport_with_oauth("https://backend.example/sse").unwrap();
    *t.message_url.write() = Some("http://backend.example/messages".to_string());

    let err = t
        .get_oauth_token()
        .await
        .expect_err("a downgraded message endpoint must not receive the token");
    assert!(
        err.to_string().contains("cleartext"),
        "the refusal must name the reason, got: {err}"
    );
}

#[tokio::test]
async fn get_oauth_token_without_oauth_is_none_over_cleartext() {
    // Row 12: the guard is about credentials, not about plaintext per se.
    let t = make_transport("http://backend.example/mcp");
    assert!(t.get_oauth_token().await.unwrap().is_none());
}
