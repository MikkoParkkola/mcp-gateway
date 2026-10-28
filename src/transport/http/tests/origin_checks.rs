// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! resolve_message_url and evaluate_redirect: each refuses a cross-origin hop.

use super::*;

// =========================================================================
// resolve_message_url
// =========================================================================

#[test]
fn resolve_message_url_absolute_cross_origin_rejected() {
    // A backend-advertised absolute endpoint on a different origin than the SSE
    // stream must be rejected: sending per-user credentials there is the SSRF +
    // credential-exfil vector this guard closes.
    let t = make_transport("http://localhost:8080/sse");
    let err = t
        .resolve_message_url("http://other:9090/messages")
        .unwrap_err();
    assert!(
        err.to_string().contains("cross-origin"),
        "expected cross-origin rejection, got: {err}"
    );
}

#[test]
fn resolve_message_url_absolute_https() {
    let t = make_transport("https://api.example.com/sse");
    let result = t
        .resolve_message_url("https://api.example.com/messages?session_id=abc")
        .unwrap();
    assert_eq!(result, "https://api.example.com/messages?session_id=abc");
}

#[test]
fn resolve_message_url_relative_path() {
    let t = make_transport_sse("http://localhost:8080/sse");
    let result = t.resolve_message_url("/messages?session_id=123").unwrap();
    assert_eq!(result, "http://localhost:8080/messages?session_id=123");
}

#[test]
fn resolve_message_url_relative_sibling() {
    let t = make_transport_sse("http://localhost:8080/api/sse");
    let result = t.resolve_message_url("messages").unwrap();
    assert_eq!(result, "http://localhost:8080/api/messages");
}

// Authority-replacing endpoints that do NOT start with `http://`/`https://`
// but resolve cross-origin via WHATWG URL rules (network-path, backslash,
// scheme-relative). A prefix classifier routes these to the relative branch and
// misses them; resolve-then-check catches them. All four MUST be rejected.
fn assert_cross_origin_rejected(base: &str, endpoint: &str) {
    let t = make_transport(base);
    let err = t.resolve_message_url(endpoint).unwrap_err();
    assert!(
        matches!(&err, crate::Error::Transport(m) if m.contains("cross-origin")),
        "expected cross-origin rejection for endpoint {endpoint:?}, got: {err:?}"
    );
}

#[test]
fn resolve_message_url_network_path_metadata_host_rejected() {
    assert_cross_origin_rejected(
        "http://localhost:8080/sse",
        "//169.254.169.254/latest/meta-data/",
    );
}

#[test]
fn resolve_message_url_backslash_authority_rejected() {
    assert_cross_origin_rejected("http://localhost:8080/sse", "\\\\169.254.169.254/x");
}

#[test]
fn resolve_message_url_slash_backslash_authority_rejected() {
    assert_cross_origin_rejected("http://localhost:8080/sse", "/\\attacker-host/x");
}

#[test]
fn resolve_message_url_scheme_relative_authority_rejected() {
    assert_cross_origin_rejected("http://localhost:8080/sse", "https:/\\/\\attacker-host/x");
}

// =========================================================================
// evaluate_redirect (redirect-policy same-origin credential-exfil guard)
// =========================================================================

fn url(s: &str) -> url::Url {
    url::Url::parse(s).unwrap()
}

#[test]
fn evaluate_redirect_cross_origin_public_host_rejected() {
    // A same-origin backend answering with `30x Location: https://evil…` points
    // at a PUBLIC host that clears the SSRF check but is a different origin.
    // Following it would replay the per-user bearer cross-origin: must reject.
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("https://evil.example.com/steal"),
        0,
    );
    match decision {
        RedirectDecision::Reject(msg) => assert!(
            msg.contains("cross-origin"),
            "expected cross-origin rejection, got: {msg}"
        ),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn evaluate_redirect_same_origin_allowed() {
    // A redirect that stays on the base origin (different path) is legitimate
    // per the MCP spec and must be followed.
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("https://api.example.com/messages?session_id=abc"),
        0,
    );
    assert_eq!(decision, RedirectDecision::Follow);
}

#[test]
fn evaluate_redirect_same_origin_different_port_rejected() {
    // Same host+scheme but a different port is a distinct origin (WHATWG) —
    // still a credential-exfil target, so reject.
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("https://api.example.com:8443/messages"),
        0,
    );
    assert!(
        matches!(&decision, RedirectDecision::Reject(m) if m.contains("cross-origin")),
        "expected cross-origin rejection, got: {decision:?}"
    );
}

#[test]
fn evaluate_redirect_internal_range_still_ssrf_rejected() {
    // An internal/metadata target is rejected by the SSRF guard, which runs
    // before the same-origin check, so the reason names SSRF (not cross-origin).
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("http://169.254.169.254/latest/meta-data/"),
        0,
    );
    match decision {
        RedirectDecision::Reject(msg) => {
            assert!(
                msg.contains("SSRF"),
                "expected SSRF rejection reason, got: {msg}"
            );
            assert!(
                !msg.contains("cross-origin"),
                "SSRF guard must fire before same-origin, got: {msg}"
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn evaluate_redirect_hop_cap_stops() {
    // The fifth redirect is followed and the sixth stopped: MAX_REDIRECT_HOPS counts redirects followed.
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("https://api.example.com/again"),
        5,
    );
    assert_eq!(decision, RedirectDecision::Follow);
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("https://api.example.com/again"),
        6,
    );
    assert_eq!(decision, RedirectDecision::Stop);
}

#[test]
fn evaluate_redirect_cross_origin_rejected_mid_chain() {
    // A same-origin first hop must not become a springboard for a later
    // cross-origin pivot: every target is compared against the ORIGINAL base
    // origin, not the immediately-preceding hop. Here the chain has already
    // followed same-origin hops (previous_hops in 1..5) and now pivots to a
    // public but foreign origin — it must still Reject, not Follow.
    for previous_hops in [2, 4] {
        let decision = evaluate_redirect(
            &url("https://api.example.com/sse"),
            &url("https://evil.example.com/steal"),
            previous_hops,
        );
        match decision {
            RedirectDecision::Reject(msg) => assert!(
                msg.contains("cross-origin"),
                "expected cross-origin rejection at hop {previous_hops}, got: {msg}"
            ),
            other => panic!("expected Reject at hop {previous_hops}, got {other:?}"),
        }
    }
}

/// The `same_origin` truth table: the transport's origin rule, including a
/// default port against an explicit one. `doctor` reports through
/// `transport_follows_redirect`, which uses this same rule.
#[test]
fn same_origin_truth_table() {
    let cases = [
        ("https://h.test/a", "https://h.test/b", true),
        ("https://h.test/", "https://h.test:443/", true),
        ("http://h.test/", "http://h.test:80/x", true),
        ("https://h.test/", "http://h.test/", false),
        ("https://h.test/", "https://h.test:8443/", false),
        ("https://h.test/", "https://g.test/", false),
        ("http://127.0.0.1:8080/", "http://127.0.0.1:8081/", false),
        ("http://127.0.0.1:8080/", "http://localhost:8080/", false),
        (
            "http://[::1]:8080/",
            "http://[0:0:0:0:0:0:0:1]:8080/x",
            true,
        ),
        ("http://[::1]:8080/", "http://[::2]:8080/", false),
    ];
    for (a, b, expected) in cases {
        assert_eq!(
            same_origin(&url(a), &url(b)),
            expected,
            "same_origin({a}, {b})"
        );
    }
}
