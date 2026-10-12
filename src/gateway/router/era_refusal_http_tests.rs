// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8368: `/mcp` answers a modern request for a removed method with the
//! text stdio now answers with (`server/tests/era_parity.rs`), and the header
//! checks keep their place ahead of the body-only refusals. Literal strings.

use axum::http::StatusCode;
use serde_json::json;

use super::direct_guards_fixture::{Answer, fixture, send_with_headers};

fn modern_params(caps: impl Into<serde_json::Value>) -> serde_json::Value {
    let caps: serde_json::Value = caps.into();
    json!({ "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": caps,
        "io.modelcontextprotocol/clientInfo": { "name": "era", "version": "1" }
    }})
}

/// ERA.1b: HTTP refuses each removed method -32601 / 404 with the revision's
/// text, the answer stdio gives the same request.
#[tokio::test]
async fn http_refuses_every_removed_method_with_the_stdio_text() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    for method in [
        "ping",
        "logging/setLevel",
        "resources/subscribe",
        "resources/unsubscribe",
        "notifications/roots/list_changed",
    ] {
        let headers = [
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", method),
        ];
        let (status, body) = send_with_headers(
            &fx,
            "/mcp",
            "k-std",
            method,
            modern_params(json!({})),
            None,
            &headers,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}: {body}");
        assert_eq!(body["error"]["code"], -32601, "{method}: {body}");
        assert_eq!(
            body["error"]["message"],
            format!("method '{method}' was removed in MCP 2026-07-28"),
            "{method}: {body}"
        );
    }
}

/// A missing capability answers 400, not 404.
#[tokio::test]
async fn http_answers_a_missing_capability_400() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "roots/list"),
    ];
    let (status, body) = send_with_headers(
        &fx,
        "/mcp",
        "k-std",
        "roots/list",
        modern_params(json!({})),
        None,
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32021, "{body}");
}

/// The header-against-body check still runs first: a header naming another
/// method is -32020, not the removed-method refusal.
#[tokio::test]
async fn http_header_mismatch_still_precedes_the_removed_method_refusal() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/list"),
    ];
    let (status, body) = send_with_headers(
        &fx,
        "/mcp",
        "k-std",
        "ping",
        modern_params(json!({})),
        None,
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32020, "{body}");
}
