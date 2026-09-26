// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 text A amendment (coordinator ruling B): a tool the backend's complete
//! catalogue lacks is refused with the design's exact text A on BOTH routes;
//! only the Meta-MCP route appends the profile-scoped "did you mean?" hint
//! (the #555 / MIK-7518 suggestion contract), and neither route says to list
//! and retry.

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::f13_fetch_on_miss_tests::{ListMode, cold};
use crate::config::InputSchemaEnforcement;

/// The design's text A, exactly (F13-design §2 step 4).
fn text_a(tool: &str) -> String {
    format!("the backend does not list a tool named `{tool}`")
}

/// The refusal text the caller reads, through `gateway_invoke`'s envelope on
/// the meta route or as the direct route's tool result.
async fn refusal_text(router: &axum::Router, meta: bool, tool: &str) -> String {
    let (uri, body) = if meta {
        let args = json!({"server": "edits", "tool": tool, "arguments": {}});
        let body = json!({"jsonrpc": "2.0", "id": 41, "method": "tools/call",
            "params": {"name": "gateway_invoke", "arguments": args}});
        ("/mcp", body)
    } else {
        let body = json!({"jsonrpc": "2.0", "id": 42, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}});
        ("/mcp/edits", body)
    };
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    let outer = body["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    let result = serde_json::from_str::<Value>(outer)
        .ok()
        .filter(|inner| inner.get("isError").is_some())
        .unwrap_or_else(|| body["result"].clone());
    assert_eq!(result["isError"], json!(true), "not a refusal: {body}");
    result["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// F13 text A amendment: exact wording on both routes, the hint on meta only.
/// New-API row: text A does not exist on base (the call is forwarded);
/// proven by mutants M6 (text U for absent) and M13 (drop or move the hint).
#[tokio::test]
async fn f13_text_a_is_exact_on_both_routes_and_meta_adds_only_a_hint() {
    let fx = cold(InputSchemaEnforcement::Closed, ListMode::Serve).await;

    // Far from every listed name: no hint anywhere, so both routes read the
    // design's text A and nothing else.
    for meta in [true, false] {
        let text = refusal_text(&fx.router, meta, "nosuch").await;
        assert_eq!(text, text_a("nosuch"), "meta={meta}");
    }

    // Close to the listed `edit`: the direct route still reads text A alone;
    // the meta route reads text A, then the scoped hint naming `edit`.
    let direct = refusal_text(&fx.router, false, "edti").await;
    assert_eq!(direct, text_a("edti"));
    let meta = refusal_text(&fx.router, true, "edti").await;
    let hint = meta
        .strip_prefix(&format!("{}. ", text_a("edti")))
        .unwrap_or_else(|| panic!("meta text A must lead, then the hint: {meta}"));
    assert!(
        hint.contains("edit"),
        "the hint must name the close tool: {meta}"
    );
    for text in [&direct, &meta] {
        assert!(!text.contains("retry"), "text A must not say retry: {text}");
    }
}
