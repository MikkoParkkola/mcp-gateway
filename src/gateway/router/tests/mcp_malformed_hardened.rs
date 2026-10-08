// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8162: under `hardened`, `/mcp` tells a request that declared the modern
//! revision in its body and omitted a field which field it omitted, as the
//! direct route does, instead of asking it to declare elicitation.

use crate::gateway::router::direct_guards_fixture::{Answer, fixture_hardened_signed, send};
use pretty_assertions::assert_eq;
use serde_json::json;

const KEY: &str = "k-std";

/// `MIK-8162.ORDER.1`: a body-only modern declaration missing
/// `clientCapabilities` gets 400 / -32602 naming it, on both routes alike.
#[tokio::test]
async fn a_body_declared_malformed_request_is_told_what_it_omitted() {
    let fx = fixture_hardened_signed(Answer::Ok, false).await;
    let params = json!({"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}});
    let (mcp_status, mcp) = send(&fx, "/mcp", KEY, "tools/list", params.clone(), None).await;
    let (direct_status, direct) = send(&fx, "/mcp/alpha", KEY, "tools/list", params, None).await;
    assert_eq!(mcp_status, axum::http::StatusCode::BAD_REQUEST, "{mcp}");
    assert_eq!(mcp["error"]["code"], -32602, "{mcp}");
    assert!(
        mcp["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("clientCapabilities")),
        "{mcp}"
    );
    assert_eq!(
        (direct_status, &direct["error"]),
        (mcp_status, &mcp["error"])
    );
}

/// `MIK-8162.ORDER.2`: a request that declares nothing is still a legacy
/// client, refused until it declares elicitation.
#[tokio::test]
async fn a_legacy_request_still_gets_the_elicitation_refusal() {
    let fx = fixture_hardened_signed(Answer::Ok, false).await;
    let (status, body) = send(&fx, "/mcp", KEY, "tools/list", json!({}), None).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32600, "{body}");
}
