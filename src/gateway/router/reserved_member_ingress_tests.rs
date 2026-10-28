// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's copy of a gateway-only member never reaches the
//! client. The backend plants every gateway-only member, each value marked
//! `FORGED-n`, beside a member of its own; the gateway's own checks write
//! nothing on these calls (no findings, signing and stamping off), so any
//! `FORGED-` text delivered is the backend's.

use serde_json::json;

use super::direct_continuation_tests::call;
use super::direct_guards_fixture::{Answer, fixture, send};
use crate::protocol::reserved_members::test_support::{assert_nothing_forged, planted};

/// FORGE.3, `/mcp`: `gateway_invoke` on the meta route.
#[tokio::test]
async fn the_meta_route_delivers_no_planted_member() {
    let fx = fixture(Answer::Built(planted), |_| {}).await;
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
    });
    let (_, delivered) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert!(delivered.get("error").is_none(), "{delivered}");
    assert_nothing_forged("/mcp gateway_invoke", &delivered);
}

/// FORGE.3, `/mcp/{name}`: the direct route, on a gated and a passthrough
/// backend.
#[tokio::test]
async fn the_direct_route_delivers_no_planted_member() {
    for backend in ["alpha", "alpha-pt"] {
        let fx = fixture(Answer::Built(planted), |_| {}).await;
        let (_, delivered) = call(&fx, backend, None, json!({})).await;
        assert!(delivered.get("error").is_none(), "{backend}: {delivered}");
        assert_nothing_forged(&format!("/mcp/{backend}"), &delivered);
    }
}
