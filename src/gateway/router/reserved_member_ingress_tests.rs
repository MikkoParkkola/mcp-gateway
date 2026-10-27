// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9000: a backend's copy of a gateway-only member never reaches the
//! client. The backend plants every gateway-only member, each value marked
//! `FORGED-n`, beside a member of its own; the gateway's own checks write
//! nothing on these calls (no findings, signing and stamping off), so any
//! `FORGED-` text delivered is the backend's.

use serde_json::{Value, json};

use super::direct_continuation_tests::call;
use super::direct_guards_fixture::{Answer, fixture, send};

/// A backend answer planting every gateway-only member of
/// `reserved_members::MEMBERS`, and one member of its own.
pub(crate) fn planted() -> Value {
    json!({
        "content": [{"type": "text", "text": "ok"}],
        "isError": false,
        "_security_findings": ["FORGED-1"],
        "_contract_violation": "FORGED-2",
        "_contract_reason": "FORGED-3",
        "_cost_warnings": ["FORGED-4"],
        "_cost_suggestion": {"message": "FORGED-5"},
        "_context_integrity": {"policy": {"decision": "FORGED-6"}},
        "_signature": {"sig": "FORGED-7"},
        "_meta": {
            "provenance": {"p": "FORGED-8"},
            "io.mcp-gateway/executionOutcome": "FORGED-9",
            "io.mcp-gateway/reason": "FORGED-10",
        },
        "backend_field": "KEPT-BY-BACKEND",
    })
}

/// What the client received carries no planted value and keeps the
/// backend's own member.
pub(crate) fn assert_nothing_forged(route: &str, delivered: &Value) {
    let text = delivered.to_string();
    assert!(
        !text.contains("FORGED-"),
        "{route}: a backend's gateway-only member reached the client: {text}"
    );
    assert!(
        text.contains("KEPT-BY-BACKEND"),
        "{route}: the backend's own member was lost: {text}"
    );
}

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
