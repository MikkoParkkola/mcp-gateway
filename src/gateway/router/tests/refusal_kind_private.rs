// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The check that refused a call is recorded, never shown: it reaches no
//! response body and no log line (`Debug` omits it).

use super::*;
use pretty_assertions::assert_eq;

use crate::gateway::authz::AuthorizationError;
use crate::security::decision_record::DecisionKind;

const KIND_SPELLINGS: [&str; 3] = ["kind", "AdminCapability", "admin_capability"];

#[test]
fn debug_output_omits_the_kind() {
    let refusal = AuthorizationError::forbidden(DecisionKind::AdminCapability, -32600, "no");
    let printed = format!("{refusal:?}");
    assert_eq!(
        printed,
        "AuthorizationError { code: -32600, status: 403, message: \"no\" }"
    );
    for spelling in KIND_SPELLINGS {
        assert!(!printed.contains(spelling), "{printed}");
    }
}

#[tokio::test]
async fn a_refused_admin_call_body_carries_no_kind() {
    let (state, _store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "gateway_reload_config", "arguments": {} }
            })
            .to_string(),
        ))
        .unwrap();
    let response = create_router(state).oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("requires admin access"), "refused: {text}");
    for spelling in KIND_SPELLINGS {
        assert!(!text.contains(spelling), "{spelling} leaked: {text}");
    }
}
