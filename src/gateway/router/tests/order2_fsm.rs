// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use pretty_assertions::assert_eq;

/// MIK-7272.ORDER2.FSM.3: the real modern HTTP path must refuse state changes.
#[tokio::test]
async fn order2_fsm_modern_http_refuses_state_even_with_an_offered_session() {
    let router = create_router(modern_router_app_state());
    for offered_session in [None, Some("client-offered-session")] {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "gateway_set_state");
        if let Some(session) = offered_session {
            request = request.header("mcp-session-id", session);
        }
        let request = request
            .body(axum::body::Body::from(
                json!({
                    "jsonrpc": "2.0", "id": 73, "method": "tools/call",
                    "params": {
                        "name": "gateway_set_state", "arguments": {"state": "triage"},
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {}
                        }
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert!(response.headers().get("mcp-session-id").is_none());
        let bytes = to_bytes(response.into_body(), 65_536).await.unwrap();
        let response: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["id"], 73);
        assert_eq!(response["error"]["code"], -32600, "{response}");
        assert_eq!(
            response["error"]["message"],
            "Protocol error: The workflow state is per-session, and this connection has no session. MCP 2026-07-28 removed protocol-level sessions; capability visibility is decided by the authorization presented on each request."
        );
        assert!(response.get("result").is_none(), "{response}");
    }
}
