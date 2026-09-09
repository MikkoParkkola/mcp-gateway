// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

/// MIK-7272.ORDER2.FSM.5: the shared stdio dispatcher preserves its state owner.
#[tokio::test]
async fn order2_fsm_stdio_dispatch_retains_successful_owned_transitions() {
    let meta = test_meta_mcp();
    for (id, previous, next) in [(81, "default", "triage"), (82, "triage", "complete")] {
        let response = Gateway::dispatch_single(
            &meta,
            &test_tool_policy(),
            &test_mtls_policy(),
            &json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {"name": "gateway_set_state", "arguments": {"state": next}}
            }),
            super::super::STDIO_SESSION_ID,
        )
        .await
        .expect("an identified stdio call returns a response");
        assert_eq!(response["id"], id);
        assert!(response.get("error").is_none(), "{response}");
        let result: serde_json::Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("the successful state tool returns JSON text"),
        )
        .unwrap();
        assert_eq!(result["previous"], previous);
        assert_eq!(result["current"], next);
        assert_eq!(result["session_id"], "stdio-session");
    }
}
