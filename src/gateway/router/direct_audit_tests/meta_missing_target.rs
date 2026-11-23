// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A `/mcp` `gateway_invoke` refused for a missing `server` or `tool` is
//! answered as before and leaves one `invalid` -32602 record whose decision
//! kind is the request's form (`syntax`), never `unrecorded`.

use super::*;

/// `gateway_invoke` with `arguments`, numbered 5.
fn invoke_with(arguments: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
           "params": {"name": "gateway_invoke", "arguments": arguments}})
    .to_string()
}

#[tokio::test]
async fn missing_server_is_recorded_as_syntax_on_mcp() {
    for (arguments, missing) in [
        (json!({"tool": "t"}), "server"),
        (json!({"server": "alpha"}), "tool"),
    ] {
        let fx = fixture(Setup::default()).await;
        let (status, answer) =
            post_to(&fx, "/mcp", &invoke_with(&arguments), &Caller::Anonymous).await;
        assert_eq!(answer["error"]["code"], -32602, "{missing}: {answer}");
        assert_eq!(
            answer["error"]["message"],
            format!("JSON-RPC error -32602: Missing '{missing}' parameter"),
            "{missing}: {answer}"
        );
        assert_eq!(answer["id"], 5, "{missing}: {answer}");
        let all = invocations(&fx);
        let [entry] = all.as_slice() else {
            panic!("{missing}: exactly one record (HTTP {status}): {all:?}; answer {answer}");
        };
        assert_eq!(entry["outcome"], "invalid", "{missing}: {entry}");
        assert_eq!(entry["error_code"], -32602, "{missing}: {entry}");
        assert_eq!(entry["decision"]["kind"], "syntax", "{missing}: {entry}");
        assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "{missing}: never sent");
    }
}
