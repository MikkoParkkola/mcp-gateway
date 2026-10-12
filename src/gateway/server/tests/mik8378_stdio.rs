// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8378 rows (design r1.2), stdio: a non-scalar id is refused (ENV.4, a
//! GUARD, true today), and a dirty `gateway_invoke` key is refused, never
//! stripped into `server` (ENV.2, red on the MIK-8154 PR 2 head).

use std::sync::Arc;

use serde_json::{Value, json};

use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::server::stdio_single::InputSanitizing;

async fn dispatch(request: Value) -> Option<Value> {
    let meta = Arc::new(MetaMcp::new(Arc::new(BackendRegistry::new())));
    let tool_policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    super::super::Gateway::dispatch_single_for_client(
        &meta,
        &tool_policy,
        &mtls_policy,
        request,
        super::super::StdioClient {
            session_id: "mik8378-stdio",
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
            discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
            sanitize: InputSanitizing::On,
        },
    )
    .await
}

/// ENV.4 GUARD: an object or array id is refused, -32600 with id null.
#[tokio::test]
async fn e4_a_non_scalar_id_is_refused_on_stdio() {
    for id in [json!({"x": "a\u{0}b"}), json!(["a\u{7}"])] {
        let request = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "gateway_list_servers", "arguments": {}}});
        let response = dispatch(request).await.expect("a refusal is answered");
        assert_eq!(
            response.pointer("/error/code"),
            Some(&json!(-32600)),
            "{id}: {response}"
        );
        assert_eq!(response["id"], Value::Null, "{id}: {response}");
    }
}

/// ENV.2 position 1 on stdio: a dirty own key of `gateway_invoke`'s
/// arguments is refused with the protocol refusal.
#[tokio::test]
async fn e2a_a_dirty_gateway_invoke_key_is_refused_on_stdio() {
    let request = json!({"jsonrpc": "2.0", "id": "e2a", "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments":
            {"ser\u{7}ver": "alpha", "tool": "read", "arguments": {}}}});
    let response = dispatch(request).await.expect("a refusal is answered");
    assert_eq!(
        response.pointer("/error/code"),
        Some(&json!(-32600)),
        "{response}"
    );
    let message = response
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(message.contains("control characters"), "{response}");
}

/// ENV.2 position 3 on stdio: a dirty key cleaning to a gateway directive in
/// `gateway_invoke`'s tool arguments is refused with the protocol refusal.
#[tokio::test]
async fn e2f_a_dirty_directive_is_refused_on_stdio() {
    let request = json!({"jsonrpc": "2.0", "id": "e2f", "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments":
            {"server": "alpha", "tool": "read", "arguments": {"_fu\u{7}ll": true}}}});
    let response = dispatch(request).await.expect("a refusal is answered");
    assert_eq!(
        response.pointer("/error/code"),
        Some(&json!(-32600)),
        "{response}"
    );
    let message = response
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(message.contains("control characters"), "{response}");
}
