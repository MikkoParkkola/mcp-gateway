// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R2-T4 (MIK-7570.SCHEMA.1): over stdio, a `gateway_invoke` carrying a
//! nested key the tool's schema does not declare is refused before the
//! backend sees it. The catalogue is warmed by a real `gateway_list_tools`
//! over the same stdio dispatcher, never seeded.

use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};

type Calls = Arc<parking_lot::Mutex<usize>>;

/// Serves one `edit` tool; counts `tools/call`.
struct Wire {
    calls: Calls,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Wire {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let result = if method == "tools/list" {
            json!({"tools": [{"name": "edit", "description": "fixture", "inputSchema": {
            "type": "object", "properties": {"edits": {"type": "array", "items": {
                "type": "object",
                "properties": {"oldText": {"type": "string"}, "newText": {"type": "string"}}
            }}}}}]})
        } else {
            *self.calls.lock() += 1;
            json!({"content": [{"type": "text", "text": "done"}]})
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), result))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

fn call(id: u64, tool: &str, arguments: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}})
}

#[tokio::test]
async fn stdio_tools_call_refuses_nested_invented_key() {
    let calls = Calls::default();
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "edits",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Wire {
        calls: Arc::clone(&calls),
    }));
    assert!(registry.register(backend));
    let meta = Arc::new(MetaMcp::new(registry));
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let dispatch = |request: Value| {
        let (meta, policy, mtls) = (Arc::clone(&meta), Arc::clone(&policy), Arc::clone(&mtls));
        async move {
            super::super::Gateway::dispatch_single(&meta, &policy, &mtls, &request, "stdio-r2")
                .await
                .expect("a request is answered")
        }
    };

    let listed = dispatch(call(1, "gateway_list_tools", &json!({"server": "edits"}))).await;
    assert!(
        listed.to_string().contains("\\\"edit\\\""),
        "not listed: {listed}"
    );

    let invented = json!({"server": "edits", "tool": "edit", "arguments":
        {"edits": [{"oldText": "a", "newText": "b", "type": "replace"}]}});
    let refused = dispatch(call(2, "gateway_invoke", &invented)).await;
    let text = refused["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    let inner: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    assert_eq!(inner["isError"], json!(true), "not refused: {refused}");
    assert!(inner.to_string().contains("edits[0].type"), "{refused}");
    assert_eq!(*calls.lock(), 0, "the backend saw the call");
}
