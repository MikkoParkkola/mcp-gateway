// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.PARENT.6 test 3 (stdio leg): a surfaced backend tool's envelope is
//! returned as the backend sent it, so a backend's `public` must be clamped on
//! the way out of the real stdio dispatch.

use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};

const TOOL: &str = "scoped_echo";

/// A backend whose one tool answers with `"cacheScope": "public"`.
struct PublicClaimingBackend;

#[async_trait::async_trait]
impl crate::transport::Transport for PublicClaimingBackend {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({ "tools": [{
                "name": TOOL,
                "description": "echo",
                "inputSchema": { "type": "object" },
                "annotations": { "readOnlyHint": true }
            }]})
        } else {
            raw_call_answer()
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), body))
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

fn raw_call_answer() -> Value {
    json!({
        "content": [{ "type": "text", "text": "fine" }],
        "isError": false,
        "cacheScope": "public"
    })
}

async fn stdio_meta() -> Arc<MetaMcp> {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(
        Arc::new(PublicClaimingBackend) as Arc<dyn crate::transport::Transport>
    );
    backend
        .get_tools_shared()
        .await
        .expect("warm the tool cache");
    assert!(registry.register(backend));
    Arc::new(
        MetaMcp::new(registry).with_surfaced_tools(vec![SurfacedToolConfig {
            server: "demo".to_string(),
            tool: TOOL.to_string(),
        }]),
    )
}

#[tokio::test]
async fn stdio_surfaced_tool_never_delivers_a_public_scope() {
    assert_eq!(
        raw_call_answer()["cacheScope"],
        "public",
        "fixture is public"
    );
    let meta = stdio_meta().await;
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": { "name": TOOL, "arguments": {} }
    });

    let body = super::super::Gateway::dispatch_single(&meta, &policy, &mtls, &request, "stdio-p6")
        .await
        .expect("a request is answered");

    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(body["result"]["isError"], false, "{body}");
    assert_eq!(body["result"]["cacheScope"], "private", "{body}");
}
