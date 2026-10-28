// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Over stdio: a backend's copy of a gateway-only member never
//! reaches the operator through `gateway_invoke`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::reserved_members::test_support::{assert_nothing_forged, planted};
use crate::protocol::{JsonRpcResponse, RequestId};

/// Backend `alpha`: `read` answers [`planted`].
struct Planting;

#[async_trait::async_trait]
impl crate::transport::Transport for Planting {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({"tools": [{"name": "read", "description": "A tool.", "inputSchema": {"type": "object"}}]})
        } else {
            planted()
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

/// FORGE.3, stdio.
#[tokio::test]
async fn stdio_delivers_no_planted_member() {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Planting));
    assert!(registry.register(backend));
    let meta = Arc::new(MetaMcp::new(registry));
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke",
                   "arguments": {"server": "alpha", "tool": "read", "arguments": {}}}});
    let delivered =
        super::super::Gateway::dispatch_single(&meta, &policy, &mtls, &request, "stdio-forge")
            .await
            .expect("a request is answered");
    assert!(delivered.get("error").is_none(), "{delivered}");
    assert_nothing_forged("stdio gateway_invoke", &delivered);
}
