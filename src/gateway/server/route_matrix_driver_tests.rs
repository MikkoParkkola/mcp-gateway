// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only driver for the route x check matrix (MIK-8137 family, b3): one
//! backend `tools/call` through the real stdio dispatch, nothing more. The
//! matrix (`gateway::route_check_matrix_tests`) owns every assertion.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};

/// A backend serving one tool, `read`, counting the `tools/call` sends.
struct Counting {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Counting {
    async fn request(&self, method: &str, _params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({ "tools": [{ "name": "read", "inputSchema": { "type": "object" } }] })
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            json!({ "content": [{ "type": "text", "text": "ok" }], "isError": false })
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

/// What one stdio call produced: the answer and the backend sends.
pub(crate) struct Sent {
    pub(crate) body: Value,
    pub(crate) backend_calls: usize,
}

/// R5: stdio `tools/call gateway_invoke alpha read`, with the production
/// firewall (request and response scanning) on the stdio Meta-MCP, its only
/// instance, writing audit rows to `audit`.
#[cfg(feature = "firewall")]
pub(crate) async fn stdio_firewalled(audit: &Path, args: Value) -> Sent {
    use crate::security::firewall::{Firewall, FirewallConfig};
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Counting {
        calls: Arc::clone(&calls),
    }) as Arc<dyn crate::transport::Transport>);
    backend.get_tools_shared().await.expect("warm the tool cache");
    assert!(registry.register(backend));
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_requests: true,
            scan_responses: true,
            credential_redaction: true,
            audit_log: Some(audit.to_path_buf()),
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(firewall));
    let meta = Arc::new(meta);
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": { "name": "gateway_invoke",
            "arguments": { "server": "alpha", "tool": "read", "arguments": args } },
    });
    let body = super::Gateway::dispatch_single(&meta, &policy, &mtls, &request, "stdio-matrix")
        .await
        .expect("a request is answered");
    Sent {
        body,
        backend_calls: calls.load(Ordering::SeqCst),
    }
}
