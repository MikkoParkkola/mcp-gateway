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
    seen: Arc<std::sync::Mutex<Vec<Value>>>,
    /// The text every `tools/call` answers.
    answer: &'static str,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Counting {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({ "tools": [{ "name": "read", "inputSchema": { "type": "object" } }] })
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen
                .lock()
                .expect("seen lock")
                .push(params.unwrap_or_default());
            json!({ "content": [{ "type": "text", "text": self.answer }], "isError": false })
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
    /// The params each backend send carried.
    pub(crate) seen: Vec<Value>,
}

/// R5: stdio `tools/call gateway_invoke alpha read` on a Meta-MCP holding
/// `firewall` (its only instance), as the stdio server wires it.
async fn stdio_call(
    firewall: Option<Arc<crate::security::firewall::Firewall>>,
    args: Value,
    answer: &'static str,
) -> Sent {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Counting {
        calls: Arc::clone(&calls),
        seen: Arc::clone(&seen),
        answer,
    }) as Arc<dyn crate::transport::Transport>);
    backend.get_tools_shared().await.expect("warm the tool cache");
    assert!(registry.register(backend));
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(firewall);
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
    let seen = seen.lock().expect("seen lock").clone();
    Sent {
        body,
        backend_calls: calls.load(Ordering::SeqCst),
        seen,
    }
}

/// R5 with the production firewall (request and response scanning) writing
/// audit rows to `audit`.
pub(crate) async fn stdio_firewalled(audit: &Path, args: Value) -> Sent {
    stdio_firewalled_answering(audit, args, "ok").await
}

/// [`stdio_firewalled`] whose backend answers `answer`.
pub(crate) async fn stdio_firewalled_answering(
    audit: &Path,
    args: Value,
    answer: &'static str,
) -> Sent {
    use crate::security::firewall::{Firewall, FirewallConfig};
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
    stdio_call(Some(firewall), args, answer).await
}

/// R5 with no firewall: what the stdio route itself does to the arguments.
pub(crate) async fn stdio_plain(args: Value) -> Sent {
    stdio_call(None, args, "ok").await
}
