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

pub(crate) use super::signing_allocation_tests::route_matrix_stdio_tasks::{
    stdio_sanitizing, stdio_task_surfaced,
};

/// A backend serving one tool, `read`, counting the `tools/call` sends.
struct Counting {
    calls: Arc<AtomicUsize>,
    /// The result every `tools/call` answers.
    answer: Value,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Counting {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({ "tools": [{ "name": "read", "inputSchema": { "type": "object" } }] })
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answer.clone()
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

/// R5: stdio `tools/call gateway_invoke alpha read` with `args`, its params
/// carrying `meta` as `_meta` when given, on a Meta-MCP that `arm` prepares
/// (a firewall, a chain signer) as the stdio server would. The backend
/// answers `answer`.
async fn stdio_call(
    arm: impl FnOnce(&mut MetaMcp),
    (args, meta): (Value, Option<Value>),
    answer: Value,
) -> Sent {
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
        answer,
    }) as Arc<dyn crate::transport::Transport>);
    backend
        .get_tools_shared()
        .await
        .expect("warm the tool cache");
    assert!(registry.register(backend));
    let mut gateway_meta = MetaMcp::new(registry);
    arm(&mut gateway_meta);
    let gateway_meta = Arc::new(gateway_meta);
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let mut params = json!({ "name": "gateway_invoke",
        "arguments": { "server": "alpha", "tool": "read", "arguments": args } });
    if let Some(meta) = meta {
        params["_meta"] = meta;
    }
    let request = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params });
    let body =
        super::Gateway::dispatch_single(&gateway_meta, &policy, &mtls, &request, "stdio-matrix")
            .await
            .expect("a request is answered");
    Sent {
        body,
        backend_calls: calls.load(Ordering::SeqCst),
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
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                enabled: true,
                scan_requests: true,
                scan_responses: true,
                credential_redaction: true,
                audit_log: Some(audit.to_path_buf()),
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test(),
    );
    stdio_call(
        |meta| {
            meta.share_keyring_with_for_test(&firewall);
            meta.set_firewall(Some(firewall));
        },
        (args, None),
        text_result(answer),
    )
    .await
}

/// A plain text tool result.
fn text_result(text: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
}

/// R5 with no firewall, the backend asking one elicitation question the
/// client never declared.
pub(crate) async fn stdio_asking() -> Sent {
    let question = json!({
        "resultType": "input_required",
        "inputRequests": { "k1": {
            "method": "elicitation/create",
            "params": { "message": "Which account?", "requestedSchema": { "type": "object" } }
        }},
        "requestState": "backend-state-1"
    });
    stdio_call(|_| {}, (json!({}), None), question).await
}

/// R5 with a chain signer emitting on request, the call carrying a chain nonce.
pub(crate) async fn stdio_chained() -> Sent {
    use crate::gateway::chain_test_support::{NONCE_KEY, signer};
    stdio_call(
        |meta| meta.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest),
        (json!({}), Some(json!({ NONCE_KEY: "matrix-nonce" }))),
        text_result("ok"),
    )
    .await
}
