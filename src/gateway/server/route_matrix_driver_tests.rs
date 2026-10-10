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
    served_sanitizing, stdio_sanitizing, stdio_task_read, stdio_task_surfaced,
    stdio_x14_signed_round,
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

/// A stdio Meta-MCP serving `alpha` over `transport`, prepared by `arm` (a
/// firewall, a chain signer) as the stdio server would.
async fn stdio_meta(
    arm: impl FnOnce(&mut MetaMcp),
    transport: Arc<dyn crate::transport::Transport>,
) -> Arc<MetaMcp> {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(transport);
    backend
        .get_tools_shared()
        .await
        .expect("warm the tool cache");
    assert!(registry.register(backend));
    let mut gateway_meta = MetaMcp::new(registry);
    arm(&mut gateway_meta);
    Arc::new(gateway_meta)
}

/// One stdio `tools/call` with `params` through the real stdio dispatch.
async fn stdio_send(gateway_meta: &Arc<MetaMcp>, params: Value) -> Value {
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params });
    super::Gateway::dispatch_single(gateway_meta, &policy, &mtls, &request, "stdio-matrix")
        .await
        .expect("a request is answered")
}

/// The params of `gateway_invoke alpha read` with `args`.
fn invoke_read(args: Value) -> Value {
    json!({ "name": "gateway_invoke",
        "arguments": { "server": "alpha", "tool": "read", "arguments": args } })
}

/// R5: stdio `tools/call gateway_invoke alpha read` with `args`, its params
/// carrying `meta` as `_meta` when given, on a Meta-MCP that `arm` prepares.
/// The backend answers `answer`.
async fn stdio_call(
    arm: impl FnOnce(&mut MetaMcp),
    (args, meta): (Value, Option<Value>),
    answer: Value,
) -> Sent {
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(Counting {
        calls: Arc::clone(&calls),
        answer,
    });
    let gateway_meta = stdio_meta(arm, transport).await;
    let mut params = invoke_read(args);
    if let Some(meta) = meta {
        params["_meta"] = meta;
    }
    let body = stdio_send(&gateway_meta, params).await;
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
    let firewall = audited_firewall(audit);
    stdio_call(
        |meta| meta.set_firewall(Some(firewall)),
        (args, None),
        text_result(answer),
    )
    .await
}

/// The production firewall (request and response scanning) writing audit
/// rows to `audit`.
fn audited_firewall(audit: &Path) -> Arc<crate::security::firewall::Firewall> {
    audited_firewall_with(audit, |_| {})
}

/// [`audited_firewall`] with `tune` applied to its config.
fn audited_firewall_with(
    audit: &Path,
    tune: impl FnOnce(&mut crate::security::firewall::FirewallConfig),
) -> Arc<crate::security::firewall::Firewall> {
    use crate::security::firewall::{Firewall, FirewallConfig};
    let mut config = FirewallConfig {
        enabled: true,
        scan_requests: true,
        scan_responses: true,
        credential_redaction: true,
        audit_log: Some(audit.to_path_buf()),
        ..FirewallConfig::default()
    };
    tune(&mut config);
    Arc::new(Firewall::from_config(config, None))
}

/// R5: a clean `gateway_invoke read` over stdio with anomaly detection on.
/// The route-stage scan keys the detector on the one stdio caller; with no
/// identity it would refuse every call unscored (P3).
pub(crate) async fn stdio_anomaly_clean(audit: &Path) -> Sent {
    let firewall = audited_firewall_with(audit, |config| config.anomaly_detection = true);
    stdio_call(
        |meta| meta.set_firewall(Some(firewall)),
        (json!({}), None),
        text_result("ok"),
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

/// A backend serving `read` whose first `tools/call` asks one form question
/// (`k1`) and whose later ones answer `ok`, counting its sends.
struct AsksOnce {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for AsksOnce {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({ "tools": [{ "name": "read", "inputSchema": { "type": "object" } }] })
        } else if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            json!({
                "resultType": "input_required",
                "inputRequests": { "k1": {
                    "method": "elicitation/create",
                    "params": { "message": "Which account?", "requestedSchema": { "type": "object" } }
                }},
                "requestState": "backend-state-1"
            })
        } else {
            text_result("ok")
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

/// R5: a modern `gateway_invoke read` over stdio whose backend asks one
/// question; the continuation retry answers it with `answer`. Firewalled as
/// [`stdio_firewalled`], writing audit rows to `audit`. Returns the retry's
/// outcome and the backend's sends.
pub(crate) async fn stdio_retry_answering(audit: &Path, answer: &str) -> Sent {
    let calls = Arc::new(AtomicUsize::new(0));
    let firewall = audited_firewall(audit);
    let gateway_meta = stdio_meta(
        |meta| meta.set_firewall(Some(firewall)),
        Arc::new(AsksOnce {
            calls: Arc::clone(&calls),
        }),
    )
    .await;
    let mut params = invoke_read(json!({}));
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": { "elicitation": { "form": {} } }
    });
    let asked = stdio_send(&gateway_meta, params.clone()).await;
    let state = asked["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("an interim answer with a state: {asked}"))
        .to_owned();
    params["requestState"] = json!(state);
    params["inputResponses"] =
        json!({ "k1": { "action": "accept", "content": { "account": answer } } });
    let body = stdio_send(&gateway_meta, params).await;
    Sent {
        body,
        backend_calls: calls.load(Ordering::SeqCst),
    }
}

/// R5: two `gateway_invoke read` calls, with `args.0` then `args.1`, over one
/// stdio Meta-MCP whose firewall config `tune` adjusts (P3 A10: the call
/// budget and the tenant guard the route-stage scan now keys on the stdio
/// caller). Returns both answers and the backend's sends.
pub(crate) async fn stdio_twice(
    audit: &Path,
    tune: impl FnOnce(&mut crate::security::firewall::FirewallConfig),
    args: (Value, Value),
) -> (Value, Value, usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    let firewall = audited_firewall_with(audit, tune);
    let gateway_meta = stdio_meta(
        |meta| meta.set_firewall(Some(firewall)),
        Arc::new(Counting {
            calls: Arc::clone(&calls),
            answer: text_result("ok"),
        }),
    )
    .await;
    let first = stdio_send(&gateway_meta, invoke_read(args.0)).await;
    let second = stdio_send(&gateway_meta, invoke_read(args.1)).await;
    (first, second, calls.load(Ordering::SeqCst))
}
