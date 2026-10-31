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

#[cfg(feature = "firewall")]
pub(crate) use super::signing_allocation_tests::route_matrix_stdio_tasks::stdio_task_traced;
pub(crate) use super::signing_allocation_tests::route_matrix_stdio_tasks::{
    served_sanitizing, served_sanitizing_call, served_sanitizing_with, stdio_blocked_task,
    stdio_sanitizing, stdio_task_read, stdio_task_refused_without_a_grant, stdio_task_surfaced,
    stdio_x14_consumed_then_refused, stdio_x14_signed_round,
};

/// MIK-8747: keyed stdio calls across eras on one key.
#[path = "route_matrix_driver_era_tests.rs"]
pub(crate) mod era;
mod playbook_drivers;
#[path = "route_matrix_driver_response_tests.rs"]
pub(crate) mod response;
pub(crate) use playbook_drivers::{
    playbook_of, stdio_params_counted, stdio_params_over, stdio_playbook_flaky, stdio_playbook_runs,
};

/// A backend serving two tools, `read` and `write`, counting the `tools/call`
/// sends. `write` is advertised so a policy denial of it is the policy's doing,
/// never an unknown-tool refusal (MIK-8362 STEPFW.1c).
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
            json!({ "tools": [
                { "name": "read", "inputSchema": { "type": "object" } },
                { "name": "write", "inputSchema": { "type": "object" } }
            ] })
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
    stdio_send_under(gateway_meta, params, crate::security::ToolPolicy::default()).await
}

/// [`stdio_send`] under the tool policy `policy`.
async fn stdio_send_under(
    gateway_meta: &Arc<MetaMcp>,
    params: Value,
    policy: crate::security::ToolPolicy,
) -> Value {
    let policy = Arc::new(policy);
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params });
    super::Gateway::dispatch_single(gateway_meta, &policy, &mtls, &request, "stdio-matrix")
        .await
        .expect("a request is answered")
}

/// The params of `gateway_invoke alpha read` with `args`.
fn invoke_read(args: &Value) -> Value {
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
    let mut params = invoke_read(&args);
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
    stdio_call(arm_firewall(firewall), (args, None), text_result(answer)).await
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
    // The detector exists only with a transition tracker, as in production.
    let tracker = config
        .anomaly_detection
        .then(|| Arc::new(crate::transition::TransitionTracker::new()));
    Arc::new(Firewall::from_config(config, tracker).keyed_for_test())
}

/// Arm a Meta-MCP with `firewall` the way the gateway does: it adopts the
/// firewall's keyring, then installs it (#2210, MIK-8276).
fn arm_firewall(firewall: Arc<crate::security::firewall::Firewall>) -> impl FnOnce(&mut MetaMcp) {
    move |meta| {
        meta.share_keyring_with_for_test(&firewall);
        meta.set_firewall(Some(firewall));
    }
}

/// R5: a clean `gateway_invoke read` over stdio with anomaly detection on.
/// The route-stage scan keys the detector on the one stdio caller; with no
/// identity it would refuse every call unscored (P3).
pub(crate) async fn stdio_anomaly_clean(audit: &Path) -> Sent {
    let firewall = audited_firewall_with(audit, |config| config.anomaly_detection = true);
    stdio_call(arm_firewall(firewall), (json!({}), None), text_result("ok")).await
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

/// R5 whose backend answers `answer` under the context-integrity `kernel`
/// (MIK-8325 S8: an enforced follow-up question over stdio).
pub(crate) async fn stdio_answering_gated(
    kernel: crate::context_integrity::ContextIntegrityKernel,
    answer: Value,
) -> Sent {
    stdio_call(
        |meta| meta.set_context_integrity_kernel(kernel),
        // A modern client that declares form elicitation, so the question
        // clears the capability gate (MRTR.9) and reaches the content gate.
        (
            json!({}),
            Some(json!({
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
            })),
        ),
        answer,
    )
    .await
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

/// R5 by the surfaced name, with the same signer and nonce (MIK-8159.CHAIN.1):
/// stdio `tools/call read` on a Meta-MCP that surfaces `alpha`'s `read`.
pub(crate) async fn stdio_surfaced_chained() -> Sent {
    use crate::gateway::chain_test_support::{NONCE_KEY, signer};
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(Counting {
        calls: Arc::clone(&calls),
        answer: text_result("ok"),
    });
    let gateway_meta = stdio_meta(
        |meta| {
            // Surfacing is a consuming builder; the placeholder is dropped.
            let built = std::mem::replace(meta, MetaMcp::new(Arc::new(BackendRegistry::new())));
            *meta = built.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
                server: "alpha".to_string(),
                tool: "read".to_string(),
            }]);
            meta.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest);
        },
        transport,
    )
    .await;
    let params = json!({ "name": "read", "arguments": {}, "_meta": { NONCE_KEY: "matrix-nonce" } });
    let body = stdio_send(&gateway_meta, params).await;
    Sent {
        body,
        backend_calls: calls.load(Ordering::SeqCst),
    }
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
        arm_firewall(firewall),
        Arc::new(AsksOnce {
            calls: Arc::clone(&calls),
        }),
    )
    .await;
    let mut params = invoke_read(&json!({}));
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
        arm_firewall(firewall),
        Arc::new(Counting {
            calls: Arc::clone(&calls),
            answer: text_result("ok"),
        }),
    )
    .await;
    let first = stdio_send(&gateway_meta, invoke_read(&args.0)).await;
    let second = stdio_send(&gateway_meta, invoke_read(&args.1)).await;
    (first, second, calls.load(Ordering::SeqCst))
}

/// R5, MIK-8150 NONCE.5: on the production-built hardened stdio gateway, a
/// keyed signed `gateway_invoke` runs under `t1`; the key reused for other
/// arguments is refused by execution admission (409) under `t2`; the honest
/// call is re-sent under `t2` with its own key; then a third call under `t2`.
/// Returns (the admission refusal, the re-send, the third send, the backend's
/// `tools/call` count). Blocking: the fixture owns its runtime, as the stdio
/// signing rows do.
pub(crate) fn stdio_admission_then_resend() -> (Value, Value, Value, usize) {
    use super::signing_allocation_tests::signing_nonce_allocations_support::{
        BACKEND, Fixture, SESSION, TOOL, runtime,
    };
    use crate::gateway::meta_mcp::signing::NONCE_META;
    use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
    runtime().block_on(async {
        let fixture = Fixture::start_hardened().await;
        let call = |key: &'static str, nonce: &'static str, cmd: &'static str| {
            let fixture = &fixture;
            async move {
                let request = serde_json::json!({
                    "jsonrpc": "2.0", "id": nonce, "method": "tools/call",
                    "params": {"name": "gateway_invoke",
                        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"cmd": cmd}},
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                            NONCE_META: nonce,
                            IDEMPOTENCY_KEY_META: key,
                        }}
                });
                super::Gateway::dispatch_single_for_client(
                    &fixture.meta,
                    &fixture.tool_policy,
                    &fixture.mtls_policy,
                    request,
                    super::StdioClient {
                        session_id: SESSION,
                        channel: &crate::gateway::input_bridge::NoClientChannel,
                        handshake_capabilities: crate::protocol::meta::Declared::NONE,
                        tasks: None,
                        serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
                        discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
                        sanitize: super::stdio_single::InputSanitizing::Off,
                    },
                )
                .await
                .expect("a request carrying an id must produce a response")
            }
        };
        let first = call("t-k1", "stdio-adm-t1-0001", "one").await;
        assert!(
            first.get("error").is_none(),
            "premise: the first call ran: {first}"
        );
        let refused = call("t-k1", "stdio-adm-t2-0001", "other").await;
        let resent = call("t-k2", "stdio-adm-t2-0001", "other").await;
        let third = call("t-k3", "stdio-adm-t2-0001", "other").await;
        (refused, resent, third, fixture.backend.tools_call_count())
    })
}

/// One stdio answer's delivery: whether the frame delivers a result, and how
/// many nonces were given back across its dispatch and its delivery tail.
pub(crate) struct Delivered {
    pub(crate) delivers_result: bool,
    pub(crate) given_back: usize,
}

/// MIK-8353 STDIO-SETTLE: on the production-built hardened stdio gateway, a
/// signed `gateway_invoke` carrying a forged continuation (refused before its
/// backend, so the call settles a refund), then the honest call re-sent under
/// that nonce, then a third send under it. Each goes through the staged
/// dispatch and `judge_and_commit`, the delivery tail stdio's loop runs, so a
/// give-back in either place is counted. Blocking: the fixture owns its
/// current-thread runtime, which the give-back count is kept on.
pub(crate) fn stdio_refund_through_delivery() -> [Delivered; 3] {
    use super::signing_allocation_tests::signing_nonce_allocations_support::{
        BACKEND, Fixture, SESSION, TOOL, runtime,
    };
    use crate::gateway::meta_mcp::signing::{NONCE_META, given_back_on_this_thread};
    const NONCE: &str = "stdio-settle-nonce-0001";
    runtime().block_on(async {
        let fixture = Fixture::start_hardened().await;
        // The refusal must be effect-free to earn a refund (NONCEFX.9): a
        // cold schema slot would fetch `tools/list` first and keep the nonce.
        let backend = fixture
            .meta
            .backends
            .for_test()
            .get(BACKEND)
            .expect("backend");
        backend
            .get_tools_shared()
            .await
            .expect("warm the schema slot");
        assert!(backend.has_cached_tools(), "premise: the schema is warm");
        let send = |extra: Value| {
            let fixture = &fixture;
            async move {
                let mut params = serde_json::json!({"name": "gateway_invoke",
                    "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {}},
                    "_meta": {NONCE_META: NONCE}});
                if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
                    params.extend(extra.clone());
                }
                let request = serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
                let before = given_back_on_this_thread();
                let reads = fixture.meta.stdio_reads();
                let ((answer, staged), hidden) = crate::gateway::outbound::read_scoped(
                    reads.guard(),
                    Box::pin(super::Gateway::dispatch_single_staged(
                        &fixture.meta,
                        &fixture.tool_policy,
                        &fixture.mtls_policy,
                        request.clone(),
                        super::StdioClient {
                            session_id: SESSION,
                            channel: &crate::gateway::input_bridge::NoClientChannel,
                            handshake_capabilities: crate::protocol::meta::Declared::NONE,
                            tasks: None,
                            serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
                            discover:
                                crate::gateway::server::stdio_single::DiscoverListing::Configured,
                            sanitize: super::stdio_single::InputSanitizing::Off,
                        },
                    )),
                )
                .await;
                let answer = answer.expect("a request carrying an id is answered");
                let frame = super::Gateway::judge_and_commit(
                    &fixture.meta,
                    &reads,
                    SESSION,
                    (answer, request.get("params"), hidden.as_ref()),
                    staged,
                )
                .await;
                Delivered {
                    delivers_result: frame.delivers_result(),
                    given_back: given_back_on_this_thread() - before,
                }
            }
        };
        let forged = serde_json::json!({
            "requestState": "forged",
            "inputResponses": {"q": {"action": "accept"}},
        });
        let refused = send(forged).await;
        let resent = send(serde_json::json!({})).await;
        let third = send(serde_json::json!({})).await;
        [refused, resent, third]
    })
}

/// MIK-8382, the premise of R5's `KeyedPrincipal` N/A: stdio `gateway_invoke
/// alpha read` with idempotency on, keyed `k-a`, `k-a` again, then `k-b`.
/// Returns the three answers and the backend's sends.
pub(crate) async fn stdio_keyed_calls() -> ([Value; 3], usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    let gateway_meta = stdio_meta(
        |meta| {
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                crate::idempotency::CLEANUP_INTERVAL,
            );
        },
        Arc::new(Counting {
            calls: Arc::clone(&calls),
            answer: text_result("ok"),
        }),
    )
    .await;
    let keyed = |key: &str| {
        let mut params = invoke_read(&json!({}));
        params["_meta"] = json!({ (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key });
        params
    };
    let answers = [
        stdio_send(&gateway_meta, keyed("k-a")).await,
        stdio_send(&gateway_meta, keyed("k-a")).await,
        stdio_send(&gateway_meta, keyed("k-b")).await,
    ];
    (answers, calls.load(Ordering::SeqCst))
}

#[path = "stdio_question_key_tests.rs"]
mod stdio_question_key;
