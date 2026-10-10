// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 §13.3 rows M3, M6 and M14: relay detection on retried rounds
//! (bridged and modern) and on bridged prompts, through `invoke_tool`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::backend::BackendRegistry;
use crate::gateway::input_bridge::{ClientChannel, DeliveryError, NoClientChannel};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::protocol::RequestId;
use crate::protocol::meta::Era;
use crate::protocol::mrtr::{NO_RETRY, RetryFields};
use crate::security::firewall::{
    CollusionAction, CollusionConfig, Firewall, FirewallConfig, RelayCaller,
};

/// Ordinary prose, long enough for several fingerprints.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// Backend `asks`: a call without `inputResponses` asks `request`; a retry
/// is answered. Every `tools/call` is recorded.
struct Asks {
    calls: Arc<parking_lot::Mutex<Vec<Value>>>,
    request: Value,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Asks {
    async fn request(
        &self,
        _method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let params = params.unwrap_or(Value::Null);
        let retry = params.get("inputResponses").is_some();
        self.calls.lock().push(params);
        let body = if retry {
            json!({"content": [{"type": "text", "text": "done"}], "isError": false})
        } else {
            json!({"resultType": "input_required",
                   "inputRequests": {"k1": self.request.clone()},
                   "requestState": "round-1"})
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            RequestId::Number(1),
            body,
        ))
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

/// A Meta-MCP whose backend `asks` asks `request`, under a `block` relay
/// firewall with `sources`; the firewall and the backend's call log.
fn meta_asking(
    request: Value,
    sources: Vec<String>,
) -> (MetaMcp, Arc<Firewall>, Arc<parking_lot::Mutex<Vec<Value>>>) {
    use crate::config::{BackendConfig, TransportConfig};
    let registry = Arc::new(BackendRegistry::new());
    let config = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://asks.internal/mcp".to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        input_schema_enforcement: crate::config::InputSchemaEnforcement::Off,
        ..BackendConfig::default()
    };
    let backend = Arc::new(crate::backend::Backend::new(
        "asks",
        config,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let calls = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(Asks {
        calls: Arc::clone(&calls),
        request,
    }));
    let _ = registry.register(backend);
    // With a keyring its gateway mints with, as the gateway pairs them
    // (#2210, MIK-8276).
    let keys = Arc::new(crate::protocol::continuation::ContinuationState::new());
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    sources,
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .with_continuations(Arc::clone(&keys)),
    );
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    meta.set_continuation_for_test(keys);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(60),
    );
    (meta, firewall, calls)
}

/// `alice` was delivered [`PROSE`] from `asks:ask`.
fn seed_alice(firewall: &Firewall) {
    let delivered = json!({"content": [{"type": "text", "text": PROSE}]});
    firewall.record_delivery(RelayCaller::Keyed("alice"), "asks", "ask", &delivered);
}

/// A legacy client answering every prompt with `reply`'s `result`.
struct Replying {
    reply: Value,
}

#[async_trait::async_trait]
impl ClientChannel for Replying {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> std::result::Result<Value, DeliveryError> {
        Ok(json!({"jsonrpc": "2.0", "result": self.reply.clone()}))
    }
}

/// A roots answer carrying `name`.
fn roots(name: &str) -> Value {
    json!({"roots": [{"uri": "file:///orchard", "name": name}]})
}

fn args(arguments: &Value) -> Value {
    json!({"server": "asks", "tool": "ask", "arguments": arguments})
}

fn keyed(key: &str) -> RetryFields {
    RetryFields {
        idempotency_key: Some(key.to_string()),
        ..Default::default()
    }
}

/// A caller keyed as `key`, declaring `capabilities`, in `era`.
fn caller<'a>(
    key: &'a str,
    capabilities: &Value,
    era: Era,
    channel: &'a dyn ClientChannel,
    retry: &'a RetryFields,
) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        input_capabilities: declaring(capabilities),
        verified_identity: Some(&NAMED_CALLER),
        caller_key: Some(key),
        is_modern: era == Era::Modern,
        era,
        channel,
        retry,
        ..allow_all_ctx_named(None, None)
    }
}

/// The JSON-RPC code of an `Err`, `None` for `Ok`.
fn code_of(result: &crate::Result<Value>) -> Option<i32> {
    result.as_ref().err().map(crate::Error::to_rpc_code)
}

/// M3: a bridged retry round whose answers carry what `alice` was delivered
/// is refused before it reaches the backend, and the key is released.
#[tokio::test]
async fn meta_retry_round_relay_refused() {
    let (meta, firewall, calls) =
        meta_asking(json!({"method": "roots/list"}), vec!["asks:*".to_string()]);
    seed_alice(&firewall);
    let retry = keyed("key-m3");
    let relaying = Replying {
        reply: roots(PROSE),
    };
    let bob = caller("bob", &json!({"roots": {}}), Era::Legacy, &relaying, &retry);
    let result = meta
        .invoke_tool(&args(&json!({})), Some("session-m3"), &bob)
        .await;
    assert!(
        !calls.lock().is_empty(),
        "base: the first round was dispatched"
    );
    assert_eq!(
        code_of(&result),
        Some(-32002),
        "relay not refused: {result:?}"
    );
    assert_eq!(
        calls.lock().len(),
        1,
        "the relaying round reached the backend"
    );

    let clean = Replying {
        reply: roots("north slope"),
    };
    let bob = caller("bob", &json!({"roots": {}}), Era::Legacy, &clean, &retry);
    let result = meta
        .invoke_tool(&args(&json!({})), Some("session-m3"), &bob)
        .await;
    assert!(result.is_ok(), "the clean exchange must run: {result:?}");
    assert_eq!(
        calls.lock().len(),
        3,
        "the refusal must release the key, so the clean exchange dispatches both rounds"
    );
}

/// M6: an elicitation prompt bridged to `alice` is a delivery, classified by
/// the gateway (no `sources`): `bob` sending its text is refused.
#[tokio::test]
async fn meta_bridged_prompt_recorded() {
    let prompt = format!("{PROSE} Contact: keeper@orchardcoop.fi");
    let request = json!({"method": "elicitation/create",
                         "params": {"message": prompt,
                                    "requestedSchema": {"type": "object", "properties": {}}}});
    let (meta, _firewall, calls) = meta_asking(request, Vec::new());
    let accepting = Replying {
        reply: json!({"action": "accept", "content": {}}),
    };
    let declared = json!({"elicitation": {}});
    let alice = caller("alice", &declared, Era::Legacy, &accepting, &NO_RETRY);
    let delivered = meta
        .invoke_tool(&args(&json!({})), Some("session-m6a"), &alice)
        .await;
    assert!(
        delivered.is_ok(),
        "base: the bridged exchange completes: {delivered:?}"
    );
    assert_eq!(calls.lock().len(), 2, "base: both rounds were dispatched");

    let bob = caller("bob", &json!({}), Era::Legacy, &NoClientChannel, &NO_RETRY);
    let relay = args(&json!({"text": prompt}));
    let result = meta.invoke_tool(&relay, Some("session-m6b"), &bob).await;
    assert_eq!(
        code_of(&result),
        Some(-32002),
        "relay not refused: {result:?}"
    );
    assert_eq!(calls.lock().len(), 2, "the relay reached the backend");
}

/// M6 under an enforcing context-integrity gate: the gate withholds the
/// classified copy of the prompt, but `alice` still receives the whole text,
/// so `bob` sending it is refused all the same.
#[tokio::test]
async fn meta_bridged_prompt_recorded_under_enforcement() {
    use crate::context_integrity::{
        ContextIntegrityDecisionKind, ContextIntegrityKernel, ContextIntegrityPolicy,
        ContextIntegrityPolicyMode,
    };
    let prompt = format!("{PROSE} Contact: keeper@orchardcoop.fi");
    let request = json!({"method": "elicitation/create",
                         "params": {"message": prompt,
                                    "requestedSchema": {"type": "object", "properties": {}}}});
    let (meta, _firewall, calls) = meta_asking(request, Vec::new());
    let deny = ContextIntegrityDecisionKind::Deny;
    meta.set_context_integrity_kernel(ContextIntegrityKernel::new(ContextIntegrityPolicy {
        mode: ContextIntegrityPolicyMode::Enforce,
        untrusted_instruction_decision: deny,
        guarded_material_decision: deny,
        personal_data_decision: deny,
        destructive_instruction_decision: deny,
        tool_poisoning_decision: deny,
        high_risk_action_decision: deny,
        allow_benign_read_only: true,
        non_bypassable: false,
    }));
    let accepting = Replying {
        reply: json!({"action": "accept", "content": {}}),
    };
    let declared = json!({"elicitation": {}});
    let alice = caller("alice", &declared, Era::Legacy, &accepting, &NO_RETRY);
    let first = meta
        .invoke_tool(&args(&json!({})), Some("session-m6c"), &alice)
        .await;
    assert!(first.is_ok(), "base: the exchange runs: {first:?}");
    let sent = calls.lock().len();

    let bob = caller("bob", &json!({}), Era::Legacy, &NoClientChannel, &NO_RETRY);
    let relay = args(&json!({"text": prompt}));
    let result = meta.invoke_tool(&relay, Some("session-m6d"), &bob).await;
    assert_eq!(
        code_of(&result),
        Some(-32002),
        "relay not refused: {result:?}"
    );
    assert_eq!(calls.lock().len(), sent, "the relay reached the backend");
}

/// M14: a modern retry whose redeemed answers carry what `alice` was
/// delivered is refused at the first dispatch.
#[tokio::test]
async fn meta_modern_retry_relay_refused() {
    let (meta, firewall, calls) =
        meta_asking(json!({"method": "roots/list"}), vec!["asks:*".to_string()]);
    seed_alice(&firewall);
    let declared = json!({"roots": {}});
    let bob = caller("bob", &declared, Era::Modern, &NoClientChannel, &NO_RETRY);
    let asked = meta
        .invoke_tool(&args(&json!({})), Some("session-m14"), &bob)
        .await
        .expect("base: the question is handed back");
    let state = asked["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("base: no continuation was minted: {asked}"))
        .to_string();
    let resume = RetryFields {
        request_state: Some(state),
        input_responses: Some(json!({"k1": roots(PROSE)})),
        ..Default::default()
    };
    let bob = caller("bob", &declared, Era::Modern, &NoClientChannel, &resume);
    let result = meta
        .invoke_tool(&args(&json!({})), Some("session-m14"), &bob)
        .await;
    assert_eq!(
        code_of(&result),
        Some(-32002),
        "relay not refused: {result:?}"
    );
    assert_eq!(
        calls.lock().len(),
        1,
        "the relaying retry reached the backend"
    );
}
