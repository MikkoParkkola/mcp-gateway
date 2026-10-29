// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call refused before its backend on the relay path: a secret that cannot
//! be injected is marked refused, and a dispatch error the backend never saw,
//! answered as a tool result, stages no receipt naming the backend.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};

use super::tests::{PROSE, Seen};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

/// A backend that answers every call with [`PROSE`]: text long enough to
/// fingerprint, so its delivery stages a receipt.
struct Prose;

#[async_trait::async_trait]
impl crate::transport::Transport for Prose {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tool = json!({"name": "send", "description": "A tool.", "inputSchema": {"type": "object"}});
            return Ok(JsonRpcResponse::success(id, json!({"tools": [tool]})));
        }
        let answer = json!({"content": [{"type": "text", "text": PROSE}], "isError": false});
        Ok(JsonRpcResponse::success(id, answer))
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

/// A backend whose every call fails before it is reached: the transport
/// reports the backend unavailable, a pre-dispatch error.
struct Unreachable(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for Unreachable {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "tools/call" {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        if method == "tools/list" {
            let tool = json!({"name": "send", "description": "A tool.", "inputSchema": {"type": "object"}});
            return Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({"tools": [tool]}),
            ));
        }
        Err(crate::Error::BackendUnavailable("alpha".to_owned()))
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

/// `alpha` on `transport`, under a relay firewall over `alpha:*`, with
/// `injector`.
fn alpha_relay_meta(
    transport: Arc<dyn crate::transport::Transport>,
    injector: crate::secret_injection::SecretInjector,
) -> MetaMcp {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    backend.set_transport_for_test(transport);
    assert!(registry.register(backend));
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                rules: crate::yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    sources: vec!["alpha:*".to_string()],
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test(),
    );
    let mut meta = MetaMcp::new(registry).with_secret_injector(injector);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    meta.share_keyring_with_for_test(&firewall);
    meta
}

/// A secret that cannot be injected (its environment variable is unset)
/// refuses the call before its backend: the invocation is marked refused,
/// so a task never records it as a call a backend ran, and nothing is sent.
#[tokio::test]
async fn an_uninjectable_secret_refuses_the_call_before_its_backend() {
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let rule: crate::secret_injection::CredentialRule = serde_json::from_value(json!({
        "name": "token",
        "value": "{env.REFUSED_CALL_ROW_UNSET_SECRET}",
        "inject_key": "token"
    }))
    .expect("rule parses");
    let injector = crate::secret_injection::SecretInjector::new(HashMap::from([(
        "alpha".to_string(),
        vec![rule],
    )]));
    let meta = alpha_relay_meta(Arc::new(Seen(Arc::clone(&seen))), injector);
    // Authenticated: the relay check refuses an anonymous caller first.
    let bob = MetaMcpCallerContext {
        caller_key: Some("bob"),
        ..ctx(&AllowAll)
    };
    let call = json!({"server": "alpha", "tool": "send", "arguments": {}});
    let invoked = Box::pin(meta.invoke_tool_sourced(&call, None, &bob, "t".to_owned())).await;
    assert!(
        seen.lock().is_empty(),
        "premise: nothing reached the backend"
    );
    // Premise: refused by the injection failure itself, not by an earlier exit.
    let answer = match &invoked.outcome {
        Ok(super::super::SourcedOutcome::Live((value, _, _))) => value.to_string(),
        Ok(super::super::SourcedOutcome::Stored(_)) => panic!("premise: a stored answer"),
        Err(error) => panic!("premise: refused earlier than the injection: {error}"),
    };
    assert!(
        answer.contains("Failed to resolve credential 'token'"),
        "premise: the injection failure is the answer: {answer}"
    );
    assert_eq!(
        invoked.pre_send,
        crate::gateway::meta_mcp::dispatch_log::PreSend::Refused,
        "an uninjectable secret is a refusal before the backend"
    );
}

/// The receipts naming `alpha` that one invocation of `meta` stages, read
/// inside the delivery's own receipt scope, as the meta path collects them.
async fn alpha_receipts(meta: &MetaMcp) -> (super::super::Invoked, usize) {
    let bob = MetaMcpCallerContext {
        caller_key: Some("bob"),
        ..ctx(&AllowAll)
    };
    let call = json!({"server": "alpha", "tool": "send", "arguments": {}});
    super::collecting(async {
        let invoked = Box::pin(meta.invoke_tool_sourced(&call, None, &bob, "t".to_owned())).await;
        let staged = super::RELAY_RECEIPTS
            .with(|r| r.borrow().iter().filter(|r| r.server == "alpha").count());
        (invoked, staged)
    })
    .await
}

/// A dispatch error the backend never saw (unavailable), answered as a tool
/// result, is the gateway's text: no receipt names the backend for it. The
/// control, an answered call, stages one in the same scope.
#[tokio::test]
async fn a_pre_dispatch_error_answered_as_a_result_stages_no_receipt() {
    let none = crate::secret_injection::SecretInjector::new(HashMap::new());
    let answered = alpha_relay_meta(Arc::new(Prose), none);
    let (_, control) = alpha_receipts(&answered).await;
    assert_eq!(control, 1, "control: an answered call stages its receipt");
    let tried = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let refused = alpha_relay_meta(
        Arc::new(Unreachable(Arc::clone(&tried))),
        crate::secret_injection::SecretInjector::new(HashMap::new()),
    );
    let (invoked, staged) = alpha_receipts(&refused).await;
    assert_eq!(
        invoked.pre_send,
        crate::gateway::meta_mcp::dispatch_log::PreSend::Refused,
        "premise: the dispatch error is a refusal before the backend"
    );
    assert!(
        tried.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "premise: the call reached its transport, which reported the backend unavailable"
    );
    assert_eq!(staged, 0, "a receipt was staged for the gateway's text");
}
