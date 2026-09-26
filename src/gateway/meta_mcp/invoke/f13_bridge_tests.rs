// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13-T9c: the Meta-MCP bridged round's cold-slot fill goes out as the
//! caller it carries, with that caller's headers and binding
//! (`BridgeDispatcher.headers` / `.cache_binding`).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};

use super::{BridgeDispatcher, MetaMcp};
use crate::backend::{Backend, BackendRegistry, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::input_bridge::{BackendInvoker, BridgeError};
use crate::gateway::meta_mcp::InvokeScope;
use crate::gateway::router::CallerStanding;
use crate::identity_propagation::{
    CallerProof, IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::{JsonRpcResponse, RequestId};

/// One `PerUser` slot's wire: counts `tools/list` and `tools/call` and keeps
/// each list's headers.
#[derive(Default)]
struct Slot {
    lists: AtomicUsize,
    calls: AtomicUsize,
    list_headers: Mutex<Vec<Vec<(String, String)>>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Slot {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let permission = crate::transport::ResendPermission::Permitted;
        self.request_with_headers(method, params, &[], None, permission)
            .await
    }

    async fn request_with_headers(
        &self,
        method: &str,
        _params: Option<Value>,
        extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        let result = if method == "tools/list" {
            self.lists.fetch_add(1, Ordering::SeqCst);
            self.list_headers.lock().push(extra_headers.to_vec());
            json!({"tools": [{"name": "edit", "inputSchema":
                {"type": "object", "properties": {"edits": {"type": "array"}}}}]})
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            json!({"content": []})
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

/// F13-T9c: a bridged round on beta's cold `PerUser` slot, carrying beta's
/// minted header and binding. The round's check lists beta's own slot once,
/// with beta's header, and refuses the undeclared key before dispatch;
/// alpha's slot and the shared one see nothing. Red on base: the bridged
/// check never fetches, so the round forwards the call. Mutant M8b (drop
/// `.headers` or `.cache_binding` at the bridged check) reddens it.
#[tokio::test]
async fn f13_t9c_a_bridged_round_fills_as_its_own_caller() {
    let config = BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "edits".to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "edits",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let (shared, alpha, beta) = (
        Arc::new(Slot::default()),
        Arc::new(Slot::default()),
        Arc::new(Slot::default()),
    );
    backend.set_transport_for_test(Arc::clone(&shared) as Arc<dyn crate::transport::Transport>);
    for (binding, wire) in [("alpha@edits", &alpha), ("beta@edits", &beta)] {
        let key = PoolKey::PerUser {
            binding: binding.to_owned(),
        };
        let wire = Arc::clone(wire) as Arc<dyn crate::transport::Transport>;
        backend.set_pooled_transport_for_test(&key, wire);
    }
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend));
    let meta = MetaMcp::new(registry);

    let arguments = json!({"edits": [], "zzextra": 1});
    let headers = vec![(
        "Authorization".to_owned(),
        "Bearer minted-for-beta".to_owned(),
    )];
    let round = BridgeDispatcher {
        meta: &meta,
        server: "edits",
        tool: "edit",
        arguments: &arguments,
        prompt_cache_key: None,
        inbound_meta: None,
        want_full: false,
        session_id: None,
        caller_identity: None,
        caller_proof: CallerProof::Anonymous,
        headers: &headers,
        cache_binding: Some("beta@edits"),
        account_credential: None,
        api_key_name: None,
        trace_id: "f13-t9c",
        policy_epoch: 0,
        protocol_revision: None,
        routing_profile: "default",
        scope: InvokeScope::allow_all(CallerStanding::Standard),
    };
    let outcome = round.invoke(json!({})).await;
    match outcome {
        Err(BridgeError::NotAdmitted { message }) => {
            assert!(message.contains("zzextra"), "{message}");
        }
        other => panic!("the bridged round was not refused: {other:?}"),
    }
    assert_eq!(
        beta.lists.load(Ordering::SeqCst),
        1,
        "beta's slot was not listed"
    );
    let sent = beta.list_headers.lock().clone();
    let as_beta = sent[0]
        .iter()
        .any(|(n, v)| n == "Authorization" && v == "Bearer minted-for-beta");
    assert!(as_beta, "the fill did not carry beta's header: {sent:?}");
    let elsewhere = alpha.lists.load(Ordering::SeqCst) + shared.lists.load(Ordering::SeqCst);
    let dispatched = [&shared, &alpha, &beta]
        .iter()
        .map(|s| s.calls.load(Ordering::SeqCst))
        .sum::<usize>();
    assert_eq!((elsewhere, dispatched), (0, 0));
}
