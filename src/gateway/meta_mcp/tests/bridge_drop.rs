// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R23b(ii): a legacy in-band bridged exchange dropped after its second round
//! was sent keeps its idempotency key. The gateway asks the client itself and
//! re-dispatches inside one tools/call, so no client continuation receives
//! the key; stopping to ask does not prove the backend has not acted.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Every `tools/call` answers with the backend's question, counted.
struct AlwaysAsking(AtomicUsize);

#[async_trait::async_trait]
impl crate::transport::Transport for AlwaysAsking {
    async fn request(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        assert_eq!(method, "tools/call");
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({
                "resultType": "input_required",
                "inputRequests": {"k1": {
                    "method": "elicitation/create",
                    "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}
                }},
                "requestState": "state"
            }),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Answers the first question; on the second, signals and never answers.
struct ParksOnSecondAsk {
    asked: AtomicUsize,
    second: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl crate::gateway::input_bridge::ClientChannel for ParksOnSecondAsk {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<serde_json::Value>,
    ) -> std::result::Result<serde_json::Value, crate::gateway::input_bridge::DeliveryError> {
        if self.asked.fetch_add(1, Ordering::SeqCst) >= 1 {
            self.second.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(
            json!({"jsonrpc": "2.0", "result": {"action": "accept", "content": {"account": "work"}}}),
        )
    }
}

/// R23b(ii) (F14): the backend answered round two by asking again, the
/// bridge put that question to the client, and the call was dropped while it
/// waited. Round two reached the backend, so the key is kept, not released.
#[tokio::test]
async fn a_legacy_bridged_exchange_dropped_after_round_two_keeps_its_key() {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "asking_backend",
        crate::config::BackendConfig::r2_off(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport = Arc::new(AlwaysAsking(AtomicUsize::new(0)));
    backend.set_transport_for_test(transport.clone());
    let _ = registry.register(backend);
    let mut meta = MetaMcp::new(registry);
    let cache = Arc::new(crate::idempotency::IdempotencyCache::new());
    meta.enable_idempotency(Arc::clone(&cache), Duration::from_secs(300));
    let second = Arc::new(tokio::sync::Notify::new());
    let channel = ParksOnSecondAsk {
        asked: AtomicUsize::new(0),
        second: Arc::clone(&second),
    };
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("k-r23b-ii".to_string()),
        ..Default::default()
    };
    let mut ctx = allow_all_ctx();
    ctx.era = crate::protocol::meta::Era::Legacy;
    ctx.input_capabilities = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}}
        }})),
        None,
    )
    .declared_capabilities();
    ctx.channel = &channel;
    ctx.retry = &retry;
    let call = json!({"server": "asking_backend", "tool": "book", "arguments": {}});
    tokio::select! {
        outcome = crate::gateway::delivery_facts::scope(meta.invoke_tool(&call, Some("session-drop"), &ctx)) => {
            panic!("the exchange finished instead of waiting on the second question: {outcome:?}")
        }
        () = second.notified() => {}
    }
    assert_eq!(
        transport.0.load(Ordering::SeqCst),
        2,
        "premise: rounds one and two reached the backend"
    );
    assert!(
        !cache.is_empty(),
        "the dropped exchange released its key after round two was sent"
    );
}
