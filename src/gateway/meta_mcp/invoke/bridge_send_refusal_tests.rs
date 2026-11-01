// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A bridged round refused at its send (the per-user lender's refusal shape,
//! -32001) ends the legacy client's call as that refusal, never as the
//! bridge's generic "exchange could not be completed".

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::input_bridge::{ClientChannel, DeliveryError};
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::protocol::RequestId;
use crate::transport::Transport;

/// Lists `book`; the first `tools/call` asks for input, every later one is
/// refused at its send as the per-user lender refuses it.
struct AsksThenRefused {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Transport for AsksThenRefused {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({"tools": [{"name": "book", "inputSchema": {"type": "object"}}]})
        } else if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            json!({
                "resultType": "input_required",
                "inputRequests": {"k1": {"method": "elicitation/create",
                    "params": {"message": "Which account?", "requestedSchema": {"type": "object", "properties": {}}}}},
                "requestState": "s1"
            })
        } else {
            return Err(crate::Error::Forbidden {
                code: -32001,
                status: 403,
                message: "per-user send refused: this credential was refused".to_string(),
            });
        };
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
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

/// A client that accepts every question at once.
struct Accepting;

#[async_trait::async_trait]
impl ClientChannel for Accepting {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> Result<Value, DeliveryError> {
        Ok(json!({"jsonrpc": "2.0", "result": {"action": "accept", "content": {}}}))
    }
}

#[tokio::test]
async fn a_bridged_round_refused_at_its_send_ends_as_that_refusal() {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "asker",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(AsksThenRefused {
        calls: Arc::clone(&calls),
    }));
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);
    let meta = MetaMcp::new(registry);
    let channel = Accepting;
    let mut caller = ctx(&AllowAll);
    caller.era = crate::protocol::meta::Era::Legacy;
    caller.input_capabilities = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}},
        }})),
        None,
    )
    .declared_capabilities();
    caller.channel = &channel;
    let args = json!({"server": "asker", "tool": "book", "arguments": {}});
    let answer = meta
        .invoke_tool(&args, Some("session-bridge-refusal"), &caller)
        .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "premise: round two reached its send: {answer:?}"
    );
    match answer {
        Err(crate::Error::Forbidden { code: -32001, .. }) => {}
        other => panic!("the round's refusal, not the bridge's -32003: {other:?}"),
    }
}
