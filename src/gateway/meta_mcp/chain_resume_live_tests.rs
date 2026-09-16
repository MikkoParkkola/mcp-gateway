// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7212.MRTR.12 — the resume half of a chain interim stop, against a live
//! backend transport.
//!
//! Design: `docs/design/2026-09-16-mrtr-12-chain-interim-stop.md` §"Revision 2".
//!
//! Revision 1 shipped the stop and is pinned by rows that hand-build the
//! envelope. Nothing there drives a resume, so the defect these rows exist for
//! — the redeemed answers never reaching the step that asked — was invisible
//! to a green suite. These rows drive the real entry point instead, so what
//! they pin is the behaviour a client sees.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::RequestId;
use crate::transport::Transport;

static ALLOW_ALL: AllowAll = AllowAll;

/// A backend that asks a question the first time `ask` is called and answers
/// plainly ever after.
///
/// Every `tools/call` it receives is recorded whole, so a row can ask what the
/// gateway actually sent rather than what it reported sending.
#[derive(Default)]
struct AsksOnce {
    calls: Mutex<Vec<Value>>,
}

impl AsksOnce {
    /// The recorded `params` of every `tools/call`, in order.
    fn calls(&self) -> Vec<Value> {
        self.calls.lock().expect("stub lock").clone()
    }
}

#[async_trait::async_trait]
impl Transport for AsksOnce {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let params = params.unwrap_or(Value::Null);
        if method == "tools/call" {
            self.calls.lock().expect("stub lock").push(params.clone());
        }
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let answered = params.get("inputResponses").is_some();
        let result = if name == "ask" && !answered {
            json!({
                "resultType": "input_required",
                "inputRequests": {
                    "q1": {"method": "elicitation/create", "params": {"message": "which?"}}
                },
                "requestState": "backend-state-1"
            })
        } else {
            json!({"content": [{"type": "text", "text": name}], "isError": false})
        };
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            result,
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

/// A gateway over one backend whose transport is `stub`.
fn meta_over(stub: Arc<AsksOnce>) -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "srv",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    ));
    backend.set_transport_for_test(stub);
    let _ = registry.register(backend);
    MetaMcp::new(registry)
}

/// An identity for the caller.
///
/// Not decoration: `mint_continuation` refuses to mint without a principal
/// fingerprint, so a caller without one can never be stopped at all.
fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "user-1".to_string(),
        email: "user@example.test".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example.test".to_string(),
    }
}

/// A caller that declared elicitation and carries an identity — the two things
/// a continuation needs to exist. `retry` is substituted per call.
fn resuming_ctx<'a>(
    who: &'a VerifiedIdentity,
    caps: &'a crate::protocol::meta::Declared,
    retry: &'a crate::protocol::mrtr::RetryFields,
) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        signing: None,
        execution: None,
        credential_principal: None,
        is_modern: true,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        api_key_name: Some("test-caller"),
        agent_id: None,
        grant_subject: None,
        verified_identity: Some(who),
        is_admin: false,
        input_capabilities: *caps,
        retry,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        task: None,
        era: crate::protocol::meta::Era::Modern,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

/// The declared capabilities of a client that can answer an elicitation.
fn elicitation_caps() -> crate::protocol::meta::Declared {
    crate::protocol::meta::Declared::from_handshake(Some(&json!({"elicitation": {}})))
}

/// The first `requestState` reachable in a response, including inside a text
/// block that carries JSON — which is where a tool result puts it.
fn request_state_in(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(state)) = map.get("requestState") {
                return Some(state.clone());
            }
            map.values().find_map(request_state_in)
        }
        Value::Array(items) => items.iter().find_map(request_state_in),
        Value::String(text) => serde_json::from_str::<Value>(text)
            .ok()
            .as_ref()
            .and_then(request_state_in),
        _ => None,
    }
}

/// The two-step chain these rows drive: a step that asks, then one that must
/// not run until it is answered.
fn chain() -> Value {
    json!([
        {"tool": "srv:ask", "arguments": {}},
        {"tool": "srv:after", "arguments": {}}
    ])
}

#[tokio::test]
async fn mrtr_12_resume_applies_the_answers_to_the_pending_step() {
    let stub = Arc::new(AsksOnce::default());
    let meta = meta_over(Arc::clone(&stub));
    let who = identity();
    let caps = elicitation_caps();

    // GIVEN: a chain whose first step asks the client a question.
    let stop = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_execute",
        json!({"chain": chain()}),
        None,
        resuming_ctx(&who, &caps, &crate::protocol::mrtr::NO_RETRY),
    ))
    .await;
    let stop_json = serde_json::to_value(&stop).expect("response is JSON");
    let handle = request_state_in(&stop_json)
        .unwrap_or_else(|| panic!("the stop publishes a resume handle; got {stop_json}"));

    // WHEN: the caller comes back with the answers, against that handle.
    let retry = crate::protocol::mrtr::RetryFields {
        request_state: Some(handle),
        input_responses: Some(json!({"q1": {"action": "accept", "content": {"pick": "b"}}})),
        ..Default::default()
    };
    let resumed = Box::pin(meta.handle_tools_call(
        RequestId::Number(2),
        "gateway_execute",
        json!({"chain": chain()}),
        None,
        resuming_ctx(&who, &caps, &retry),
    ))
    .await;
    let resumed_json = serde_json::to_value(&resumed).expect("response is JSON");

    // THEN: the step that asked was re-invoked carrying both the answers and
    // the backend's own state — not asked the same question a second time.
    let asks: Vec<Value> = stub
        .calls()
        .into_iter()
        .filter(|params| params.get("name").and_then(Value::as_str) == Some("ask"))
        .collect();
    assert_eq!(
        asks.len(),
        2,
        "the pending step runs once more, not more; resume said {resumed_json}"
    );
    let resumed_call = &asks[1];
    assert!(
        resumed_call.get("inputResponses").is_some(),
        "the answers must reach the step that asked for them; got {resumed_call}"
    );
    assert_eq!(
        resumed_call.get("requestState").and_then(Value::as_str),
        Some("backend-state-1"),
        "the backend's own state must travel back with them"
    );
}
