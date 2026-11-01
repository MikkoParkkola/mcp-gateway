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
    let answer = bridged_invoke(backend, &Accepting).await;
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

/// Invoke `asker`'s `book` as a legacy client that answers questions through
/// `channel`, so a backend asking for input is bridged.
async fn bridged_invoke(
    backend: Arc<Backend>,
    channel: &dyn ClientChannel,
) -> crate::Result<Value> {
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);
    let meta = MetaMcp::new(registry);
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
    caller.channel = channel;
    let args = json!({"server": "asker", "tool": "book", "arguments": {}});
    meta.invoke_tool(&args, Some("session-bridge-refusal"), &caller)
        .await
}

/// Lists `book` once; every later list is refused at its send as the
/// per-user lender refuses it. The first `tools/call` asks for input.
struct AsksThenListRefused {
    lists: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Transport for AsksThenListRefused {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            if self.lists.fetch_add(1, Ordering::SeqCst) > 0 {
                return Err(lend_refusal());
            }
            json!({"tools": [{"name": "book", "inputSchema": {"type": "object"}}]})
        } else if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            json!({
                "resultType": "input_required",
                "inputRequests": {"k1": {"method": "elicitation/create",
                    "params": {"message": "Which account?", "requestedSchema": {"type": "object", "properties": {}}}}},
                "requestState": "s1"
            })
        } else {
            json!({"content": [{"type": "text", "text": "booked"}]})
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

/// A client that accepts every question, after emptying the backend's
/// catalogues: round two's key check then fills its slot cold.
struct EmptiesThenAccepts {
    backend: Arc<Backend>,
}

#[async_trait::async_trait]
impl ClientChannel for EmptiesThenAccepts {
    async fn send_request(
        &self,
        session_id: &str,
        id: &str,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, DeliveryError> {
        self.backend.empty_tool_catalogues_for_test();
        Accepting.send_request(session_id, id, method, params).await
    }
}

/// M5 (`bridged_refused_fill`): round two's cold fill refused at its send
/// by the lender ends the exchange as that refusal, and no `tools/call` is
/// sent after it.
#[tokio::test]
async fn a_bridged_rounds_cold_fill_refused_at_its_send_ends_as_that_refusal() {
    let (lists, calls) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let backend = Arc::new(Backend::new(
        "asker",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(AsksThenListRefused {
        lists: Arc::clone(&lists),
        calls: Arc::clone(&calls),
    }));
    let channel = EmptiesThenAccepts {
        backend: Arc::clone(&backend),
    };
    let answer = bridged_invoke(backend, &channel).await;
    assert_eq!(
        lists.load(Ordering::SeqCst),
        2,
        "premise: round two filled its emptied slot: {answer:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no tools/call after the refused fill: {answer:?}"
    );
    match answer {
        Err(crate::Error::Forbidden { code: -32001, .. }) => {}
        other => panic!("the fill's refusal, not the bridge's -32003: {other:?}"),
    }
}

/// Lists `book`, and refuses every `tools/call` at its send as the per-user
/// lender does, counting each call that reached the send.
struct RefusedAtSend {
    calls: Arc<AtomicUsize>,
}

fn lend_refusal() -> crate::Error {
    crate::Error::Forbidden {
        code: -32001,
        status: 403,
        message: "per-user send refused: this credential was refused".to_string(),
    }
}

#[async_trait::async_trait]
impl Transport for RefusedAtSend {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/list" {
            return Ok(crate::protocol::JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({"tools": [{"name": "book", "inputSchema": {"type": "object"}}]}),
            ));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(lend_refusal())
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

/// One `gateway_invoke` of `book` on a backend that refuses its call at the
/// send; the answer and the calls that reached the send.
async fn invoke_refused() -> (crate::Result<Value>, usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "refused",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(RefusedAtSend {
        calls: Arc::clone(&calls),
    }));
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);
    let meta = MetaMcp::new(registry);
    let caller = ctx(&AllowAll);
    let args = json!({"server": "refused", "tool": "book", "arguments": {}});
    let answer = meta.invoke_tool(&args, None, &caller).await;
    (answer, calls.load(Ordering::SeqCst))
}

/// The first dispatch's fold site: a call refused at its send is answered as
/// that refusal, and was sent exactly once (nothing retried it).
#[tokio::test]
async fn a_dispatch_refused_at_its_send_is_that_refusal_sent_once() {
    let (answer, calls) = invoke_refused().await;
    assert_eq!(
        calls, 1,
        "the refused call reached its send once: {answer:?}"
    );
    match answer {
        Err(crate::Error::Forbidden { code: -32001, .. }) => {}
        other => panic!("the send's refusal, not a folded result: {other:?}"),
    }
}

/// Answers `tools/call` with a backend's own -32001: in band when `in_band`,
/// else as the transport's error (`peer_refusal` builds a backend's 4xx so).
struct BackendRefuses {
    in_band: bool,
}

#[async_trait::async_trait]
impl Transport for BackendRefuses {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/list" {
            return Ok(crate::protocol::JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({"tools": [{"name": "book", "inputSchema": {"type": "object"}}]}),
            ));
        }
        if self.in_band {
            return Ok(crate::protocol::JsonRpcResponse::error(
                Some(RequestId::Number(1)),
                -32001,
                "the backend's own denial",
            ));
        }
        Err(crate::Error::JsonRpc {
            code: -32001,
            message: "the backend's own denial".to_string(),
            data: None,
        })
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

/// A backend's own -32001 is the backend's answer, not the gateway's
/// refusal of the caller: still folded into an error result, and still
/// sampled against the backend's error budget (it cannot exempt itself).
async fn assert_backend_refusal_stays_the_backends(in_band: bool) {
    let backend = Arc::new(Backend::new(
        "denies",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(BackendRefuses { in_band }));
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);
    let meta = MetaMcp::new(registry);
    let caller = ctx(&AllowAll);
    let args = json!({"server": "denies", "tool": "book", "arguments": {}});
    let answer = meta.invoke_tool(&args, None, &caller).await;
    let Ok(value) = &answer else {
        panic!("a backend's denial is a folded result, not a gateway refusal: {answer:?}");
    };
    assert_eq!(value["isError"], true, "{value}");
    assert!(
        value.to_string().contains("the backend's own denial"),
        "premise: the backend's denial: {value}"
    );
    assert_eq!(
        meta.kill_switch.window_counts("denies"),
        (0, 1),
        "sampled as the backend's failure"
    );
}

#[tokio::test]
async fn a_backends_in_band_denial_stays_the_backends() {
    assert_backend_refusal_stays_the_backends(true).await;
}

#[tokio::test]
async fn a_backends_transport_denial_stays_the_backends() {
    assert_backend_refusal_stays_the_backends(false).await;
}

/// `meta` over one backend, `refused`, whose call is refused at its send,
/// with a one-step playbook `plan` on it; and the calls that reached the send.
fn refused_plan_meta() -> (MetaMcp, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "refused",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(RefusedAtSend {
        calls: Arc::clone(&calls),
    }));
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);
    let meta = MetaMcp::new(registry);
    let mut engine = crate::playbook::PlaybookEngine::new();
    let definition = json!({
        "playbook": "1.0", "name": "plan", "description": "one step",
        "steps": [{"name": "only", "server": "refused", "tool": "book", "arguments": {}}],
    });
    engine.register(serde_json::from_value(definition).expect("the playbook parses"));
    meta.set_playbook_engine(engine);
    (meta, calls)
}

/// A composite step refused at its send: sent exactly once (no strategy
/// resends it) and answered as a refusal, never as a backend error folded
/// into the plan. Returns the answer for the composite's own refusal shape.
async fn assert_step_refused_once(tool: &str, arguments: Value) -> Value {
    let (meta, calls) = refused_plan_meta();
    let answer = serde_json::to_value(
        Box::pin(meta.handle_tools_call(
            RequestId::Number(1),
            tool,
            arguments,
            None,
            ctx(&AllowAll),
        ))
        .await,
    )
    .expect("the answer is JSON");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the step reached its send once: {answer}"
    );
    assert!(
        !answer.to_string().contains("retrying once is safe"),
        "no retry is suggested: {answer}"
    );
    answer
}

#[tokio::test]
async fn a_playbook_step_refused_at_its_send_is_refused_once() {
    let answer = assert_step_refused_once("gateway_run_playbook", json!({"name": "plan"})).await;
    assert_eq!(
        answer["error"]["message"],
        crate::gateway::meta_mcp::STEP_NOT_PERMITTED,
        "the neutral step refusal: {answer}"
    );
}

#[tokio::test]
async fn a_chain_step_refused_at_its_send_is_refused_once() {
    let answer = assert_step_refused_once(
        "gateway_execute",
        json!({"chain": [{"tool": "refused:book", "arguments": {}}]}),
    )
    .await;
    // A chain names the refused step and keeps the refusal's own code
    // (`chain_exec::step_failure`).
    assert_eq!(answer["error"]["code"], -32001, "{answer}");
    let message = answer["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("Chain step 0 (refused:book) refused: "),
        "the chain's step refusal: {answer}"
    );
}

/// Whether the delivery cell still vouches for its answer when a step runs.
#[derive(Clone, Copy)]
enum Cell {
    Vouched,
    Unvouched,
}

/// The delivery effect a playbook step's send refusal records in a `cell`.
async fn step_refusal_effect(cell: Cell) -> serde_json::Map<String, Value> {
    crate::gateway::delivery_facts::scope(crate::playbook::in_step(0, async move {
        if matches!(cell, Cell::Unvouched) {
            crate::gateway::delivery_facts::unvouched();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(Backend::new(
            "refused",
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        backend.set_transport_for_test(Arc::new(RefusedAtSend {
            calls: Arc::clone(&calls),
        }));
        let registry = Arc::new(BackendRegistry::new());
        let _ = registry.register(backend);
        let meta = MetaMcp::new(registry);
        let caller = ctx(&AllowAll);
        let args = json!({"server": "refused", "tool": "book", "arguments": {}});
        let outcome = meta
            .invoke_tool_with_source(&args, None, &caller, "vouch".into())
            .await;
        assert!(
            matches!(&outcome, Err(crate::Error::Forbidden { code: -32001, .. })),
            "premise: the step was refused at its send: {:?}",
            outcome.as_ref().err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "premise: sent once");
        let mut fields = serde_json::Map::new();
        crate::gateway::delivery_facts::record_fields(
            crate::gateway::delivery_facts::snapshot().as_ref(),
            false,
            &mut fields,
        );
        fields
    }))
    .await
}

/// The vouch rule at the first dispatch's fold site: a playbook step refused
/// at its send records `refused` while the cell vouches for its answer, and
/// nothing once the composite has unvouched it (an absorbed step never marks
/// the composite's record).
#[tokio::test]
async fn a_step_refused_at_its_send_records_refused_only_while_vouched() {
    let vouched = step_refusal_effect(Cell::Vouched).await;
    assert_eq!(vouched["response_effect"], "refused", "{vouched:?}");
    let unvouched = step_refusal_effect(Cell::Unvouched).await;
    assert!(unvouched.get("response_effect").is_none(), "{unvouched:?}");
}

/// The parked arm's marked-account branch and its caller-refusal branch
/// (`legacy_bridge.rs`) take disjoint errors: a marked account refusal is a
/// JSON-RPC error carrying its account, never `Forbidden`, and a lend
/// refusal is `Forbidden`, never marked. So the branches' order cannot change
/// an answer, and a marked refusal keeps its connect offer.
#[test]
fn a_marked_refusal_and_a_lend_refusal_are_disjoint() {
    const TEXT: &str = "account is not connected";
    let marked = crate::personal_accounts::refusal::mark(
        crate::Error::Config(TEXT.to_string()),
        &crate::identity_propagation::PropagationError::AccountNotConnected(TEXT.to_string()),
        Some("work"),
    );
    assert!(
        crate::personal_accounts::refusal::marked(&marked).is_some(),
        "premise: a marked refusal: {marked:?}"
    );
    assert!(!super::gate::is_authorization_refusal(&marked));
    let lend = lend_refusal();
    assert!(super::gate::is_authorization_refusal(&lend));
    assert!(crate::personal_accounts::refusal::marked(&lend).is_none());
}
