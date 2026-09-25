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

/// A backend that asks a question the first time each named tool is called and
/// answers plainly ever after.
///
/// Every `tools/call` it receives is recorded whole, so a row can ask what the
/// gateway actually sent rather than what it reported sending.
struct AsksOnce {
    calls: Mutex<Vec<Value>>,
    asking: Vec<&'static str>,
}

impl Default for AsksOnce {
    fn default() -> Self {
        Self::new(&["ask"])
    }
}

impl AsksOnce {
    /// A backend whose `asking` tools each stop once before answering.
    fn new(asking: &[&'static str]) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            asking: asking.to_vec(),
        }
    }

    /// The recorded `params` of every `tools/call`, in order.
    fn calls(&self) -> Vec<Value> {
        self.calls.lock().expect("stub lock").clone()
    }

    /// The recorded calls to one tool, in order.
    fn calls_to(&self, tool: &str) -> Vec<Value> {
        self.calls()
            .into_iter()
            .filter(|params| params.get("name").and_then(Value::as_str) == Some(tool))
            .collect()
    }

    /// Which tools ran, in order — what a chain actually executed.
    fn ran(&self) -> Vec<String> {
        self.calls()
            .iter()
            .filter_map(|params| params.get("name").and_then(Value::as_str))
            .map(str::to_owned)
            .collect()
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
        let result = if self.asking.contains(&name) && !answered {
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
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        is_modern: true,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        api_key_name: Some("test-caller"),
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        stdio_nonce: None,
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

/// One `gateway_execute` of the two-step chain, as JSON.
async fn execute(
    meta: &MetaMcp,
    id: i64,
    who: &VerifiedIdentity,
    caps: &crate::protocol::meta::Declared,
    retry: &crate::protocol::mrtr::RetryFields,
) -> Value {
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(id),
        "gateway_execute",
        json!({"chain": chain()}),
        None,
        resuming_ctx(who, caps, retry),
    ))
    .await;
    serde_json::to_value(&response).expect("response is JSON")
}

/// A caller coming back with an answer against `handle`.
fn answers(handle: &str) -> crate::protocol::mrtr::RetryFields {
    crate::protocol::mrtr::RetryFields {
        request_state: Some(handle.to_string()),
        input_responses: Some(json!({"q1": {"action": "accept", "content": {"pick": "b"}}})),
        ..Default::default()
    }
}

/// The resume handle a stop published, or a panic naming what it published
/// instead.
fn handle_in(response: &Value) -> String {
    request_state_in(response)
        .unwrap_or_else(|| panic!("the stop publishes a resume handle; got {response}"))
}

/// Every string anywhere in `value` that opens as one of this gateway's own
/// sealed envelopes — including inside a text block that carries JSON.
///
/// A response is allowed to carry exactly one: the handle the client is meant
/// to present back. Any second one is an envelope that leaked to the caller.
fn envelope_tokens(
    value: &Value,
    state: &crate::protocol::continuation::ContinuationState,
    now: u64,
) -> Vec<String> {
    match value {
        Value::Object(map) => map
            .values()
            .flat_map(|item| envelope_tokens(item, state, now))
            .collect(),
        Value::Array(items) => items
            .iter()
            .flat_map(|item| envelope_tokens(item, state, now))
            .collect(),
        Value::String(text) => {
            if state.keyring().open(text, now).is_ok() {
                return vec![text.clone()];
            }
            serde_json::from_str::<Value>(text)
                .ok()
                .map(|nested| envelope_tokens(&nested, state, now))
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

#[tokio::test]
async fn mrtr_12_a_stop_does_not_run_the_successor() {
    let stub = Arc::new(AsksOnce::default());
    let meta = meta_over(Arc::clone(&stub));
    let who = identity();
    let caps = elicitation_caps();

    let stop = execute(&meta, 1, &who, &caps, &crate::protocol::mrtr::NO_RETRY).await;

    // A stop suspends the chain. A successor that ran anyway would have acted
    // on an answer the caller has not given yet, and no later refusal can undo
    // a backend call that already happened.
    assert_eq!(
        stub.ran(),
        vec!["ask".to_string()],
        "the step after the one that asked must not run; stop said {stop}"
    );
}

#[tokio::test]
async fn mrtr_12_a_stop_publishes_exactly_one_envelope() {
    let stub = Arc::new(AsksOnce::default());
    let meta = meta_over(Arc::clone(&stub));
    let who = identity();
    let caps = elicitation_caps();

    let stop = execute(&meta, 1, &who, &caps, &crate::protocol::mrtr::NO_RETRY).await;

    // The step envelope minted for the pending step is the gateway's own
    // secret: it is bound to that step and redeemable. Publishing it next to
    // the chain handle would hand the caller a second, narrower key.
    let now = crate::protocol::continuation::now_unix_secs();
    let tokens = envelope_tokens(&stop, &meta.continuation(), now);
    assert_eq!(
        tokens.len(),
        1,
        "a stop hands back one handle and no other envelope; got {tokens:?} in {stop}"
    );
    assert_eq!(
        tokens.first().map(String::as_str),
        request_state_in(&stop).as_deref(),
        "the one envelope published is the handle the caller presents back"
    );
}

#[tokio::test]
async fn mrtr_12_a_second_stop_keeps_the_first_deadline_and_counts_the_round() {
    let stub = Arc::new(AsksOnce::new(&["ask", "after"]));
    let meta = meta_over(Arc::clone(&stub));
    let who = identity();
    let caps = elicitation_caps();
    let now = crate::protocol::continuation::now_unix_secs();

    // GIVEN: a chain that stops at step 0, resumed.
    let first = execute(&meta, 1, &who, &caps, &crate::protocol::mrtr::NO_RETRY).await;
    let first_payload = meta
        .continuation()
        .keyring()
        .open(&handle_in(&first), now)
        .expect("the first handle is this gateway's own envelope");

    // WHEN: the answered step completes and the next one asks in its turn.
    let second = execute(&meta, 2, &who, &caps, &answers(&handle_in(&first))).await;
    let second_payload = meta
        .continuation()
        .keyring()
        .open(&handle_in(&second), now)
        .expect("the second handle is this gateway's own envelope");

    // THEN: the second question is the next step's, and the exchange has spent
    // a round for each stop. The deadline is checked where it is observable,
    // in `mrtr_12_a_later_stop_keeps_the_exchange_deadline`.
    assert_eq!(
        second_payload.next_step,
        Some(1),
        "the second stop is pending at the step that asked second"
    );
    assert_eq!(
        (first_payload.rounds_used, second_payload.rounds_used),
        (1, 2),
        "each stop spends one of the exchange's interim rounds"
    );

    // AND: the answers reach the step that asked second, not the first one.
    let resumed = execute(&meta, 3, &who, &caps, &answers(&handle_in(&second))).await;
    let after = stub.calls_to("after");
    assert_eq!(
        after.len(),
        2,
        "the second pending step runs once more; resume said {resumed}"
    );
    assert!(
        after[1].get("inputResponses").is_some(),
        "the answers must reach the step that asked for them; got {}",
        after[1]
    );
    assert_eq!(
        after[1].get("requestState").and_then(Value::as_str),
        Some("backend-state-1"),
        "the backend's own state must travel back with them"
    );
    assert_eq!(
        stub.ran(),
        vec!["ask", "ask", "after", "after"],
        "every step runs exactly twice: once asking, once answered"
    );
}

#[tokio::test]
async fn mrtr_12_a_chain_handle_is_spent_by_the_resume_it_plans() {
    let stub = Arc::new(AsksOnce::default());
    let meta = meta_over(Arc::clone(&stub));
    let who = identity();
    let caps = elicitation_caps();

    let stop = execute(&meta, 1, &who, &caps, &crate::protocol::mrtr::NO_RETRY).await;
    let handle = handle_in(&stop);
    let first = execute(&meta, 2, &who, &caps, &answers(&handle)).await;
    assert!(
        first.get("error").is_none(),
        "the first resume is the one the handle was minted for; got {first}"
    );

    // A replayed handle is a second exchange bought with one stop's
    // authorisation. The ledger, not the caller, decides a handle is spent.
    let replay = execute(&meta, 3, &who, &caps, &answers(&handle)).await;
    assert!(
        replay.get("error").is_some(),
        "presenting a spent chain handle again must be refused; got {replay}"
    );
    assert_eq!(
        stub.calls_to("ask").len(),
        2,
        "a refused replay must not reach the backend a third time"
    );
}

/// A chain handle the gateway itself would have minted, with a deadline chosen
/// so that a later seal which re-armed it is visible.
///
/// Hand-built because the deadline is the one fact two live stops cannot
/// disagree about: both mint within the same second, so an exchange that
/// re-armed its expiry on every stop reads identically to one that froze it.
async fn handle_expiring_at(meta: &MetaMcp, expires_at: u64, now: u64) -> String {
    let state = meta.continuation();
    let hold = state
        .in_flight()
        .hold("srv", expires_at, now)
        .await
        .expect("the in-flight table has room for one exchange");
    let mut payload = crate::protocol::continuation::Payload::mint(
        "srv".into(),
        Some("backend-state-1".into()),
        crate::protocol::mrtr::principal_fingerprint(Some(&identity()))
            .expect("the caller has a fingerprint"),
        super::chain_interim::chain_digest(chain().as_array().expect("the chain is an array")),
        "replica-a".into(),
        hold,
        now,
    )
    .with_purpose(crate::protocol::continuation::ContinuationPurpose::ChainResume);
    payload.next_step = Some(0);
    payload.expires_at = expires_at;
    state.keyring().mint(&payload).expect("mint")
}

#[tokio::test]
async fn mrtr_12_a_later_stop_keeps_the_exchange_deadline() {
    let stub = Arc::new(AsksOnce::new(&["ask", "after"]));
    let meta = meta_over(Arc::clone(&stub));
    let who = identity();
    let caps = elicitation_caps();
    let now = crate::protocol::continuation::now_unix_secs();
    let deadline = now + 11;

    // GIVEN: an exchange already stopped once, with a deadline of its own.
    let handle = handle_expiring_at(&meta, deadline, now).await;

    // WHEN: the answered step completes and the next one asks in its turn.
    let second = execute(&meta, 1, &who, &caps, &answers(&handle)).await;

    // THEN: the new question inherits the deadline the exchange opened with. A
    // stop that re-armed it would let a caller hold an exchange open forever by
    // answering slowly, which is the bound the deadline exists to impose.
    let payload = meta
        .continuation()
        .keyring()
        .open(&handle_in(&second), now)
        .expect("the second handle is this gateway's own envelope");
    assert_eq!(
        payload.next_step,
        Some(1),
        "the second stop is pending at the step that asked second"
    );
    assert_eq!(
        payload.expires_at, deadline,
        "a later stop extended the deadline the exchange opened with"
    );
}
