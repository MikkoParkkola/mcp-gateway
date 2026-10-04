// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance tests for MRTR.7 — bridging a modern backend's questions to a
//! legacy client.
//!
//! One test per row of the MRTR.7 block in
//! `docs/requirements/RELEASE-4.0.0-test-plan.md`. Each is named for the row it
//! proves and fails, before the bridge exists, on the assertion that names the
//! behaviour rather than on a missing symbol.

use mcp_gateway::gateway::input_bridge::{ServerRequestKind, is_bridge_reply_id};

/// Row 310 — the wire method and the pending-id prefix of every relayed
/// request, against literals written here, and the ingress gate admitting
/// exactly those prefixes.
///
/// The literals are spelled out rather than read back off the enum on purpose.
/// Two sets both derived from the type under test agree with each other however
/// that type drifts, so a test written that way cannot see the drift it exists
/// to catch: a kind minted on the outbound side and missing on the inbound side
/// fails as a caller timeout, far from the enum that caused it.
#[test]
fn ac_mrtr_7a_wire_methods_and_id_prefixes_match_the_admitted_set() {
    // The set itself first. The loop below runs over `ALL`, so an `ALL` that
    // repeats one variant and omits another passes every assertion in it while
    // the omitted kind is minted with a prefix nothing admits.
    for kind in [
        ServerRequestKind::Sampling,
        ServerRequestKind::Elicitation,
        ServerRequestKind::Roots,
    ] {
        assert_eq!(
            ServerRequestKind::ALL
                .iter()
                .filter(|&&k| k == kind)
                .count(),
            1,
            "{kind:?} must appear in ALL exactly once"
        );
    }

    // Every kind, matched explicitly. A wildcard arm would let a fourth variant
    // arrive with no method and no prefix asserted at all.
    for kind in ServerRequestKind::ALL {
        let (method, prefix) = match kind {
            ServerRequestKind::Sampling => ("sampling/createMessage", "sampling-"),
            ServerRequestKind::Elicitation => ("elicitation/create", "elicitation-"),
            ServerRequestKind::Roots => ("roots/list", "roots-"),
        };
        assert_eq!(kind.method(), method, "wire method for {kind:?}");
        assert_eq!(kind.prefix(), prefix, "pending-id prefix for {kind:?}");
    }

    // The admitted set, against the same literals. `roots-` is the one that
    // fails today: the shipped ingress condition knows two prefixes and the
    // bridge mints three.
    for prefix in ["sampling-", "elicitation-", "roots-"] {
        assert!(
            is_bridge_reply_id(&format!("{prefix}7")),
            "ingress gate must admit a reply id under {prefix}"
        );
    }

    // And nothing else. An over-wide gate routes another subsystem's reply into
    // the bridge's pending map, where it resolves a request nobody asked.
    for foreign in ["", "sampling", "roots", "proxy-7", "elicitation"] {
        assert!(
            !is_bridge_reply_id(foreign),
            "ingress gate must not admit {foreign:?}"
        );
    }
}

// ── fixtures ─────────────────────────────────────────────────────────────────

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};

use mcp_gateway::gateway::input_bridge::{
    BackendInvoker, BridgeBounds, BridgeError, BridgeObserver, BridgeRecord, ChallengeGate,
    ClientChannel, DeliveryError, InputBridge, NoClientChannel, OpenChallengeGate,
};
use mcp_gateway::protocol::meta::{Declared, classify_request};
use mcp_gateway::protocol::mrtr::{InputRequired, Refusal};

/// One request the gateway put on the wire, as the client would have seen it.
#[derive(Debug, Clone)]
struct Frame {
    session: String,
    id: String,
    method: String,
    params: Option<Value>,
}

/// What the fake client does when it is asked.
enum Reply {
    /// Answer immediately with this raw JSON-RPC envelope.
    Now(Value),
    /// Answer with this envelope after waiting.
    After(Duration, Value),
    /// Accept, with content naming the params the request carried.
    ///
    /// Positional scripts cannot answer a batch: prompt order is unspecified,
    /// so a script cannot say which answer belongs to which key. An echo makes
    /// each answer derivable from its own question and the correlation
    /// assertable however the batch was ordered.
    Echo,
    /// Never answer. The bridge's own bound is what must end the wait, so the
    /// fixture waits far past every bound rather than timing itself out.
    Silent,
}

/// A client that records what it was asked and answers from a script.
struct FakeClient {
    frames: Mutex<Vec<Frame>>,
    replies: Mutex<VecDeque<Reply>>,
}

impl FakeClient {
    fn new(replies: Vec<Reply>) -> Self {
        Self {
            frames: Mutex::new(Vec::new()),
            replies: Mutex::new(replies.into()),
        }
    }

    /// A client that is never expected to be asked anything.
    fn mute() -> Self {
        Self::new(Vec::new())
    }

    fn frames(&self) -> Vec<Frame> {
        self.frames.lock().expect("frames").clone()
    }

    fn methods(&self) -> Vec<String> {
        self.frames().into_iter().map(|f| f.method).collect()
    }
}

#[async_trait::async_trait]
impl ClientChannel for FakeClient {
    async fn send_request(
        &self,
        session_id: &str,
        id: &str,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, DeliveryError> {
        self.frames.lock().expect("frames").push(Frame {
            session: session_id.to_string(),
            id: id.to_string(),
            method: method.to_string(),
            params: params.clone(),
        });
        let reply = self.replies.lock().expect("replies").pop_front();
        match reply {
            Some(Reply::Now(envelope)) => Ok(envelope),
            Some(Reply::Echo) => Ok(json!({
                "jsonrpc": "2.0",
                "result": {"action": "accept", "content": {"echo": params}},
            })),
            Some(Reply::After(delay, envelope)) => {
                tokio::time::sleep(delay).await;
                Ok(envelope)
            }
            // An unscripted prompt is a silent one: a script that ran out means
            // the bridge asked more than the row said it would, and the row's
            // own bound is what should say so.
            None | Some(Reply::Silent) => {
                tokio::time::sleep(Duration::from_secs(86_400)).await;
                Err(DeliveryError::NoSession)
            }
        }
    }
}

/// A backend that records how it was retried and answers from a script.
struct FakeBackend {
    calls: Mutex<Vec<Value>>,
    results: Mutex<VecDeque<Value>>,
}

impl FakeBackend {
    fn new(results: Vec<Value>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            results: Mutex::new(results.into()),
        }
    }

    /// A backend that must not be re-invoked at all.
    fn never() -> Self {
        Self::new(Vec::new())
    }

    fn calls(&self) -> Vec<Value> {
        self.calls.lock().expect("calls").clone()
    }
}

#[async_trait::async_trait]
impl BackendInvoker for FakeBackend {
    async fn invoke(&self, retry_params: Value) -> Result<Value, BridgeError> {
        self.calls.lock().expect("calls").push(retry_params);
        Ok(self
            .results
            .lock()
            .expect("results")
            .pop_front()
            .unwrap_or_else(completed))
    }
}

/// Everything the bridge observed.
#[derive(Default)]
struct Records(Mutex<Vec<BridgeRecord>>);

impl Records {
    fn all(&self) -> Vec<BridgeRecord> {
        self.0.lock().expect("records").clone()
    }
}

impl BridgeObserver for Records {
    fn record(&self, record: BridgeRecord) {
        self.0.lock().expect("records").push(record);
    }
}

// ── builders ─────────────────────────────────────────────────────────────────

/// A completed tool result — anything without `resultType: input_required`.
fn completed() -> Value {
    json!({"content": [{"type": "text", "text": "done"}]})
}

/// One `inputRequests` entry.
fn entry(method: &str, params: &Value) -> Value {
    json!({"method": method, "params": params})
}

/// An interim result carrying these entries under these keys.
fn interim(entries: &[(&str, Value)]) -> InputRequired {
    InputRequired {
        requests: entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect(),
        request_state: Some("state-1".to_string()),
    }
}

/// A client reply accepting with this content.
fn accepted(content: &Value) -> Reply {
    Reply::Now(json!({"jsonrpc": "2.0", "result": {"action": "accept", "content": content}}))
}

/// A client reply whose `result` is the given value verbatim.
fn result(value: &Value) -> Reply {
    Reply::Now(json!({"jsonrpc": "2.0", "result": value}))
}

/// What a client declared at `initialize`, parsed by the gateway's own reader.
fn declared(capabilities: &Value) -> Declared {
    classify_request(
        Some(&json!({"_meta": {
            mcp_gateway::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            mcp_gateway::protocol::meta::KEY_CLIENT_CAPABILITIES: capabilities,
        }})),
        None,
    )
    .declared_capabilities()
}

/// A client that declared every capability, in both elicitation modes.
fn declared_all() -> Declared {
    declared(&json!({
        "sampling": {},
        "roots": {},
        "elicitation": {"form": {}, "url": {}},
    }))
}

/// The session every test bridges on.
const SESSION: &str = "session-mrtr7";

/// Drive one bridged call with the shipped bounds.
async fn bridge(
    client: &FakeClient,
    backend: &FakeBackend,
    records: &Records,
    caps: Declared,
    slice: Option<&[String]>,
    first: &InputRequired,
) -> Result<Value, BridgeError> {
    bridge_with(
        client,
        backend,
        records,
        caps,
        slice,
        first,
        BridgeBounds::DEFAULT,
    )
    .await
}

/// Drive one bridged call with explicit bounds.
async fn bridge_with(
    client: &FakeClient,
    backend: &FakeBackend,
    records: &Records,
    caps: Declared,
    slice: Option<&[String]>,
    first: &InputRequired,
    bounds: BridgeBounds,
) -> Result<Value, BridgeError> {
    InputBridge {
        channel: client,
        backend,
        gate: &OpenChallengeGate,
        observer: records,
        bounds,
    }
    .run(SESSION, caps, slice, first)
    .await
}

/// Drive one bridged call under a policy gate, at the shipped bounds.
async fn bridge_gated(
    client: &FakeClient,
    backend: &FakeBackend,
    gate: &dyn ChallengeGate,
    records: &Records,
    caps: Declared,
    first: &InputRequired,
) -> Result<Value, BridgeError> {
    InputBridge {
        channel: client,
        backend,
        gate,
        observer: records,
        bounds: BridgeBounds::DEFAULT,
    }
    .run(SESSION, caps, None, first)
    .await
}

/// A backend result that asks again, under these keys.
///
/// The wire shape rather than [`interim`]'s parsed struct: `first` arrives
/// already parsed, but every later round arrives as whatever the backend's
/// `invoke` returned, so a row driving more than one round has to hand the
/// bridge the same bytes a real backend would.
fn asking(entries: &[(&str, Value)]) -> Value {
    let mut requests = serde_json::Map::new();
    for (key, value) in entries {
        requests.insert((*key).to_string(), value.clone());
    }
    json!({
        "resultType": "input_required",
        "inputRequests": requests,
        "requestState": "state-1",
    })
}

/// One elicitation entry carrying this message.
fn ask(message: &str) -> Value {
    entry(
        "elicitation/create",
        &json!({"mode": "form", "message": message}),
    )
}

/// `count` client replies, each accepting with the same content.
///
/// Built by iterator rather than `vec![_; n]` because [`Reply`] is not `Clone`.
fn accepts(count: usize, content: &Value) -> Vec<Reply> {
    (0..count).map(|_| accepted(content)).collect()
}

/// A marker only ever carried in the backend's opaque state.
const STATE_CANARY: &str = "OPAQUE-CANARY-7A";

/// A marker the gate below is configured to refuse.
const BLOCKED: &str = "BLOCKED-TOKEN-7A";

/// A gate that refuses any batch whose rendering carries `marker`, and keeps
/// every batch it was shown.
///
/// It records as well as refuses on purpose: a gate that only refuses cannot
/// tell "round two was inspected and admitted" from "round two was never
/// inspected", and that is the whole distinction the multi-round row exists to
/// make.
struct MarkerGate {
    marker: &'static str,
    inspected: Mutex<Vec<String>>,
}

impl MarkerGate {
    fn new(marker: &'static str) -> Self {
        Self {
            marker,
            inspected: Mutex::new(Vec::new()),
        }
    }

    fn inspected(&self) -> Vec<String> {
        self.inspected.lock().expect("inspected").clone()
    }
}

impl ChallengeGate for MarkerGate {
    fn admit(&self, challenge: &Value) -> Result<(), BridgeError> {
        let rendered = challenge.to_string();
        self.inspected
            .lock()
            .expect("inspected")
            .push(rendered.clone());
        if rendered.contains(self.marker) {
            return Err(BridgeError::ChallengeRefused { dispatched: false });
        }
        Ok(())
    }
}

#[path = "mik_7212_mrtr7_bridge_acs/mik_1990.rs"]
mod mik_1990;

#[path = "mik_7212_mrtr7_bridge_acs/cov3_run_branches.rs"]
mod cov3_run_branches;
#[path = "mik_7212_mrtr7_bridge/first_round.rs"]
mod first_round;
#[path = "mik_7212_mrtr7_bridge/last_round.rs"]
mod last_round;

#[path = "mik_7212_mrtr7_bridge_acs/answers.rs"]
mod answers;
#[path = "mik_7212_mrtr7_bridge_acs/bounds.rs"]
mod bounds;
#[path = "mik_7212_mrtr7_bridge_acs/client_delivery.rs"]
mod client_delivery;
#[path = "mik_7212_mrtr7_bridge_acs/policy_gate.rs"]
mod policy_gate;
#[path = "mik_7212_mrtr7_bridge_acs/removed_surface.rs"]
mod removed_surface;
