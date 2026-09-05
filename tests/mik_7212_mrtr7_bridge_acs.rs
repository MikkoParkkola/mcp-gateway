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

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};

use mcp_gateway::gateway::input_bridge::{
    BackendInvoker, BridgeBounds, BridgeError, BridgeObserver, BridgeRecord, ClientChannel,
    DeliveryError, InputBridge,
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
    async fn invoke(&self, retry_params: Value) -> Value {
        self.calls.lock().expect("calls").push(retry_params);
        self.results
            .lock()
            .expect("results")
            .pop_front()
            .unwrap_or_else(completed)
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
        observer: records,
        bounds,
    }
    .run(SESSION, caps, slice, first)
    .await
}

// ── MRTR.7a — what reaches the client ────────────────────────────────────────

/// Row 308 — a backend's elicitation params reach the client whole.
///
/// Asserted as one object equal to what the backend sent, not field by field:
/// a per-field assertion passes an implementation that also adds fields the
/// backend never wrote, and the client cannot tell the gateway's inventions
/// from the backend's request.
#[tokio::test]
async fn ac_mrtr_7a_elicitation_params_reach_the_client_whole() {
    let params = json!({
        "mode": "url",
        "message": "Authorise the deploy",
        "requestedSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}},
        "url": "https://example.test/authorise",
    });
    let client = FakeClient::new(vec![accepted(&json!({"ok": true}))]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k1", entry("elicitation/create", &params))]),
    )
    .await;
    assert!(outcome.is_ok(), "bridged call failed: {outcome:?}");

    let frames = client.frames();
    assert_eq!(frames.len(), 1, "one entry, one frame");
    assert_eq!(frames[0].method, "elicitation/create");
    assert_eq!(
        frames[0].session, SESSION,
        "asked on the caller's own session"
    );
    assert!(
        is_bridge_reply_id(&frames[0].id),
        "id {:?} must be one the ingress gate admits",
        frames[0].id
    );
    assert_eq!(
        frames[0].params.as_ref(),
        Some(&params),
        "params must equal the backend's, with nothing dropped and nothing invented"
    );
}

/// Row 309 — an entry naming a method outside the closed set is refused, and
/// nothing is sent.
///
/// Driven through the bridge rather than through `InputRequired::undeclared`,
/// which already answers `UnrecognisedMethod` today: a test calling that
/// directly is green before the bridge exists and proves nothing about what
/// reaches the client. The zero-frames half is the half that fails against a
/// bridge that forwards by method name.
#[tokio::test]
async fn ac_mrtr_7a_a_method_outside_the_closed_set_is_refused_unsent() {
    let client = FakeClient::mute();
    let backend = FakeBackend::never();
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k1", entry("tools/call", &json!({"name": "rm"})))]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Refused {
            key: "k1".to_string(),
            reason: Refusal::UnrecognisedMethod,
        }),
    );
    assert!(
        client.frames().is_empty(),
        "nothing may be sent: {:?}",
        client.methods()
    );
    assert!(backend.calls().is_empty(), "backend must not be retried");
}

/// The bounds the bridge ships with, against the numbers written here.
///
/// Against literals rather than against the constant, because every bound row
/// below drives `DEFAULT` and would follow it silently wherever it moved. The
/// per-prompt value is the one worth pinning: it is deliberately not the
/// 120-second elicitation timeout, and a "simplification" back onto that
/// constant makes the aggregate unreachable while every other row still passes.
#[test]
fn ac_mrtr_7b_the_shipped_bounds_are_the_documented_ones() {
    assert_eq!(
        BridgeBounds::DEFAULT.rounds,
        3,
        "retries after the first call"
    );
    assert_eq!(
        BridgeBounds::DEFAULT.requests,
        8,
        "requests across the call"
    );
    assert_eq!(
        BridgeBounds::DEFAULT.aggregate,
        Duration::from_secs(120),
        "aggregate wall-clock budget"
    );
    assert_eq!(
        BridgeBounds::DEFAULT.per_prompt,
        Duration::from_secs(30),
        "per-prompt ceiling, which must stay below the aggregate"
    );
    assert!(
        BridgeBounds::DEFAULT.per_prompt < BridgeBounds::DEFAULT.aggregate,
        "a per-prompt ceiling equal to the aggregate makes the aggregate unreachable"
    );
}

/// Row 311 — a client that declared only `elicitation` is not asked for
/// `sampling`, even when the per-request slice is empty.
///
/// Two halves, because the row's own assertion cannot fail on its own: a bridge
/// that sends nothing at all satisfies "sampling was not sent". The neighbour
/// runs the same client, the same empty slice and the same elicitation entry
/// alone, and must reach the client — so the second half's silence is the
/// capability gate and not a fixture that never speaks.
///
/// `Some(&[])` and `None` are different states and the row's word "empty"
/// reaches both, so each is pinned separately. `None` is the request saying
/// nothing and leaves `declared` standing — row 325 drives that direction.
/// `Some(&[])` is the request declaring an empty set, and it narrows to
/// nothing: reading an explicit empty declaration as "no narrowing requested"
/// is the fail-open direction, and it is the one an implementer reaches for
/// because it keeps the neighbour speaking. The neighbour therefore runs on a
/// slice that names `elicitation`, which proves the bridge speaks without
/// deciding the empty case, and the empty case is asserted on its own at the
/// end.
#[tokio::test]
async fn ac_mrtr_7a_an_undeclared_variant_is_not_asked_under_an_empty_slice() {
    let elicitation_only = declared(&json!({"elicitation": {"form": {}}}));
    let empty: [String; 0] = [];
    let naming = ["elicitation".to_string()];
    let slice = Some(&naming[..]);

    // The neighbour: what the client declared, and the slice names, is asked.
    let client = FakeClient::new(vec![accepted(&json!({"ok": true}))]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        elicitation_only,
        slice,
        &interim(&[(
            "k1",
            entry(
                "elicitation/create",
                &json!({"mode": "form", "message": "Which branch?"}),
            ),
        )]),
    )
    .await;
    assert!(
        outcome.is_ok(),
        "declared variant must still be asked: {outcome:?}"
    );
    assert_eq!(
        client.methods(),
        vec!["elicitation/create".to_string()],
        "a slice naming the declared capability must not narrow it away"
    );

    // The row: the same batch plus a variant the client never declared.
    let client = FakeClient::mute();
    let backend = FakeBackend::never();
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        elicitation_only,
        slice,
        &interim(&[
            (
                "k1",
                entry(
                    "elicitation/create",
                    &json!({"mode": "form", "message": "Which branch?"}),
                ),
            ),
            (
                "k2",
                entry(
                    "sampling/createMessage",
                    &json!({"messages": [], "maxTokens": 1}),
                ),
            ),
        ]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Refused {
            key: "k2".to_string(),
            reason: Refusal::Capability("sampling"),
        }),
        "the undeclared entry must name itself and its capability"
    );
    assert!(
        client.frames().is_empty(),
        "a refused batch asks nothing at all, not even its declared half: {:?}",
        client.methods()
    );
    assert!(backend.calls().is_empty(), "backend must not be retried");

    // The empty case on its own: an explicitly empty slice declares an empty
    // set, so even the capability the session declared is not asked. Only the
    // silence is asserted, not which error names it — the row is about what
    // reaches the client, and pinning a variant here would invent a contract
    // the design does not state.
    let client = FakeClient::mute();
    let backend = FakeBackend::never();
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        elicitation_only,
        Some(&empty[..]),
        &interim(&[(
            "k1",
            entry(
                "elicitation/create",
                &json!({"mode": "form", "message": "Which branch?"}),
            ),
        )]),
    )
    .await;

    assert!(
        outcome.is_err(),
        "an empty slice declares an empty set, so the round cannot complete: {outcome:?}"
    );
    assert!(
        client.frames().is_empty(),
        "an empty slice narrows to nothing, so nothing is asked: {:?}",
        client.methods()
    );
}

/// Row 325 — a capability declared in the session is asked for when the
/// per-request slice is absent.
///
/// The only direction that can fail. Under a slice-authoritative bridge an
/// absent slice and an undeclared capability both come out as "do not ask", so
/// the narrowing row above passes either way; only the permitted path shows the
/// session store is the authority.
#[tokio::test]
async fn ac_mrtr_7a_a_session_declared_capability_is_asked_with_no_slice() {
    let answer = json!({"role": "assistant", "content": {"type": "text", "text": "ok"}});
    let client = FakeClient::new(vec![result(&answer)]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared(&json!({"sampling": {}})),
        None,
        &interim(&[(
            "k1",
            entry(
                "sampling/createMessage",
                &json!({"messages": [], "maxTokens": 8}),
            ),
        )]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "an absent slice must not narrow: {outcome:?}"
    );
    assert_eq!(
        client.methods(),
        vec!["sampling/createMessage".to_string()],
        "the session's own declaration is what permits the ask"
    );
}

/// Row 326 — `sampling` and `roots` each complete an accepted round, not only
/// a refused one.
///
/// Every other accepted row is elicitation, so a bridge wired for elicitation
/// and stubbed for the other two passes all of them. Each variant is driven to
/// a retry here, and the answer is asserted where the backend would read it.
#[tokio::test]
async fn ac_mrtr_7a_sampling_and_roots_each_complete_an_accepted_round() {
    let sampled = json!({"role": "assistant", "content": {"type": "text", "text": "hello"}});
    let listed = json!({"roots": [{"uri": "file:///work", "name": "work"}]});

    for (method, params, answer) in [
        (
            "sampling/createMessage",
            json!({"messages": [], "maxTokens": 8}),
            sampled,
        ),
        ("roots/list", json!({}), listed),
    ] {
        let client = FakeClient::new(vec![result(&answer)]);
        let backend = FakeBackend::new(vec![completed()]);
        let records = Records::default();

        let outcome = bridge(
            &client,
            &backend,
            &records,
            declared_all(),
            None,
            &interim(&[("k1", entry(method, &params))]),
        )
        .await;

        assert!(outcome.is_ok(), "{method} round failed: {outcome:?}");
        assert_eq!(client.methods(), vec![method.to_string()]);
        let calls = backend.calls();
        assert_eq!(calls.len(), 1, "{method} must retry the backend once");
        assert_eq!(
            calls[0].pointer("/inputResponses/k1"),
            Some(&answer),
            "{method} answer must reach the backend under its own key"
        );
    }
}

// ── MRTR.7b — what comes back ────────────────────────────────────────────────

/// Row 313 — an accepted answer reaches the backend under the backend's own
/// key.
///
/// The key is the assertion. `InputRequired::requests` is collected from a JSON
/// map, so the backend's authoring order is already lost before the bridge sees
/// it and the key is the only correlation between a question and its answer. A
/// test asserting only that a retry happened passes against a bridge that files
/// every answer under a key it invented.
#[tokio::test]
async fn ac_mrtr_7b_an_accepted_answer_is_filed_under_the_backend_key() {
    let content = json!({"branch": "main"});
    let client = FakeClient::new(vec![accepted(&content)]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[(
            "server-chose-this",
            entry(
                "elicitation/create",
                &json!({"mode": "form", "message": "Which branch?"}),
            ),
        )]),
    )
    .await;

    assert!(outcome.is_ok(), "accepted round failed: {outcome:?}");
    let calls = backend.calls();
    assert_eq!(calls.len(), 1, "one answered round, one retry");
    assert_eq!(
        calls[0].pointer("/inputResponses/server-chose-this"),
        Some(&content),
        "the answer must arrive under the key the backend assigned"
    );
    assert_eq!(
        calls[0].get("requestState").and_then(Value::as_str),
        Some("state-1"),
        "the backend's opaque state must be echoed back untouched"
    );
}

/// Row 314 — a decline fails the call, and says a person declined rather than
/// that something broke.
///
/// A successful JSON-RPC result carrying a decline arrives through the door a
/// transport-error path does not cover. The reason is the load-bearing half: a
/// test asserting only "no retry" passes against a bridge that maps every
/// non-accept onto a transport fault, which is exactly the distinction the
/// `phase` label was added to preserve.
#[tokio::test]
async fn ac_mrtr_7b_a_decline_fails_the_call_as_a_refusal_by_a_person() {
    let client = FakeClient::new(vec![result(&json!({"action": "decline"}))]);
    let backend = FakeBackend::never();
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[(
            "k1",
            entry(
                "elicitation/create",
                &json!({"mode": "form", "message": "Deploy?"}),
            ),
        )]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Delivery {
            key: "k1".to_string(),
            error: DeliveryError::Declined {
                action: "decline".to_string(),
            },
        }),
        "a decline must not be reported as a transport fault"
    );
    assert!(backend.calls().is_empty(), "backend must not be retried");
}

/// Row 315 — a JSON-RPC `error` reply fails the call carrying the client's own
/// code.
///
/// The shipped elicitation helper resolves an error reply through its success
/// arm, so an error envelope is read as an answer today. Both the code and the
/// message are asserted: a bridge that reports "the client refused" without the
/// client's own code leaves an operator with nothing to look up.
#[tokio::test]
async fn ac_mrtr_7b_an_error_reply_fails_the_call_as_a_client_refusal() {
    let client = FakeClient::new(vec![Reply::Now(json!({
        "jsonrpc": "2.0",
        "error": {"code": -32601, "message": "elicitation not supported"},
    }))]);
    let backend = FakeBackend::never();
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[(
            "k1",
            entry(
                "elicitation/create",
                &json!({"mode": "form", "message": "Deploy?"}),
            ),
        )]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Delivery {
            key: "k1".to_string(),
            error: DeliveryError::ClientRefused {
                code: -32601,
                message: "elicitation not supported".to_string(),
            },
        }),
    );
    assert!(backend.calls().is_empty(), "backend must not be retried");
}

/// Row 316 — an accept whose body cannot be read as an answer fails as
/// `Malformed`.
///
/// Both shapes, because they fail differently: `content` absent is a client
/// that accepted and said nothing, and a `content` that is not an object is a
/// client that said something unusable. Either forwarded to the backend files
/// an answer nobody gave under a key the backend will read.
#[tokio::test]
async fn ac_mrtr_7b_an_unusable_accept_fails_as_malformed() {
    for body in [
        json!({"action": "accept"}),
        json!({"action": "accept", "content": "not an object"}),
        json!({"action": "accept", "content": ["nor", "this"]}),
    ] {
        let client = FakeClient::new(vec![result(&body)]);
        let backend = FakeBackend::never();
        let records = Records::default();

        let outcome = bridge(
            &client,
            &backend,
            &records,
            declared_all(),
            None,
            &interim(&[(
                "k1",
                entry(
                    "elicitation/create",
                    &json!({"mode": "form", "message": "Deploy?"}),
                ),
            )]),
        )
        .await;

        assert_eq!(
            outcome,
            Err(BridgeError::Delivery {
                key: "k1".to_string(),
                error: DeliveryError::Malformed,
            }),
            "unusable accept {body} must fail as malformed"
        );
        assert!(
            backend.calls().is_empty(),
            "backend must not be retried for {body}"
        );
    }
}

/// Row 317 — an accepted `content` that does not satisfy the backend's own
/// `requestedSchema` is forwarded unchanged.
///
/// Deliberately the opposite of the row above, and written next to it for that
/// reason: an implementer who reads `Malformed` alone adds a validator, and the
/// validator rejects an answer the backend asked for and would have accepted.
/// The gateway does not second-guess a contract between a backend and its
/// client — a shape it cannot read is a bridge failure, a shape it can read and
/// disagrees with is not the bridge's business.
#[tokio::test]
async fn ac_mrtr_7b_content_violating_the_requested_schema_is_forwarded_unchanged() {
    let content = json!({"branch": 7, "unasked": true});
    let client = FakeClient::new(vec![accepted(&content)]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[(
            "k1",
            entry(
                "elicitation/create",
                &json!({
                    "mode": "form",
                    "message": "Which branch?",
                    "requestedSchema": {
                        "type": "object",
                        "properties": {"branch": {"type": "string"}},
                        "required": ["branch"],
                    },
                }),
            ),
        )]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "a schema mismatch is not the bridge's to refuse: {outcome:?}"
    );
    let calls = backend.calls();
    assert_eq!(calls.len(), 1, "the round must still complete");
    assert_eq!(
        calls[0].pointer("/inputResponses/k1"),
        Some(&content),
        "the answer must reach the backend byte for byte, wrong type and extra field included"
    );
}

// ── MRTR.7b — the bounds, the batch, and the projection ──────────────────────

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

/// Row 318 — a backend that keeps asking is cut off after three retries, and
/// its neighbour that asks exactly three times still completes.
///
/// Both halves, in one test, because neither is worth much alone. The failing
/// half passes against a bridge that cuts off at two retries, and the
/// completing half passes against a bridge with no bound at all; only the pair
/// pins the boundary to the one value that satisfies both. The count asserted
/// is retries — the invocation that produced `first` happened before the bridge
/// was entered, so `rounds: 3` is three calls through this backend and four
/// backend invocations in total.
#[tokio::test]
async fn ac_mrtr_7b_the_retry_bound_cuts_off_after_three_retries() {
    let content = json!({"branch": "main"});

    // The half that must be cut off: every retry asks again.
    let client = FakeClient::new(accepts(6, &content));
    let backend = FakeBackend::new(vec![asking(&[("k", ask("again?"))]); 6]);
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k", ask("first?"))]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::RoundsExhausted),
        "a backend that never stops asking must be cut off by the retry bound"
    );
    assert_eq!(
        backend.calls().len(),
        3,
        "three retries, so four backend invocations counting the one that produced the first ask"
    );

    // The neighbour: three asks in total, answered on the fourth invocation.
    let client = FakeClient::new(accepts(3, &content));
    let backend = FakeBackend::new(vec![
        asking(&[("k", ask("second?"))]),
        asking(&[("k", ask("third?"))]),
        completed(),
    ]);
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k", ask("first?"))]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "a backend that asks exactly three times must complete: {outcome:?}"
    );
    assert_eq!(
        backend.calls().len(),
        3,
        "the last retry is the one that completes, not one over the bound"
    );
}

/// Row 319 — the request budget is spent before a batch is sent, not while it
/// is being sent.
///
/// `client.frames().len()` is the assertion that separates the two readings. A
/// bridge checking the budget after each send stops partway through the
/// offending batch and still reports `RequestBudgetExhausted`, so an assertion
/// on the error alone passes it; only the frame count says whether the three
/// requests that could never have been afforded were put to a person anyway.
/// The neighbour spends the budget exactly and must be sent whole.
#[tokio::test]
async fn ac_mrtr_7b_the_request_budget_is_checked_before_a_batch_is_sent() {
    let content = json!({"ok": true});
    let five = [
        ("a", ask("a?")),
        ("b", ask("b?")),
        ("c", ask("c?")),
        ("d", ask("d?")),
        ("e", ask("e?")),
    ];

    // Five, then six: the second batch cannot fit in the eight that remain.
    let client = FakeClient::new(accepts(11, &content));
    let backend = FakeBackend::new(vec![asking(&[
        ("f", ask("f?")),
        ("g", ask("g?")),
        ("h", ask("h?")),
        ("i", ask("i?")),
        ("j", ask("j?")),
        ("k", ask("k?")),
    ])]);
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&five),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::RequestBudgetExhausted),
        "a batch that cannot fit the budget must fail the call"
    );
    assert_eq!(
        client.frames().len(),
        5,
        "not one request of the unaffordable batch may be put to the client"
    );

    // The neighbour: five then three is exactly eight, and all eight are sent.
    let client = FakeClient::new(accepts(8, &content));
    let backend = FakeBackend::new(vec![
        asking(&[("f", ask("f?")), ("g", ask("g?")), ("h", ask("h?"))]),
        completed(),
    ]);
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&five),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "eight requests exactly is inside the budget: {outcome:?}"
    );
    assert_eq!(
        client.frames().len(),
        8,
        "a batch that fits must be sent in full"
    );
}

/// Row 320 — a prompt nobody answers ends its round at the per-prompt bound,
/// and the rounds still remaining run.
///
/// The second round is what makes this row worth writing. A bridge that turns
/// one unanswered prompt into a failed call satisfies "abandoned at the
/// per-prompt bound" perfectly and fails here, on the round that never ran. The
/// elapsed floor is asserted so that a bridge abandoning immediately — which
/// would also let the second round run — cannot pass: the wait has to be the
/// bound's, and the fixture never times itself out.
///
/// Scaled bounds, in milliseconds, so the suite stays fast. The relation is
/// what is asserted; the shipped literals are pinned elsewhere.
#[tokio::test]
async fn ac_mrtr_7b_an_unanswered_prompt_ends_its_round_not_the_call() {
    let bounds = BridgeBounds {
        aggregate: Duration::from_millis(400),
        per_prompt: Duration::from_millis(60),
        ..BridgeBounds::DEFAULT
    };
    let content = json!({"branch": "main"});
    let client = FakeClient::new(vec![Reply::Silent, accepted(&content)]);
    let backend = FakeBackend::new(vec![asking(&[("k2", ask("second?"))]), completed()]);
    let records = Records::default();

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        bridge_with(
            &client,
            &backend,
            &records,
            declared_all(),
            None,
            &interim(&[("k1", ask("first?"))]),
            bounds,
        ),
    )
    .await
    .expect(
        "a bridge with no per-prompt bound waits on the fixture's own 86_400s silence, \
             which is a hung suite rather than a failing row: the bound is what must end it",
    );
    let elapsed = started.elapsed();

    assert!(
        outcome.is_ok(),
        "one unanswered prompt must not end the call: {outcome:?}"
    );
    assert!(
        elapsed >= bounds.per_prompt,
        "the wait must be ended by the per-prompt bound, not sooner: waited {elapsed:?}"
    );
    assert!(
        elapsed < bounds.per_prompt * 3,
        "the wait must be the per-prompt bound's, not merely under the aggregate: a bridge \
         abandoning at a multiple of the bound still leaves room for round 2 and would \
         otherwise pass; waited {elapsed:?} against a bound of {:?}",
        bounds.per_prompt
    );
    assert_eq!(
        client.frames().len(),
        2,
        "the round after the abandoned one must still put its question"
    );
    assert_eq!(
        backend.calls().len(),
        2,
        "the abandoned round retries the backend, and the answered one retries it again"
    );
}

/// Row 321 — rounds each answered inside the per-prompt bound are still ended
/// by the aggregate deadline.
///
/// The only row that can observe the aggregate bound at all. A single
/// unanswered prompt is abandoned at the per-prompt bound and can never reach
/// it, so unless several answered rounds are driven the aggregate is a number
/// no test touches. Each reply lands comfortably inside `per_prompt`; their sum
/// passes `aggregate`, and the call must end on the budget rather than on any
/// one prompt.
#[tokio::test]
async fn ac_mrtr_7b_answered_rounds_are_ended_by_the_aggregate_deadline() {
    let bounds = BridgeBounds {
        rounds: 12,
        requests: 20,
        aggregate: Duration::from_millis(500),
        per_prompt: Duration::from_millis(200),
    };
    let envelope =
        json!({"jsonrpc": "2.0", "result": {"action": "accept", "content": {"ok": true}}});
    let client = FakeClient::new(
        (0..12)
            .map(|_| Reply::After(Duration::from_millis(50), envelope.clone()))
            .collect(),
    );
    let backend = FakeBackend::new(vec![asking(&[("k", ask("again?"))]); 12]);
    let records = Records::default();

    let outcome = bridge_with(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k", ask("first?"))]),
        bounds,
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Deadline),
        "the aggregate budget must end a call whose rounds each answer in time"
    );
    assert!(
        backend.calls().len() >= 2,
        "the deadline must be reached across several answered rounds, not on one prompt: {} retries",
        backend.calls().len()
    );
    assert!(
        backend
            .calls()
            .iter()
            .any(|retry| retry.pointer("/inputResponses/k").is_some()),
        "a retry must carry the answer it collected, looked up structurally rather than as a \
         substring: the key `k` also appears in the question this retry echoes, so a text \
         search passes against a bridge that timed every prompt out and filed nothing"
    );
}

/// Row 322 — three questions in one batch, all answered, produce one retry
/// carrying three answers, each under the key that asked it.
///
/// The row no other 7b row implies. A bridge that resolves on the first answer
/// and retries immediately satisfies every bound row, every projection row and
/// every refusal row, because none of them names a batch that succeeds. The
/// answers are echoed rather than scripted positionally: prompt order within a
/// batch is unspecified, so a positional script would assert the order the
/// implementation happened to choose, and each answer has to be derivable from
/// its own question instead.
#[tokio::test]
async fn ac_mrtr_7b_a_batch_of_three_answers_arrives_in_one_retry() {
    let client = FakeClient::new(vec![Reply::Echo, Reply::Echo, Reply::Echo]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[
            ("one", ask("one?")),
            ("two", ask("two?")),
            ("three", ask("three?")),
        ]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "an answered batch must complete: {outcome:?}"
    );
    let calls = backend.calls();
    assert_eq!(
        calls.len(),
        1,
        "one batch, one retry — not one retry per answer"
    );
    for (key, message) in [("one", "one?"), ("two", "two?"), ("three", "three?")] {
        assert_eq!(
            calls[0].pointer(&format!("/inputResponses/{key}/echo/message")),
            Some(&json!(message)),
            "the answer filed under {key} must be the one that key's question drew"
        );
    }
    assert_eq!(
        calls[0]
            .pointer("/inputResponses")
            .and_then(Value::as_object)
            .map(serde_json::Map::len),
        Some(3),
        "three questions must produce three answers and nothing else"
    );
}

/// Row 327 — a cancel, an unrecognised action and a reply with no member each
/// fail as themselves, and none of them reaches the backend.
///
/// Three cases in one test because what the row asserts is that they stay
/// distinct: each alone passes against a bridge that collapses every non-accept
/// onto one error. The dangerous arm is the unmatched one — an `action` the
/// bridge cannot name, falling through to the accept path, forwards a body
/// nobody agreed to — so `UnknownAction` is asserted apart from `Declined`
/// rather than merged with it. `FakeBackend::never` makes the no-retry half a
/// fact about the fixture rather than a count that happens to be zero.
#[tokio::test]
async fn ac_mrtr_7b_cancel_unnamed_action_and_no_member_fail_distinguishably() {
    let cases: Vec<(&str, Reply, DeliveryError)> = vec![
        (
            "a cancel",
            result(&json!({"action": "cancel"})),
            DeliveryError::Declined {
                action: "cancel".to_string(),
            },
        ),
        (
            "an action outside the declared set",
            result(&json!({"action": "teleport"})),
            DeliveryError::UnknownAction {
                action: "teleport".to_string(),
            },
        ),
        (
            "a reply carrying neither result nor error",
            Reply::Now(json!({"jsonrpc": "2.0"})),
            DeliveryError::NoReplyMember,
        ),
    ];

    for (name, reply, expected) in cases {
        let client = FakeClient::new(vec![reply]);
        let backend = FakeBackend::never();
        let records = Records::default();

        let outcome = bridge(
            &client,
            &backend,
            &records,
            declared_all(),
            None,
            &interim(&[("k1", ask("Which branch?"))]),
        )
        .await;

        assert_eq!(
            outcome,
            Err(BridgeError::Delivery {
                key: "k1".to_string(),
                error: expected,
            }),
            "{name} must fail as itself"
        );
        assert!(
            backend.calls().is_empty(),
            "{name} must not re-invoke the backend"
        );
    }
}

/// Row 328 — *each* bridged round is counted with `phase="bridge"`, and no part
/// of what a person answered appears in any record.
///
/// The counter's name is not asserted, because no name exists to assert:
/// `NFR.OBS.4` is recorded as having no design and no counters
/// (`docs/requirements/RELEASE-4.0.0-cluster-a-readiness.md:44`), so a literal
/// here would be this test inventing the contract it claims to check. The two
/// halves the row does name are both asserted, and each is written so that the
/// cheapest wrong implementation fails it.
///
/// Three rounds rather than one, because "each round" is the half a single
/// successful round cannot observe: a counter emitted once per *call* carries
/// `phase="bridge"` and satisfies a one-round row completely, while losing
/// exactly the per-round resolution the requirement is about. Three answered
/// rounds demand at least three bridge-phase records, which no once-per-call
/// counter can produce.
///
/// The absence is the half that rots — a label added later to carry "what was
/// answered" breaks nothing and fails nothing — so it is asserted against the
/// captured records rather than by reading the emit sites, over every counter
/// name and every label key and value. Each round answers with its own
/// sentinel, so a bridge that leaks only the last answer, or only the first,
/// is caught rather than sampled.
#[tokio::test]
async fn ac_mrtr_7ab_a_bridged_round_is_counted_without_the_answer_body() {
    const SENTINELS: [&str; 3] = [
        "sentinel-answer-body-mrtr7-one",
        "sentinel-answer-body-mrtr7-two",
        "sentinel-answer-body-mrtr7-three",
    ];

    let client = FakeClient::new(
        SENTINELS
            .iter()
            .map(|sentinel| accepted(&json!({"branch": sentinel})))
            .collect(),
    );
    let backend = FakeBackend::new(vec![
        asking(&[("k2", ask("Which remote?"))]),
        asking(&[("k3", ask("Which tag?"))]),
        completed(),
    ]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k1", ask("Which branch?"))]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "the three rounds must complete: {outcome:?}"
    );
    let observed = records.all();
    let bridged = observed
        .iter()
        .filter(|record| record.labels.get("phase").map(String::as_str) == Some("bridge"))
        .count();
    assert!(
        bridged >= SENTINELS.len(),
        "each of the {} bridged rounds must be counted with phase=\"bridge\", and {bridged} \
         record(s) carry it: a counter emitted once per call passes the same row driven \
         through a single round",
        SENTINELS.len()
    );
    for record in &observed {
        for sentinel in SENTINELS {
            assert!(
                !record.counter.contains(sentinel),
                "an answer body must not reach a counter name: {:?}",
                record.counter
            );
            for (key, value) in &record.labels {
                assert!(
                    !key.contains(sentinel) && !value.contains(sentinel),
                    "an answer body must not reach a label: {key}={value}"
                );
            }
        }
    }
}

/// The control for rows 318-321: the fixture those rows retry with is the shape
/// the parser actually reads.
///
/// Every multi-round row drives its later rounds through [`asking`], and a
/// bridge is observable as looping only if the parser classifies what the
/// backend returned as another question. A fixture the parser refuses to
/// classify is indistinguishable, from outside, from a bridge that never loops:
/// both end the call after one round, and the row would then be failing for a
/// reason that has nothing to do with the bound it names. This asserts the
/// fixture rather than the bridge, so unlike its neighbours it may legitimately
/// pass while the bridge is still a stub.
#[test]
fn ac_mrtr_7b_the_asking_fixture_is_what_the_parser_reads() {
    let parsed = InputRequired::from_result(&asking(&[("k1", ask("Which branch?"))]))
        .expect("the retry fixture must parse as an unfinished round");

    assert_eq!(
        parsed.requests,
        vec![("k1".to_string(), ask("Which branch?"))],
        "the fixture must carry the backend's own key and its entry verbatim"
    );
    assert_eq!(
        parsed.request_state.as_deref(),
        Some("state-1"),
        "the fixture must carry the state a retry has to echo back"
    );
}

/// A control, not an acceptance row: it proves `declared_all` declares.
///
/// The `_meta` keys are reverse-DNS, and a fixture writing the bare names is
/// read as a shape carrying no declaration at all — so every capability row
/// would gate on `Declared::NONE` and pass whatever the bridge did with the
/// permission it was never given. Asserting the fixture against the parser is
/// what stops that from being reintroduced silently; the row tests cannot see
/// it, because a client that declared nothing is a state they are allowed to
/// encounter.
#[test]
fn ac_mrtr_7a_the_capability_fixture_declares_what_it_names() {
    let all = declared_all();
    for capability in ["sampling", "roots", "elicitation"] {
        assert!(
            all.has(capability),
            "the fixture claiming every capability must declare {capability}, \
             or every capability row gates on a client that declared nothing"
        );
    }
}
