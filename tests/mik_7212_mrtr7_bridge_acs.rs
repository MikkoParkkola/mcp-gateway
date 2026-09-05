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
            "protocolVersion": "2026-07-28",
            "clientCapabilities": capabilities,
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
/// The empty slice is the trap §6 names: `&[]` means the request said nothing,
/// not that the client can do nothing. Read as a denial it refuses the
/// neighbour too, which is how a bridge that looks correct asks nobody.
#[tokio::test]
async fn ac_mrtr_7a_an_undeclared_variant_is_not_asked_under_an_empty_slice() {
    let elicitation_only = declared(&json!({"elicitation": {"form": {}}}));
    let empty: [String; 0] = [];
    let slice = Some(&empty[..]);

    // The neighbour: what the client did declare is asked, empty slice and all.
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
        "an empty slice must not narrow anything"
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
