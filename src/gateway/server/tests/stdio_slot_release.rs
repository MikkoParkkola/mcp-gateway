// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 stage 3 (family continuation-slot-release), stdio arm: a sealed
//! question keeps its slot when the writer takes its frame, and gives it back
//! when the answer never reaches the writer: withheld by the read judge,
//! refused by its delivery record, cancelled before it was queued, or still
//! queued when the session ended. Driven through the real read loop, with the
//! session's Meta-MCP read through the `stdio_meta_mcp_for_test` seam.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::config::Config;
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::MetaMcp;
use crate::test_wait::HANG_BOUND;

const BACKEND: &str = "fixture";
/// Asks at once, naming the caller's `customer_id` as its tenant.
const ASKING: &str = "ask";
/// Asks after [`SLOW`], so a cancel can arrive first.
const SLOW_ASKING: &str = "slow_ask";
const SLOW: Duration = Duration::from_millis(800);
/// An interim round with `requestState` and no questions (MIK-8177).
const STATE_ONLY: &str = "state_only";

type Stdout = Lines<BufReader<DuplexStream>>;

/// A backend whose `tools/call` answers with a question about the tenant
/// the call names.
async fn spawn_backend() -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(|axum::Json(request): axum::Json<Value>| async move {
            let method = request.get("method").and_then(Value::as_str).unwrap_or("");
            let result = match method {
                "initialize" => json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": BACKEND, "version": "0"},
                }),
                "tools/list" => json!({"tools": [
                    {"name": ASKING, "inputSchema": {"type": "object"}},
                    {"name": SLOW_ASKING, "inputSchema": {"type": "object"}},
                    {"name": STATE_ONLY, "inputSchema": {"type": "object"}},
                ]}),
                "tools/call" => {
                    let params = request.get("params").cloned().unwrap_or_default();
                    if params["name"] == SLOW_ASKING {
                        tokio::time::sleep(SLOW).await;
                    }
                    let tenant = params["arguments"]["customer_id"].clone();
                    if params["name"] == STATE_ONLY {
                        return axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"),
                        "result": {
                            "resultType": "input_required",
                            "requestState": "backend-state",
                            "content": [{"type": "text",
                                         "text": json!({"customer_id": tenant}).to_string()}],
                        }}));
                    }
                    json!({
                        "resultType": "input_required",
                        "inputRequests": {"k1": {
                            "method": "elicitation/create",
                            "params": {"message": "Which account?",
                                       "requestedSchema": {"type": "object"}},
                        }},
                        "requestState": "backend-state",
                        "content": [{"type": "text",
                                     "text": json!({"customer_id": tenant}).to_string()}],
                    })
                }
                _ => json!({}),
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    format!("http://{address}/")
}

/// What a session's config switches on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Setup {
    Plain,
    /// The read judge withholds a caller's second tenant.
    JudgeBlocks,
    /// A fail-closed transparency log (auth on, as the gateway requires).
    LogFailClosed,
}

struct Session {
    stdin: DuplexStream,
    stdout: Stdout,
    meta: Arc<MetaMcp>,
    task: JoinHandle<crate::Result<()>>,
    _dir: tempfile::TempDir,
}

/// A stdio session under `setup`, its stdout `capacity` bytes deep, with
/// the handshake answered.
async fn open(setup: Setup, capacity: usize) -> Session {
    let backend_url = spawn_backend().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let quoted = |name: &str| {
        serde_json::to_string(&dir.path().join(name).display().to_string()).expect("a JSON string")
    };
    let security = match setup {
        Setup::Plain => String::new(),
        Setup::JudgeBlocks => "security:\n  firewall:\n    tenant_guard:\n      arg_keys: [customer_id]\n      cross_tenant_reads: block\n".to_string(),
        Setup::LogFailClosed => format!(
            "security:\n  transparency_log:\n    enabled: true\n    path: {}\nauth:\n  enabled: true\n  api_keys:\n    - name: stdio\n      key_sha256: {}\n",
            quoted("audit.jsonl"),
            serde_json::to_string(&crate::config::api_key_digest_spec(b"k")).expect("a JSON string"),
        ),
    };
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\ntasks:\n  store_dir: {}\n{security}",
        quoted("tasks")
    );
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("config loads");
    let mut gateway = Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());
    let meta = gateway.stdio_meta_mcp_for_test();
    let (stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(capacity);
    let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let meta = timeout(HANG_BOUND, meta)
        .await
        .expect("the session reports its Meta-MCP")
        .expect("the seam's sender is kept until it is sent");
    let mut session = Session {
        stdin,
        stdout: BufReader::new(reader).lines(),
        meta,
        task,
        _dir: dir,
    };
    let init = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {"elicitation": {}},
                   "clientInfo": {"name": "slot-release", "version": "0"}},
    });
    session.send(&init).await;
    let answered = session.next_frame().await;
    assert_eq!(
        answered["id"],
        json!(0),
        "the handshake is answered first: {answered}"
    );
    session
}

impl Session {
    async fn send(&mut self, frame: &Value) {
        self.stdin
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("write to the gateway's stdin");
    }

    async fn next_frame(&mut self) -> Value {
        let line = timeout(HANG_BOUND, self.stdout.next_line())
            .await
            .expect("a frame arrives within the bound")
            .expect("stdout reads")
            .expect("stdout is open");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("not one JSON frame ({e}): {line:?}"))
    }

    /// The answer to `id`, skipping anything else the session sends.
    async fn answer(&mut self, id: i64) -> Value {
        loop {
            let frame = self.next_frame().await;
            if frame.get("method").is_none() && frame["id"] == json!(id) {
                return frame;
            }
        }
    }

    async fn held(&self) -> usize {
        let now = crate::protocol::continuation::now_unix_secs();
        self.meta.continuation().in_flight().len(now).await
    }
}

/// A modern `gateway_invoke` of `tool` reading `tenant`, from a client that
/// can answer a question.
fn call(id: i64, tool: &str, tenant: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": tool,
                          "arguments": {"customer_id": tenant}},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
                "io.modelcontextprotocol/clientInfo": {"name": "slot-release", "version": "0"},
            },
        },
    })
}

/// Whether `answer` delivered a sealed question.
fn delivered(answer: &Value) -> bool {
    let text = answer.to_string();
    answer.get("error").is_none()
        && text.contains("requestState")
        && !text.contains("backend-state")
}

/// Whether any string in `value` (or in a JSON document a string carries) is
/// a live envelope under `meta`'s continuation keyring.
fn carries_envelope(meta: &MetaMcp, value: &Value) -> bool {
    match value {
        Value::String(text) => {
            meta.continuation().keyring().open_now(text).is_ok()
                || serde_json::from_str::<Value>(text)
                    .is_ok_and(|inner| !inner.is_string() && carries_envelope(meta, &inner))
        }
        Value::Array(items) => items.iter().any(|item| carries_envelope(meta, item)),
        Value::Object(fields) => fields.values().any(|field| carries_envelope(meta, field)),
        _ => false,
    }
}

/// Control: a sealed question the writer takes keeps its slot for the retry.
#[tokio::test]
async fn a_delivered_stdio_question_keeps_its_slot() {
    let mut session = open(Setup::Plain, 1 << 20).await;
    session.send(&call(5, ASKING, "t1")).await;
    let answer = session.answer(5).await;
    assert!(
        delivered(&answer),
        "control: a sealed question is delivered: {answer}"
    );
    assert_eq!(session.held().await, 1, "{answer}");
}

/// SLOT.1, stdio arm: the read judge withholds a second tenant's question.
/// The first, delivered, keeps its slot; the withheld one gives its back.
#[tokio::test]
async fn a_stdio_question_withheld_by_the_read_judge_gives_its_slot_back() {
    let mut session = open(Setup::JudgeBlocks, 1 << 20).await;
    session.send(&call(5, ASKING, "t1")).await;
    let first = session.answer(5).await;
    assert!(
        delivered(&first),
        "the first tenant's question is delivered: {first}"
    );
    session.send(&call(6, ASKING, "t2")).await;
    let withheld = session.answer(6).await;
    assert!(
        !delivered(&withheld),
        "the second tenant's question is withheld: {withheld}"
    );
    assert_eq!(
        session.held().await,
        1,
        "the withheld question kept its slot: {withheld}"
    );
}

/// SLOT.2, stdio arm: a question whose delivery record cannot be written
/// under fail-closed never leaves, so its slot is given back.
#[tokio::test]
async fn a_stdio_question_refused_by_its_delivery_record_gives_its_slot_back() {
    let mut session = open(Setup::LogFailClosed, 1 << 20).await;
    session
        .meta
        .transparency_log()
        .expect("the session logs")
        .fail_next_append_of_kind_for_test("response_delivery_attempt");
    session.send(&call(5, ASKING, "t1")).await;
    let refused = session.answer(5).await;
    assert_eq!(refused["error"]["code"], json!(-32005), "{refused}");
    assert_eq!(
        session.held().await,
        0,
        "the refused question kept its slot: {refused}"
    );
}

/// MIK-8177.STATE.1, stdio arm: a state-only interim round (a sealed
/// `requestState`, no questions) whose delivery record cannot be written
/// never leaves, so its slot is given back, while an unrelated delivered
/// question keeps its own. Guard, not a red proof: stage 3's scoped stdio
/// release already frees it on base (measured, with the positive control
/// below); it pins that the state-only shape stays covered.
#[tokio::test]
async fn a_stdio_state_only_round_refused_by_its_delivery_record_gives_its_slot_back() {
    let mut session = open(Setup::LogFailClosed, 1 << 20).await;
    session.send(&call(4, ASKING, "t1")).await;
    let kept = session.answer(4).await;
    assert!(
        delivered(&kept),
        "the unrelated question is delivered: {kept}"
    );
    // Positive control: a delivered state-only round is sealed and holds a
    // slot, so the refused one below had a slot to give back.
    session.send(&call(3, STATE_ONLY, "t1")).await;
    let sealed = session.answer(3).await;
    assert_eq!(
        session.held().await,
        2,
        "a delivered state-only round holds its slot: {sealed}"
    );
    session
        .meta
        .transparency_log()
        .expect("the session logs")
        .fail_next_append_of_kind_for_test("response_delivery_attempt");
    session.send(&call(5, STATE_ONLY, "t1")).await;
    let refused = session.answer(5).await;
    assert_eq!(refused["error"]["code"], json!(-32005), "{refused}");
    assert_eq!(
        session.held().await,
        2,
        "only the delivered rounds' slots are held: {refused}"
    );
}

/// SLOT.7 guard, not a red proof: the cancel stops the backend call before
/// it seals anything, so no slot is ever taken (green on base too). It pins
/// that a cancelled call leaves nothing held; the drop-before-write case is
/// `a_stdio_question_still_queued_at_session_end_gives_its_slot_back`.
#[tokio::test]
async fn a_stdio_question_cancelled_before_it_is_queued_gives_its_slot_back() {
    let mut session = open(Setup::Plain, 1 << 20).await;
    session.send(&call(5, SLOW_ASKING, "t1")).await;
    session
        .send(
            &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                      "params": {"requestId": 5, "reason": "test"}}),
        )
        .await;
    tokio::time::sleep(SLOW * 3).await;
    assert_eq!(
        session.held().await,
        0,
        "the cancelled question kept its slot"
    );
}

/// SLOT.7: a question still queued for the writer when the session ends
/// never reaches the client, so its slot is given back. Two questions on a
/// stdout too shallow for either: the writer takes one (handed off, kept,
/// though its write never completes) and blocks on it, so the other is still
/// queued when the session ends, and gives its slot back.
#[tokio::test]
async fn a_stdio_question_still_queued_at_session_end_gives_its_slot_back() {
    let mut session = open(Setup::Plain, 256).await;
    session.send(&call(5, ASKING, "t1")).await;
    session.send(&call(6, ASKING, "t1")).await;
    // Both questions sealed before the session ends: one is with the writer,
    // the other can only be in the queue behind it.
    let deadline = tokio::time::Instant::now() + HANG_BOUND;
    while session.held().await < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "both questions are sealed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let Session {
        stdin,
        stdout,
        meta,
        task,
        _dir,
    } = session;
    drop(stdin);
    drop(stdout);
    timeout(Duration::from_secs(20), task)
        .await
        .expect("the session ends within its bound")
        .expect("the serve task does not panic")
        .expect("run_stdio_on returns Ok");
    let now = crate::protocol::continuation::now_unix_secs();
    assert_eq!(
        meta.continuation().in_flight().len(now).await,
        1,
        "want the taken question's slot only: the queued one never left"
    );
}

/// [`call`] under an idempotency key, so execution admission owns it.
fn keyed_call(id: i64, key: &str) -> Value {
    let mut body = call(id, ASKING, "t1");
    body["params"]["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    body
}

/// Send `body` and cancel request `id` after its answer has settled and
/// before it is queued, so the answer is dropped unsent.
async fn cancel_after_commit(session: &mut Session, body: &Value, id: i64) {
    let pause = crate::gateway::server::stdio_seams::pause_after_commit_for_test();
    session.send(body).await;
    timeout(HANG_BOUND, pause.reached())
        .await
        .expect("the answer settles and reaches the enqueue");
    let cancel = crate::gateway::server::stdio_seams::watch_cancel_for_test();
    session
        .send(
            &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                      "params": {"requestId": id, "reason": "test"}}),
        )
        .await;
    // The cancel is recorded before the paused answer is released.
    timeout(HANG_BOUND, cancel.seen())
        .await
        .expect("the serve loop records the cancel");
    pause.release();
}

/// A keyed `gateway_run_playbook` of a one-step playbook whose step asks:
/// the question nests in the playbook output, so execution admission
/// retains it (unlike a top-level `gateway_invoke` question).
fn keyed_playbook_call(meta: &MetaMcp, id: i64, key: &str) -> Value {
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "ask-once",
        "description": "one step whose backend stops to ask",
        "steps": [ { "name": "step", "tool": ASKING, "server": BACKEND,
                     "arguments": {"customer_id": "t1"} } ]
    }))
    .expect("the playbook fixture deserialises");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    meta.set_playbook_engine(engine);
    let mut body = call(id, ASKING, "t1");
    body["params"]["name"] = json!("gateway_run_playbook");
    body["params"]["arguments"] = json!({"name": "ask-once"});
    body["params"]["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    body
}

/// C1-stdio-nested (SLOT.8 stored-delivery arm over stdio; MIK-8176 lead
/// re-ruling): a keyed playbook's nested question is retained by execution
/// admission. Cancelled after settlement and before the enqueue, its frame is
/// dropped unsent and the request's holds go with it, yet a replay under the
/// same key delivers the stored question. The store must own the slot: after
/// the replay is delivered, the slot is still held. Red on base.
#[tokio::test]
async fn c1_stdio_a_replayed_nested_question_keeps_its_slot() {
    let mut session = open(Setup::Plain, 1 << 20).await;
    let first = keyed_playbook_call(&session.meta, 5, "c1-stdio-nested");
    cancel_after_commit(&mut session, &first, 5).await;
    let mut repeat = first.clone();
    repeat["id"] = json!(6);
    session.send(&repeat).await;
    let replay = session.next_frame().await;
    assert_eq!(
        replay["id"],
        json!(6),
        "the cancelled answer was never sent: {replay}"
    );
    assert!(
        replay.get("error").is_none() && carries_envelope(&session.meta, &replay),
        "the replay delivers the stored nested question: {replay}"
    );
    assert_eq!(
        session.held().await,
        1,
        "the replayed question's slot is still held (the store owns it)"
    );
}

/// C1-stdio guard (SLOT.8, execution-admission store; MIK-8176): execution
/// admission does not retain a TOP-LEVEL input-required response
/// (`complete_delivery_read` returns before storing one; a question nested
/// in a playbook output is retained, and rows C1/C1b cover that shape). A
/// keyed top-level question cancelled after settlement and before the
/// enqueue is dropped unsent: its slot is released at once, not held until
/// expiry, and a replay under the same key is refused as unavailable
/// (MIK-8297). If admission ever retains this shape, this row fails: the
/// store would then have to own the slot.
#[tokio::test]
async fn c1_stdio_a_cancelled_unsent_question_is_not_retained_and_frees_its_slot() {
    let mut session = open(Setup::Plain, 1 << 20).await;
    cancel_after_commit(&mut session, &keyed_call(5, "c1-stdio"), 5).await;
    session.send(&keyed_call(6, "c1-stdio")).await;
    let replay = session.next_frame().await;
    assert_eq!(
        replay["id"],
        json!(6),
        "the cancelled answer was never sent: {replay}"
    );
    assert_eq!(
        replay["error"]["code"],
        json!(409),
        "admission retained no question to replay: {replay}"
    );
    assert!(
        replay.to_string().contains("unavailable"),
        "the refusal is Unavailable: {replay}"
    );
    assert_eq!(
        session.held().await,
        0,
        "the dropped question's slot is released, not held until expiry"
    );
    // MIK-8176 (d) evidence: a fresh key recovers the question.
    session.send(&keyed_call(7, "c1-stdio-fresh")).await;
    let fresh = session.answer(7).await;
    assert!(
        delivered(&fresh),
        "a fresh key delivers the question again: {fresh}"
    );
}
