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

const BACKEND: &str = "fixture";
/// Asks at once, naming the caller's `customer_id` as its tenant.
const ASKING: &str = "ask";
/// Asks after [`SLOW`], so a cancel can arrive first.
const SLOW_ASKING: &str = "slow_ask";
const SLOW: Duration = Duration::from_millis(800);
const ARRIVAL: Duration = Duration::from_secs(5);

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
                ]}),
                "tools/call" => {
                    let params = request.get("params").cloned().unwrap_or_default();
                    if params["name"] == SLOW_ASKING {
                        tokio::time::sleep(SLOW).await;
                    }
                    let tenant = params["arguments"]["customer_id"].clone();
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
    let meta = timeout(ARRIVAL, meta)
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
        let line = timeout(ARRIVAL, self.stdout.next_line())
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
    let deadline = tokio::time::Instant::now() + ARRIVAL;
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
