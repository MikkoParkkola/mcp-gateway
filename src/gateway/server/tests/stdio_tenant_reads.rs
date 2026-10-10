// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.2 rows 3 and 4 over stdio (design §4.3): the real serve loop,
//! over in-memory pipes, judges every answer for the one stdio client. A
//! call naming A, then one naming B: off delivers both; block refuses B.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::config::Config;
use crate::gateway::Gateway;

const BACKEND: &str = "fixture";
const TOOL: &str = "rows";

/// An HTTP MCP backend whose one tool answers a tenant-free "ok".
async fn spawn_backend() -> String {
    spawn_backend_answering(Answer::Now).await
}

/// When the fixture tool answers.
#[derive(Clone, Copy)]
enum Answer {
    Now,
    /// Never: the call stays in flight, so its task stays working.
    Never,
}

/// [`spawn_backend`] whose tool answers per `answer`.
async fn spawn_backend_answering(answer: Answer) -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| async move {
            let method = request.get("method").and_then(Value::as_str).unwrap_or("");
            let result = match method {
                "initialize" => json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": BACKEND, "version": "0"},
                }),
                "tools/list" => json!({"tools": [{
                    "name": TOOL,
                    "description": "reads rows",
                    "inputSchema": {"type": "object"},
                }]}),
                "tools/call" => {
                    if matches!(answer, Answer::Never) {
                        std::future::pending::<()>().await;
                    }
                    json!({
                        "content": [{"type": "text", "text": "ok"}],
                        "isError": false,
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

fn call(id: i64, tenant: &str) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": BACKEND, "tool": TOOL, "arguments": {"customer_id": tenant},
        }},
    })
    .to_string()
}

/// The next stdout frame answering `id`.
async fn answer(
    lines: &mut tokio::io::Lines<BufReader<tokio::io::DuplexStream>>,
    id: i64,
) -> Value {
    loop {
        let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("an answer within the bound")
            .expect("stdout readable")
            .expect("stdout open");
        let frame: Value = serde_json::from_str(&line).expect("one JSON frame per line");
        if frame.get("id").and_then(Value::as_i64) == Some(id) {
            return frame;
        }
    }
}

/// One initialized stdio session against `backend_url` under `mode`.
struct Session {
    client: tokio::io::DuplexStream,
    lines: tokio::io::Lines<BufReader<tokio::io::DuplexStream>>,
    task: tokio::task::JoinHandle<()>,
    dir: tempfile::TempDir,
}

/// Whether the session's gateway keeps a transparency log.
#[derive(Clone, Copy)]
enum Log {
    Off,
    On,
}

/// The transparency log's file, under the session's directory.
const AUDIT: &str = "audit.jsonl";

impl Session {
    async fn open(backend_url: &str, mode: &str) -> Self {
        Self::open_with(backend_url, mode, Log::Off).await
    }

    async fn open_with(backend_url: &str, mode: &str, log: Log) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        let quoted = |name: &str| {
            serde_json::to_string(&dir.path().join(name).display().to_string())
                .expect("a JSON string")
        };
        let log = match log {
            Log::Off => String::new(),
            Log::On => format!(
                "  transparency_log:\n    enabled: true\n    path: {}\n",
                quoted(AUDIT)
            ),
        };
        let yaml = format!(
            "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n\
             tasks:\n  store_dir: {}\n\
             security:\n{log}  firewall:\n    tenant_guard:\n      arg_keys: [customer_id]\n      cross_tenant_reads: {mode}\n",
            quoted("tasks")
        );
        crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
        let config = Config::load(Some(&path)).expect("config loads");
        let gateway = Gateway::new(config)
            .await
            .expect("gateway boots")
            .with_data_dir(dir.path().to_path_buf());
        let (client, input) = tokio::io::duplex(64 * 1024);
        let (output, reader) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(async move {
            drop(gateway.run_stdio_on(input, output, None).await);
        });
        let mut session = Self {
            client,
            lines: BufReader::new(reader).lines(),
            task,
            dir,
        };
        let init = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "min2", "version": "0"}},
        });
        let _ = session.ask(&init, 1).await;
        session
    }

    /// Send `frame` and wait for the answer to `id`.
    async fn ask(&mut self, frame: &Value, id: i64) -> Value {
        self.client
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("stdin");
        answer(&mut self.lines, id).await
    }

    /// Every record the session's transparency log holds, in order.
    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.path().join(AUDIT))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("log line is JSON"))
            .collect()
    }

    /// The delivery-attempt records of the session's tool calls, in order.
    fn call_deliveries(&self) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["event"] == "response_delivery_attempt")
            .filter(|r| r["tool"] == "gateway_invoke")
            .collect()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Round 7 (review P1): polling a task that is still working serves no
/// stored output, so it reads no tenant. Under block, the second poll of one
/// long-running task is answered like the first, not refused as a read of a
/// second, unknown tenant.
#[tokio::test]
async fn stdio_polls_of_a_working_task_are_not_refused() {
    let backend_url = spawn_backend_answering(Answer::Never).await;
    let mut session = Session::open(&backend_url, "block").await;
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":
            {"extensions": {"io.modelcontextprotocol/tasks": {}}},
        "io.modelcontextprotocol/clientInfo": {"name": "min2", "version": "0"},
    });
    let mut call: Value = serde_json::from_str(&call(2, "cust-a")).expect("call JSON");
    call["params"]["_meta"] = meta.clone();
    call["params"]["_meta"]["io.mcp-gateway/idempotency-key"] = json!("min2-working-task");
    call["params"]["task"] = json!({});
    let created = session.ask(&call, 2).await;
    let task_id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a task handle: {created}"))
        .to_owned();
    for id in [3, 4] {
        let poll = json!({"jsonrpc": "2.0", "id": id, "method": "tasks/get",
                          "params": {"taskId": task_id, "_meta": meta}});
        let poll = session.ask(&poll, id).await;
        assert_eq!(
            poll.pointer("/result/status").and_then(Value::as_str),
            Some("working"),
            "poll {id} of a working task is answered: {poll}"
        );
    }
}

/// The answers to two calls, A then B, under `mode`.
async fn a_then_b(mode: &str) -> (Value, Value) {
    let backend_url = spawn_backend().await;
    let mut session = Session::open(&backend_url, mode).await;
    let a = session
        .ask(&serde_json::from_str(&call(2, "cust-a")).expect("call"), 2)
        .await;
    let b = session
        .ask(&serde_json::from_str(&call(3, "cust-b")).expect("call"), 3)
        .await;
    (a, b)
}

#[tokio::test]
async fn stdio_a_then_b_block_refuses() {
    let (a, b) = a_then_b("off").await;
    assert!(a.get("result").is_some(), "control: off delivers A: {a}");
    assert!(b.get("result").is_some(), "control: off delivers B: {b}");

    let (a, b) = a_then_b("block").await;
    assert!(
        a.get("result").is_some(),
        "the first tenant is ordinary: {a}"
    );
    assert!(
        b.get("error").is_some() && b.get("result").is_none(),
        "a stdio read of B after A must be refused: {b}"
    );
}

/// The answers to one stdio batch `[A as id_a, B as id_b]` under block.
async fn batch_a_then_b(id_a: i64, id_b: i64) -> Vec<Value> {
    let backend_url = spawn_backend().await;
    let mut session = Session::open(&backend_url, "block").await;
    let batch = format!("[{},{}]", call(id_a, "cust-a"), call(id_b, "cust-b"));
    session
        .client
        .write_all(format!("{batch}\n").as_bytes())
        .await
        .expect("stdin");
    let line = tokio::time::timeout(Duration::from_secs(10), session.lines.next_line())
        .await
        .expect("the batch answer within the bound")
        .expect("stdout readable")
        .expect("stdout open");
    serde_json::from_str(&line).expect("one JSON array")
}

/// S1 (review findings 5 and round 2): a stdio batch answering A then B is
/// judged item by item, each with its own params and reading: block refuses
/// only the B item, also when the two items share an id.
#[tokio::test]
async fn stdio_batch_items_judged() {
    for (id_a, id_b) in [(2, 3), (2, 2)] {
        let answers = batch_a_then_b(id_a, id_b).await;
        assert_eq!(answers.len(), 2, "{answers:?}");
        assert!(
            answers[0].get("result").is_some(),
            "ids {id_a}/{id_b}: the A item is delivered: {answers:?}"
        );
        assert!(
            answers[1].get("error").is_some(),
            "ids {id_a}/{id_b}: the B item after A in one batch is refused: {answers:?}"
        );
    }
}

/// The delivery record's form of a served frame's hash.
fn hash_of(frame: &Value) -> String {
    format!("sha256:{}", crate::hashing::canonical_json_sha256(frame))
}

/// A logged session's answers to A then B under block.
async fn logged_a_then_b() -> (Session, Value, Value) {
    let backend_url = spawn_backend().await;
    let mut session = Session::open_with(&backend_url, "block", Log::On).await;
    let a = session
        .ask(&serde_json::from_str(&call(2, "cust-a")).expect("call"), 2)
        .await;
    let b = session
        .ask(&serde_json::from_str(&call(3, "cust-b")).expect("call"), 3)
        .await;
    assert!(a.get("result").is_some(), "base: A is delivered: {a}");
    assert!(b.get("error").is_some(), "base: B is refused: {b}");
    (session, a, b)
}

/// MIK-7920.STDIO.1 (MIK-7407.RESPONSE.5): the delivery record of a stdio read
/// the cross-tenant judge refused hashes the refusal the client received, not
/// the result it withheld. A's record is the control: it hashes A as served.
#[tokio::test]
async fn stdio_refused_read_records_the_refusal() {
    let (session, a, b) = logged_a_then_b().await;
    let deliveries = session.call_deliveries();
    assert_eq!(deliveries.len(), 2, "one record per call: {deliveries:#?}");
    assert_eq!(
        deliveries[0]["response_hash"],
        hash_of(&a).as_str(),
        "control: A's record is A as served: {:#}",
        deliveries[0]
    );
    assert_eq!(
        deliveries[1]["response_hash"],
        hash_of(&b).as_str(),
        "B's record must be the refusal served, not the withheld result: {:#}",
        deliveries[1]
    );
    assert_eq!(
        deliveries[1]["error_code"], b["error"]["code"],
        "{:#}",
        deliveries[1]
    );
}

/// MIK-7920.STDIO.2: a judged stdio read is one record, as on `/mcp` and the
/// direct route (MIK-7799): its verdict rides the delivery record, and no
/// standalone `tenant_read` record is written.
#[tokio::test]
async fn stdio_judged_read_is_one_record() {
    let (session, _a, _b) = logged_a_then_b().await;
    let records = session.records();
    assert!(
        !records.iter().any(|r| r["event"] == "tenant_read"),
        "a standalone tenant_read record: {records:#?}"
    );
    let deliveries = session.call_deliveries();
    assert!(
        deliveries
            .last()
            .is_some_and(|r| r.get("cross_tenant_read").is_some()),
        "B's delivery record carries its verdict: {deliveries:#?}"
    );
}

/// MIK-7920.STDIO.4: each batch item's delivery record hashes the item served.
#[tokio::test]
async fn stdio_batch_items_record_what_is_served() {
    let backend_url = spawn_backend().await;
    let mut session = Session::open_with(&backend_url, "block", Log::On).await;
    let batch = format!("[{},{}]", call(2, "cust-a"), call(3, "cust-b"));
    session
        .client
        .write_all(format!("{batch}\n").as_bytes())
        .await
        .expect("stdin");
    let line = tokio::time::timeout(Duration::from_secs(10), session.lines.next_line())
        .await
        .expect("the batch answer within the bound")
        .expect("stdout readable")
        .expect("stdout open");
    let answers: Vec<Value> = serde_json::from_str(&line).expect("one JSON array");
    assert_eq!(answers.len(), 2, "{answers:?}");
    assert!(
        answers[1].get("error").is_some(),
        "base: B is refused: {answers:?}"
    );
    let deliveries = session.call_deliveries();
    assert_eq!(deliveries.len(), 2, "one record per item: {deliveries:#?}");
    for (item, record) in answers.iter().zip(&deliveries) {
        assert_eq!(
            record["response_hash"],
            hash_of(item).as_str(),
            "the record hashes the item served: {item} vs {record:#}"
        );
    }
}

/// MIK-8195 W4: `tasks/*` over stdio is served only to a modern request that
/// declared the Tasks extension. A 2025 request is not found; a modern one
/// without the extension is refused with the capability code, and neither
/// reaches the store.
#[tokio::test]
async fn stdio_tasks_methods_refuse_legacy_and_undeclared_requests() {
    let backend_url = spawn_backend().await;
    let mut session = Session::open(&backend_url, "off").await;

    let legacy = json!({"jsonrpc": "2.0", "id": 2, "method": "tasks/get",
                        "params": {"taskId": "absent"}});
    let legacy = session.ask(&legacy, 2).await;
    assert_eq!(
        legacy.pointer("/error/code"),
        Some(&json!(-32601)),
        "{legacy}"
    );
    assert!(
        legacy
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("requires MCP 2026-07-28")),
        "{legacy}"
    );

    let undeclared = json!({"jsonrpc": "2.0", "id": 3, "method": "tasks/get",
    "params": {"taskId": "absent", "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "min2", "version": "0"},
    }}});
    let undeclared = session.ask(&undeclared, 3).await;
    assert_eq!(
        undeclared.pointer("/error/code"),
        Some(&json!(
            crate::protocol::era::MISSING_REQUIRED_CLIENT_CAPABILITY
        )),
        "{undeclared}"
    );
}
