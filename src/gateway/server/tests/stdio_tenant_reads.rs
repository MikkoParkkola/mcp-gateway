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
    _dir: tempfile::TempDir,
}

impl Session {
    async fn open(backend_url: &str, mode: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        let yaml = format!(
            "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n\
             tasks:\n  store_dir: {}\n\
             security:\n  firewall:\n    tenant_guard:\n      arg_keys: [customer_id]\n      cross_tenant_reads: {mode}\n",
            serde_json::to_string(&dir.path().join("tasks").display().to_string())
                .expect("a JSON string")
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
            _dir: dir,
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
