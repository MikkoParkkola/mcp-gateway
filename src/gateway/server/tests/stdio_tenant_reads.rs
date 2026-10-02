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
                "tools/list" => json!({"tools": [{
                    "name": TOOL,
                    "description": "reads rows",
                    "inputSchema": {"type": "object"},
                }]}),
                "tools/call" => json!({
                    "content": [{"type": "text", "text": "ok"}],
                    "isError": false,
                }),
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

/// The answers to two calls, A then B, under `mode`.
async fn a_then_b(mode: &str) -> (Value, Value) {
    let backend_url = spawn_backend().await;
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
    let (mut client, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(async move {
        drop(gateway.run_stdio_on(input, output, None).await);
    });
    let mut lines = BufReader::new(reader).lines();
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "min2", "version": "0"}},
    });
    client
        .write_all(format!("{init}\n").as_bytes())
        .await
        .expect("stdin");
    let _ = answer(&mut lines, 1).await;
    client
        .write_all(format!("{}\n", call(2, "cust-a")).as_bytes())
        .await
        .expect("stdin");
    let a = answer(&mut lines, 2).await;
    client
        .write_all(format!("{}\n", call(3, "cust-b")).as_bytes())
        .await
        .expect("stdin");
    let b = answer(&mut lines, 3).await;
    drop(client);
    task.abort();
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
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n\
         tasks:\n  store_dir: {}\n\
         security:\n  firewall:\n    tenant_guard:\n      arg_keys: [customer_id]\n      cross_tenant_reads: block\n",
        serde_json::to_string(&dir.path().join("tasks").display().to_string())
            .expect("a JSON string")
    );
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("config loads");
    let gateway = Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());
    let (mut client, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(async move {
        drop(gateway.run_stdio_on(input, output, None).await);
    });
    let mut lines = BufReader::new(reader).lines();
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "min2", "version": "0"}},
    });
    client
        .write_all(format!("{init}\n").as_bytes())
        .await
        .expect("stdin");
    let _ = answer(&mut lines, 1).await;
    let batch = format!("[{},{}]", call(id_a, "cust-a"), call(id_b, "cust-b"));
    client
        .write_all(format!("{batch}\n").as_bytes())
        .await
        .expect("stdin");
    let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("the batch answer within the bound")
        .expect("stdout readable")
        .expect("stdout open");
    drop(client);
    task.abort();
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
