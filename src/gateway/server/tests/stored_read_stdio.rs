// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392.STORED.1 T2 (batch A): stdio tasks/get, through the real serve
//! loop over in-memory pipes, judges the stored task's target against the
//! current catalogue. Once the listing withholds the tool, the read answers
//! -32601 ("Unknown tool"), never the stored output. The control reads the
//! same task while the tool is visible.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::config::Config;
use crate::gateway::Gateway;

const BACKEND: &str = "fixture";
const TOOL: &str = "rows";
const OUTPUT: &str = "stored-output-8392-t2";

/// An HTTP MCP backend whose one tool answers [`OUTPUT`].
async fn spawn_backend() -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(|axum::Json(request): axum::Json<Value>| async move {
            let result = match request.get("method").and_then(Value::as_str).unwrap_or("") {
                "initialize" => json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": BACKEND, "version": "0"},
                }),
                "tools/list" => json!({"tools": [{
                    "name": TOOL, "description": "reads rows", "inputSchema": {"type": "object"},
                }]}),
                "tools/call" => {
                    json!({"content": [{"type": "text", "text": OUTPUT}], "isError": false})
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

struct Session {
    client: tokio::io::DuplexStream,
    lines: tokio::io::Lines<BufReader<tokio::io::DuplexStream>>,
    backends: Arc<crate::backend::BackendRegistry>,
    task: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Session {
    async fn open(backend_url: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        let store = serde_json::to_string(&dir.path().join("tasks").display().to_string())
            .expect("a JSON string");
        let yaml = format!(
            "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n\
             tasks:\n  store_dir: {store}\n"
        );
        crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
        let config = Config::load(Some(&path)).expect("config loads");
        let gateway = Gateway::new(config)
            .await
            .expect("gateway boots")
            .with_data_dir(dir.path().to_path_buf());
        let backends = Arc::clone(&gateway.backends);
        let (client, input) = tokio::io::duplex(64 * 1024);
        let (output, reader) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(async move {
            drop(gateway.run_stdio_on(input, output, None).await);
        });
        let mut session = Self {
            client,
            lines: BufReader::new(reader).lines(),
            backends,
            task,
            _dir: dir,
        };
        let init = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "s1-t2", "version": "0"}},
        });
        let _ = session.ask(&init, 1).await;
        session
    }

    async fn ask(&mut self, frame: &Value, id: i64) -> Value {
        self.client
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("stdin");
        loop {
            let line = tokio::time::timeout(Duration::from_secs(10), self.lines.next_line())
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
}

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":
            {"extensions": {"io.modelcontextprotocol/tasks": {}}},
        "io.modelcontextprotocol/clientInfo": {"name": "s1-t2", "version": "0"},
    })
}

/// T2: red on the release line, where stdio tasks/get delivers the output.
#[tokio::test]
async fn t2_stdio_tasks_get_answers_absent_once_the_listing_withholds_the_tool() {
    let backend_url = spawn_backend().await;
    let mut session = Session::open(&backend_url).await;
    let mut meta = modern_meta();
    meta["io.mcp-gateway/idempotency-key"] = json!("s1-t2");
    let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {}},
        "task": {}, "_meta": meta}});
    let created = session.ask(&call, 2).await;
    let task_id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {created}"))
        .to_owned();
    let get = |id: i64| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tasks/get",
            "params": {"taskId": task_id, "_meta": modern_meta()}})
    };
    let bound = std::time::Instant::now() + Duration::from_secs(10);
    let mut next = 10;
    let control = loop {
        let got = session.ask(&get(next), next).await;
        next += 1;
        if got.to_string().contains(OUTPUT) || std::time::Instant::now() >= bound {
            break got;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        control.to_string().contains(OUTPUT),
        "control: while visible the stored output is served: {control}"
    );
    let invalid: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": 7}
    }))
    .expect("a tool");
    session
        .backends
        .get(BACKEND)
        .expect("the backend is registered")
        .store_shared_tools_for_test(vec![invalid]);
    let read = session.ask(&get(next), next).await;
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "T2: a blocked stored read answers as an absent name: {read}"
    );
    assert!(
        !read.to_string().contains(OUTPUT),
        "T2: output delivered: {read}"
    );
    // The criterion: indistinguishable from a name that matches no tool. The
    // same session calls the tool by its own name, which nothing surfaces.
    let twin_id = next + 1;
    let twin = session
        .ask(
            &json!({"jsonrpc": "2.0", "id": twin_id, "method": "tools/call",
                "params": {"name": TOOL, "arguments": {}, "_meta": modern_meta()}}),
            twin_id,
        )
        .await;
    assert!(
        twin.get("error").is_some(),
        "premise: an absent name is refused: {twin}"
    );
    assert_eq!(
        read.get("error"),
        twin.get("error"),
        "T2: a blocked stored read answers exactly as an absent name on stdio"
    );
}
