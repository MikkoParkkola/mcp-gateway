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
                // `cmd: "leak"` answers a credential the firewall redacts.
                "tools/call" => {
                    let leak = request.pointer("/params/arguments/cmd") == Some(&json!("leak"));
                    let text = if leak {
                        // The egress fixture's credential, which is firewall-gated.
                        format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890")
                    } else {
                        OUTPUT.to_owned()
                    };
                    json!({"content": [{"type": "text", "text": text}], "isError": false})
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
    dir: tempfile::TempDir,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Session {
    async fn open(backend_url: &str) -> Self {
        Self::open_with(backend_url, "").await
    }

    /// [`Self::open`] with `extra` appended to the gateway's config, `{DIR}`
    /// in it standing for the session's own directory.
    async fn open_with(backend_url: &str, extra: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let extra = extra.replace("{DIR}", &dir.path().display().to_string());
        let path = dir.path().join("gateway.yaml");
        let store = serde_json::to_string(&dir.path().join("tasks").display().to_string())
            .expect("a JSON string");
        let yaml = format!(
            "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n\
             tasks:\n  store_dir: {store}\n{extra}"
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
            dir,
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

/// A modern `tasks/get` of `task_id`.
fn get(task_id: &str, id: i64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tasks/get",
        "params": {"taskId": task_id, "_meta": modern_meta()}})
}

/// A task of `gateway_invoke` under idempotency `key`, read with `tasks/get`
/// until its stored output is served: the task id, the last read, and the
/// next free request id.
async fn stored_task(session: &mut Session, key: &str) -> (String, Value, i64) {
    let mut meta = modern_meta();
    meta["io.mcp-gateway/idempotency-key"] = json!(key);
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
    let bound = std::time::Instant::now() + Duration::from_secs(10);
    let mut next = 10;
    loop {
        let got = session.ask(&get(&task_id, next), next).await;
        next += 1;
        if got.to_string().contains(OUTPUT) || std::time::Instant::now() >= bound {
            return (task_id, got, next);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// T2: red on the release line, where stdio tasks/get delivers the output.
#[tokio::test]
async fn t2_stdio_tasks_get_answers_absent_once_the_listing_withholds_the_tool() {
    let backend_url = spawn_backend().await;
    let mut session = Session::open(&backend_url).await;
    let (task_id, control, next) = stored_task(&mut session, "s1-t2").await;
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
    let read = session.ask(&get(&task_id, next), next).await;
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

/// A session whose gateway writes a transparency log in its own directory,
/// and the log's path.
async fn logged_session() -> (Session, std::path::PathBuf) {
    logged_session_with("").await
}

/// [`logged_session`] with `security` appended under its `security:` key.
async fn logged_session_with(security: &str) -> (Session, std::path::PathBuf) {
    let backend_url = spawn_backend().await;
    // Single quotes: in a double-quoted scalar a Windows path's backslashes are escapes.
    let extra = format!(
        "security:\n  transparency_log:\n    enabled: true\n    path: '{{DIR}}/audit.jsonl'\n{security}"
    );
    let session = Session::open_with(&backend_url, &extra).await;
    let log = session.dir.path().join("audit.jsonl");
    (session, log)
}

/// The delivery records of `gateway_invoke` calls in the log at `path`.
fn invoke_deliveries(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| {
            row["event"] == "response_delivery_attempt" && row["tool"] == "gateway_invoke"
        })
        .collect()
}

fn invoke(id: i64) -> Value {
    invoke_cmd(id, "read")
}

fn invoke_cmd(id: i64, cmd: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"cmd": cmd}},
    }})
}

/// The real serve loop opens one delivery's facts per message: a call
/// through it records what the gateway did to the answer.
#[tokio::test]
async fn the_serve_loop_records_a_delivery_effect() {
    let (mut session, log) = logged_session().await;
    let answer = session.ask(&invoke(2), 2).await;
    assert!(answer.get("error").is_none(), "premise: answered: {answer}");
    let rows = invoke_deliveries(&log);
    let [row] = rows.as_slice() else {
        panic!("one delivery record: {rows:?}");
    };
    assert_eq!(row["response_effect"], "delivered", "{row}");
}

/// Each batch item through the real serve loop gets its own delivery's facts
/// (A14): of a redacted item and a clean one, one records `rewritten` and the
/// other `delivered`, never one cell's effect for both.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_batch_item_records_a_delivery_effect() {
    let warn = "  firewall:\n    enabled: true\n    rules:\n      - match: \"rows\"\n        action: warn\n";
    let (mut session, log) = logged_session_with(warn).await;
    let batch = json!([invoke_cmd(3, "leak"), invoke_cmd(4, "plain")]);
    session
        .client
        .write_all(format!("{batch}\n").as_bytes())
        .await
        .expect("stdin");
    let answer = loop {
        let line = tokio::time::timeout(Duration::from_secs(10), session.lines.next_line())
            .await
            .expect("an answer within the bound")
            .expect("stdout readable")
            .expect("stdout open");
        let frame: Value = serde_json::from_str(&line).expect("one JSON frame per line");
        if frame.is_array() {
            break frame;
        }
    };
    let text = answer.to_string();
    assert!(
        text.contains("[REDACTED") && text.contains(OUTPUT) && !text.contains("\"error\""),
        "premise: one redacted, one clean, both answered: {answer}"
    );
    let mut effects: Vec<Value> = invoke_deliveries(&log)
        .iter()
        .map(|row| row["response_effect"].clone())
        .collect();
    effects.sort_by_key(Value::to_string);
    assert_eq!(effects, [json!("delivered"), json!("rewritten")]);
}

/// A task read serves the stored answer, not one this request produced: its
/// delivery states no effect and no findings.
#[tokio::test]
async fn a_stdio_task_read_states_no_effect() {
    let (mut session, log) = logged_session().await;
    let (_, read, _) = stored_task(&mut session, "unvouched-read").await;
    assert!(read.to_string().contains(OUTPUT), "premise: served: {read}");
    let rows: Vec<Value> = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| row["event"] == "response_delivery_attempt")
        .collect();
    let row = rows.last().expect("the read's delivery record");
    for field in ["response_effect", "response_findings"] {
        assert!(row.get(field).is_none(), "{field}: {row}");
    }
}

/// The delivery record of the one `gateway_invoke` call in the log at `log`.
fn only_invoke_delivery(log: &std::path::Path) -> Value {
    let rows = invoke_deliveries(log);
    let [row] = rows.as_slice() else {
        panic!("one delivery record: {rows:?}");
    };
    row.clone()
}

/// Response inspection read this clean answer and found nothing,
/// so with no firewall the record says scanned clean (`[]`), not unscanned.
#[tokio::test]
async fn an_inspected_clean_answer_records_no_findings() {
    let (mut session, log) = logged_session().await;
    let answer = session.ask(&invoke(5), 5).await;
    assert!(answer.get("error").is_none(), "premise: answered: {answer}");
    let row = only_invoke_delivery(&log);
    assert_eq!(row["response_findings"], json!([]), "{row}");
    assert_eq!(row["response_effect"], "delivered", "{row}");
}

/// With response inspection disabled and the firewall's response scan off,
/// no scanner reads the answer, so the record says no scan ran (`null`),
/// never "scanned clean". (With the firewall's scan on, `[]` is correct: the
/// firewall read it.)
#[tokio::test]
async fn a_disabled_inspection_records_no_scan() {
    let disabled =
        "  response_inspection:\n    enabled: false\n  firewall:\n    scan_responses: false\n";
    let (mut session, log) = logged_session_with(disabled).await;
    let answer = session.ask(&invoke(6), 6).await;
    assert!(answer.get("error").is_none(), "premise: answered: {answer}");
    let row = only_invoke_delivery(&log);
    assert_eq!(row["response_findings"], json!(null), "{row}");
}
