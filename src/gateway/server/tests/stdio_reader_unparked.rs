// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7684: the stdio reader never waits for stdout room.
//!
//! A client that stops reading stdout fills the writer queue. Parse errors and
//! batches used to be answered from the reader itself, so the reader parked on
//! the full queue and never read EOF: `run_stdio_on` did not return. Driven
//! through `Gateway::run_stdio_on` over in-memory pipes, with no backends.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::config::Config;
use crate::gateway::Gateway;

/// More lines than the writer queue holds (`STDOUT_QUEUE_DEPTH`), so on the
/// old code the reader parks before it reaches EOF.
const FLOOD: usize = super::super::STDOUT_QUEUE_DEPTH + 200;
/// Bound on each wait for a frame in the reading control.
const ARRIVAL: Duration = Duration::from_secs(10);

struct Served {
    stdin: DuplexStream,
    stdout: Lines<BufReader<DuplexStream>>,
    task: JoinHandle<crate::Result<()>>,
    _dir: tempfile::TempDir,
}

/// A gateway with no backends serving stdio. stdin is large, so the test's
/// own writes never wait on a parked reader; stdout holds `output_capacity`
/// bytes. The handshake is done and its answer read.
async fn serve(output_capacity: usize) -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let yaml = format!(
        "backends: {{}}\ntasks:\n  store_dir: {}\n",
        serde_json::to_string(&dir.path().join("tasks").display().to_string())
            .expect("a JSON string")
    );
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("config loads");
    let gateway = Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());
    let (stdin, input) = tokio::io::duplex(8 << 20);
    let (output, reader) = tokio::io::duplex(output_capacity);
    let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut served = Served {
        stdin,
        stdout: BufReader::new(reader).lines(),
        task,
        _dir: dir,
    };
    let initialize = json!({
        "jsonrpc": "2.0", "id": "init", "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mik7684", "version": "0"},
        },
    });
    send(&mut served.stdin, &initialize.to_string()).await;
    let line = timeout(ARRIVAL, served.stdout.next_line())
        .await
        .expect("the handshake is answered")
        .expect("stdout reads")
        .expect("stdout is open");
    let answer: Value = serde_json::from_str(&line).expect("one JSON frame");
    assert_eq!(answer["id"], json!("init"), "{answer}");
    served
}

async fn send(stdin: &mut DuplexStream, lines: &str) {
    stdin
        .write_all(format!("{lines}\n").as_bytes())
        .await
        .expect("write to the gateway's stdin");
}

fn batch(id: usize) -> String {
    json!([{"jsonrpc": "2.0", "id": id, "method": "ping"}]).to_string()
}

/// Close stdin with stdout still unread and require `run_stdio_on` to return
/// `Ok` within the drain deadline plus a margin.
async fn eof_returns_while_stdout_is_unread(mut served: Served) {
    drop(served.stdin);
    let bound = super::super::STDIO_DRAIN_TIMEOUT + Duration::from_secs(15);
    timeout(bound, &mut served.task)
        .await
        .unwrap_or_else(|_| panic!("run_stdio_on must return within {bound:?} of EOF"))
        .expect("the serve task does not panic")
        .expect("run_stdio_on returns Ok");
    // Held until here: dropping the reader would unblock the writer.
    drop(served.stdout);
}

/// T1. Parse errors past a full queue do not park the reader.
#[tokio::test]
async fn parse_errors_on_a_full_stdout_do_not_park_the_reader() {
    let mut served = serve(64).await;
    let flood = vec!["{not json"; FLOOD].join("\n");
    send(&mut served.stdin, &flood).await;
    eof_returns_while_stdout_is_unread(served).await;
}

/// T2 (AC2). Batches past a full queue do not park the reader.
#[tokio::test]
async fn batches_on_a_full_stdout_do_not_park_the_reader() {
    let mut served = serve(64).await;
    let flood: Vec<String> = (0..FLOOD).map(batch).collect();
    send(&mut served.stdin, &flood.join("\n")).await;
    eof_returns_while_stdout_is_unread(served).await;
}

/// T3. Positive control: a client that reads loses nothing. Every batch item,
/// every single request and every parse error is answered exactly once, read
/// through to EOF so a duplicate would be counted too.
#[tokio::test]
async fn a_reading_client_gets_every_answer() {
    let mut served = serve(1 << 20).await;
    let mut lines = Vec::new();
    for k in 0..10 {
        lines.push(
            json!([
                {"jsonrpc": "2.0", "id": k, "method": "ping"},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 200 + k, "method": "ping"},
            ])
            .to_string(),
        );
        lines.push("{not json".to_string());
        lines.push(json!({"jsonrpc": "2.0", "id": 100 + k, "method": "ping"}).to_string());
    }
    send(&mut served.stdin, &lines.join("\n")).await;
    drop(served.stdin);
    let mut batch_ids = Vec::new();
    let mut single_ids = Vec::new();
    let mut parse_errors = 0;
    while let Some(line) = timeout(ARRIVAL, served.stdout.next_line())
        .await
        .expect("stdout ends within the bound")
        .expect("stdout reads")
    {
        let frame: Value = serde_json::from_str(&line).expect("one JSON frame");
        match &frame {
            Value::Array(items) => {
                for item in items {
                    assert!(item.get("result").is_some(), "a batch item failed: {item}");
                    batch_ids.push(item["id"].clone());
                }
            }
            _ if frame["error"]["code"] == json!(-32700) => parse_errors += 1,
            _ if frame.get("method").is_none() => {
                assert!(frame.get("result").is_some(), "a ping failed: {frame}");
                single_ids.push(frame["id"].clone());
            }
            _ => {}
        }
    }
    batch_ids.sort_by_key(|id| id.as_u64());
    single_ids.sort_by_key(|id| id.as_u64());
    let expected: Vec<Value> = (0..10).chain(200..210).map(|k| json!(k)).collect();
    assert_eq!(batch_ids, expected);
    assert_eq!(single_ids, (100..110).map(|k| json!(k)).collect::<Vec<_>>());
    assert_eq!(parse_errors, 10);
    timeout(ARRIVAL, &mut served.task)
        .await
        .expect("EOF returns promptly when stdout is read")
        .expect("no panic")
        .expect("Ok");
}

/// T4. An `initialize` that cannot be queued ends the session instead of
/// parking the reader: with stdin still open and stdout unread, the serve
/// loop returns within the initialize bound, the drain and the teardown.
#[tokio::test]
async fn an_initialize_on_a_full_stdout_ends_the_session() {
    let mut served = serve(64).await;
    let flood = vec!["{not json"; FLOOD].join("\n");
    send(&mut served.stdin, &flood).await;
    let initialize = json!({
        "jsonrpc": "2.0", "id": "init-2", "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mik7684", "version": "0"},
        },
    });
    send(&mut served.stdin, &initialize.to_string()).await;
    let bound = super::super::STDIO_DRAIN_TIMEOUT * 2 + Duration::from_secs(25);
    timeout(bound, &mut served.task)
        .await
        .unwrap_or_else(|_| panic!("run_stdio_on must return within {bound:?}, stdin open"))
        .expect("the serve task does not panic")
        .expect("run_stdio_on returns Ok");
    drop((served.stdin, served.stdout));
}

/// The busy refusal of a batch keeps JSON-RPC 2.0 §6 shapes: one
/// invalid-request object for `[]`, an invalid request per non-object
/// element, a busy error per element with an id, nothing for notifications.
#[test]
fn a_refused_batch_is_answered_per_element() {
    let refuse = super::super::stdio_busy_batch_response;
    let invalid = json!({"jsonrpc": "2.0", "id": null,
        "error": {"code": -32600, "message": "Invalid Request"}});
    assert_eq!(refuse(&json!([])), Some(invalid.clone()));
    let refused = refuse(&json!([
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        1,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {},
    ]))
    .expect("three elements are answered");
    let items = refused.as_array().expect("an array");
    assert_eq!(items.len(), 3, "{refused}");
    assert_eq!(items[0]["id"], json!(1));
    assert_eq!(items[0]["error"]["code"], json!(-32000));
    assert_eq!(items[1], invalid);
    assert_eq!(
        items[2], invalid,
        "a malformed object is not a notification"
    );
    assert_eq!(
        refuse(&json!([{"jsonrpc": "2.0", "method": "notifications/initialized"}])),
        None
    );
}
