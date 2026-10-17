// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design row 14: once the U1 seal is taken, both HTTP routes refuse a
//! request that reaches its count point (503 with its own id), while a
//! request counted before the seal still completes. With the window mode
//! `off`, every request is served, as in 3.5.x.
//!
//! - Held *before* counting: a request held in its body read across the
//!   shutdown, so its count point runs after the seal.
//! - Held *after* counting: a request forwarded to a backend that holds it.
//! - The seal is observed as the final window write entering its stall gate
//!   (the seal is taken before that write is queued), so refusals are proven
//!   while persistence is still stalled, and no row waits on a sleep or on
//!   the disk.
//!
//! Counted totals are not asserted here: the in-process gateway counts into
//! the process-wide registry other rows share. "Refused and not counted" is
//! pinned on an isolated registry in `protocol_revision_telemetry::slice_tests`.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::super::Gateway;
use super::window_seal_http_backend::HeldBackend;
use crate::config::{BackendConfig, Config, ProtocolRevisionWindow, TransportConfig};
use crate::protocol_revision_telemetry::window::{self, stall_seam};

/// Bound on each wait for something that must happen.
const ARRIVAL: Duration = Duration::from_secs(60);

fn config(dir: &std::path::Path, mode: ProtocolRevisionWindow, backend: &str) -> Config {
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = 0;
    config.server.shutdown_timeout = Duration::from_secs(30);
    config.server.protocol_revision_window = mode;
    config.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
    config.backends.insert(
        "remote_docs".to_string(),
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: backend.to_string(),
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..BackendConfig::r2_off()
        },
    );
    config
}

fn initialize(id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "row14", "version": "1"}}
    })
    .to_string()
}

/// Send `path`'s headers and `body`, keeping back its last byte if `hold`.
async fn send(port: u16, path: &str, body: &str, hold: bool) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\nUser-Agent: curl/8.4.0\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.expect("headers");
    let sent = if hold { body.len() - 1 } else { body.len() };
    stream.write_all(&body.as_bytes()[..sent]).await.expect("body");
    stream
}

/// Send the held last byte (if any) and read the whole answer.
async fn answer(mut stream: TcpStream, body: &str, held: bool) -> (u16, String) {
    if held {
        // A server that answered early has closed its read side; the answer
        // is still readable, and it is what the row judges.
        let _ = stream.write_all(&body.as_bytes()[body.len() - 1..]).await;
    }
    let mut response = Vec::new();
    tokio::time::timeout(ARRIVAL, stream.read_to_end(&mut response))
        .await
        .expect("a response arrives")
        .expect("read the response");
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, text)
}

async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(start.elapsed() < ARRIVAL, "{what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// What a row observed: the two requests held before counting (`/mcp`, then
/// `/mcp/{name}`) and the one held after counting (`/mcp/{name}`).
struct Answers {
    meta_before: (u16, String),
    backend_before: (u16, String),
    backend_after: (u16, String),
}

async fn across_shutdown(mode: ProtocolRevisionWindow) -> Answers {
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = HeldBackend::start().await;
    let mut gateway = Gateway::new(config(dir.path(), mode, &backend.url))
        .await
        .expect("gateway")
        .with_data_dir(dir.path().to_path_buf())
        .with_window_save_interval(Duration::from_secs(3600));
    let bound = gateway.bound_port_for_test();
    let gate = gateway.inflight_for_test();
    let trigger = gateway.shutdown_trigger_for_test();
    let server = tokio::spawn(async move { Box::pin(gateway.run()).await });
    let port = tokio::time::timeout(ARRIVAL, bound)
        .await
        .expect("binds")
        .expect("reports its port");
    let gate = gate.await.expect("run hands over its in-flight gate");
    let idle = gate.available_permits();

    let path = window::window_paths(dir.path()).0;
    let record = mode == ProtocolRevisionWindow::Record;
    if record {
        eventually("the segment never opened", || {
            window::load(dir.path()).is_ok_and(|w| w.http_segments.len() == 1)
        })
        .await;
    }
    let (close_in, close_go) = stall_seam::arm(&path, stall_seam::Role::Close);

    let (after_body, meta_body, backend_body) = (initialize(43), initialize(41), initialize(42));
    let after = send(port, "/mcp/remote_docs", &after_body, false).await;
    let meta = send(port, "/mcp", &meta_body, true).await;
    let held = send(port, "/mcp/remote_docs", &backend_body, true).await;
    // `/mcp/{name}` takes its in-flight permit before reading the body, so two
    // taken permits mean both backend-route requests are in their handlers.
    // The `/mcp` request was accepted before the second of them, on the same
    // listener, so it is in its body read too.
    eventually("the held requests never reached their handlers", || {
        gate.available_permits() <= idle - 2
    })
    .await;

    trigger.send(()).expect("run holds the trigger");
    if record {
        let close_in = Arc::new(std::sync::Mutex::new(close_in));
        let entered = tokio::task::spawn_blocking(move || {
            close_in
                .lock()
                .expect("receiver")
                .recv_timeout(ARRIVAL)
                .is_ok()
        });
        assert!(entered.await.expect("join"), "the shutdown never sealed");
    }
    let meta_before = answer(meta, &meta_body, true).await;
    let backend_before = answer(held, &backend_body, true).await;
    backend.release();
    let backend_after = answer(after, &after_body, false).await;
    drop(close_go);
    let _ = tokio::time::timeout(ARRIVAL, server).await;
    Answers {
        meta_before,
        backend_before,
        backend_after,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_record_a_request_counted_after_the_seal_is_refused_on_both_routes() {
    let answers = across_shutdown(ProtocolRevisionWindow::Record).await;
    let (status, meta) = &answers.meta_before;
    assert_eq!(*status, 503, "{meta}");
    assert!(meta.contains("\"id\":41"), "{meta}");
    let (status, backend) = &answers.backend_before;
    assert_eq!(*status, 503, "{backend}");
    assert!(backend.contains("\"id\":42"), "{backend}");
    let (status, after) = &answers.backend_after;
    assert_ne!(*status, 503, "a request counted before the seal was refused: {after}");
    assert!(!after.contains("window sealed"), "{after}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_off_every_request_is_served_across_the_shutdown() {
    let answers = across_shutdown(ProtocolRevisionWindow::Off).await;
    for (status, text) in [
        &answers.meta_before,
        &answers.backend_before,
        &answers.backend_after,
    ] {
        assert_ne!(*status, 503, "{text}");
        assert!(!text.contains("window sealed"), "{text}");
    }
    assert_eq!(answers.meta_before.0, 200, "{}", answers.meta_before.1);
}
