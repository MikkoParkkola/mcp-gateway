// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design row 14: after the U1 seal, both HTTP routes refuse a request that
//! reaches its count point (503, its own id) and do not count it; with the
//! window mode `off` the same request is served, as in 3.5.x.
//!
//! The request is held in its body read across the shutdown, so its handler
//! (and its count point) runs after the seal. The row waits on the sealed
//! segment in the window file, never on a sleep.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::super::Gateway;
use crate::config::{BackendConfig, Config, ProtocolRevisionWindow, TransportConfig};
use crate::protocol_revision_telemetry::window;

/// Bound on each wait for something that must happen.
const ARRIVAL: Duration = Duration::from_secs(60);

fn config(dir: &std::path::Path, mode: ProtocolRevisionWindow) -> Config {
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
                http_url: "http://127.0.0.1:65535/mcp".to_string(),
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..BackendConfig::r2_off()
        },
    );
    config
}

/// Send `path`'s headers and all but the last body byte; the caller finishes it.
async fn held_request(port: u16, path: &str, body: &str) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\nUser-Agent: curl/8.4.0\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.expect("headers");
    stream
        .write_all(&body.as_bytes()[..body.len() - 1])
        .await
        .expect("most of the body");
    stream
}

async fn finish(mut stream: TcpStream, body: &str) -> (u16, String) {
    // A server that answered early (without reading the body) has closed its
    // read side; the answer is still readable, and it is what the row judges.
    let _ = stream.write_all(&body.as_bytes()[body.len() - 1..]).await;
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

fn initialize(id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "row14", "version": "1"}}
    })
    .to_string()
}

/// Start `run`, hold one request on each route, trigger the shutdown, and
/// finish both requests once `ready` says the shutdown has reached them.
async fn across_shutdown(
    mode: ProtocolRevisionWindow,
    ready: impl Fn(&std::path::Path) -> bool,
) -> ([(u16, String); 2], Option<u64>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut gateway = Gateway::new(config(dir.path(), mode))
        .await
        .expect("gateway")
        .with_data_dir(dir.path().to_path_buf());
    let bound = gateway.bound_port_for_test();
    let trigger = gateway.shutdown_trigger_for_test();
    let server = tokio::spawn(async move { Box::pin(gateway.run()).await });
    let port = tokio::time::timeout(ARRIVAL, bound)
        .await
        .expect("binds")
        .expect("reports its port");

    let (meta_body, backend_body) = (initialize(41), initialize(42));
    let meta = held_request(port, "/mcp", &meta_body).await;
    let backend = held_request(port, "/mcp/remote_docs", &backend_body).await;
    trigger.send(()).expect("run holds the trigger");
    let start = std::time::Instant::now();
    while !ready(dir.path()) {
        assert!(start.elapsed() < ARRIVAL, "the shutdown never reached its seal");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let answers = [finish(meta, &meta_body).await, finish(backend, &backend_body).await];
    let _ = tokio::time::timeout(ARRIVAL, server).await;
    let sealed_total = window::load(dir.path())
        .ok()
        .and_then(|w| w.http_segments.first().map(|s| s.snapshot.total));
    (answers, sealed_total)
}

fn sealed(dir: &std::path::Path) -> bool {
    window::load(dir).is_ok_and(|w| w.http_segments.first().is_some_and(|s| s.closed_cleanly))
}

#[tokio::test]
async fn with_record_both_routes_refuse_a_request_counted_after_the_seal() {
    let ([(meta_status, meta), (backend_status, backend)], sealed_total) =
        across_shutdown(ProtocolRevisionWindow::Record, sealed).await;
    assert_eq!(meta_status, 503, "{meta}");
    assert!(meta.contains("\"id\":41"), "{meta}");
    assert_eq!(backend_status, 503, "{backend}");
    assert!(backend.contains("\"id\":42"), "{backend}");
    assert_eq!(sealed_total, Some(0), "a refused request was counted");
}

#[tokio::test]
async fn with_off_the_same_requests_are_served() {
    // Nothing to wait on with `off`: give the shutdown its broadcast.
    let ([(meta_status, meta), (_, backend)], _) =
        across_shutdown(ProtocolRevisionWindow::Off, |_| true).await;
    assert_eq!(meta_status, 200, "{meta}");
    assert!(!backend.contains("window sealed"), "{backend}");
    assert!(!meta.contains("window sealed"), "{meta}");
}
