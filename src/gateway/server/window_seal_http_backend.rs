// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stand-in streamable-HTTP backend for the row-14 shutdown tests: it holds
//! every request until the row releases it, then answers each with its own
//! id. A request forwarded to it has passed its count point, so holding it
//! keeps a counted request in flight across the seal.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// The backend's URL and the release every held request waits on.
pub(super) struct HeldBackend {
    pub(super) url: String,
    released: Arc<Notify>,
    gate: Arc<std::sync::atomic::AtomicBool>,
    seen: Seen,
}

/// The client name of the one request this backend holds.
pub(super) const HELD_MARKER: &str = "row14-after";

/// Every request body the backend has read, in arrival order.
type Seen = Arc<std::sync::Mutex<Vec<String>>>;

impl HeldBackend {
    pub(super) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind backend");
        let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
        let released = Arc::new(Notify::new());
        let gate = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = Seen::default();
        let (wait, open, log) = (Arc::clone(&released), Arc::clone(&gate), Arc::clone(&seen));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (wait, open, log) = (Arc::clone(&wait), Arc::clone(&open), Arc::clone(&log));
                tokio::spawn(answer(stream, wait, open, log));
            }
        });
        Self {
            url,
            released,
            gate,
            seen,
        }
    }

    /// Whether a request body naming `marker` has reached the backend.
    pub(super) fn received(&self, marker: &str) -> bool {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|body| body.contains(marker))
    }

    /// Answer every held request, and every later one at once.
    pub(super) fn release(&self) {
        self.gate.store(true, std::sync::atomic::Ordering::SeqCst);
        self.released.notify_waiters();
    }
}

async fn answer(
    mut stream: TcpStream,
    released: Arc<Notify>,
    open: Arc<std::sync::atomic::AtomicBool>,
    seen: Seen,
) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let (head_end, length) = loop {
        let Ok(read) = stream.read(&mut chunk).await else { return };
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (end + 4, length);
        }
    };
    while buffer.len() < head_end + length {
        let Ok(read) = stream.read(&mut chunk).await else { return };
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    if buffer.starts_with(b"GET") {
        let _ = stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n")
            .await;
        return;
    }
    seen.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(String::from_utf8_lossy(&buffer[head_end..head_end + length]).into_owned());
    // Only the row's own request is held; the gateway's own handshake with
    // this backend is answered at once, or it would block the forward.
    let released = released.notified();
    let held = String::from_utf8_lossy(&buffer[head_end..head_end + length]).contains(HELD_MARKER);
    if held && !open.load(std::sync::atomic::Ordering::SeqCst) {
        released.await;
    }
    let body: serde_json::Value =
        serde_json::from_slice(&buffer[head_end..head_end + length]).unwrap_or_default();
    let reply = match body.get("id") {
        Some(id) => serde_json::json!({
            "jsonrpc": "2.0", "id": id,
            "result": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "serverInfo": {"name": "held", "version": "1"}, "tools": []}
        })
        .to_string(),
        None => String::new(),
    };
    let status = if reply.is_empty() { "202 Accepted" } else { "200 OK" };
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{reply}",
        reply.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}
