// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R22: the resend after an expired session follows a
//! request that reached the server, so a never-sent error from the resend
//! must not tell the caller nothing ran.

use super::*;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};

const FRESH: &str = "fresh-session-after-expiry";

/// One request read off `stream`: its method line, headers and body.
fn read_request(stream: &std::net::TcpStream) -> (String, String, Value) {
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    reader.read_line(&mut first).expect("a request line");
    let mut headers = String::new();
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("a header line");
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().expect("a length");
        }
        headers.push_str(&line);
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).expect("the body");
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (first, headers, body)
}

fn respond(mut stream: &std::net::TcpStream, status: &str, extra: &str, body: &str) {
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n{extra}\r\n{body}",
        body.len()
    );
    stream.write_all(reply.as_bytes()).expect("write the reply");
}

/// A server that answers the stale session's request with 404 (expired),
/// re-initialises, and closes its own listener when the client confirms the
/// new session (`notifications/initialized`) and before answering it. Every
/// reply closes its connection, so the resend must connect again, and is
/// refused: deterministic, no race.
fn expiring_server() -> (String, std::sync::mpsc::Receiver<usize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("address"));
    let (done, served_count) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut served = 0usize;
        let mut listener = Some(listener);
        while let Some(open) = listener.as_ref() {
            let (stream, _) = open.accept().expect("accept");
            let (first, headers, body) = read_request(&stream);
            served += 1;
            let method = body["method"].as_str().unwrap_or_default().to_owned();
            if !first.starts_with("POST") {
                respond(&stream, "405 Method Not Allowed", "", "");
            } else if method == "initialize" {
                let result = json!({"jsonrpc": "2.0", "id": body["id"], "result": {
                    "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                    "serverInfo": {"name": "mock", "version": "0"}}});
                respond(
                    &stream,
                    "200 OK",
                    &format!("mcp-session-id: {FRESH}\r\n"),
                    &result.to_string(),
                );
            } else if body.get("id").is_none() {
                // The new session is confirmed: stop listening first, then answer.
                drop(listener.take());
                respond(&stream, "202 Accepted", "", "");
            } else if !headers.contains(FRESH) {
                respond(&stream, "404 Not Found", "", "");
            } else {
                let result = json!({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": []}});
                respond(&stream, "200 OK", "", &result.to_string());
            }
        }
        let _ = done.send(served);
    });
    (url, served_count)
}

/// R22: the stale session's request reached the server (404), the session
/// was healed, and the resend never connected. The transport answers a
/// failure that may have run (`Transport`), with the connect cause kept, not
/// the never-sent `TransportConnect` that would release the caller's key.
///
/// The freed port can be bound by a test running in parallel before the
/// resend connects; that resend then meets a stranger, not a refusal. Every
/// run must still read may-have-run; the scenario runs again until one resend
/// met the refusal this row is about.
#[tokio::test]
async fn a_resend_that_never_connected_after_an_expired_session_may_have_run() {
    for _ in 0..3 {
        // A resend answered at all met a stranger on the freed port.
        let Some(error) = resend_after_expiry().await else {
            continue;
        };
        assert!(
            matches!(error, crate::Error::Transport(_)),
            "a resend after a sent request read as never sent: {error:?}"
        );
        assert!(!error.is_pre_dispatch(), "{error:?}");
        if error
            .to_string()
            .contains("after the expired session's request was sent")
        {
            return;
        }
    }
    panic!("no run's resend met a refused connection");
}

/// One run: a session that expires, heals, and whose resend is refused;
/// `None` when the resend was answered.
async fn resend_after_expiry() -> Option<crate::Error> {
    let (url, served_count) = expiring_server();
    let transport = make_transport(&url);
    *transport.message_url.write() = Some(url.clone());
    set_default_session(&transport, "stale-session");
    let error = transport.request("tools/list", None).await.err();
    // Bounded, so a server left waiting on a connection that never came fails
    // the row instead of hanging it.
    let served = served_count
        .recv_timeout(Duration::from_secs(30))
        .expect("the server closed its listener");
    assert!(
        served >= 3,
        "premise: the stale request, initialize and its confirmation were served ({served})"
    );
    assert_eq!(
        default_session(&transport).as_deref(),
        Some(FRESH),
        "premise: the session was healed"
    );
    error
}
