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
pub(super) fn read_request(stream: &std::net::TcpStream) -> (String, String, Value) {
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

pub(super) fn respond(mut stream: &std::net::TcpStream, status: &str, extra: &str, body: &str) {
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n{extra}\r\n{body}",
        body.len()
    );
    stream.write_all(reply.as_bytes()).expect("write the reply");
}

/// A listening socket on a loopback port, and on Linux a second socket bound
/// to the same port that never listens (both `SO_REUSEPORT`): closing the
/// listener leaves the port held by its twin, so no other socket can take it,
/// and a connection to it is refused. macOS drops a connection to a port such
/// a twin holds instead of refusing it, even beside the open listener, so
/// there no twin is bound: the closed listener's own connections stay in
/// `TIME_WAIT` (the server closes each first) and keep an ordinary bind off
/// the port, and a connection to it is refused.
pub(super) fn held_listener() -> (std::net::TcpListener, Option<tokio::net::TcpSocket>) {
    let listening = tokio::net::TcpSocket::new_v4().expect("a socket");
    #[cfg(target_os = "linux")]
    listening.set_reuseport(true).expect("reuse the port");
    listening
        .bind("127.0.0.1:0".parse().expect("an address"))
        .expect("bind");
    #[cfg(target_os = "linux")]
    let holder = {
        let port = listening.local_addr().expect("its address");
        let holder = tokio::net::TcpSocket::new_v4().expect("a socket");
        holder.set_reuseport(true).expect("reuse the port");
        holder.bind(port).expect("hold the port");
        Some(holder)
    };
    #[cfg(not(target_os = "linux"))]
    let holder = None;
    let listener = listening
        .listen(16)
        .expect("listen")
        .into_std()
        .expect("a std listener");
    listener.set_nonblocking(false).expect("blocking accepts");
    (listener, holder)
}

/// A server that answers the stale session's request with 404 (expired),
/// re-initialises, and closes its own listener when the client confirms the
/// new session (`notifications/initialized`) and before answering it. Every
/// reply closes its connection, so the resend must connect again, and is
/// refused: the port stays held ([`held_listener`]), so nothing else can
/// answer it. Keep the returned holder until the resend has failed.
///
/// Each request is reported (its method, or "GET") before it is answered, so
/// by the time the client has an answer, the server has already reported it.
fn expiring_server() -> (
    String,
    std::sync::mpsc::Receiver<String>,
    Option<tokio::net::TcpSocket>,
) {
    let (listener, holder) = held_listener();
    let url = format!("http://{}/mcp", listener.local_addr().expect("address"));
    let (report, served) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut listener = Some(listener);
        while let Some(open) = listener.as_ref() {
            let (stream, _) = open.accept().expect("accept");
            let (first, headers, body) = read_request(&stream);
            let method = body["method"].as_str().unwrap_or_default().to_owned();
            let _ = report.send(if first.starts_with("POST") {
                method.clone()
            } else {
                "GET".to_owned()
            });
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
    });
    (url, served, holder)
}

/// R22: the stale session's request reached the server (404), the session
/// was healed, and the resend never connected. The transport answers a
/// failure that may have run (`Transport`), with the connect cause kept, not
/// the never-sent `TransportConnect` that would release the caller's key.
#[tokio::test]
async fn a_resend_that_never_connected_after_an_expired_session_may_have_run() {
    let (url, served, _held) = expiring_server();
    let transport = make_transport(&url);
    *transport.message_url.write() = Some(url.clone());
    set_default_session(&transport, "stale-session");
    let outcome = transport.request("tools/list", None).await;
    // Everything the client was answered was reported before its answer, so
    // the reports are complete now: drained, not waited for.
    let served: Vec<String> = served.try_iter().collect();
    for step in ["tools/list", "initialize", "notifications/initialized"] {
        assert!(
            served.iter().any(|method| method == step),
            "premise: {step} reached the server; served {served:?}, the request answered {outcome:?}"
        );
    }
    assert_eq!(
        default_session(&transport).as_deref(),
        Some(FRESH),
        "premise: the session was healed"
    );
    let error = outcome.expect_err("the resend could not connect");
    assert!(
        matches!(error, crate::Error::Transport(_)),
        "a resend after a sent request read as never sent: {error:?}"
    );
    assert!(!error.is_pre_dispatch(), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("after the expired session's request was sent"),
        "{error}"
    );
}

/// An injected value the recovering server echoes.
const ECHOED: &str = "recovery-secret-5b2e";

/// How the recovering server answers the stale session's request.
#[derive(Clone, Copy)]
enum Expiry {
    /// 404: an error, never scrubbed as an answer.
    NotFound,
    /// A 200 whose error says the session was not found, and echoes
    /// [`ECHOED`]: an answer the scrub redacts.
    EchoingError,
}

/// A server that expires the stale session as `expiry`, re-initialises with
/// an `initialize` answer that echoes [`ECHOED`], and answers the resend
/// with a clean empty tool list. It serves until the test ends.
fn recovering_server(expiry: Expiry) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("address"));
    std::thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            let (first, headers, body) = read_request(&stream);
            let method = body["method"].as_str().unwrap_or_default();
            if !first.starts_with("POST") {
                respond(&stream, "405 Method Not Allowed", "", "");
            } else if method == "initialize" {
                let result = json!({"jsonrpc": "2.0", "id": body["id"], "result": {
                    "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                    "serverInfo": {"name": ECHOED, "version": "0"}}});
                respond(
                    &stream,
                    "200 OK",
                    &format!("mcp-session-id: {FRESH}\r\n"),
                    &result.to_string(),
                );
            } else if body.get("id").is_none() {
                respond(&stream, "202 Accepted", "", "");
            } else if headers.contains(FRESH) {
                let result = json!({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": []}});
                respond(&stream, "200 OK", "", &result.to_string());
            } else {
                match expiry {
                    Expiry::NotFound => respond(&stream, "404 Not Found", "", ""),
                    Expiry::EchoingError => {
                        let error = json!({"jsonrpc": "2.0", "id": body["id"], "error": {
                            "code": -32_000, "message": format!("session not found: {ECHOED}")}});
                        respond(&stream, "200 OK", "", &error.to_string());
                    }
                }
            }
        }
    });
    url
}

/// F3: a call that recovers an expired session answers with the resend's
/// clean answer, but during the call the backend echoed an injected value
/// (in the re-handshake's `initialize` answer, and in the second shape in
/// the expired answer too), and the gateway removed it: the record says
/// `rewritten`, never `refused`. The handshake runs in a discarded cell, so
/// this also pins that a discarded send's redaction reaches the call.
#[tokio::test]
async fn a_recovered_calls_record_keeps_every_redaction_of_the_call() {
    for expiry in [Expiry::NotFound, Expiry::EchoingError] {
        let url = recovering_server(expiry);
        let transport = make_transport(&url);
        *transport.message_url.write() = Some(url.clone());
        set_default_session(&transport, "stale-session");
        let needles =
            crate::security::needles::NeedleSet::with_grace(std::time::Duration::from_secs(3_600));
        needles.insert("b", ECHOED);
        transport.attach_needles(Arc::new(needles));
        let mut fields = serde_json::Map::new();
        let answer = crate::gateway::delivery_facts::scope(async {
            let answer = transport.request("tools/list", None).await;
            crate::gateway::delivery_facts::record_fields(
                crate::gateway::delivery_facts::snapshot().as_ref(),
                false,
                &mut fields,
            );
            answer
        })
        .await;
        let answer = answer.expect("the resend answered");
        assert_eq!(answer.result, Some(json!({"tools": []})), "premise");
        assert_eq!(
            default_session(&transport).as_deref(),
            Some(FRESH),
            "premise: the session was healed"
        );
        assert_eq!(fields["response_effect"], "rewritten");
    }
}
