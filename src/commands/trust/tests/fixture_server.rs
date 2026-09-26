// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The loopback HTTP server the trust-lab active-fixture tests call.

use std::io::{Read, Write};

pub(super) fn spawn_loopback_fixture_server() -> (String, std::sync::mpsc::Receiver<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Blocking again before the read: on Windows the accepted
                    // socket inherits the listener's non-blocking mode, so a read
                    // that raced the client's request returned `WouldBlock` and
                    // the fixture recorded an empty request.
                    let mut buf = [0_u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]).to_string();
                    let body = r#"{"forecast":"sunny","raw_fixture_payload":"do-not-store"}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                    let _ = tx.send(request);
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        let _ = tx.send("timeout waiting for fixture request".to_string());
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(err) => {
                    let _ = tx.send(format!("fixture server accept error: {err}"));
                    break;
                }
            }
        }
    });

    (format!("http://{addr}"), rx)
}

/// A client whose request arrives after the server has already accepted.
///
/// The delay makes the race deterministic: the server's first read happens
/// before any byte is on the wire. With the accepted socket left
/// non-blocking (Windows inherits it from the listener), that read returns
/// `WouldBlock` and the recorded request is empty.
#[test]
fn a_request_sent_after_accept_is_still_recorded() {
    let (base_url, rx) = spawn_loopback_fixture_server();
    let addr = base_url.trim_start_matches("http://");
    let mut client = std::net::TcpStream::connect(addr).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    client
        .write_all(b"GET /fixture/late HTTP/1.1\r\nhost: x\r\n\r\n")
        .unwrap();
    let request = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert!(
        request.starts_with("GET /fixture/late "),
        "the fixture server must record a request that arrives after accept: {request:?}"
    );
}
