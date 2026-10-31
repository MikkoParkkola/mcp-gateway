// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The capability HTTP send's latency notes (test plan rows 21, 23c, 25, 26):
//! one sample per call, each attempt timed from its send through its body,
//! the backoff between attempts not, its end from the last attempt.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use super::client::send_with_retry;
use crate::counters::End;
use crate::gateway::{send_timer_seam as seam, with_dispatch_scope};

const SEND: Duration = Duration::from_millis(7);

/// A local listener that answers every connection with `reply` (or never
/// answers when `None`), on its own thread.
fn listener(reply: Option<&'static str>) -> String {
    let server = TcpListener::bind("127.0.0.1:0").expect("a local port");
    let addr = server.local_addr().expect("its address");
    std::thread::spawn(move || {
        for stream in server.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            match reply {
                Some(reply) => {
                    let _ = stream.write_all(reply.as_bytes());
                }
                // Hold the connection open, never answering.
                None => std::thread::sleep(Duration::from_secs(30)),
            }
        }
    });
    format!("http://{addr}/")
}

/// A listener that sends a 200 with a 100-byte body, writes part of it, and
/// stalls, on its own thread.
fn stalled_body() -> String {
    let server = TcpListener::bind("127.0.0.1:0").expect("a local port");
    let addr = server.local_addr().expect("its address");
    std::thread::spawn(move || {
        for stream in server.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial");
            std::thread::sleep(Duration::from_secs(30));
        }
    });
    format!("http://{addr}/")
}

/// Review F2: a response whose body stalls past the client's timeout notes
/// `TimedOut`: the send is timed through its body, not to its headers.
#[tokio::test]
async fn a_stalled_body_notes_timed_out() {
    let url = stalled_body();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .expect("a client");
    let health = crate::failsafe::HealthTracker::new("test");
    seam::inject(SEND);
    let (result, notes) = with_dispatch_scope(async {
        send_with_retry(client.get(&url), "test", false, &health).await
    })
    .await;
    seam::clear();
    assert!(matches!(result, Err(crate::Error::Protocol(_))), "{result:?}");
    assert_eq!(notes.backend_sample(), Some((SEND, End::TimedOut)));
}

/// Row 21 (HTTP): an answered send notes one sample, Answered.
#[tokio::test]
async fn an_answered_http_send_notes_one_sample() {
    let url = listener(Some(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ));
    let health = crate::failsafe::HealthTracker::new("test");
    seam::inject(SEND);
    let (result, notes) = with_dispatch_scope(async {
        send_with_retry(reqwest::Client::new().get(&url), "test", false, &health).await
    })
    .await;
    seam::clear();
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(notes.backend_sample(), Some((SEND, End::Answered)));
}

/// Row 25 (HTTP): a send past the client's timeout notes `TimedOut`, read from
/// reqwest's own flag although the error is wrapped as `Transport`. A short
/// client timeout keeps the real wait short; only the end is asserted.
#[tokio::test]
async fn an_http_send_past_its_timeout_notes_timed_out() {
    let url = listener(None);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .expect("a client");
    let health = crate::failsafe::HealthTracker::new("test");
    seam::inject(SEND);
    let (result, notes) = with_dispatch_scope(async {
        send_with_retry(client.get(&url), "test", false, &health).await
    })
    .await;
    seam::clear();
    assert!(
        matches!(result, Err(crate::Error::Transport(_))),
        "{result:?}"
    );
    assert_eq!(notes.backend_sample(), Some((SEND, End::TimedOut)));
}

/// Row 26 (HTTP), review F3: a send retried after connect failures is one
/// sample, the attempts' times summed (each attempt timed on its own, so the
/// backoff between them is not), Failed at the end.
#[tokio::test]
async fn retried_http_sends_note_once() {
    // A port nothing listens on: every attempt fails to connect.
    let closed = TcpListener::bind("127.0.0.1:0").expect("a port");
    let url = format!("http://{}/", closed.local_addr().expect("addr"));
    drop(closed);
    let health = crate::failsafe::HealthTracker::new("test");
    seam::inject(SEND);
    let (result, notes) = with_dispatch_scope(async {
        send_with_retry(reqwest::Client::new().get(&url), "test", true, &health).await
    })
    .await;
    seam::clear();
    assert!(result.is_err());
    let attempts = super::client::MAX_SEND_ATTEMPTS;
    assert_eq!(
        notes.backend_sample(),
        Some((SEND * attempts, End::Failed)),
        "each attempt timed, the backoff not"
    );
}
