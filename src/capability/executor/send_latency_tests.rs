// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The capability HTTP send's latency notes (test plan rows 21, 23c, 25, 26):
//! one per call, retries and backoff summed into it, its end from the send.

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

/// Row 25 (HTTP): a send past the client's timeout notes TimedOut, read from
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

/// Row 26 (HTTP): a send retried after connect failures notes once, for the
/// whole call, Failed at the end.
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
    assert_eq!(
        notes.backend_sample(),
        Some((SEND, End::Failed)),
        "one note, the call's end"
    );
}
