// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8377 LIVE.1, the certificate half: a stream admitted under a client
//! certificate is dead once the certificate's `notAfter` has passed, judged
//! at every decision, and never re-judged as a caller without it (design
//! d2.1 L-2). The certificate and its `notAfter` are the request extensions
//! the TLS layer inserts; MIK-8350 captures them at attach.

use super::audience_fixture::{World, tool};
use crate::mtls::CertIdentity;
use crate::mtls::identity::CertNotAfter;

/// How long the row's certificate stays valid after the row starts.
const VALID_FOR: u64 = 60;

fn alpha(read: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

/// The TLS layer's extensions for a certificate valid until `not_after`.
fn with_cert(not_after: u64) -> impl FnOnce(&mut axum::http::Request<axum::body::Body>) {
    move |request| {
        let extensions = request.extensions_mut();
        extensions.insert(CertIdentity {
            common_name: Some("listener".to_string()),
            display_name: "CN=listener".to_string(),
            ..CertIdentity::default()
        });
        extensions.insert(CertNotAfter(not_after));
    }
}

/// The listen stream k-std opens under a certificate valid until `not_after`.
async fn certified(w: &World, not_after: u64) -> super::audience_ear::Ear {
    w.listen_with("k-std", with_cert(not_after)).await
}

/// LIVE.1-cert: while the certificate is valid a visible change is told; one
/// second past its `notAfter` the stream is closed, not told.
#[tokio::test]
async fn live_1_cert_a_stream_past_its_certificate_not_after_is_closed() {
    let w = World::start().await;
    let not_after = crate::clock::unix_secs().expect("clock after 1970") + VALID_FOR;
    let mut ear = certified(&w, not_after).await;

    let valid = crate::clock::test_clock::at_secs(not_after - 1);
    w.store_shared("alpha", alpha("r2"));
    assert_eq!(
        ear.told(&w).await,
        1,
        "premise: a valid certificate is told"
    );
    drop(valid);

    let _past = crate::clock::test_clock::at_secs(not_after + 1);
    w.store_shared("alpha", alpha("r3"));
    assert!(ear.closed(&w).await, "past notAfter the stream is closed");
}

/// LIVE.1-equal: at exactly `notAfter` the certificate is no longer valid
/// (live only while now < notAfter).
#[tokio::test]
async fn live_1_equal_a_stream_at_its_certificate_not_after_is_closed() {
    let w = World::start().await;
    let not_after = crate::clock::unix_secs().expect("clock after 1970") + VALID_FOR;
    let mut ear = certified(&w, not_after).await;

    let _at = crate::clock::test_clock::at_secs(not_after);
    w.store_shared("alpha", alpha("r2"));
    assert!(ear.closed(&w).await, "at notAfter the stream is closed");
}

/// LIVE.1-clock: a clock that cannot be read (in this codebase, one that
/// reads before 1970, MIK-8202) cannot show the certificate valid, so the
/// stream is closed rather than judged as if it were.
#[tokio::test]
async fn live_1_clock_an_unreadable_clock_closes_a_certified_stream() {
    let w = World::start().await;
    let not_after = crate::clock::unix_secs().expect("clock after 1970") + VALID_FOR;
    let mut ear = certified(&w, not_after).await;

    let _unreadable = crate::clock::test_clock::before_epoch();
    w.store_shared("alpha", alpha("r2"));
    assert!(
        ear.closed(&w).await,
        "an unreadable clock closes the stream"
    );
}

/// LIVE.1-cert over the legacy GET stream, through the real route: past
/// `notAfter` the GET stream is closed (its body ends), not told.
#[tokio::test]
async fn live_1_cert_a_get_stream_past_its_certificate_not_after_is_closed() {
    let w = World::start().await;
    let not_after = crate::clock::unix_secs().expect("clock after 1970") + VALID_FOR;
    let mut ear = w.sse_with("k-std", with_cert(not_after)).await;

    let _past = crate::clock::test_clock::at_secs(not_after + 1);
    w.store_shared("alpha", alpha("r2"));
    assert!(
        ear.closed(&w).await,
        "past notAfter the GET stream is closed"
    );
}

/// BASELINE-DEAD: a certificate already past `notAfter` when the GET stream
/// attaches makes its baseline Dead, so the stream closes before any frame.
#[tokio::test]
async fn baseline_dead_a_stream_attached_past_not_after_is_closed() {
    let w = World::start().await;
    let not_after = crate::clock::unix_secs().expect("clock after 1970") - 1;
    let mut ear = w.sse_with("k-std", with_cert(not_after)).await;
    assert!(
        ear.closed(&w).await,
        "a stream whose identity is dead at attach is closed"
    );
}

/// QUEUED-THEN-DEAD: a hint queued while the certificate was valid, then
/// held at the GET write check while `notAfter` passes, is not written; the
/// stream closes. The write-time re-check sees the lapse.
#[tokio::test]
async fn queued_then_dead_a_hint_held_past_not_after_is_not_written() {
    let w = World::start().await;
    let not_after = crate::clock::unix_secs().expect("clock after 1970") + VALID_FOR;
    let mut ear = w.sse_with("k-std", with_cert(not_after)).await;
    let (reached, release) = w.state.multiplexer.before_write_check.arm();
    w.store_shared("alpha", alpha("r2"));
    crate::test_pause::within("the frame reaching the write check", reached.notified()).await;
    let _past = crate::clock::test_clock::at_secs(not_after + 1);
    release.notify_one();
    assert!(
        ear.closed(&w).await,
        "the held hint is not written once notAfter has passed"
    );
}
