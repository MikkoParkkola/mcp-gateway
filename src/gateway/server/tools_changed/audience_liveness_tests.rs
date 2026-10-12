// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8377 LIVE.1, the certificate half: a stream admitted under a client
//! certificate is dead once the certificate's `notAfter` has passed, judged
//! at every decision, and never re-judged as a caller without it (design
//! d2.1 L-2). The certificate and its `notAfter` are the request extensions
//! the TLS layer inserts; MIK-8350 captures them at attach.

use super::audience_ear::Attach;
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

/// BASELINE-DEAD (lead ruling): an identity already dead at attach is
/// refused there, with no stream opened. The answer is the status and body
/// that route gives an invalid credential (401).
async fn refused_like_an_invalid_credential(route: Attach) {
    let w = World::start().await;
    let not_after = crate::clock::unix_secs().expect("clock after 1970") - 1;
    let dead = w.attach_raw(route, "k-std", with_cert(not_after)).await;
    let invalid = w.attach_raw(route, "k-not-a-key", |_| {}).await;
    assert_eq!(
        invalid.0,
        axum::http::StatusCode::UNAUTHORIZED,
        "premise: an invalid credential is 401 on {route:?}"
    );
    assert_eq!(
        dead, invalid,
        "an identity dead at attach is refused as an invalid credential on {route:?}"
    );
}

#[tokio::test]
async fn baseline_dead_a_get_attach_past_not_after_is_refused() {
    refused_like_an_invalid_credential(Attach::Get).await;
}

#[tokio::test]
async fn baseline_dead_a_listen_attach_past_not_after_is_refused() {
    refused_like_an_invalid_credential(Attach::Listen).await;
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

/// METRIC (lead condition 2): a stream closed by a lapsed certificate is
/// counted once under `reason="cert"` in `mcp_view_liveness_dead_total`. A
/// current-thread runtime runs inside the local recorder, so the forced
/// clock and the counter both stay on this thread.
#[cfg(feature = "metrics")]
#[test]
fn metric_a_certificate_death_is_counted_once_as_cert() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(async {
                let w = World::start().await;
                let not_after = crate::clock::unix_secs().expect("clock after 1970") + VALID_FOR;
                let mut ear = certified(&w, not_after).await;
                let _past = crate::clock::test_clock::at_secs(not_after + 1);
                w.store_shared("alpha", alpha("r2"));
                assert!(
                    ear.closed(&w).await,
                    "premise of the count: the stream died"
                );
            });
    });
    let text = handle.render();
    let counted: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("mcp_view_liveness_dead_total{"))
        .collect();
    assert_eq!(counted.len(), 1, "one death, one series: {text}");
    assert!(counted[0].contains(r#"reason="cert""#), "{text}");
    assert!(
        matches!(counted[0].rsplit(' ').next(), Some("1" | "1.0")),
        "counted once: {text}"
    );
}

/// PROXY.2-peer: a stream whose grant subject came from a trusted proxy is
/// dead once that proxy's address is no longer in `trusted_proxies`, never
/// re-judged as the API-key subject. A unit row on `live()`: the setting is
/// restart-only, so no running gateway can drop a peer while a stream lives;
/// the check is defence in depth (design d2.1 L-4).
#[test]
fn proxy_2_peer_a_stream_from_an_untrusted_proxy_is_dead() {
    let peer: std::net::SocketAddr = "10.0.0.9:443".parse().expect("an address");
    let subject = crate::gateway::streaming::ViewSubject {
        proxy_peer: Some(peer),
        ..crate::gateway::streaming::ViewSubject::default()
    };
    let ctx = |identity| crate::gateway::streaming::LiveCtx {
        agent: None,
        caller_identity: identity,
        cf_verifier: None,
    };
    let untrusted = crate::security::caller_identity::CallerIdentityConfig::default();
    assert!(
        subject.live(&ctx(&untrusted)).is_err(),
        "a proxy no longer trusted makes the stream dead"
    );
    let trusted = crate::security::caller_identity::CallerIdentityConfig {
        trusted_proxies: vec![peer.ip()],
        ..crate::security::caller_identity::CallerIdentityConfig::default()
    };
    assert!(
        subject.live(&ctx(&trusted)).is_ok(),
        "control: a still-trusted proxy is live"
    );
}
