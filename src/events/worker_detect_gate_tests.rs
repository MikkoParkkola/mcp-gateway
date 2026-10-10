// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8125 `DETECT-GATE`: a backend's detected HTTP flavour changes at
//! runtime, under the transport's own lock, not through a config reload. A
//! flip that makes the backend ineligible for upstream events, landing after
//! an attempt's checks and before its send, does not deliver that attempt's
//! event; and detection never waits on a send in flight.
//!
//! The attempt stops at its last step before the send (`before_send`); the
//! flip is published there, through the transport's real setter, and read by
//! the gateway's live eligibility predicate (`upstream_live_ineligible`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use super::super::{counting_callback, logged_services, queued_with};
use crate::config::{BackendConfig, Config};
use crate::events::EventsHub;

const BACKEND: &str = "x";
const NAME: &str = "backend.x.resources_changed";

/// A hub whose backend source offers the upstream kinds of backend `x`,
/// reached over HTTP, with its live connection detected as Streamable HTTP
/// (eligible). Returned with the transport, so a row can flip its flavour.
fn hub_over_detected_backend(
    dir: &std::path::Path,
    services: &super::super::Services,
) -> (Arc<EventsHub>, Arc<crate::transport::HttpTransport>) {
    let backend_config: BackendConfig =
        serde_yaml::from_str("http_url: http://127.0.0.1:9/mcp").expect("config");
    let mut config = Config::default();
    config
        .backends
        .insert(BACKEND.to_owned(), backend_config.clone());
    services.live.set(config);
    let backend = crate::backend::Backend::new(
        BACKEND,
        backend_config,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    let transport = crate::transport::HttpTransport::new(
        "http://127.0.0.1:9/mcp",
        std::collections::HashMap::new(),
        Duration::from_secs(1),
        true,
    )
    .expect("transport");
    backend.install_http_for_test(&transport);
    transport.set_detected(Some(true));
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(registry.register(Arc::new(backend)), "registered");
    let ineligible =
        crate::events::upstream_live_ineligible(Arc::clone(&services.live), Arc::clone(&registry));
    assert!(ineligible().is_empty(), "premise: x starts eligible");
    let events = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&events, dir).expect("hub");
    hub.install_backend_source_with_upstream(
        Arc::new(|| vec![BACKEND.to_owned()]),
        registry,
        ineligible,
    );
    (hub, transport)
}

/// One attempt of a queued `backend.x.resources_changed` event, paused just
/// before its send while the transport publishes each of `flips` in turn;
/// the posts its callback got.
async fn attempt_across_flips(flips: &[Option<bool>]) -> usize {
    let dir = tempfile::tempdir().expect("dir");
    let services = logged_services(dir.path());
    let (hub, transport) = hub_over_detected_backend(dir.path(), &services);
    let (port, accepted) = counting_callback().await;
    queued_with(&hub, port, "evt_x", NAME, |_, _| {});
    let (reached, release) = hub.before_send.arm();
    let drive = async {
        reached.notified().await;
        for flavour in flips {
            transport.set_detected(*flavour);
        }
        release.notify_one();
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(hub.attempt(&services, "evt_x"), drive)
    })
    .await
    .expect("the attempt finished");
    tokio::time::sleep(Duration::from_millis(300)).await;
    accepted.load(Ordering::SeqCst)
}

/// T15 `DETECT-GATE.1`: the connection is re-detected as the legacy SSE
/// handshake (ineligible for upstream events) between the attempt's checks
/// and its send: nothing is sent. Control: no flip, the attempt sends.
#[tokio::test]
async fn a_flavour_flip_before_the_send_sends_nothing() {
    assert!(
        attempt_across_flips(&[]).await >= 1,
        "premise: sent while the backend stays eligible"
    );
    assert_eq!(
        attempt_across_flips(&[Some(false)]).await,
        0,
        "sent for a backend re-detected as ineligible before the send"
    );
}

/// T15b (W3): the connection flips to the legacy handshake and back to
/// Streamable HTTP before the send. Admission judges the backend as it is
/// then, eligible, so the event is delivered: a flip that has been undone is
/// not a refusal, and dropping the event would lose one still authorized.
#[tokio::test]
async fn a_flavour_flip_undone_before_the_send_still_sends() {
    assert!(
        attempt_across_flips(&[Some(false), Some(true)]).await >= 1,
        "not sent though the backend was eligible again at admission"
    );
}

/// A callback that accepts each connection and never answers; the
/// connections it accepted, and whether a client has closed one.
async fn silent_callback() -> (u16, Arc<AtomicUsize>, Arc<AtomicBool>) {
    use tokio::io::AsyncReadExt as _;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let ended = Arc::new(AtomicBool::new(false));
    let (seen, closed) = (Arc::clone(&accepted), Arc::clone(&ended));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            let closed = Arc::clone(&closed);
            tokio::spawn(async move {
                let mut buf = [0_u8; 1024];
                while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
                closed.store(true, Ordering::SeqCst);
            });
        }
    });
    (port, accepted, ended)
}

/// Polls `done` every 20 ms for up to `limit`.
async fn within(limit: Duration, done: impl Fn() -> bool) -> bool {
    let until = tokio::time::Instant::now() + limit;
    while !done() {
        if tokio::time::Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

/// T16 `DETECT-GATE.2` (PIN): while a send is in flight, a detection that
/// publishes a new flavour returns without waiting on the send's network I/O.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_detection_does_not_wait_for_a_send_in_flight() {
    let dir = tempfile::tempdir().expect("dir");
    let services = Arc::new(logged_services(dir.path()));
    let (hub, transport) = hub_over_detected_backend(dir.path(), &services);
    let (port, connections, ended) = silent_callback().await;
    queued_with(&hub, port, "evt_x", NAME, |_, _| {});
    let attempt = tokio::spawn({
        let (hub, services) = (Arc::clone(&hub), Arc::clone(&services));
        async move { hub.attempt(&services, "evt_x").await }
    });
    assert!(
        within(Duration::from_secs(10), || connections
            .load(Ordering::SeqCst)
            >= 1)
        .await,
        "premise: the send is in flight"
    );
    // Judged against the send's own end: the attempt cannot finish until the
    // client gives up on the silent callback (`TOTAL_TIMEOUT`, 10 s), so a
    // detection that waited on the send could neither return inside 5 s nor
    // return while the attempt is still in flight. Read on the client side,
    // not the server's EOF observer, which can lag the client giving up.
    let detection = std::thread::spawn(move || transport.set_detected(Some(false)));
    assert!(
        within(Duration::from_secs(5), || detection.is_finished()).await,
        "a detection waited on a send's network I/O"
    );
    assert!(
        !attempt.is_finished() && !ended.load(Ordering::SeqCst),
        "premise: the send was still in flight when the detection returned"
    );
    attempt.abort();
}
