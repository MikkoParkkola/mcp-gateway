// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T35 (design r3, R1a d2 MEDIUM and d1 MED5): a revival signal reaches a
//! task parked while its backend was gone, whenever it was sent.

use axum::http::StatusCode;
use axum::response::IntoResponse as _;

use super::*;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// A peer that signals every request it gets and answers none usefully.
async fn counting_peer(contacted: Arc<tokio::sync::Notify>) -> String {
    let app = axum::Router::new().fallback(move || {
        let contacted = Arc::clone(&contacted);
        async move {
            contacted.notify_one();
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    url
}

fn backend_at(url: String) -> Arc<Backend> {
    Arc::new(Backend::new(
        "b",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout: Duration::from_secs(5),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// T35, parked half: the backend registers and its revival is signalled
/// after the task found it gone but before the task waits. The task still
/// retries at once: its park ended by the revival, not by its 30 s timer.
/// Asserts the cause of the wake, not how long it took.
#[tokio::test]
async fn t35_a_revival_sent_as_the_task_parks_is_not_missed() {
    let shared = shared();
    shared
        .need
        .lock()
        .add(&Interest::ResourcesChanged)
        .expect("room");
    let registry = Arc::new(BackendRegistry::new());
    let (reached, release) = shared.before_park.arm();
    let task = tokio::spawn(run(Arc::clone(&shared), Arc::clone(&registry), Weak::new()));
    crate::test_pause::within("the task finding b gone", reached.notified()).await;

    let contacted = Arc::new(tokio::sync::Notify::new());
    assert!(registry.register(backend_at(counting_peer(Arc::clone(&contacted)).await)));
    // What `revive_backend` sends for a live entry.
    shared.wake.send_modify(|n| *n += 1);
    release.notify_one();

    crate::test_pause::within("the revived backend being contacted", contacted.notified()).await;
    shared.stop.cancel();
    task.await.expect("the task ends cleanly");
    assert_eq!(
        shared.waits.ends().first(),
        Some(&WaitEnd::Revival),
        "the park ended by the revival, not by its 30 s timer"
    );
}

/// A task on a backend whose sessions fail at once, stopped as its first
/// backoff (1.5 to 2.5 s after one failure) begins. Returns the task, the
/// registry, the release of that pause and the next backoff's arrival.
async fn at_first_backoff() -> (
    Arc<Shared>,
    Arc<BackendRegistry>,
    tokio::task::JoinHandle<()>,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
) {
    let shared = shared();
    shared
        .need
        .lock()
        .add(&Interest::ResourcesChanged)
        .expect("room");
    let registry = Arc::new(BackendRegistry::new());
    let contacted = Arc::new(tokio::sync::Notify::new());
    assert!(registry.register(backend_at(counting_peer(contacted).await)));
    let (reached, release) = shared.before_backoff.arm();
    let task = tokio::spawn(run(Arc::clone(&shared), Arc::clone(&registry), Weak::new()));
    crate::test_pause::within("the first backoff", reached.notified()).await;
    // The next backoff starts only after a new session: a reconnect. Its
    // release is pre-paid, so that pause only reports and passes.
    let (next, release_next) = shared.before_backoff.arm();
    release_next.notify_one();
    (shared, registry, task, release, next)
}

/// A new `Backend` for `b` with its peer already listening, so a row can
/// have it ready before the wait it will interrupt begins.
async fn replacement() -> Arc<Backend> {
    let contacted = Arc::new(tokio::sync::Notify::new());
    backend_at(counting_peer(contacted).await)
}

/// Replace `b` in `registry` with `backend` and signal it, as a config
/// reload and `revive_backend` do. Nothing here awaits.
fn swap_in(shared: &Shared, registry: &BackendRegistry, backend: Arc<Backend>) {
    assert!(registry.remove("b"));
    assert!(registry.register(backend));
    shared.wake.send_modify(|n| *n += 1);
}

/// [`swap_in`] with a backend made on the spot.
async fn re_register(shared: &Shared, registry: &BackendRegistry) {
    swap_in(shared, registry, replacement().await);
}

/// T35, backoff half: a backend re-registered while its task backs off is
/// reconnected at once: the backoff ended by the revival, not by its deadline.
/// The row sends the revival once the task reports it is waiting, and asserts
/// the cause of the reconnect, not how long it took.
#[tokio::test]
async fn t35_a_re_registration_during_backoff_cuts_it() {
    let (shared, registry, task, release, next) = at_first_backoff().await;
    // Ready before the wait starts: after it, only synchronous calls stand
    // between the task's backoff and the revival.
    let backend = replacement().await;
    release.notify_one();
    crate::test_pause::within("the backoff wait to begin", shared.waits.began.notified()).await;
    swap_in(&shared, &registry, backend);
    crate::test_pause::within("the reconnect", next.notified()).await;
    shared.stop.cancel();
    task.await.expect("the task ends cleanly");
    assert_eq!(
        shared.waits.ends().first(),
        Some(&WaitEnd::Revival),
        "the re-registered backend is reconnected by the revival, not at the backoff's end"
    );
}

/// T35 (gpt delta review): a registration after the task's registry check
/// but before its backoff begins is not missed: the backoff still ends by the
/// revival, whatever the load made the reconnect cost.
#[tokio::test]
async fn t35_a_re_registration_before_the_backoff_begins_cuts_it() {
    let (shared, registry, task, release, next) = at_first_backoff().await;
    re_register(&shared, &registry).await;
    release.notify_one();
    crate::test_pause::within("the reconnect", next.notified()).await;
    shared.stop.cancel();
    task.await.expect("the task ends cleanly");
    assert_eq!(
        shared.waits.ends().first(),
        Some(&WaitEnd::Revival),
        "a registration signalled before the backoff still cuts it"
    );
}

/// T35 churn guard: filter changes on the same backend do not cut the
/// backoff, and do not push its deadline out either.
#[tokio::test]
async fn t35_filter_churn_neither_cuts_nor_extends_the_backoff() {
    let (shared, _registry, task, release, next) = at_first_backoff().await;
    release.notify_one();
    let next = Arc::new(next);
    let waiting = tokio::spawn({
        let next = Arc::clone(&next);
        async move { next.notified().await }
    });
    // Churn every 200 ms, past the longest backoff (2.5 s): it never cuts
    // the wait, and never holds it open.
    let mut reconnected_at = None;
    for tick in 1..=20u32 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if waiting.is_finished() {
            reconnected_at = Some(tick * 200);
            break;
        }
        shared.wake.send_modify(|n| *n += 1);
    }
    shared.stop.cancel();
    let _ = task.await;
    let at = reconnected_at.expect("the backoff ends by its own deadline while churn goes on");
    assert!(
        at > 1_000,
        "filter changes did not cut a 1.5 s+ backoff (reconnected at {at} ms)"
    );
}

/// After a lease move the reconnect waits exactly the floor: never less,
/// whatever the backoff's jitter, and never the rest of a long backoff.
#[tokio::test]
async fn a_lease_move_reconnects_exactly_the_floor_after_it_is_seen() {
    let floor = BACKOFF_FIRST;
    let now = tokio::time::Instant::now();
    // `backoff(0)` at its lowest jitter: under the floor.
    let jittered = now + floor.mul_f64(0.75);
    assert_eq!(
        run::LeaseCut::default().decide(Some(2), Some(1), jittered, now, floor),
        now + floor,
        "a jittered short backoff is raised to the floor"
    );
    assert_eq!(
        run::LeaseCut::default().decide(Some(2), Some(1), now + BACKOFF_CAP, now, floor),
        now + floor,
        "a long backoff is cut to the floor"
    );
}

/// A lease move cuts the backoff once per newly held generation, so a
/// handshake that keeps failing under it backs off as usual; a lease that is
/// gone, the run's own lease and a shared run cut nothing.
#[tokio::test]
async fn a_lease_move_cuts_the_backoff_once_per_generation() {
    let floor = BACKOFF_FIRST;
    let now = tokio::time::Instant::now();
    let later = now + Duration::from_secs(30);
    let mut cut = run::LeaseCut::default();
    assert_eq!(
        cut.decide(Some(2), Some(1), later, now, floor),
        now + floor,
        "a new generation cuts"
    );
    assert_eq!(
        cut.decide(Some(2), Some(1), later, now, floor),
        later,
        "not twice for it"
    );
    assert_eq!(
        cut.decide(None, Some(1), later, now, floor),
        later,
        "no lease held: no credential"
    );
    assert_eq!(
        cut.decide(Some(1), Some(1), later, now, floor),
        later,
        "the run's own lease"
    );
    assert_eq!(
        cut.decide(Some(3), Some(1), later, now, floor),
        now + floor,
        "another one cuts again"
    );
    assert_eq!(
        run::LeaseCut::default().decide(Some(0), Some(1), later, now, floor),
        now + floor,
        "generations are random: a smaller value is a move too"
    );
    assert_eq!(
        run::LeaseCut::default().decide(Some(2), None, later, now, floor),
        later,
        "a shared run is never cut"
    );
}
