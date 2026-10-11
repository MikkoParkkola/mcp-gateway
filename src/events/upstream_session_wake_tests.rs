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
    let _ = task.await;
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

/// Replace `b` in `registry` with a new `Backend` and signal it, as a
/// config reload and `revive_backend` do.
async fn re_register(shared: &Shared, registry: &BackendRegistry) {
    assert!(registry.remove("b"));
    let contacted = Arc::new(tokio::sync::Notify::new());
    assert!(registry.register(backend_at(counting_peer(contacted).await)));
    shared.wake.send_modify(|n| *n += 1);
}

/// T35, backoff half: a backend re-registered while its task backs off is
/// reconnected at once: the backoff ended by the revival, not by its deadline.
/// The row sends the revival once the task reports it is waiting, and asserts
/// the cause of the reconnect, not how long it took.
#[tokio::test]
async fn t35_a_re_registration_during_backoff_cuts_it() {
    let (shared, registry, task, release, next) = at_first_backoff().await;
    release.notify_one();
    crate::test_pause::within("the backoff wait to begin", shared.waits.began.notified()).await;
    re_register(&shared, &registry).await;
    crate::test_pause::within("the reconnect", next.notified()).await;
    shared.stop.cancel();
    let _ = task.await;
    assert_eq!(
        shared.waits.ends(),
        [WaitEnd::Revival],
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
    let _ = task.await;
    assert_eq!(
        shared.waits.ends(),
        [WaitEnd::Revival],
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
