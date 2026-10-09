// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T35 (design r3, R1a d2 MEDIUM and d1 MED5): a revival signal reaches a
//! task parked while its backend was gone, whenever it was sent.

use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;
use axum::response::IntoResponse as _;

use super::*;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// A peer that counts every request and answers none usefully.
async fn counting_peer(hits: Arc<AtomicUsize>) -> String {
    let app = axum::Router::new().fallback(move || {
        let hits = Arc::clone(&hits);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
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
/// retries at once, not at its 30 s timer.
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

    let hits = Arc::new(AtomicUsize::new(0));
    assert!(registry.register(backend_at(counting_peer(Arc::clone(&hits)).await)));
    // What `revive_backend` sends for a live entry.
    shared.wake.send_modify(|n| *n += 1);
    release.notify_one();

    let contacted = tokio::time::timeout(Duration::from_secs(5), async {
        while hits.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    shared.stop.cancel();
    let _ = task.await;
    assert!(
        contacted.is_ok(),
        "the revived backend is contacted at once, not at the 30 s timer"
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
    let hits = Arc::new(AtomicUsize::new(0));
    assert!(registry.register(backend_at(counting_peer(hits).await)));
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
    let hits = Arc::new(AtomicUsize::new(0));
    assert!(registry.register(backend_at(counting_peer(hits).await)));
    shared.wake.send_modify(|n| *n += 1);
}

/// T35, backoff half: a backend re-registered while its task backs off is
/// reconnected at once, not at the end of the backoff.
#[tokio::test]
async fn t35_a_re_registration_during_backoff_cuts_it() {
    let (shared, registry, task, release, next) = at_first_backoff().await;
    release.notify_one();
    tokio::time::sleep(Duration::from_millis(100)).await;
    re_register(&shared, &registry).await;
    let reconnected = tokio::time::timeout(Duration::from_millis(700), next.notified()).await;
    shared.stop.cancel();
    let _ = task.await;
    assert!(
        reconnected.is_ok(),
        "the re-registered backend is reconnected before the backoff ends"
    );
}

/// T35 (gpt delta review): a registration after the task's registry check
/// but before its backoff begins is not missed.
#[tokio::test]
async fn t35_a_re_registration_before_the_backoff_begins_cuts_it() {
    let (shared, registry, task, release, next) = at_first_backoff().await;
    re_register(&shared, &registry).await;
    release.notify_one();
    let reconnected = tokio::time::timeout(Duration::from_millis(700), next.notified()).await;
    shared.stop.cancel();
    let _ = task.await;
    assert!(
        reconnected.is_ok(),
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
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        shared.wake.send_modify(|n| *n += 1);
    }
    let early = waiting.is_finished();
    let on_time = tokio::time::timeout(Duration::from_millis(2_500), waiting).await;
    shared.stop.cancel();
    let _ = task.await;
    assert!(!early, "1 s of filter changes did not cut a 1.5 s+ backoff");
    assert!(
        on_time.is_ok(),
        "the backoff still ends by its own deadline"
    );
}
