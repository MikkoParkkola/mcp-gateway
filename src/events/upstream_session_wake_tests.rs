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
