// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the listener's reach into a backend that need no peer.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::super::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

fn backend() -> Backend {
    let cfg = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://mem.internal/mcp".to_owned(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    Backend::new(
        "mem",
        cfg,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

/// After a backend's tools notice the shared slot's cached tool list is
/// gone, so the re-read a `tools_changed` subscriber does reaches the
/// backend (I5b design section 14).
#[tokio::test]
async fn a_tools_notice_drops_the_cached_tool_list() {
    let backend = backend();
    let calls = Arc::new(AtomicU32::new(0));
    let read = || {
        let calls = Arc::clone(&calls);
        let entry = backend.shared_entry();
        async move {
            entry
                .tools_cache
                .get_or_fetch_shared(Duration::from_secs(300), || {
                    let calls = Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(Vec::new())
                    }
                })
                .await
                .expect("fill");
        }
    };
    read().await;
    read().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the second read is cached");
    backend.invalidate_tools();
    read().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the notice forced a re-read"
    );
}

/// MIK-7894: the resend-permitted set is derived from the cached tool list, so
/// a notice that drops the list drops the set with it; a stale set would keep
/// letting a tool that is no longer read-only be sent again.
#[tokio::test]
async fn a_tools_notice_clears_the_resend_permitted_set() {
    let backend = backend();
    let entry = backend.shared_entry();
    entry
        .resend_permitted
        .write()
        .insert("was_read_only".to_owned());
    backend.invalidate_tools();
    assert!(
        entry.resend_permitted.read().is_empty(),
        "a stale resend set outlived the tool list"
    );
}

/// A server that accepts connections and never answers.
async fn silent_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    format!("http://{address}/mcp")
}

/// An unset-key HTTP backend at `url` with a short timeout.
fn backend_at(url: &str) -> Arc<Backend> {
    let cfg = BackendConfig {
        transport: TransportConfig::Http {
            http_url: url.to_owned(),
            streamable_http: None,
            protocol_version: None,
        },
        timeout: Duration::from_millis(500),
        ..BackendConfig::default()
    };
    Arc::new(Backend::new(
        "silent",
        cfg,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn resolutions(backend: &Backend) -> usize {
    backend.events_resolutions.load(Ordering::SeqCst)
}

/// Wait (bounded) until no resolution is in flight.
async fn settled(backend: &Backend) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while backend.events_resolution.lock().is_some() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

/// T11: a backend that never started has no detected transport.
#[test]
fn an_unstarted_backend_has_no_detected_transport() {
    assert_eq!(backend().connected_streamable(), None);
}

/// T12 (MIK-7969 M2): concurrent subscribes waiting on one backend share
/// one resolution task, and each wait is bounded by the backend timeout.
#[tokio::test]
async fn concurrent_resolutions_share_one_start_task() {
    let backend = backend_at(&silent_url().await);
    let began = std::time::Instant::now();
    let started = futures::future::join_all((0..5).map(|_| backend.resolve_for_events())).await;
    assert!(started.iter().all(|s| !s), "a silent server never starts");
    assert!(began.elapsed() < Duration::from_secs(5), "bounded wait");
    assert_eq!(resolutions(&backend), 1, "one start task for five waits");
}

/// T12b: the wait is bounded by the backend timeout even when the start
/// itself never ends (here it queues behind a held start lock).
#[tokio::test]
async fn a_start_that_never_ends_still_bounds_the_wait() {
    let backend = backend_at(&silent_url().await);
    let entry = backend.shared_entry();
    let _held = entry.start_lock.lock().await;
    let waited = tokio::time::timeout(Duration::from_secs(5), backend.resolve_for_events()).await;
    assert_eq!(waited, Ok(false), "the wait outlived the backend timeout");
}

/// T20: a settled resolution is cleared, so the next subscribe starts anew
/// rather than reusing an old outcome.
#[tokio::test]
async fn a_settled_resolution_is_cleared() {
    let backend = backend_at(&silent_url().await);
    assert!(!backend.resolve_for_events().await);
    assert!(settled(&backend).await, "the resolution was never cleared");
    assert!(!backend.resolve_for_events().await);
    assert_eq!(resolutions(&backend), 2, "a settled start was reused");
}

/// T18: a subscribe that stops waiting leaves the start running; it
/// settles under its own handling.
#[tokio::test]
async fn a_cancelled_wait_leaves_the_start_to_settle() {
    let backend = backend_at(&silent_url().await);
    let waiter = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.resolve_for_events().await }
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while resolutions(&backend) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the start never spawned"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    waiter.abort();
    assert!(
        backend.events_resolution.lock().is_some(),
        "the start ended with its waiter"
    );
    assert!(settled(&backend).await, "the start never settled");
}

fn http(url: &str) -> Arc<crate::transport::HttpTransport> {
    crate::transport::HttpTransport::new(
        url,
        std::collections::HashMap::new(),
        Duration::from_secs(1),
        true,
    )
    .expect("transport")
}

/// T11 (MIK-7969 F2): the backend reads the installed transport's flavour
/// live, so a session recovery that switched it is seen at the next read;
/// a handle left by a transport no longer installed counts for nothing.
#[test]
fn the_slot_reads_its_installed_transport_live() {
    let backend = backend();
    let first = http("http://127.0.0.1:9/mcp");
    backend.install_http_for_test(&first);
    for flavour in [Some(true), Some(false), None] {
        first.set_detected(flavour);
        assert_eq!(backend.connected_streamable(), flavour);
    }
    first.set_detected(Some(true));
    let replacement = http("http://127.0.0.1:9/mcp");
    replacement.set_detected(Some(false));
    let erased: Arc<dyn crate::transport::Transport> = Arc::clone(&replacement) as _;
    *backend.shared_entry().transport.write() = Some(erased);
    assert_eq!(
        backend.connected_streamable(),
        None,
        "the old transport's handle answered for the new one"
    );
    *backend.shared_entry().transport.write() = None;
    assert_eq!(backend.connected_streamable(), None, "a stopped slot");
}

/// MIK-7899 CLASS.3: a listener acts on a determined era, reads a silent
/// peer as legacy, and refuses to guess while the era is unresolved (never
/// probed, or discarded with its re-probe in flight).
#[tokio::test]
async fn a_listener_reads_only_a_settled_era() {
    use crate::protocol::era::{Era, EraCache, ProbeOutcome};
    let cache = EraCache::for_backend("b");
    assert_eq!(cache.settled().await, None, "never probed");
    cache
        .resolve_with(|| async { ProbeOutcome::NoAnswer })
        .await;
    assert_eq!(cache.settled().await, Some(Era::Legacy), "a silent peer");
    let cache = EraCache::for_backend("b");
    let modern = serde_json::json!({"capabilities": {}, "supportedVersions": ["2026-07-28"]});
    cache
        .resolve_with(|| async { ProbeOutcome::Result(modern) })
        .await;
    assert_eq!(cache.settled().await, Some(Era::Modern));
    assert!(cache.discard_if(|_| true).await);
    assert_eq!(cache.settled().await, None, "discarded, re-probe pending");
}

/// MIK-8125 (d0 review W2): a publish that replaces the slot's transport is
/// never read as undetected. Old and new transports both detected the legacy
/// SSE handshake, so every reader must see `Some(false)`: the old pair, or
/// the new one. Read as `None` (unresolved), an ineligible backend's events
/// would be admitted for the length of the swap.
#[test]
fn a_transport_swap_is_never_read_as_undetected() {
    let backend = Arc::new(backend());
    let old = http("http://127.0.0.1:9/mcp");
    old.set_detected(Some(false));
    backend.install_http_for_test(&old);
    assert_eq!(backend.connected_streamable(), Some(false), "premise");
    let new = http("http://127.0.0.1:9/mcp");
    new.set_detected(Some(false));

    // Inside the swap, the slot is read without waiting: either a writer
    // holds it (the swap is atomic to readers) or the read lands in the swap
    // and must still see a legacy transport. No thread, no clock.
    let inside = Arc::new(parking_lot::Mutex::new(None::<Option<Option<bool>>>));
    let (reader, seen) = (Arc::clone(&backend), Arc::clone(&inside));
    *backend.between_listen_and_transport.lock() = Some(Box::new(move || {
        *seen.lock() = Some(reader.try_connected_streamable());
    }));
    let entry = backend.shared_entry();
    let erased: Arc<dyn crate::transport::Transport> = Arc::clone(&new) as _;
    backend
        .publish(
            &entry,
            (&erased, Some(super::handle_of(&new))),
            backend.destination(),
            || {},
        )
        .expect("published");
    match inside.lock().take().expect("the swap ran its hook") {
        None => {} // the swap held the slot: no reader could land in it
        Some(read) => assert_eq!(
            read,
            Some(false),
            "a reader inside the swap saw an undetected transport"
        ),
    }
    assert_eq!(
        backend.connected_streamable(),
        Some(false),
        "after the swap"
    );
}
