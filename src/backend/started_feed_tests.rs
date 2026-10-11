// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T1b (MIK-8347): a backend's registry hears its name once each time a
//! shared start succeeds, after the start lock is released, and never for a
//! start that failed or found the transport already live. Task recovery
//! retries pending upstream cancels on it.

use std::sync::Arc;
use std::time::Duration;

use super::publish_order_tests::upstream;
use super::{Backend, MarkWindowGate};
use crate::backend::BackendRegistry;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::test_wait::HANG_BOUND;

fn http_backend(name: &str, url: String) -> Arc<Backend> {
    Arc::new(Backend::new(
        name,
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// Red at base. Mutants: "no announcement", "announced before the start
/// lock is released" (caught when the listener runs first, which this
/// multi-thread runtime allows), "announced by a start that found the
/// transport live".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shared_start_is_announced_once_after_its_lock_is_released() {
    let registry = BackendRegistry::new();
    let backend = http_backend("order", upstream().await);
    assert!(registry.register(Arc::clone(&backend)), "fixture registration");
    let mut feed = registry.subscribe_started();
    let gate = Arc::new(MarkWindowGate::default());
    *backend.publish_gate.lock() = Some(Arc::clone(&gate));
    // The listener checks the lock the moment it hears the name.
    let listener = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move {
            let name = feed.recv().await.expect("the feed stays open");
            let free = backend.shared_entry().start_lock.try_lock().is_ok();
            (name, free, feed)
        }
    });
    let start = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.ensure_started().await }
    });
    tokio::time::timeout(HANG_BOUND, gate.reached.notified())
        .await
        .expect("the start reached publish");
    assert!(!listener.is_finished(), "announced before the start finished");
    gate.release.notify_one();
    let (name, free, mut feed) = tokio::time::timeout(HANG_BOUND, listener)
        .await
        .expect("the start is announced")
        .expect("the listener ends cleanly");
    assert_eq!(name, "order");
    assert!(free, "announced while the start lock was still held");
    tokio::time::timeout(HANG_BOUND, start)
        .await
        .expect("the start ends")
        .expect("the start task ends cleanly")
        .expect("the start succeeds");
    backend
        .ensure_started()
        .await
        .expect("a live transport is reused");
    assert!(feed.try_recv().is_err(), "a start that found it live announced");
}

/// Guard. Mutant: "a failed start is
/// announced".
#[tokio::test]
async fn a_failed_start_is_not_announced() {
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        format!("http://{}/mcp", listener.local_addr().expect("addr"))
    };
    let registry = BackendRegistry::new();
    let backend = http_backend("down", closed);
    assert!(registry.register(Arc::clone(&backend)), "fixture registration");
    let mut feed = registry.subscribe_started();
    assert!(backend.ensure_started().await.is_err(), "premise: nothing listens");
    assert!(feed.try_recv().is_err(), "a failed start was announced");
}
