// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The worker's sweep starts, frees and keeps watch pollers.

#![cfg_attr(
    test,
    allow(clippy::disallowed_methods, reason = "test code reads the host clock")
)]
use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use super::*;

/// A stored row whose capability was not offered when the source registered
/// (the startup scan still running, or a partial catalogue) gets its poller
/// from the next sweep once the capability is offered, and that poller polls.
#[tokio::test]
async fn a_sweep_starts_the_poller_of_a_capability_offered_again() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(Vec::new());
    admit(&hub, "p", "watch.weather.changed", &json!({}));
    hub.install_watch_source(Arc::clone(&host) as Arc<dyn WatchHost>);
    // The replay the registration spawned runs here, over an empty catalogue.
    tokio::task::yield_now().await;
    assert!(hub.lifecycle.lock().await.is_empty(), "nothing offered yet");
    *host.targets.lock() = vec![target("weather", true, CredentialUse::Free)];
    sweep(&hub).await;
    assert_eq!(hub.lifecycle.lock().await.len(), 1, "the sweep starts it");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while host.calls.lock().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(!host.calls.lock().is_empty(), "the started poller polls");
}

/// The sweep stops pollers no live row holds before it starts the
/// restored ones, so a stale poller never takes the last `max_pollers` slot.
/// A held watch is not stale: its poller runs to see it return,
/// so the slot here is freed by the row going.
#[tokio::test]
async fn a_sweep_frees_a_stale_slot_before_it_starts_a_restored_key() {
    let dir = tempfile::tempdir().expect("dir");
    let mut config = crate::config::EventsConfig::default();
    config.watch.max_pollers = 1;
    let hub = hub_with(dir.path(), &config);
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    admit(&hub, "p", "watch.weather.changed", &json!({}));
    admit(&hub, "p", "watch.rain.changed", &json!({}));
    hub.install_watch_source(Arc::clone(&host) as Arc<dyn WatchHost>);
    tokio::task::yield_now().await;
    assert_eq!(
        hub.lifecycle.lock().await.len(),
        1,
        "weather holds the slot"
    );
    // Weather's row goes; rain comes in.
    let weather = hub
        .store
        .subscriptions()
        .into_iter()
        .find(|s| s.name == "watch.weather.changed")
        .expect("weather row");
    let tail = crate::events::tail_policy(&crate::config::EventsConfig::default());
    hub.store
        .remove(&weather.id, Ok(Utc::now()), tail)
        .expect("removed");
    *host.targets.lock() = vec![
        target("weather", true, CredentialUse::Free),
        target("rain", true, CredentialUse::Free),
    ];
    sweep(&hub).await;
    let started = hub.lifecycle.lock().await;
    assert_eq!(started.len(), 1, "one poller, within the cap");
    assert!(
        started.iter().any(|(_, key)| key.contains("rain")),
        "the restored key took the freed slot: {started:?}"
    );
}

/// Review of #3406: a partial catalogue that leaves a watch's
/// capability unread neither drops its row nor its poller: the row keeps its
/// key, the poller runs on and decides nothing while unread, and
/// the whole catalogue finds it still started, once.
#[tokio::test]
async fn a_watch_poller_runs_through_a_partial_catalogue() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    admit(&hub, "p", "watch.weather.changed", &json!({}));
    hub.install_watch_source(Arc::clone(&host) as Arc<dyn WatchHost>);
    tokio::task::yield_now().await;
    assert_eq!(hub.lifecycle.lock().await.len(), 1, "premise: started");
    host.targets.lock().clear();
    host.partial.store(true, Ordering::Release);
    sweep(&hub).await;
    assert_eq!(
        hub.lifecycle.lock().await.len(),
        1,
        "still started while unread"
    );
    assert_eq!(hub.store.subscriptions().len(), 1, "the row is kept");
    host.partial.store(false, Ordering::Release);
    *host.targets.lock() = vec![target("weather", true, CredentialUse::Free)];
    sweep(&hub).await;
    assert_eq!(hub.lifecycle.lock().await.len(), 1, "one poller once whole");
}
