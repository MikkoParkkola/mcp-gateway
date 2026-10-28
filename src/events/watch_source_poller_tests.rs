// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A shared poller's life: whom it counts against, when it retires its key,
//! and which holders keep it running.

use std::sync::Arc;

use serde_json::json;

use super::*;

/// A shared poller counts against the principal that opened it, so one key
/// cannot fill the gateway's pollers with distinct shared arguments.
#[tokio::test]
async fn shared_pollers_count_against_the_principal_that_opened_them() {
    let dir = tempfile::tempdir().expect("dir");
    let mut config = crate::config::EventsConfig::default();
    config.watch.max_pollers_per_principal = 1;
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let source = WatchSource::new(&hub, host);
    let name = "watch.weather.changed";
    let open = |n: u32| {
        let arguments = json!({"arguments": {"city": n}});
        let key = source.lifecycle_key("p", name, &arguments, now());
        (key, arguments)
    };
    let (key, arguments) = open(1);
    source
        .on_first_subscriber(&key, "p", name, &arguments)
        .await
        .expect("the first");
    let (key, arguments) = open(2);
    let refused = source
        .on_first_subscriber(&key, "p", name, &arguments)
        .await
        .expect_err("past the principal's cap");
    assert_eq!(refused.code, -32013);
}

/// A poller that ended on its own leaves its entry behind until the core
/// reconciles; a subscribe in that gap starts a fresh poller instead of
/// joining the dead one.
#[tokio::test]
async fn a_subscribe_after_a_poller_exited_starts_a_fresh_one() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let source = WatchSource::new(&hub, host);
    let name = "watch.weather.changed";
    let arguments = json!({});
    let key = source.lifecycle_key("p", name, &arguments, now());
    source
        .on_first_subscriber(&key, "p", name, &arguments)
        .await
        .expect("started");
    let exited = Arc::clone(&source.pollers.lock()[&key].stop);
    exited.store(true, Ordering::Release);
    source
        .on_first_subscriber(&key, "p", name, &arguments)
        .await
        .expect("restarted");
    assert!(
        !source.pollers.lock()[&key].stop.load(Ordering::Acquire),
        "a live poller holds the key"
    );
}

/// A poller that ends because no live holder is left retires its key under
/// the lifecycle lock: a subscribe before the core's next reconcile starts a
/// fresh poller instead of finding the key started with nothing polling.
#[tokio::test]
async fn a_poller_without_holders_retires_its_key() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let poller = run(&hub, &host, "p", "watch.weather.changed", &json!({}));
    let started = (SourceKind::RestWatch, poller.key.clone());
    hub.lifecycle.lock().await.insert(started.clone());
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Stop));
    assert!(
        !hub.lifecycle.lock().await.contains(&started),
        "the key is no longer started"
    );
    assert!(poller.stop.load(Ordering::Acquire), "marked stopped");
}

/// A holder that commits while the poll reads the store (its subscribe found
/// the key started and joined it) keeps the poller and the key.
#[tokio::test]
async fn a_holder_that_joins_during_the_poll_keeps_the_poller() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    let poller = Arc::new(run(&hub, &host, "p", name, &json!({})));
    let started = (SourceKind::RestWatch, poller.key.clone());
    let mut lock = hub.lifecycle.lock().await;
    lock.insert(started.clone());
    let task = tokio::spawn({
        let (hub, poller) = (Arc::clone(&hub), Arc::clone(&poller));
        async move { matches!(poller.once(&hub, &mut None).await, Step::Stop) }
    });
    // The poll found no holder and now waits for the lock the subscribe holds.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    admit(&hub, "p", name, &json!({}));
    drop(lock);
    assert!(!task.await.expect("poll"), "the poller goes on");
    assert!(
        hub.lifecycle.lock().await.contains(&started),
        "still started"
    );
    assert!(!poller.stop.load(Ordering::Acquire), "not stopped");
}
