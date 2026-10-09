// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reconcile table (Family-fix MIK-7940, design r3 section 6): the REST watch
//! rows. Each test is one row: an initial state, a change, and the asserted
//! rows (R), started keys (K) and pollers, with the worker sweep never run.
//! Rows marked PIN hold on base and must stay green; the rest fail on base
//! at their own assertions until the reconcile step lands.
//!
//! Rows here: T11 (watch half, PIN), T12 (red), T21 (red), T28 (watch half,
//! PIN), D1b (PIN). T29 is pinned by the hold module's
//! `a_legacy_watch_waits_for_its_class_then_polls_shared` and
//! `a_legacy_watch_the_catalogue_drops_is_held_then_resumes`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;

const NAME: &str = "watch.weather.changed";

/// A hub with `p`'s watch row and the source installed over `host`; the
/// registration's replay has run.
async fn installed(
    dir: &std::path::Path,
    config: &crate::config::EventsConfig,
    host: &Arc<Fake>,
) -> Arc<EventsHub> {
    let hub = hub_with(dir, config);
    admit(&hub, "p", NAME, &json!({}));
    hub.install_watch_source(Arc::clone(host) as Arc<dyn WatchHost>);
    tokio::time::sleep(Duration::from_millis(10)).await;
    hub
}

/// The one stored row's id.
fn row_id(hub: &EventsHub) -> String {
    let rows = hub.store.subscriptions();
    assert_eq!(rows.len(), 1, "one row: {rows:?}");
    rows[0].id.clone()
}

/// Past the poller's first poll (about 2 s after it starts).
async fn one_poll() {
    tokio::time::sleep(Duration::from_secs(3)).await;
}

/// T11, watch half (PIN, MIK-8179 STARTED.1 with design r3 K rule): a held
/// REST watch keeps its key, so its poller can see the capability return.
#[tokio::test(start_paused = true)]
async fn t11_a_held_watch_keeps_its_key() {
    let dir = tempfile::tempdir().expect("dir");
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let hub = installed(dir.path(), &crate::config::EventsConfig::default(), &host).await;
    let id = row_id(&hub);
    let keys = hub.lifecycle.lock().await.clone();
    assert_eq!(keys.len(), 1, "started: {keys:?}");
    host.targets.lock().clear();
    one_poll().await;
    assert!(hub.store.held(&id).is_some(), "held");
    assert_eq!(*hub.lifecycle.lock().await, keys, "the key stays started");
}

/// T12 (MIK-8179 STARTED.3): a poller that retires because no row owns its
/// key leaves no entry in the poller map, so it holds no slot.
#[tokio::test(start_paused = true)]
async fn t12_a_retired_poller_leaves_no_map_entry() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let source = WatchSource::new(&hub, host);
    let key = source.lifecycle_key("p", NAME, &json!({}));
    hub.lifecycle
        .lock()
        .await
        .insert((SourceKind::RestWatch, key.clone()));
    source
        .on_first_subscriber(&key, "p", NAME, &json!({}))
        .await
        .expect("started");
    one_poll().await;
    assert!(
        !hub.lifecycle
            .lock()
            .await
            .contains(&(SourceKind::RestWatch, key.clone())),
        "premise: retired, no row owns the key"
    );
    assert!(
        !source.pollers.lock().contains_key(&key),
        "the retired poller's map entry is gone"
    );
}

/// T28, watch half (PIN, #3550): a complete read without the capability
/// holds the watch and deletes nothing; its return resumes it.
#[tokio::test(start_paused = true)]
async fn t28_a_dropped_capability_holds_the_watch_then_resumes() {
    let dir = tempfile::tempdir().expect("dir");
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let hub = installed(dir.path(), &crate::config::EventsConfig::default(), &host).await;
    let id = row_id(&hub);
    host.targets.lock().clear();
    one_poll().await;
    assert!(hub.store.held(&id).is_some(), "held");
    *host.targets.lock() = vec![target("weather", true, CredentialUse::Free)];
    tokio::time::sleep(Duration::from_secs(400)).await;
    assert_eq!(row_id(&hub), id, "the row is kept");
    assert!(hub.store.held(&id).is_none(), "resumed");
}

/// D1b (PIN, #3550): a capability turned side-effecting holds the watch,
/// and the held watch makes no call.
#[tokio::test(start_paused = true)]
async fn d1b_a_side_effecting_capability_holds_and_is_not_called() {
    let dir = tempfile::tempdir().expect("dir");
    let host = fake(vec![target("weather", false, CredentialUse::Free)]);
    let hub = hub(dir.path());
    // The row was admitted while the capability was read-only.
    admit(&hub, "p", NAME, &json!({}));
    let source = WatchSource::new(&hub, Arc::clone(&host) as Arc<dyn WatchHost>);
    let key = source.lifecycle_key("p", NAME, &json!({}));
    source
        .on_first_subscriber(&key, "p", NAME, &json!({}))
        .await
        .expect("started");
    one_poll().await;
    let id = row_id(&hub);
    assert!(hub.store.held(&id).is_some(), "held");
    assert!(host.calls.lock().is_empty(), "never called");
}
