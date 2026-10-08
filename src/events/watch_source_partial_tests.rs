// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8037: a watch is acted on only on a confirmed absence (a complete
//! catalogue without the capability, or a capability read and no longer
//! watchable), decided against one catalogue generation; since MIK-8122 the
//! act is a hold, never a withdrawal.

use std::sync::Arc;

use serde_json::json;

use super::*;

/// MIK-8037 `WATCHGONE.1`: a poll while the catalogue is partial and lacks
/// the capability (its directory was not read) calls nothing and keeps every
/// subscription; the capability may come back with the next complete load.
#[tokio::test]
async fn a_partial_catalogue_without_the_capability_keeps_its_rows() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    host.targets.lock().clear();
    host.partial.store(true, Ordering::Release);
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Polled));
    assert!(host.calls.lock().is_empty(), "no call while it is unread");
    assert_eq!(hub.store.subscriptions().len(), 1, "nothing withdrawn");
}

/// MIK-8037: the confirmation under the lifecycle lock reads completeness
/// too. A first read that finds the capability reclassified, then a partial
/// one without it, keeps the rows.
#[tokio::test]
async fn a_partial_confirmation_keeps_the_rows() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    host.script
        .lock()
        .push_back(vec![target("weather", false, CredentialUse::Free)]);
    host.partial_script.lock().push_back(false);
    host.targets.lock().clear();
    host.partial.store(true, Ordering::Release);
    let mut last = None;
    poller.once(&hub, &mut last).await;
    assert_eq!(hub.store.subscriptions().len(), 1, "nothing withdrawn");
}

/// MIK-8037 with MIK-8122: a partial catalogue that did read the capability,
/// and found it side-effecting, holds it: the capability was read, not
/// missed, and no read deletes a watch.
#[tokio::test]
async fn a_partial_catalogue_holds_a_reclassified_capability() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    *host.targets.lock() = vec![target("weather", false, CredentialUse::Free)];
    host.partial.store(true, Ordering::Release);
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Polled));
    let rows = hub.store.subscriptions();
    assert_eq!(rows.len(), 1, "kept");
    assert!(hub.store.held(&rows[0].id).is_some(), "held");
}

/// MIK-8037 with MIK-8122: `authorize` answers `-32011` (skip the
/// occurrence, keep the row) for a capability a catalogue lacks, partial,
/// moved or complete alike: the watch's poller holds it.
#[tokio::test]
async fn authorize_skips_on_any_absence() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(Vec::new());
    let source = WatchSource::new(&hub, Arc::clone(&host) as Arc<dyn WatchHost>);
    let name = "watch.weather.changed";
    host.partial.store(true, Ordering::Release);
    let partial = source.authorize("p", name, &json!({})).await;
    assert_eq!(partial.map_err(|e| e.code), Err(-32011), "unread: skip");
    host.partial.store(false, Ordering::Release);
    host.moves.store(true, Ordering::Release);
    let moved = source.authorize("p", name, &json!({})).await;
    assert_eq!(
        moved.map_err(|e| e.code),
        Err(-32011),
        "written since: skip"
    );
    host.moves.store(false, Ordering::Release);
    let complete = source.authorize("p", name, &json!({})).await;
    assert_eq!(complete.map_err(|e| e.code), Err(-32011), "removed: skip");
}

/// MIK-8037 with MIK-8122: a holder the capability's definition refuses is
/// never revoked, across a reload or not: the denial is about the catalogue.
#[tokio::test]
async fn a_definition_denial_revokes_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    host.denied.lock().push("p".into());
    host.moves.store(true, Ordering::Release);
    let mut last = None;
    poller.once(&hub, &mut last).await;
    assert_eq!(hub.store.subscriptions().len(), 1, "kept across the reload");
    let source = WatchSource::new(&hub, Arc::clone(&host) as Arc<dyn WatchHost>);
    let moved = source.authorize("p", name, &json!({})).await;
    assert_eq!(moved.map_err(|e| e.code), Err(-32011), "skip, keep");
    host.moves.store(false, Ordering::Release);
    poller.once(&hub, &mut last).await;
    assert_eq!(hub.store.subscriptions().len(), 1, "kept when unmoved");
}

/// MIK-8037 with MIK-8122: an absence is acted on only when no catalogue
/// write landed since the read; then it holds, never withdraws.
#[tokio::test]
async fn an_absence_is_held_once_stable() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    host.targets.lock().clear();
    host.moves.store(true, Ordering::Release);
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Polled));
    assert_eq!(hub.store.subscriptions().len(), 1, "kept across the write");
    let id = hub.store.subscriptions()[0].id.clone();
    assert!(hub.store.held(&id).is_none(), "not held across the write");
    host.moves.store(false, Ordering::Release);
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Polled));
    assert!(hub.store.held(&id).is_some(), "held once stable");
}
