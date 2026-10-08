// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8037: a watch subscription ends only on a confirmed absence (a
//! complete catalogue without the capability, or a capability read and no
//! longer watchable), decided against one catalogue generation.

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

/// MIK-8037: a partial catalogue that did read the capability, and found it
/// side-effecting, still withdraws: the capability was read, not missed.
#[tokio::test]
async fn a_partial_catalogue_still_withdraws_a_reclassified_capability() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    *host.targets.lock() = vec![target("weather", false, CredentialUse::Free)];
    host.partial.store(true, Ordering::Release);
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Stop));
    assert!(hub.store.subscriptions().is_empty(), "withdrawn");
}

/// MIK-8037: `authorize` answers `-32011` (skip the occurrence, keep the row)
/// for a capability a partial catalogue lacks, and `-32012` (revoke) only for
/// one a complete catalogue lacks.
#[tokio::test]
async fn authorize_revokes_only_on_a_complete_absence() {
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
    assert_eq!(complete.map_err(|e| e.code), Err(-32012), "removed: revoke");
}

/// MIK-8037: a holder denied while a reload moved the catalogue between the
/// read and the check is not revoked (the denial may be the reload's absence);
/// with the generation unmoved, it is.
#[tokio::test]
async fn a_denial_across_a_reload_revokes_nothing() {
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
    assert!(hub.store.subscriptions().is_empty(), "revoked when unmoved");
}

/// MIK-8037: a confirmed absence withdraws only when no catalogue write
/// landed since the read it was confirmed in.
#[tokio::test]
async fn an_absence_across_a_reload_withdraws_nothing() {
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
    host.moves.store(false, Ordering::Release);
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Stop));
    assert!(
        hub.store.subscriptions().is_empty(),
        "withdrawn once stable"
    );
}
