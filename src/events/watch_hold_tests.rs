// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8122: no catalogue read deletes a REST watch subscription. A watch
//! that is not watchable now is held (nothing polled), resumes by itself when
//! it is again, and lapses at its bound, as MIK-8057 holds webhooks.

use std::sync::Arc;

use serde_json::json;

use super::*;

const NAME: &str = "watch.weather.changed";

/// The one stored row's id.
fn only_row(hub: &EventsHub) -> String {
    let rows = hub.store.subscriptions();
    assert_eq!(rows.len(), 1, "one row: {rows:?}");
    rows[0].id.clone()
}

/// W1 (`HOLD.1`): a complete catalogue without the capability holds the
/// watch instead of withdrawing it; the capability coming back resumes it,
/// and polling goes on.
#[tokio::test]
async fn an_absent_capability_holds_the_watch_then_resumes_it() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    admit(&hub, "p", NAME, &json!({}));
    let poller = run(&hub, &host, "p", NAME, &json!({}));
    let id = only_row(&hub);
    host.targets.lock().clear();
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Polled));
    assert_eq!(only_row(&hub), id, "kept");
    assert!(hub.store.held(&id).is_some(), "held");
    let calls = host.calls.lock().len();
    *host.targets.lock() = vec![target("weather", true, CredentialUse::Free)];
    poller.once(&hub, &mut last).await;
    assert!(hub.store.held(&id).is_none(), "resumed");
    assert!(host.calls.lock().len() > calls, "polled again");
}

/// W2 + W3: a capability read side-effecting (a file caught mid-write) holds
/// the watch and is not called; the whole file resumes it.
#[tokio::test]
async fn a_capability_read_side_effecting_holds_and_is_not_called() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    admit(&hub, "p", NAME, &json!({}));
    let poller = run(&hub, &host, "p", NAME, &json!({}));
    let id = only_row(&hub);
    *host.targets.lock() = vec![target("weather", false, CredentialUse::Free)];
    let calls = host.calls.lock().len();
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Polled));
    assert!(hub.store.held(&id).is_some(), "held, not withdrawn");
    assert_eq!(host.calls.lock().len(), calls, "no call while held");
    *host.targets.lock() = vec![target("weather", true, CredentialUse::Free)];
    poller.once(&hub, &mut last).await;
    assert!(hub.store.held(&id).is_none(), "resumed");
}

/// W8: the watch source's `authorize` never answers the revoke code for a
/// catalogue reason: a complete absence, a side-effecting read and a key the
/// current definition refuses all skip (`-32011`) and keep the row.
#[tokio::test]
async fn authorize_never_revokes_for_a_catalogue_reason() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    admit(&hub, "p", NAME, &json!({}));
    let source = WatchSource::new(&hub, Arc::clone(&host) as Arc<dyn WatchHost>);
    host.denied.lock().push("p".into());
    let refused = source.authorize("p", NAME, &json!({})).await;
    assert_eq!(
        refused.map_err(|e| e.code),
        Err(-32011),
        "refused key: skip"
    );
    host.denied.lock().clear();
    *host.targets.lock() = vec![target("weather", false, CredentialUse::Free)];
    let side = source.authorize("p", NAME, &json!({})).await;
    assert_eq!(
        side.map_err(|e| e.code),
        Err(-32011),
        "side-effecting: skip"
    );
    host.targets.lock().clear();
    let absent = source.authorize("p", NAME, &json!({})).await;
    assert_eq!(absent.map_err(|e| e.code), Err(-32011), "absent: skip");
}

/// W13 + W15: a row whose key the current capability definition refuses is
/// kept and skipped by the poller: no call, no revoke, and the poller does
/// not retire; once the definition admits the key, polling resumes.
#[tokio::test]
async fn a_key_the_definition_refuses_is_kept_and_skipped() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    admit(&hub, "p", NAME, &json!({}));
    let poller = run(&hub, &host, "p", NAME, &json!({}));
    let id = only_row(&hub);
    host.denied.lock().push("p".into());
    let calls = host.calls.lock().len();
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Polled));
    assert_eq!(only_row(&hub), id, "kept, not revoked");
    assert_eq!(host.calls.lock().len(), calls, "no call for it");
    host.denied.lock().clear();
    poller.once(&hub, &mut last).await;
    assert!(host.calls.lock().len() > calls, "polled again");
}

/// W4: a judge that does not own a row leaves its hold alone: a webhook
/// route refresh, which judges webhook rows only, keeps a watch held.
#[tokio::test]
async fn another_sources_judgement_keeps_a_watch_hold() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    admit(&hub, "p", NAME, &json!({}));
    let poller = run(&hub, &host, "p", NAME, &json!({}));
    let id = only_row(&hub);
    host.targets.lock().clear();
    poller.once(&hub, &mut None).await;
    assert!(hub.store.held(&id).is_some(), "held");
    let not_mine = |_: &Subscription| None;
    hub.store
        .apply_holds(
            &not_mine,
            Utc::now(),
            crate::duration_bound::delta!(hours, 1),
        )
        .expect("io");
    assert!(hub.store.held(&id).is_some(), "still held");
}

/// W9: the lifecycle sweep keeps a held watch's key started while the
/// catalogue does not offer its type, so its poller sees it return.
#[tokio::test]
async fn the_sweep_keeps_a_held_watch_started() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let source = Arc::new(WatchSource::new(
        &hub,
        Arc::clone(&host) as Arc<dyn WatchHost>,
    ));
    hub.register_source(Arc::clone(&source) as Arc<dyn EventSource>);
    admit(&hub, "p", NAME, &json!({}));
    // As the replay does before any sweep: the row's class is recorded.
    source.pin_rows(&hub.store);
    let poller = run(&hub, &host, "p", NAME, &json!({}));
    let started = (SourceKind::RestWatch, poller.key.clone());
    hub.lifecycle.lock().await.insert(started.clone());
    host.targets.lock().clear();
    poller.once(&hub, &mut None).await;
    hub.reconcile_stops().await;
    assert!(
        hub.lifecycle.lock().await.contains(&started),
        "the held watch's key stays started"
    );
}

/// W11: a held row stays held across a restart until its poller judges it
/// again; its refresh is answered as held meanwhile.
#[tokio::test]
async fn a_hold_survives_a_restart() {
    let dir = tempfile::tempdir().expect("dir");
    let id = {
        let hub = hub(dir.path());
        let host = fake(vec![target("weather", true, CredentialUse::Free)]);
        admit(&hub, "p", NAME, &json!({}));
        let poller = run(&hub, &host, "p", NAME, &json!({}));
        host.targets.lock().clear();
        poller.once(&hub, &mut None).await;
        only_row(&hub)
    };
    let hub = hub(dir.path());
    assert!(hub.store.held(&id).is_some(), "held after the restart");
}

/// MIK-8151 `AC1`: a watch row written before its class was recorded gets
/// no key and no class while a partial catalogue leaves its capability
/// unread; once a complete read offers it credential-free, the next sweep
/// pins the row shared and polls under the shared key.
#[tokio::test]
async fn a_legacy_watch_waits_for_its_class_then_polls_shared() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(Vec::new());
    host.partial
        .store(true, std::sync::atomic::Ordering::Release);
    admit(&hub, "p", NAME, &json!({}));
    hub.install_watch_source(Arc::clone(&host) as Arc<dyn WatchHost>);
    tokio::task::yield_now().await;
    assert!(hub.lifecycle.lock().await.is_empty(), "no key while unread");
    let id = only_row(&hub);
    let class = |hub: &EventsHub| hub.store.subscriptions()[0].watch_class;
    assert_eq!(class(&hub), None, "no class guessed while unread");
    host.partial
        .store(false, std::sync::atomic::Ordering::Release);
    *host.targets.lock() = vec![target("weather", true, CredentialUse::Free)];
    sweep(&hub).await;
    let shared = (SourceKind::RestWatch, json!([NAME, {}]).to_string());
    assert!(
        hub.lifecycle.lock().await.contains(&shared),
        "started under the shared key"
    );
    assert_eq!(class(&hub), Some(WatchClass::Free), "pinned shared");
    assert!(hub.store.held(&id).is_none(), "not held");
}

/// MIK-8151: a watch row written before its class was recorded, whose
/// capability a whole catalogue read does not offer, is held and bounded
/// with no class recorded; once the capability is offered the row takes its
/// class, its poller starts and resumes it.
#[tokio::test]
async fn a_legacy_watch_the_catalogue_drops_is_held_then_resumes() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(Vec::new());
    admit(&hub, "p", NAME, &json!({}));
    hub.install_watch_source(Arc::clone(&host) as Arc<dyn WatchHost>);
    tokio::task::yield_now().await;
    sweep(&hub).await;
    let id = only_row(&hub);
    assert!(hub.store.held(&id).is_some(), "held by a whole read");
    let row = &hub.store.subscriptions()[0];
    assert!(row.held_until.is_some(), "bounded: {row:?}");
    assert_eq!(row.watch_class, None, "no class guessed");
    *host.targets.lock() = vec![target("weather", true, CredentialUse::Free)];
    sweep(&hub).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while hub.store.held(&id).is_some() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(hub.store.held(&id).is_none(), "resumed by its poller");
    assert_eq!(
        hub.store.subscriptions()[0].watch_class,
        Some(WatchClass::Free),
        "pinned once offered"
    );
}
