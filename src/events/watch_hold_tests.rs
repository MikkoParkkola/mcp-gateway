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
