// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The watch access check: a holder it skips (MIK-8122), and a clock that
//! fails inside it (MIK-8202).

use super::*;

/// A row whose access check answers `Undated` (the refusal may be the
/// clock's): the row is kept, nothing is called, and the poller polls on (it
/// is not retired). Then the holders and the retire check: judged on the
/// poll's one reading, a clock that cannot be read cannot empty them and
/// retire the poller.
#[tokio::test]
async fn a_watch_row_undated_by_the_clock_is_kept_and_not_called() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    let now = crate::clock::utc_now().expect("a readable clock");
    let mut last = None;
    let step = {
        let _undated = crate::events::services::forced_verdict::answer(
            crate::events::services::AccessVerdict::Undated,
        );
        poller.once(&hub, &mut last).await
    };
    assert!(matches!(step, Step::Polled), "the poller was retired");
    assert!(
        host.calls.lock().is_empty(),
        "called on an unreadable clock"
    );
    assert_eq!(
        hub.store.subscriptions().len(),
        1,
        "revoked on a refusal the clock may have caused"
    );

    // The holders and the retire check judge on the poll's one reading, never
    // on a fresh read: with the thread's clock reading before 1970, the row
    // live at that reading still holds the key and the poller is not retired.
    let _clock = crate::clock::test_clock::before_epoch();
    assert_eq!(poller.holders(&hub, now).len(), 1, "the live row lost");
    assert!(
        matches!(poller.retire(&hub, now).await, Step::Polled),
        "the poller was retired"
    );
}

/// A watch access check on a clock before 1970 dates no row, so it neither
/// admits nor refuses: it answers `clock_unreadable` (MIK-8202 A6). The
/// control: on a readable clock the same check refuses the denied holder.
#[tokio::test]
async fn a_watch_check_on_an_unreadable_clock_answers_clock_unreadable() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("crm", true, CredentialUse::Keyed)]);
    let name = "watch.crm.changed";
    admit(&hub, "p", name, &json!({}));
    host.denied.lock().push("p".into());
    let source = WatchSource::new(&hub, Arc::clone(&host) as Arc<dyn WatchHost>);
    let undated = {
        let _clock = crate::clock::test_clock::before_epoch();
        source.authorize("p", name, &json!({})).await
    };
    let undated = undated.expect_err("admitted on an unreadable clock");
    assert!(undated.is_clock_unreadable(), "{undated:?}");
    let refused = source
        .authorize("p", name, &json!({}))
        .await
        .expect_err("control: the denied holder is refused");
    assert_eq!(refused.code, -32011);
}

/// MIK-8122: a holder the capability's current definition no longer lets
/// invoke it is kept and skipped, not revoked: no call is made, the poller
/// stays, and fan-out skips the occurrence instead of revoking.
#[tokio::test]
async fn a_holder_without_access_is_skipped_not_revoked() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("crm", true, CredentialUse::Keyed)]);
    let name = "watch.crm.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    host.denied.lock().push("p".into());
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Polled));
    assert!(host.calls.lock().is_empty());
    assert_eq!(hub.store.subscriptions().len(), 1, "kept");
    let source = WatchSource::new(&hub, Arc::clone(&host) as Arc<dyn WatchHost>);
    let refused = source
        .authorize("p", name, &json!({}))
        .await
        .expect_err("fan-out re-check skips");
    assert_eq!(refused.code, -32011, "skip, keep");
}

/// Admit a live row for `principal` as `admit` does, but written by an
/// early build: it carries a bare `api_key_name` beside its bound key.
fn admit_legacy(hub: &EventsHub, principal: &str, name: &str, arguments: &serde_json::Value) {
    let row: Subscription = serde_json::from_value(json!({
        "v": 1, "principal": principal,
        "id": crate::events::rpc::subscription_id(principal, &format!("https://h/{principal}"), name, arguments),
        "url": format!("https://h/{principal}"), "name": name, "arguments": arguments,
        "secret": "whsec_x", "previous_secret": null, "previous_until": null,
        "granted_at": Utc::now(), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null,
        "api_key": {"name": format!("key-{principal}"), "principal": "0123456789ab"},
        "api_key_name": format!("key-{principal}"),
        "credential_kind": serde_json::to_value(crate::security::audit::CredentialKind::None)
            .expect("kind"),
    }))
    .expect("row");
    let config = crate::config::EventsConfig::default();
    hub.store
        .admit(
            row,
            true,
            crate::events::store::Caps {
                per_principal: 100,
                global: 100,
            },
            chrono::Duration::zero(),
            Utc::now(),
            crate::events::tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
}

/// MIK-8498 pin (P3.9): a row carrying a legacy `api_key_name` yields no
/// API key on its holder, in both holder copies today, and the copies
/// answer differently: `authorize` (the `live` holder) skips with
/// `-32011` and keeps the row, while a poll (the `once` holder) has no
/// key to call with, so it revokes the row and its poller retires.
#[tokio::test]
async fn a_row_with_a_legacy_key_name_has_no_key_to_poll_with() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("crm", true, CredentialUse::Keyed)]);
    let name = "watch.crm.changed";
    admit_legacy(&hub, "p", name, &json!({}));
    let rows = hub.store.subscriptions();
    assert_eq!(rows.len(), 1, "premise: one row");
    assert_eq!(
        rows[0].legacy_api_key_name.as_deref(),
        Some("key-p"),
        "premise: the legacy name is present"
    );
    assert!(rows[0].api_key.is_some(), "premise: a bound key is present");
    let source = WatchSource::new(&hub, Arc::clone(&host) as Arc<dyn WatchHost>);
    let refused = source
        .authorize("p", name, &json!({}))
        .await
        .expect_err("no holder for a legacy row");
    assert_eq!(refused.code, -32011, "skip, keep");
    assert_eq!(
        hub.store.subscriptions().len(),
        1,
        "authorize keeps the row"
    );
    let poller = run(&hub, &host, "p", name, &json!({}));
    let mut last = None;
    assert!(
        matches!(poller.once(&hub, &mut last).await, Step::Stop),
        "its last holder revoked, the poller retires"
    );
    assert!(host.calls.lock().is_empty(), "never called");
    assert!(
        hub.store.subscriptions().is_empty(),
        "a poll with no key to call with revokes the row"
    );
}
