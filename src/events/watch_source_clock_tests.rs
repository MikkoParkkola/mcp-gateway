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
