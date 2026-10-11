// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202: a watch poll on a clock that fails inside its access check.

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
