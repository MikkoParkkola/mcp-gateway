// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reconcile table (Family-fix MIK-7940, design r3 section 6), rows that run
//! the hub's worker. Expiry is judged on the wall clock, so these rows wait
//! in real time, bounded well under the 30 s sweep they must not rely on.

use super::*;

/// T10 (MIK-8179 STARTED.1, design r3 D4/L5, finding #9): a row that expires
/// releases its source key at the worker's expiry tick, not at the sweep.
///
/// On this thread's forced clock (MIK-8360): the row is admitted with a
/// 300 s lease and its key starts with no race against the wall clock; the
/// clock then moves past the lease, and the worker, which reads the same
/// clock on this thread, must release the key on its next tick. A 300 ms
/// lease on the real clock lapsed before the start on a slow runner.
#[tokio::test]
async fn t10_an_expired_row_releases_its_key_without_a_sweep() {
    /// Real-time bound on the wait for the release: only a hang reaches it.
    const HANG_BOUND: std::time::Duration = std::time::Duration::from_secs(60);
    let start = crate::clock::unix_secs().expect("a clock after 1970");
    let at = |secs: u64| {
        chrono::DateTime::from_timestamp(i64::try_from(secs).expect("secs"), 0).expect("a time")
    };
    let pinned = crate::clock::test_clock::at_secs(start);
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let probe = Arc::new(Probe::default());
    hub.register_source(probe.clone());
    let row: Subscription = serde_json::from_value(json!({
        "v": 1, "id": "sub_t10", "principal": "p", "url": url("p"),
        "name": NAME, "arguments": {"k": "v"}, "secret": "whsec_x",
        "previous_secret": null, "previous_until": null,
        "granted_at": at(start),
        "expires_at": at(start + 300),
        "active": true, "failed_since": null, "last_delivery_at": null,
        "last_error": null
    }))
    .expect("row");
    hub.store
        .admit(
            row,
            true,
            store::Caps {
                per_principal: 10,
                global: 10,
            },
            chrono::Duration::zero(),
            at(start),
            tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
    hub.replay_starts().await;
    assert_eq!(
        probe.first.load(Ordering::SeqCst),
        1,
        "premise: key started"
    );
    hub.start(services());
    assert!(hub.reconcile_catalogue(fanout::CatalogueScan::Complete));
    drop(pinned);
    let _lapsed = crate::clock::test_clock::at_secs(start + 301);
    let released = tokio::time::timeout(HANG_BOUND, async {
        while probe.last.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "the key is released at the worker's expiry tick, with no sweep"
    );
}

/// MIK-8202 on the worker's expiry tick (MIK-8360): a tick on a clock before
/// 1970 judges no lease and stops nothing, and leaves its bookkeeping as it
/// was, so the lease that lapsed is still seen once the clock reads again. A
/// fallback reading (a far-future "now") would stop nothing either, but would
/// move the last reading past every lease and lose this one for good.
#[tokio::test]
async fn an_expiry_tick_before_1970_judges_nothing_and_loses_nothing() {
    let start = crate::clock::unix_secs().expect("a clock after 1970");
    let at = |secs: u64| {
        chrono::DateTime::from_timestamp(i64::try_from(secs).expect("secs"), 0).expect("a time")
    };
    let pinned = crate::clock::test_clock::at_secs(start);
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let probe = Arc::new(Probe::default());
    hub.register_source(probe.clone());
    let row: Subscription = serde_json::from_value(json!({
        "v": 1, "id": "sub_t10e", "principal": "p", "url": url("p"),
        "name": NAME, "arguments": {"k": "v"}, "secret": "whsec_x",
        "previous_secret": null, "previous_until": null,
        "granted_at": at(start),
        "expires_at": at(start + 300),
        "active": true, "failed_since": null, "last_delivery_at": null,
        "last_error": null
    }))
    .expect("row");
    hub.store
        .admit(
            row,
            true,
            store::Caps {
                per_principal: 10,
                global: 10,
            },
            chrono::Duration::zero(),
            at(start),
            tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
    hub.replay_starts().await;
    assert_eq!(
        probe.first.load(Ordering::SeqCst),
        1,
        "premise: key started"
    );
    hub.stop_expired_keys().await;
    drop(pinned);
    {
        let _dark = crate::clock::test_clock::before_epoch();
        hub.stop_expired_keys().await;
        assert_eq!(
            probe.last.load(Ordering::SeqCst),
            0,
            "a tick on an unreadable clock stops nothing"
        );
    }
    let _lapsed = crate::clock::test_clock::at_secs(start + 301);
    hub.stop_expired_keys().await;
    assert_eq!(
        probe.last.load(Ordering::SeqCst),
        1,
        "the lease that lapsed is still seen once the clock reads"
    );
}
