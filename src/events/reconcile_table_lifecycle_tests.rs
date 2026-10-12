// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reconcile table (Family-fix MIK-7940, design r3 section 6), rows on the
//! worker's expiry tick. Each row forces this thread's clock
//! (`crate::clock::test_clock`) and calls the tick itself, so no real-clock
//! lease can lapse early and no sweep can do the tick's work (MIK-8360).

use super::*;

/// The epoch seconds a row starts at, and that time as a chrono time.
fn at(secs: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(i64::try_from(secs).expect("secs"), 0).expect("a time")
}

/// A hub with the probe source and one live row per `k` value, each with a
/// lease ending at `start + 300`, every key started. The clock must already
/// be forced to `start`.
async fn hub_with_rows(
    dir: &std::path::Path,
    start: u64,
    ks: &[&str],
) -> (Arc<EventsHub>, Arc<Probe>, crate::config::EventsConfig) {
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir).expect("hub");
    let probe = Arc::new(Probe::default());
    hub.register_source(probe.clone());
    for k in ks {
        let row: Subscription = serde_json::from_value(json!({
            "v": 1, "id": format!("sub_{k}"), "principal": "p", "url": url("p"),
            "name": NAME, "arguments": {"k": k}, "secret": "whsec_x",
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
    }
    hub.replay_starts().await;
    assert_eq!(
        probe.first.load(Ordering::SeqCst),
        ks.len(),
        "premise: every key started"
    );
    (hub, probe, config)
}

/// T10 (MIK-8179 STARTED.1, design r3 D4/L5, finding #9): a row that expires
/// releases its source key at the worker's expiry tick, not at the sweep.
///
/// The tick (`stop_expired_keys`, which the worker runs every turn) is
/// called directly, so no sweep runs (MIK-8360): one tick inside the lease
/// releases nothing, and one past it releases the key. A 300 ms lease on
/// the real clock once lapsed before the start on a slow runner.
#[tokio::test]
async fn t10_an_expired_row_releases_its_key_without_a_sweep() {
    let start = crate::clock::unix_secs().expect("a clock after 1970");
    let pinned = crate::clock::test_clock::at_secs(start);
    let dir = tempfile::tempdir().expect("dir");
    let (hub, probe, _config) = hub_with_rows(dir.path(), start, &["v"]).await;
    hub.stop_expired_keys().await;
    assert_eq!(
        probe.last.load(Ordering::SeqCst),
        0,
        "inside the lease, the tick releases nothing"
    );
    drop(pinned);
    let _lapsed = crate::clock::test_clock::at_secs(start + 301);
    hub.stop_expired_keys().await;
    assert_eq!(
        probe.last.load(Ordering::SeqCst),
        1,
        "past the lease, the tick releases the key"
    );
}

/// MIK-8202 on the worker's expiry tick (MIK-8360): a tick on a clock before
/// 1970 judges no lease, stops nothing, and leaves its bookkeeping exactly as
/// it was, so what happened while the clock was unreadable is still seen
/// once it reads: the lease that lapsed, and a row another path removed. A
/// fallback reading (a far-future or epoch "now") would move the bookkeeping.
#[tokio::test]
async fn an_expiry_tick_before_1970_judges_nothing_and_loses_nothing() {
    let start = crate::clock::unix_secs().expect("a clock after 1970");
    let pinned = crate::clock::test_clock::at_secs(start);
    let dir = tempfile::tempdir().expect("dir");
    let (hub, probe, config) = hub_with_rows(dir.path(), start, &["v", "w"]).await;
    hub.stop_expired_keys().await;
    // Removed by another path while the clock still reads; the tick that
    // would notice runs on the unreadable clock.
    assert!(
        hub.store
            .remove("sub_w", at(start), tail_policy(&config))
            .expect("io"),
        "removed"
    );
    drop(pinned);
    let seen = |hub: &EventsHub| {
        let seen = hub.runtime.expiry_seen.lock();
        (seen.at, seen.next, seen.removals, seen.generation)
    };
    let before = seen(&hub);
    {
        let _dark = crate::clock::test_clock::before_epoch();
        hub.stop_expired_keys().await;
        assert_eq!(
            probe.last.load(Ordering::SeqCst),
            0,
            "a tick on an unreadable clock stops nothing"
        );
        assert_eq!(seen(&hub), before, "and moves no bookkeeping");
    }
    let _lapsed = crate::clock::test_clock::at_secs(start + 301);
    hub.stop_expired_keys().await;
    assert_eq!(
        probe.last.load(Ordering::SeqCst),
        2,
        "once the clock reads, the lapsed lease and the removed row are both seen"
    );
}
