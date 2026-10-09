// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reconcile table (Family-fix MIK-7940, design r3 section 6), rows that run
//! the hub's worker. Expiry is judged on the wall clock, so these rows wait
//! in real time, bounded well under the 30 s sweep they must not rely on.

use super::*;

/// T10 (MIK-8179 STARTED.1, design r3 D4/L5, finding #9): a row that expires
/// releases its source key at the worker's expiry tick, not at the sweep.
#[tokio::test]
async fn t10_an_expired_row_releases_its_key_without_a_sweep() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let probe = Arc::new(Probe::default());
    hub.register_source(probe.clone());
    let row: Subscription = serde_json::from_value(json!({
        "v": 1, "id": "sub_t10", "principal": "p", "url": url("p"),
        "name": NAME, "arguments": {"k": "v"}, "secret": "whsec_x",
        "previous_secret": null, "previous_until": null,
        "granted_at": chrono::Utc::now(),
        "expires_at": chrono::Utc::now() + crate::duration_bound::delta!(milliseconds, 300),
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
            chrono::Utc::now(),
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
    for _ in 0..60 {
        if probe.last.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        probe.last.load(Ordering::SeqCst),
        1,
        "the key is released within 6 s of expiry, with no sweep"
    );
}
