// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A burial's governance record survives an eviction by the caps. Split from `worker_tests.rs`
//! (file-size ceiling).

use super::*;

/// A burial the caps evict in the same instant still leaves its
/// governance record, because the receipt comes from the burial itself and not
/// from a later read of the store.
#[tokio::test]
async fn a_burial_the_caps_evict_at_once_still_leaves_its_record() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        dead_letter_max_records: 0,
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = logged_services(dir.path());
    queued(&hub, 9, "evt_evicted");
    let later = Utc::now() + crate::duration_bound::delta!(minutes, 5);
    let record = hub
        .store
        .due(later, &std::collections::HashSet::new(), hub.dead_policy())
        .expect("io")
        .ready
        .remove(0);
    hub.settle(
        &services,
        &record,
        Settle::Dead {
            reason: DeadReason::Gone,
            status: None,
        },
    )
    .await;
    assert!(
        hub.store.dead_letter_by_id("evt_evicted").is_none(),
        "the cap evicted the burial at once"
    );
    let written = audit_actions(dir.path(), "events.dead_letter");
    assert_eq!(written.len(), 1, "one record for the burial: {written:?}");
    assert_eq!(written[0]["event_id"], "evt_evicted");
}
