// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An unreadable clock at fan-out: an occurrence whose source cannot judge
//! on the clock. Split from `worker_clock_tests.rs`.

use super::{ClockBlind, EventsHub, NAME, logged_services, now, private_callbacks, queued};

/// Fan-out to a source that cannot judge on the clock: the row is kept and
/// the occurrence dropped and counted as a clock drop.
#[tokio::test]
async fn fan_out_to_a_source_that_cannot_judge_on_the_clock_counts_a_drop() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = logged_services(dir.path());
    hub.register_source(ClockBlind::after(0));
    queued(&hub, 9, "evt_fo");
    let event = crate::events::fanout::SourceEvent {
        kind: crate::events::types::SourceKind::Webhook,
        name: NAME.into(),
        backend: "b".into(),
        scope: crate::events::types::Visibility::Owner,
        owner: None,
        upstream_id: "u1".into(),
        occurred_at: now(),
        data: serde_json::json!({}),
        lifecycle_key: None,
        fence: None,
    };
    hub.fan_out(&services, &event).await;
    assert_eq!(hub.runtime.clock_drops(), 1, "the drop is counted");
    assert!(hub.store.get("sub_worker").is_some(), "the row was revoked");
}
