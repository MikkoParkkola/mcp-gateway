// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7940 finding 9: an owner-scoped occurrence was authorized where it was
//! made, so the worker does not let its source refuse it after the fact.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::{EventsHub, Flipping, counting_callback, logged_services, queued_with};

/// A source that refuses every ask stands in for a task source whose task
/// record expired. Owner-scoped, the occurrence is still delivered and the
/// subscription kept; not owner-scoped, it is refused and revoked, as today.
#[tokio::test]
async fn an_owner_scoped_occurrence_is_not_refused_by_its_source() {
    for owner_scoped in [false, true] {
        let dir = tempfile::tempdir().expect("dir");
        let config = crate::config::EventsConfig {
            callback_allow_private: vec!["127.0.0.0/8".into()],
            ..crate::config::EventsConfig::default()
        };
        let hub = EventsHub::open(&config, dir.path()).expect("hub");
        hub.register_source(Arc::new(Flipping {
            admits: 0,
            asked: AtomicUsize::new(0),
        }) as Arc<dyn crate::events::EventSource>);
        let services = logged_services(dir.path());
        let (port, accepted) = counting_callback().await;
        queued_with(&hub, port, "evt_owner", "probe.flip", |_, record| {
            record.owner_scoped = owner_scoped;
        });
        hub.attempt(&services, "evt_owner").await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            accepted.load(Ordering::SeqCst) >= 1,
            owner_scoped,
            "delivered only when owner-scoped"
        );
        assert_eq!(
            hub.store.subscriptions().is_empty(),
            !owner_scoped,
            "revoked only when not owner-scoped"
        );
    }
}
