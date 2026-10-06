// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U6: the delivery charge skips a type its source exempts.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::{EventsHub, Flipping, budgeted, counting_callback, logged_services, queued_as};

/// U6: a source exempts one of its types from the delivery charge and not
/// the other: each is sent, and only the second is charged, so an exhausted
/// budget still hears that it is exhausted.
#[tokio::test]
async fn only_the_types_a_source_charges_are_charged() {
    for (name, charged) in [("probe.free", false), ("probe.flip", true)] {
        let dir = tempfile::tempdir().expect("dir");
        let config = crate::config::EventsConfig {
            callback_allow_private: vec!["127.0.0.0/8".into()],
            cost_per_delivery_usd: 0.01,
            ..crate::config::EventsConfig::default()
        };
        let hub = EventsHub::open(&config, dir.path()).expect("hub");
        hub.register_source(Arc::new(Flipping {
            admits: usize::MAX,
            asked: AtomicUsize::new(0),
            free: &["probe.free"],
        }) as Arc<dyn crate::events::EventSource>);
        let mut services = logged_services(dir.path());
        let registry = budgeted(&mut services);
        let (port, accepted) = counting_callback().await;
        queued_as(&hub, port, "evt_probe", name);
        hub.attempt(&services, "evt_probe").await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(accepted.load(Ordering::SeqCst) >= 1, "{name} sent");
        assert_eq!(
            registry.snapshot().contains_key(&format!("events:{name}")),
            charged,
            "{name} charged"
        );
    }
}
