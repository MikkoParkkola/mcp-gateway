// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7976: a record whose event type no source offers is held, never sent,
//! and its subscription kept.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use chrono::Utc;

use super::{EventsHub, Offering, audit_actions, counting_callback, logged_services, queued_as};
use crate::events::types::SourceKind;

fn open_hub(dir: &std::path::Path, max_attempts: u32) -> Arc<EventsHub> {
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        retry_max_attempts: max_attempts,
        ..crate::config::EventsConfig::default()
    };
    EventsHub::open(&config, dir).expect("hub")
}

/// A source installed after the worker started (the task source at boot), or
/// a webhook route a partial scan missed: the record waits unsent and with no
/// `sending` record, the subscription stays, and once the type is offered the
/// next attempt reaches the callback.
#[tokio::test]
async fn an_unoffered_type_is_held_then_sent_once_offered() {
    for (name, kind) in [
        ("probe.late", SourceKind::GatewayOperational),
        ("webhook.c.r.received", SourceKind::Webhook),
    ] {
        let dir = tempfile::tempdir().expect("dir");
        let hub = open_hub(dir.path(), 5);
        let services = logged_services(dir.path());
        let (port, accepted) = counting_callback().await;
        queued_as(&hub, port, "evt_late", name);
        hub.attempt(&services, "evt_late").await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(accepted.load(Ordering::SeqCst), 0, "{name}: no POST");
        assert_eq!(hub.store.subscriptions().len(), 1, "{name}: kept");
        let later = Utc::now() + chrono::Duration::minutes(5);
        let due = hub
            .store
            .due(later, &std::collections::HashSet::new())
            .expect("io");
        assert_eq!(due.ready.len(), 1, "{name}: still pending");
        assert_eq!(
            due.ready[0].last_status.as_deref(),
            Some("access_revoked"),
            "{name}"
        );
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
        assert!(!log.contains("\"status\":\"sending\""), "{name}: {log}");
        assert!(
            log.contains("\"status\":\"access_revoked\""),
            "{name}: {log}"
        );

        hub.register_source(Arc::new(Offering {
            kind,
            names: vec![name],
        }));
        hub.attempt(&services, "evt_late").await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(accepted.load(Ordering::SeqCst) >= 1, "{name}: sent");
    }
}

/// A held record is bounded like any other: past its attempts it dies
/// `exhausted`, unsent, and the subscription stays.
#[tokio::test]
async fn an_unoffered_record_past_its_bounds_dies_and_keeps_its_subscription() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = open_hub(dir.path(), 0);
    let services = logged_services(dir.path());
    let (port, accepted) = counting_callback().await;
    queued_as(&hub, port, "evt_old", "probe.late");
    hub.attempt(&services, "evt_old").await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(hub.store.dead_letter_by_id("evt_old").is_some(), "buried");
    assert_eq!(hub.store.subscriptions().len(), 1, "kept");
    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
    assert!(log.contains("\"status\":\"exhausted\""), "{log}");
}

/// Offers its type for the first `offers` lookups only: the source switched
/// off while the attempt waited for its `sending` record.
struct Vanishing {
    offers: AtomicUsize,
}

#[async_trait::async_trait]
impl crate::events::EventSource for Vanishing {
    fn kind(&self) -> SourceKind {
        SourceKind::GatewayOperational
    }
    fn descriptors(&self) -> Vec<crate::events::types::EventDescriptor> {
        Vec::new()
    }
    fn offers(&self, name: &str) -> bool {
        name == "probe.vanish"
            && self
                .offers
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
    }
    fn matches(
        &self,
        _principal: &str,
        _arguments: &serde_json::Value,
        _event: &crate::events::fanout::SourceEvent,
    ) -> bool {
        true
    }
}

/// The type is read again after the waits for the record: withdrawn during
/// them, the attempt is not sent or charged, ends `access_revoked` on record,
/// and the subscription stays.
#[tokio::test]
async fn a_type_withdrawn_after_the_sending_record_is_held() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = open_hub(dir.path(), 5);
    hub.register_source(Arc::new(Vanishing {
        offers: AtomicUsize::new(1),
    }));
    #[allow(unused_mut, reason = "set only with cost-governance")]
    let mut services = logged_services(dir.path());
    #[cfg(feature = "cost-governance")]
    let registry = super::budgeted(&mut services);
    let (port, accepted) = counting_callback().await;
    queued_as(&hub, port, "evt_vanish", "probe.vanish");
    hub.attempt(&services, "evt_vanish").await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(accepted.load(Ordering::SeqCst), 0, "no POST");
    #[cfg(feature = "cost-governance")]
    assert!(
        !registry.snapshot().contains_key("events:probe.vanish"),
        "not charged"
    );
    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
    assert!(log.contains("\"status\":\"sending\""), "{log}");
    let ended = audit_actions(dir.path(), "events.delivery_outcome");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["status"], "access_revoked");
    assert_eq!(hub.store.subscriptions().len(), 1, "kept");
}
