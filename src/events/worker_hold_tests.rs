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
        // Priced, so a charge would show in the budget's registry.
        cost_per_delivery_usd: 0.01,
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
        let later = Utc::now() + crate::duration_bound::delta!(minutes, 5);
        let due = hub
            .store
            .due(later, &std::collections::HashSet::new(), hub.dead_policy())
            .expect("io");
        assert_eq!(due.ready.len(), 1, "{name}: still pending");
        assert_eq!(
            due.ready[0].last_status.as_deref(),
            Some("source_unavailable"),
            "{name}"
        );
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
        assert!(!log.contains("\"status\":\"sending\""), "{name}: {log}");
        assert!(
            log.contains("\"status\":\"source_unavailable\""),
            "{name}: {log}"
        );
        assert!(!log.contains("access_revoked"), "{name}: nothing revoked");
        // What the client reads as `deliveryStatus.lastError`.
        assert_eq!(
            hub.store.subscriptions()[0].last_error.as_deref(),
            Some("source_unavailable"),
            "{name}"
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

/// A held record is bounded like any other: held through its attempts, never
/// sent or charged, then dead `exhausted`, and the subscription stays.
#[tokio::test]
async fn an_unoffered_record_is_held_until_exhausted_and_keeps_its_subscription() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = open_hub(dir.path(), 2);
    #[allow(unused_mut, reason = "set only with cost-governance")]
    let mut services = logged_services(dir.path());
    #[cfg(feature = "cost-governance")]
    let registry = super::budgeted(&mut services);
    let (port, accepted) = counting_callback().await;
    queued_as(&hub, port, "evt_old", "probe.late");
    for attempt in 1..=3 {
        hub.attempt(&services, "evt_old").await;
        let dead = hub.store.dead_letter_by_id("evt_old");
        assert_eq!(dead.is_some(), attempt == 3, "attempt {attempt}");
        if let Some(dead) = dead {
            assert_eq!(dead.reason, "exhausted");
        } else {
            let sub = &hub.store.subscriptions()[0];
            assert_eq!(sub.last_error.as_deref(), Some("source_unavailable"));
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(accepted.load(Ordering::SeqCst), 0, "never sent");
    #[cfg(feature = "cost-governance")]
    assert!(
        !registry.snapshot().contains_key("events:probe.late"),
        "never charged"
    );
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
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
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
/// them, the attempt is not sent or charged, ends `source_unavailable` on record,
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
    assert_eq!(ended[0]["status"], "source_unavailable");
    assert_eq!(hub.store.subscriptions().len(), 1, "kept");
}

/// MIK-8037: a source that answers `-32011` (the type's capability is not in
/// the catalogue now, which could not be read whole) holds the record like an
/// unoffered type: no POST, the subscription kept.
#[tokio::test]
async fn a_not_found_authorize_holds_the_record() {
    struct Unread;
    #[async_trait::async_trait]
    impl crate::events::EventSource for Unread {
        fn kind(&self) -> SourceKind {
            SourceKind::Webhook
        }
        fn descriptors(&self) -> Vec<crate::events::types::EventDescriptor> {
            vec![super::descriptor(
                "webhook.c.r.received",
                SourceKind::Webhook,
            )]
        }
        fn matches(
            &self,
            _principal: &str,
            _arguments: &serde_json::Value,
            _event: &crate::events::fanout::SourceEvent,
        ) -> bool {
            true
        }
        async fn authorize(
            &self,
            _principal: &str,
            _name: &str,
            _arguments: &serde_json::Value,
        ) -> Result<(), crate::events::types::RpcError> {
            Err(crate::events::types::RpcError::not_found())
        }
    }
    let dir = tempfile::tempdir().expect("dir");
    let hub = open_hub(dir.path(), 5);
    hub.register_source(Arc::new(Unread));
    let services = logged_services(dir.path());
    let (port, accepted) = counting_callback().await;
    queued_as(&hub, port, "evt_unread", "webhook.c.r.received");
    hub.attempt(&services, "evt_unread").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "no POST");
    assert_eq!(hub.store.subscriptions().len(), 1, "kept");
}
