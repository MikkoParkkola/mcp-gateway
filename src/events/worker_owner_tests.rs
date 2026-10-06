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

/// Owner-scoped skips only the source's verdict: a caller whose API key is no
/// longer configured is still refused (access is checked on every attempt).
#[tokio::test]
async fn an_owner_scoped_occurrence_still_needs_its_callers_access() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    hub.register_source(Arc::new(Flipping {
        admits: usize::MAX,
        asked: AtomicUsize::new(0),
    }) as Arc<dyn crate::events::EventSource>);
    // No API keys configured: the subscription's key is gone.
    let services = logged_services(dir.path());
    let (port, accepted) = counting_callback().await;
    queued_with(&hub, port, "evt_owner_key", "probe.flip", |sub, record| {
        record.owner_scoped = true;
        sub.credential_kind = Some(crate::security::audit::CredentialKind::ApiKey);
        sub.api_key = Some(crate::events::records::ApiKeyRef {
            name: "gone".to_owned(),
            principal: "000000000000".to_owned(),
        });
    });
    hub.attempt(&services, "evt_owner_key").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "not sent");
    assert!(hub.store.subscriptions().is_empty(), "revoked");
}
