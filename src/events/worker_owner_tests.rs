// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7940 finding 9: owner-scoped occurrences at delivery. The worker asks
//! the source either way; an expired task is the task source's to admit.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::{EventsHub, Flipping, counting_callback, logged_services, queued_with};

/// An owner-scoped occurrence is still put to its source at delivery: a source
/// whose verdict is live standing (an operational source and a demoted admin)
/// refuses, so nothing is sent and the subscription ends, owner-scoped or not.
/// A task source's expired record is the source's own exception, not the
/// worker's (MIK-7940).
#[tokio::test]
async fn an_owner_scoped_occurrence_is_refused_by_its_source() {
    for owner_scoped in [false, true] {
        let dir = tempfile::tempdir().expect("dir");
        let config = crate::config::EventsConfig {
            callback_allow_private: vec!["127.0.0.0/8".into()],
            ..crate::config::EventsConfig::default()
        };
        let hub = EventsHub::open(&config, dir.path()).expect("hub");
        hub.register_source(Arc::new(Flipping {
            free: &[],
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
            accepted.load(Ordering::SeqCst),
            0,
            "not sent ({owner_scoped})"
        );
        assert!(
            hub.store.subscriptions().is_empty(),
            "revoked ({owner_scoped})"
        );
    }
}

/// A source that admits does not excuse the caller: an owner-scoped
/// occurrence whose API key is no longer configured is still refused (access
/// is checked on every attempt).
#[tokio::test]
async fn an_owner_scoped_occurrence_still_needs_its_callers_access() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    hub.register_source(Arc::new(Flipping {
        free: &[],
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
