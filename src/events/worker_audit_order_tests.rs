// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7944 D6.EVENTS_MISC.2 and .3: an audit outage does not use up the
//! retry budget, and a burial's receipt comes before its eviction's.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use super::{
    DeadReason, EventsHub, Settle, counting_callback, logged_services, offer, queued, queued_event,
};

fn audit_log(dir: &std::path::Path) -> Arc<crate::security::TransparencyLogger> {
    Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path: dir.join("audit.jsonl").to_string_lossy().into_owned(),
                ..crate::security::TransparencyLogConfig::default()
            },
        ))
        .expect("log"),
    )
}

/// The audit lines for `event_id`, in log order, as their `action`.
fn actions_for(dir: &std::path::Path, event_id: &str) -> Vec<String> {
    std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|r| r["event_id"] == event_id)
        .filter_map(|r| r["action"].as_str().map(str::to_owned))
        .collect()
}

fn assert_burial_first(dir: &std::path::Path, event_id: &str) {
    let actions = actions_for(dir, event_id);
    let at = |a: &str| actions.iter().position(|x| x == a);
    let (buried, evicted) = (at("events.dead_letter"), at("events.dead_letter_evicted"));
    assert!(
        buried.is_some() && evicted.is_some(),
        "both receipts: {actions:?}"
    );
    assert!(buried < evicted, "burial before eviction: {actions:?}");
}

/// The first pending record, as the worker would claim it.
fn pending(hub: &EventsHub, event_id: &str) -> crate::events::outbox::OutboxRecord {
    let later = Utc::now() + chrono::Duration::minutes(5);
    hub.store
        .due(later, &std::collections::HashSet::new())
        .expect("io")
        .ready
        .into_iter()
        .find(|r| r.event_id == event_id)
        .expect("pending")
}

fn gone() -> Settle {
    Settle::Dead {
        reason: DeadReason::Gone,
        status: None,
    }
}

/// .2: claims the audit log refused sent nothing, so they do not count
/// toward `retry_max_attempts`. Once the log recovers the record is sent,
/// not buried `exhausted`.
#[tokio::test]
async fn an_audit_outage_does_not_use_up_the_attempts() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let log = audit_log(dir.path());
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        retry_max_attempts: 2,
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let mut services = logged_services(dir.path());
    services.audit = Some(Arc::clone(&log));
    let (port, accepted) = counting_callback().await;
    offer(&hub, &["webhook.c.r.received"]);
    queued(&hub, port, "evt_outage");
    log.set_append_failure_for_test(true);
    for _ in 0..3 {
        hub.attempt(&services, "evt_outage").await;
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "nothing sent yet");

    log.set_append_failure_for_test(false);
    hub.attempt(&services, "evt_outage").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        hub.store.dead_letter_by_id("evt_outage").is_none(),
        "not buried exhausted: {:?}",
        actions_for(dir.path(), "evt_outage")
    );
    assert!(
        accepted.load(Ordering::SeqCst) >= 1,
        "sent once the log recovered"
    );
}

/// .3: a burial over the byte cap is evicted at once; its own receipt is
/// written before the eviction's (worker settle).
#[tokio::test]
async fn a_self_evicting_burial_is_receipted_before_its_eviction() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        dead_letter_max_bytes: 1,
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = logged_services(dir.path());
    queued(&hub, 9, "evt_self");
    let record = pending(&hub, "evt_self");
    hub.settle(&services, &record, gone()).await;
    assert!(hub.store.dead_letter_by_id("evt_self").is_none(), "evicted");
    assert_burial_first(dir.path(), "evt_self");
}

/// .3: the same through the fan-out refusal of an oversized body.
#[tokio::test]
async fn a_self_evicting_refusal_is_receipted_before_its_eviction() {
    use crate::events::fanout::{MAX_BODY, SourceEvent};
    use crate::events::types::{SourceKind, Visibility};
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        dead_letter_max_bytes: 1,
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = logged_services(dir.path());
    offer(&hub, &["webhook.c.r.received"]);
    queued(&hub, 9, "evt_seed");
    let event = SourceEvent {
        kind: SourceKind::Webhook,
        name: "webhook.c.r.received".into(),
        backend: "b".into(),
        scope: Visibility::Owner,
        owner: None,
        upstream_id: "big".into(),
        occurred_at: Utc::now(),
        data: serde_json::json!({ "blob": "x".repeat(MAX_BODY + 1) }),
        lifecycle_key: None,
    };
    hub.fan_out(&services, &event).await;
    let id = crate::events::fanout::event_id(SourceKind::Webhook, "big", "sub_worker");
    assert_burial_first(dir.path(), &id);
}

/// .3 across callers: while one burial is between its store call and its
/// receipts, a second burial that evicts the first waits, so the first
/// burial's receipt still comes before its eviction.
#[tokio::test]
async fn an_eviction_by_another_burial_follows_the_first_burials_receipt() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        dead_letter_max_records: 1,
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = Arc::new(logged_services(dir.path()));
    queued(&hub, 9, "evt_x");
    queued_event(&hub, "evt_y");
    let (x, y) = (pending(&hub, "evt_x"), pending(&hub, "evt_y"));
    let (reached, release) = hub.before_receipts.arm();
    let first = tokio::spawn({
        let (hub, services) = (Arc::clone(&hub), Arc::clone(&services));
        async move { hub.settle(&services, &x, gone()).await }
    });
    reached.notified().await;
    let second = tokio::spawn({
        let (hub, services) = (Arc::clone(&hub), Arc::clone(&services));
        async move { hub.settle(&services, &y, gone()).await }
    });
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while !second.is_finished() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    release.notify_one();
    first.await.expect("first");
    second.await.expect("second");
    assert_burial_first(dir.path(), "evt_x");
}
