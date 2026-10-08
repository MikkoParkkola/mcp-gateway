// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7944 `D6.EVENTS_MISC.2` and `.3`: an audit outage does not use up the
//! retry budget, and a burial's receipt comes before its eviction's.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use super::{
    DeadReason, EventsHub, Settle, counting_callback, logged_services, offer, queued, queued_event,
    queued_with,
};

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
        .due(later, &std::collections::HashSet::new(), hub.dead_policy())
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

/// A pending record as stored, read from its file: `due` offers one record
/// per subscription, so a second one is read here.
fn stored(dir: &std::path::Path, event_id: &str) -> crate::events::outbox::OutboxRecord {
    let file = dir
        .join("outbox")
        .join(crate::events::outbox::OutboxRecord::file(event_id));
    serde_json::from_slice(&std::fs::read(file).expect("read")).expect("record")
}

/// .2: claims the audit log refused sent nothing, so they do not count
/// toward `retry_max_attempts`. Once the log recovers the record is sent,
/// not buried `exhausted`.
#[tokio::test]
async fn an_audit_outage_does_not_use_up_the_attempts() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        retry_max_attempts: 2,
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = logged_services(dir.path());
    let log = services.audit.clone().expect("log");
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
    // R2c: numbers stay unique. The refused claims left nothing on record,
    // so the one `sending` record is attempt 4, not a reused 1.
    let sending: Vec<u64> = std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("evt_outage") && l.contains("\"status\":\"sending\""))
        .filter_map(|l| {
            let at = l.find("\"attempt\":")? + "\"attempt\":".len();
            let digits: String = l[at..].chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect();
    assert_eq!(sending, [4], "one sending record, numbered on: {sending:?}");
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

/// Run `first` until it stops at the armed `before_receipts` point, then
/// `second` (given 2 s to finish while `first` waits), then release `first`.
async fn raced<A, B>(hub: &EventsHub, first: A, second: B)
where
    A: std::future::Future<Output = ()> + Send + 'static,
    B: std::future::Future<Output = ()> + Send + 'static,
{
    use crate::test_pause::within;
    let (reached, release) = hub.before_receipts.arm();
    let first = tokio::spawn(first);
    within("the first burial's pause", reached.notified()).await;
    let second = tokio::spawn(second);
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while !second.is_finished() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    release.notify_one();
    within("the first burial", first).await.expect("first");
    within("the second step", second).await.expect("second");
}

/// A hub with `config`, one subscription and its pending record `evt_x`.
fn buried_setup(
    dir: &std::path::Path,
    config: &crate::config::EventsConfig,
) -> (
    Arc<EventsHub>,
    Arc<super::Services>,
    crate::events::outbox::OutboxRecord,
) {
    let hub = EventsHub::open(config, dir).expect("hub");
    let services = Arc::new(logged_services(dir));
    queued(&hub, 9, "evt_x");
    let x = stored(dir, "evt_x");
    (hub, services, x)
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
    let (hub, services, x) = buried_setup(dir.path(), &config);
    queued_event(&hub, "evt_y");
    let y = stored(dir.path(), "evt_y");
    let (a, b) = (Arc::clone(&hub), Arc::clone(&hub));
    let (sa, sb) = (Arc::clone(&services), Arc::clone(&services));
    raced(
        &hub,
        async move { a.settle(&sa, &x, gone()).await },
        async move { b.settle(&sb, &y, gone()).await },
    )
    .await;
    assert_burial_first(dir.path(), "evt_x");
}

/// .3 across callers: a fan-out refusal that evicts a burial waits for that
/// burial's receipt.
#[tokio::test]
async fn an_eviction_by_a_fan_out_refusal_follows_the_burials_receipt() {
    use crate::events::fanout::{MAX_BODY, SourceEvent};
    use crate::events::types::{SourceKind, Visibility};
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        dead_letter_max_records: 1,
        ..crate::config::EventsConfig::default()
    };
    let (hub, services, x) = buried_setup(dir.path(), &config);
    offer(&hub, &["webhook.c.r.received"]);
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
    let (a, b) = (Arc::clone(&hub), Arc::clone(&hub));
    let (sa, sb) = (Arc::clone(&services), Arc::clone(&services));
    raced(
        &hub,
        async move { a.settle(&sa, &x, gone()).await },
        async move { b.fan_out(&sb, &event).await },
    )
    .await;
    assert_burial_first(dir.path(), "evt_x");
}

/// .3 across callers: the retention sweep that evicts a burial waits for
/// that burial's receipt.
#[tokio::test]
async fn an_eviction_by_the_sweep_follows_the_burials_receipt() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        dead_letter_retention: Duration::from_secs(1),
        ..crate::config::EventsConfig::default()
    };
    let (hub, services, x) = buried_setup(dir.path(), &config);
    let (a, b) = (Arc::clone(&hub), Arc::clone(&hub));
    let (sa, sb) = (Arc::clone(&services), Arc::clone(&services));
    raced(
        &hub,
        async move { a.settle(&sa, &x, gone()).await },
        async move {
            // Past the retention by the time the sweep runs.
            tokio::time::sleep(Duration::from_millis(1200)).await;
            b.sweep_dead_letters(&sb).await;
        },
    )
    .await;
    assert_burial_first(dir.path(), "evt_x");
}

/// .2: the attempt limit and the backoff count sends, so a failure after
/// unsent claims is retried, not buried `exhausted`.
#[tokio::test]
async fn a_failure_after_unsent_claims_is_judged_by_its_sends() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        retry_max_attempts: 2,
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    queued(&hub, 9, "evt_judged");
    let mut record = pending(&hub, "evt_judged");
    record.attempt = 3;
    record.unsent = 2;
    record.first_attempt_at = Some(Utc::now());
    let (settle, _) = hub.judge(&record, &super::status(503));
    assert!(
        matches!(settle, Settle::Retry { .. }),
        "one send of two allowed: {settle:?}"
    );
}

/// MIK-8061: an expiry burial the byte cap evicts at once is receipted
/// before its eviction, in the worker's own pass.
#[tokio::test]
async fn a_self_evicting_expiry_burial_is_receipted_before_its_eviction() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        dead_letter_max_bytes: 1,
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = Arc::new(logged_services(dir.path()));
    queued_with(&hub, 9, "evt_exp", "webhook.c.r.received", |_, record| {
        record.attempt = 1;
    });
    let now = Utc::now();
    let mut row = hub.store.subscriptions().remove(0);
    row.expires_at = Some(now - chrono::Duration::seconds(1));
    let caps = crate::events::store::Caps {
        per_principal: 10,
        global: 10,
    };
    let tail = crate::events::store::TailPolicy {
        ttl: Duration::from_secs(3600),
        max: 10,
        max_per_principal: 10,
    };
    hub.store
        .admit(row, true, caps, chrono::Duration::zero(), now, tail)
        .expect("io")
        .expect("refreshed to an expiry in the past");
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    hub.dispatch(&services, &slots).await;
    assert!(hub.store.dead_letter_by_id("evt_exp").is_none(), "evicted");
    assert_burial_first(dir.path(), "evt_exp");
}
