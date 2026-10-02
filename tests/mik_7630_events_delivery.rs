// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630 increment I2: delivery protocol rows (design §10: T15-T17, T20
//! without `_meta`, T29, T31-T33 fan-out and retry clauses, T43).
//!
//! Events are triggered by POSTs to the inbound webhook route; today the route
//! accepts them and emits nothing, so every row goes red at its first
//! delivery assertion. Receiver rows need `SSL_CERT_FILE`, honoured only on
//! Unix other than Apple (see `mik_7630_events_subscribe.rs`).
#![cfg(all(unix, not(target_vendor = "apple")))]

#[path = "mik_7630_events/delivery.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod delivery;
#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;
#[path = "mik_7630_events/receiver.rs"]
#[allow(dead_code, reason = "shared receiver; each binary uses a subset")]
mod receiver;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use delivery::{
    DEADLINE, audit_mentioning, dead_with_reason, delivery_config, events_at_least, fast_retry,
    fire, sha256_hex, start, start_cfg, subscribe, unsubscribe, wait_until,
};
use gateway::{ALICE, EVENT};
use receiver::{ConnCounter, EventReply, Received, Receiver, whsec};
use serde_json::{Value, json};

/// Wall-clock seconds at which `r` arrived.
#[allow(clippy::cast_possible_truncation, reason = "unix seconds fit in i64")]
fn arrived_unix(r: &Received) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs_f64();
    (now - r.at.elapsed().as_secs_f64()).round() as i64
}

fn ids(posts: &[Received]) -> BTreeSet<String> {
    posts
        .iter()
        .map(|p| p.header("webhook-id").unwrap_or_default())
        .collect()
}

/// T17 (EVENTS.5): 503, 503, 200 gives three POSTs with one `webhook-id`,
/// identical bytes, and a fresh timestamp and valid signature per attempt.
/// Real clock: each timestamp must match the attempt's arrival within 2 s.
#[tokio::test]
async fn retries_keep_webhook_id_and_resign() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, fast_retry()).await;
    let secret = whsec(32);
    subscribe(&gw, ALICE, &rx.url, &secret, json!({})).await;
    rx.script([EventReply::Status(503), EventReply::Status(503)]);
    fire(&gw, "d-17", "o/r").await;
    let posts = events_at_least(&rx, 3).await;
    assert_eq!(posts.len(), 3, "no attempt after the 200");
    assert_eq!(ids(&posts).len(), 1, "one webhook-id across retries");
    for post in &posts {
        assert_eq!(post.body, posts[0].body, "identical body bytes");
        assert!(post.signed_by(&secret), "each attempt signs its own ts");
        let ts: i64 = post
            .header("webhook-timestamp")
            .and_then(|t| t.parse().ok())
            .expect("numeric webhook-timestamp");
        assert!(
            (ts - arrived_unix(post)).abs() <= 2,
            "timestamp is the attempt's own time"
        );
    }
}

/// T20 (EVENTS.6), without the `_meta` clause (I3): the body is exactly the
/// protocol fields and the transform output, nothing the gateway invented.
#[tokio::test]
async fn delivered_body_contains_only_protocol_fields_and_source_data() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    fire(&gw, "d-20", "o/r").await;
    let posts = events_at_least(&rx, 1).await;
    let body = posts[0].json();
    let keys: BTreeSet<&str> = body
        .as_object()
        .expect("object body")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from(["cursor", "data", "eventId", "name", "timestamp"])
    );
    assert_eq!(body["name"], EVENT);
    assert_eq!(body["cursor"], Value::Null);
    assert_eq!(
        body["data"],
        json!({"event_type": "github.opened", "fields": {"repo": "o/r", "ref": "main"}})
    );
    assert_eq!(
        body["eventId"].as_str(),
        posts[0].header("webhook-id").as_deref(),
        "webhook-id carries the eventId"
    );
}

/// T29 (SAFETY.2): three attempts write exactly three attributed audit
/// records carrying the attempt number, the hash of the bytes received, the
/// callback host but not its path, and the tenant attribution. Assumed field
/// names: `attempt` and `tenants` (MIN.1 writes `tenants` only when
/// `tenant_guard.arg_keys` is set, so the row sets it to `repo`).
#[tokio::test]
async fn every_delivery_attempt_writes_one_attributed_audit_record() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut cfg = delivery_config(root.path(), &fast_retry());
    cfg["security"]["firewall"] = json!({"tenant_guard": {"arg_keys": ["repo"]}});
    let gw = start_cfg(root.path(), &rx, cfg).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    rx.script([EventReply::Status(503), EventReply::Status(503)]);
    fire(&gw, "d-29", "o/r").await;
    let posts = events_at_least(&rx, 3).await;
    let event_id = posts[0].json()["eventId"]
        .as_str()
        .expect("eventId")
        .to_owned();
    let hash = sha256_hex(&posts[0].body);
    let root_path = root.path().to_path_buf();
    wait_until(DEADLINE, || {
        audit_mentioning(&root_path, &event_id)
            .iter()
            .filter(|r| r.get("attempt").is_some())
            .count()
            >= 3
    })
    .await;
    // Only delivery-attempt records: a governance record may name the id too.
    let records: Vec<Value> = audit_mentioning(root.path(), &event_id)
        .into_iter()
        .filter(|r| r.get("attempt").is_some())
        .collect();
    assert_eq!(records.len(), 3, "one record per attempt: {records:?}");
    let attempts: BTreeSet<u64> = records
        .iter()
        .filter_map(|r| r["attempt"].as_u64())
        .collect();
    assert_eq!(attempts, BTreeSet::from([1, 2, 3]));
    for record in &records {
        let text = record.to_string();
        assert!(text.contains(&hash), "body hash of the bytes sent: {text}");
        assert!(text.contains("127.0.0.1"), "callback host: {text}");
        assert!(!text.contains("/hook"), "never the callback path: {text}");
        assert!(
            record.get("tenants").is_some(),
            "tenant attribution: {text}"
        );
    }
}

/// T31 (EVENTS.5): 410 and 413 are tried once and dead-lettered; a body over
/// 262 144 bytes is never sent.
#[tokio::test]
async fn _410_and_413_are_not_retried() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, fast_retry()).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    let settle = Duration::from_millis(1500);

    rx.script([EventReply::Status(410)]);
    fire(&gw, "d-31a", "o/r").await;
    events_at_least(&rx, 1).await;
    dead_with_reason(root.path(), "gone").await;
    tokio::time::sleep(settle).await;
    assert_eq!(rx.events().len(), 1, "410 is not retried");

    rx.script([EventReply::Status(413)]);
    fire(&gw, "d-31b", "o/r").await;
    events_at_least(&rx, 2).await;
    dead_with_reason(root.path(), "too_large").await;
    tokio::time::sleep(settle).await;
    assert_eq!(rx.events().len(), 2, "413 is not retried");

    fire(&gw, "d-31c", &"x".repeat(300_000)).await;
    let root_path = root.path().to_path_buf();
    let two = wait_until(DEADLINE, || {
        delivery::dead_letters(&root_path)
            .iter()
            .filter(|d| d["reason"] == "too_large")
            .count()
            >= 2
    })
    .await;
    assert!(two, "an oversize body is dead-lettered too_large");
    assert_eq!(rx.events().len(), 2, "an oversize body is never POSTed");
}

/// T32 (RELIABLE.1): a receiver that always answers 503 gets five attempts
/// with one `webhook-id`, then one dead letter `exhausted`; a restart after
/// attempt 2 resumes the same record instead of starting over. Real clock
/// with `retry_base: 200ms`; F1 allows one duplicate per crash, so 5 or 6.
#[tokio::test]
async fn exhausted_retries_dead_letter_within_the_window() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut gw = start(root.path(), &rx, fast_retry()).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    rx.event_default(EventReply::Status(503));
    fire(&gw, "d-32", "o/r").await;
    events_at_least(&rx, 2).await;
    gw.restart().await;
    let dead = dead_with_reason(root.path(), "exhausted").await;
    assert_eq!(dead.len(), 1, "one dead letter for one occurrence");
    let posts = rx.events();
    assert!(
        (5..=6).contains(&posts.len()),
        "five attempts (one crash duplicate allowed), got {}",
        posts.len()
    );
    assert_eq!(ids(&posts).len(), 1, "the restart kept the webhook-id");
    let span = posts[0].at.elapsed() - posts[posts.len() - 1].at.elapsed();
    assert!(span < Duration::from_secs(15 * 60), "inside retry_window");
}

/// T33 (RELIABLE.2), fan-out and retry clauses: one inbound delivery fanned
/// to two subscriptions sharing a callback URL carries two `webhook-id`s,
/// and each subscription's retry keeps its own.
#[tokio::test]
async fn event_id_is_stable_per_occurrence_and_subscription() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, fast_retry()).await;
    let a = subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    let b = subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({"repo": "o/r"})).await;
    rx.script([EventReply::Status(503), EventReply::Status(503)]);
    fire(&gw, "d-33", "o/r").await;
    let posts = events_at_least(&rx, 4).await;
    let mut by_sub: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for post in &posts {
        by_sub
            .entry(post.header("x-mcp-subscription-id").unwrap_or_default())
            .or_default()
            .insert(post.header("webhook-id").unwrap_or_default());
    }
    assert_eq!(
        by_sub.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([a, b])
    );
    for (sub, seen) in &by_sub {
        assert_eq!(seen.len(), 1, "{sub}: retries keep their webhook-id");
    }
    assert_eq!(ids(&posts).len(), 2, "two subscriptions, two webhook-ids");
}

/// T15 (EVENTS.5): a 307 to a second listener is a failed attempt, retried,
/// and never followed: the second listener sees no connection.
#[tokio::test]
async fn delivery_does_not_follow_redirects() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let elsewhere = ConnCounter::start().await;
    let gw = start(root.path(), &rx, fast_retry()).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    rx.script([EventReply::Redirect(format!(
        "https://127.0.0.1:{}/hook",
        elsewhere.port
    ))]);
    fire(&gw, "d-15", "o/r").await;
    let posts = events_at_least(&rx, 2).await;
    assert_eq!(ids(&posts).len(), 1, "the 307 was retried as a failure");
    assert_eq!(elsewhere.connections(), 0, "the redirect was not followed");
}

/// T16 (EVENTS.5): a 500 with a canary body and header surfaces only as the
/// category `http_5xx`; the canary is in no RPC answer, audit record or log.
#[tokio::test]
async fn delivery_status_never_echoes_receiver_content() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, fast_retry()).await;
    let secret = whsec(32);
    subscribe(&gw, ALICE, &rx.url, &secret, json!({})).await;
    let canary = format!("CANARY-{}", rand::random::<u64>());
    rx.event_default(EventReply::Canary(500, canary.clone()));
    fire(&gw, "d-16", "o/r").await;
    events_at_least(&rx, 1).await;
    let mut answer = Value::Null;
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while tokio::time::Instant::now() < deadline {
        answer = gw
            .rpc(
                Some(ALICE),
                "events/subscribe",
                delivery::params(&rx.url, &secret, json!({})),
            )
            .await;
        if answer["result"]["deliveryStatus"]["lastError"] == "http_5xx" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        answer["result"]["deliveryStatus"]["lastError"], "http_5xx",
        "{answer}"
    );
    assert!(!answer.to_string().contains(&canary), "RPC answer");
    assert!(
        delivery::audit_records(root.path())
            .iter()
            .all(|r| !r.to_string().contains(&canary)),
        "audit records"
    );
    assert!(!gw.all_logs().contains(&canary), "log lines");
}

/// T43 (EVENTS.8): the full chain into a signature-checking receiver; a
/// non-matching filter delivers nothing and unsubscribe stops delivery.
/// Substitution: the inbound POST is unsigned (the fixture sets
/// `webhooks.require_signature: false`); the outbound side is fully checked.
#[tokio::test]
async fn end_to_end_with_a_signature_checking_receiver() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    let secret = whsec(32);
    let id = subscribe(&gw, ALICE, &rx.url, &secret, json!({"repo": "o/r"})).await;
    fire(&gw, "d-43a", "o/r").await;
    let posts = events_at_least(&rx, 1).await;
    let post = &posts[0];
    assert!(post.signed_by(&secret), "valid Standard Webhooks signature");
    assert_eq!(post.header("x-mcp-subscription-id"), Some(id));
    let ts: i64 = post
        .header("webhook-timestamp")
        .and_then(|t| t.parse().ok())
        .expect("timestamp");
    assert!((ts - arrived_unix(post)).abs() <= 300, "fresh timestamp");
    assert_eq!(post.json()["data"]["fields"]["repo"], "o/r");
    let settle = Duration::from_millis(1500);
    fire(&gw, "d-43b", "other/x").await;
    tokio::time::sleep(settle).await;
    assert_eq!(rx.events().len(), 1, "a non-matching repo delivers nothing");
    assert_eq!(
        unsubscribe(&gw, ALICE, &rx.url, json!({"repo": "o/r"})).await,
        json!({})
    );
    fire(&gw, "d-43c", "o/r").await;
    tokio::time::sleep(settle).await;
    assert_eq!(rx.events().len(), 1, "nothing after unsubscribe");
}
