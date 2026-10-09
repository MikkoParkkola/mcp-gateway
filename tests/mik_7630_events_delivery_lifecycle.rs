// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630 increment I2: lifecycle, store and inbound rows (design §10:
//! T18, T22 delivery half, T23 delivery clauses, T46 keeps-delivering,
//! T47, T55).
//!
//! Today the inbound route emits nothing, so each row goes red at its first
//! delivery assertion. Unix; the child
//! trusts the receiver's CA through `Receiver::trust_env` (MIK-8188).
#![cfg(unix)]

#[path = "mik_7630_events/delivery.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod delivery;
#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;
#[path = "mik_7630_events/receiver.rs"]
#[allow(dead_code, reason = "shared receiver; each binary uses a subset")]
mod receiver;

use std::time::Duration;

use delivery::{
    DEADLINE, delivery_status, events_at_least, fire, records, start, subscribe, unsubscribe,
    wait_until,
};
use gateway::{ALICE, CAROL};
use receiver::{EventReply, Receiver, whsec};
use serde_json::json;

const SETTLE: Duration = Duration::from_millis(1500);

/// T18 (EVENTS.3): after a rotation the next delivery carries two `v1,`
/// signatures, new first; once `secret_rotation_grace` (3 s here) passes,
/// only the new one.
#[tokio::test]
async fn secret_rotation_dual_signs_for_the_grace_window() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({"secret_rotation_grace": "3s"})).await;
    let (old, new) = (whsec(32), whsec(32));
    subscribe(&gw, ALICE, &rx.url, &old, json!({})).await;
    subscribe(&gw, ALICE, &rx.url, &new, json!({})).await;
    fire(&gw, "d-18a", "o/r").await;
    let posts = events_at_least(&rx, 1).await;
    let header = posts[0].header("webhook-signature").unwrap_or_default();
    assert_eq!(header.split(' ').count(), 2, "two signatures: {header}");
    assert!(posts[0].signed_by(&new) && posts[0].signed_by(&old));
    tokio::time::sleep(Duration::from_secs(4)).await;
    fire(&gw, "d-18b", "o/r").await;
    let posts = events_at_least(&rx, 2).await;
    let header = posts[1].header("webhook-signature").unwrap_or_default();
    assert_eq!(header.split(' ').count(), 1, "grace over: {header}");
    assert!(posts[1].signed_by(&new) && !posts[1].signed_by(&old));
}

/// T22 (EVENTS.4), delivery half: after a restart on the same store an event
/// is delivered with no re-subscribe and no new verification.
#[tokio::test]
async fn subscriptions_survive_restart_and_ttl_is_negotiated() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut gw = start(root.path(), &rx, json!({})).await;
    let secret = whsec(32);
    subscribe(&gw, ALICE, &rx.url, &secret, json!({})).await;
    let challenges = rx.challenges().len();
    gw.restart().await;
    gw.event_names(Some(ALICE), Some(gateway::EVENT)).await;
    fire(&gw, "d-22", "o/r").await;
    let posts = events_at_least(&rx, 1).await;
    assert!(posts[0].signed_by(&secret), "the stored secret signs it");
    assert_eq!(rx.challenges().len(), challenges, "no new verification");
}

/// T23 (EVENTS.7), delivery clauses: carol sending alice's exact key changes
/// nothing (alice still receives), and alice's unsubscribe cancels a pending
/// retry: the receiver sees nothing more.
#[tokio::test]
async fn unsubscribe_is_idempotent_and_scoped_to_the_caller() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({"retry_base": "3s"})).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    assert_eq!(unsubscribe(&gw, CAROL, &rx.url, json!({})).await, json!({}));
    fire(&gw, "d-23a", "o/r").await;
    events_at_least(&rx, 1).await;

    rx.event_default(EventReply::Status(503));
    fire(&gw, "d-23b", "o/r").await;
    events_at_least(&rx, 2).await;
    assert_eq!(unsubscribe(&gw, ALICE, &rx.url, json!({})).await, json!({}));
    let seen = rx.events().len();
    let root_path = root.path().to_path_buf();
    let cancelled = wait_until(DEADLINE, || records(&root_path, "outbox").is_empty()).await;
    assert!(cancelled, "the pending retry is cancelled");
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(rx.events().len(), seen, "nothing after the answer");
}

/// T46 (EVENTS.3), keeps-delivering clause: a subscription refreshed past
/// its first expiry and past the verification tail keeps delivering with no
/// new challenge. Real clock: `min_ttl: 1s`, `ttlMs: 2000` and a 2 s tail
/// stand in for the design's 24 h.
#[tokio::test]
async fn verification_lives_as_long_as_its_subscriptions() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(
        root.path(),
        &rx,
        json!({"min_ttl": "1s", "verified_tail_ttl": "2s"}),
    )
    .await;
    let secret = whsec(32);
    for _ in 0..5 {
        let mut p = delivery::params(&rx.url, &secret, json!({}));
        p["ttlMs"] = json!(2000);
        let answer = gw.rpc(Some(ALICE), "events/subscribe", p).await;
        assert!(answer["result"]["id"].is_string(), "{answer}");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(rx.challenges().len(), 1, "refreshes need no challenge");
    fire(&gw, "d-46", "o/r").await;
    let posts = events_at_least(&rx, 1).await;
    assert!(posts[0].signed_by(&secret));
    assert_eq!(rx.challenges().len(), 1, "delivery needs no challenge");
}

/// T47 (EVENTS.5): with `suspend_min_attempts: 5` over a 60 s window (the
/// design's 100 over 60 min, scaled), 4 failures leave the subscription
/// active, the 5th suspends it and nothing more is attempted; a refresh
/// reports `active: false`, reactivates it, and the held event is delivered.
/// Assumption: an occurrence fanned out while suspended is queued in the
/// outbox (not dropped) and is retried once the refresh reactivates.
#[tokio::test]
async fn sustained_failure_suspends_and_refresh_reactivates() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(
        root.path(),
        &rx,
        json!({"retry_max_attempts": 1, "suspend_window": "60s", "suspend_min_attempts": 5}),
    )
    .await;
    let secret = whsec(32);
    subscribe(&gw, ALICE, &rx.url, &secret, json!({})).await;
    rx.event_default(EventReply::Status(503));
    let active = |root: &std::path::Path| records(root, "subs")[0]["active"].clone();
    for n in 0..4 {
        fire(&gw, &format!("d-47-{n}"), "o/r").await;
        events_at_least(&rx, n + 1).await;
    }
    tokio::time::sleep(SETTLE).await;
    assert_eq!(active(root.path()), json!(true), "4 failures: still active");
    fire(&gw, "d-47-4", "o/r").await;
    events_at_least(&rx, 5).await;
    let root_path = root.path().to_path_buf();
    let suspended = wait_until(DEADLINE, || active(&root_path) == json!(false)).await;
    assert!(suspended, "the 5th failure suspends");
    fire(&gw, "d-47-held", "o/r").await;
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        rx.events().len(),
        5,
        "a suspended subscription is not tried"
    );
    rx.event_default(EventReply::Status(200));
    let status = delivery_status(&gw, ALICE, &rx.url, &secret, json!({})).await;
    assert_eq!(status["active"], false, "{status}");
    assert_eq!(active(root.path()), json!(true), "the refresh reactivates");
    events_at_least(&rx, 6).await;
}

/// T55 (EVENTS.7): the receiver holds the first POST open; unsubscribe
/// answers `{}`; the held POST then fails with 503, which would schedule a
/// retry within about a second under `fast_retry`; nothing more (retry or
/// new event) reaches the receiver.
#[tokio::test]
async fn unsubscribe_during_an_in_flight_post_sends_nothing_after_the_answer() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, delivery::fast_retry()).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    rx.script([EventReply::Hold(Duration::from_secs(3), 503)]);
    fire(&gw, "d-55a", "o/r").await;
    events_at_least(&rx, 1).await;
    assert_eq!(unsubscribe(&gw, ALICE, &rx.url, json!({})).await, json!({}));
    let at_answer = rx.events().len();
    fire(&gw, "d-55b", "o/r").await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(rx.events().len(), at_answer, "nothing after the answer");
}

/// MIK-7854.EVENTS.1: the expiry is counted from the commit, after the
/// callback challenge. A challenge held 8 s against a 7 s TTL still commits
/// a row that outlives the answer, granted for exactly the asked TTL, and
/// `refreshBefore` names the stored expiry.
#[tokio::test]
async fn a_slow_challenge_does_not_eat_a_short_ttl() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({"min_ttl": "1s"})).await;
    rx.reply(receiver::Reply::SlowEcho(Duration::from_secs(8)));
    let mut params = delivery::params(&rx.url, &whsec(32), json!({}));
    params["ttlMs"] = json!(7000);
    let answer = gw.rpc(Some(ALICE), "events/subscribe", params).await;
    let answered = chrono::Utc::now();
    assert!(answer["result"]["id"].is_string(), "{answer}");
    let time = |v: &serde_json::Value| -> chrono::DateTime<chrono::Utc> {
        v.as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("a time: {v}"))
    };
    let row = records(root.path(), "subs")[0].clone();
    let (granted, expires) = (time(&row["granted_at"]), time(&row["expires_at"]));
    assert_eq!(expires - granted, chrono::Duration::seconds(7), "{row}");
    assert!(expires > answered, "the row outlives the answer: {row}");
    assert_eq!(
        time(&answer["result"]["refreshBefore"]).timestamp(),
        expires.timestamp(),
        "{answer}"
    );
    fire(&gw, "d-ttl", "o/r").await;
    events_at_least(&rx, 1).await;
}
