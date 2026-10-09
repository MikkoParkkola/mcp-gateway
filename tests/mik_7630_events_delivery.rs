// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630 increments I2 and I3: delivery protocol rows (design §10: T15-T17,
//! T20, T29, T30, T31-T33 fan-out and retry clauses, T43).
//!
//! Events are triggered by POSTs to the inbound webhook route; today the route
//! accepts them and emits nothing, so every row goes red at its first
//! delivery assertion. Receiver rows trust its CA through
//! `Receiver::trust_env` (MIK-8188).
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

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use delivery::{
    DEADLINE, INBOUND_SECRET_ENV, audit_mentioning, dead_with_reason, delivery_config,
    events_at_least, fast_retry, fire, fire_signed, push_ref, sha256_hex, signed_inbound_config,
    start, start_cfg, start_cfg_env, subscribe, unsubscribe, wait_until,
};
use gateway::{ALICE, EVENT, Gateway};
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

/// MIK-7889 (#2695): a subscription made with the static bearer keeps
/// delivering while that bearer runs, so the full digest recorded at subscribe
/// time and the running gateway's digest are wired to the same value.
#[tokio::test]
async fn a_static_bearer_subscription_keeps_delivering() {
    const BEARER: &str = "static-bearer-7889-0123456789abcdef";
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut cfg = delivery::delivery_config(root.path(), &json!({}));
    cfg["auth"]["bearer_token"] = json!(BEARER);
    let gw = start_cfg(root.path(), &rx, cfg).await;
    subscribe(&gw, BEARER, &rx.url, &whsec(32), json!({})).await;
    fire(&gw, "d-7889", "o/r").await;
    let posts = events_at_least(&rx, 1).await;
    assert_eq!(
        posts.len(),
        1,
        "the bearer's subscription was not delivered"
    );
}

/// The `_meta` key the gateway's provenance receipt rides under (§3.6).
const PROVENANCE: &str = "io.github.mikkoparkkola/provenance";

/// T20 (EVENTS.6): the body is exactly the protocol fields and the
/// transform output, nothing the gateway invented; `_meta` holds only the
/// provenance receipt (I3).
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
        BTreeSet::from(["_meta", "cursor", "data", "eventId", "name", "timestamp"])
    );
    let meta: Vec<&String> = body["_meta"]
        .as_object()
        .expect("_meta object")
        .keys()
        .collect();
    assert_eq!(meta, [PROVENANCE], "_meta holds only the receipt");
    let stamped = &body["_meta"][PROVENANCE];
    assert_eq!(stamped["receipt"]["subject_kind"], "event");
    assert_eq!(stamped["receipt"]["tool"], EVENT);
    assert!(
        stamped.get("signature").is_none(),
        "stamping is off: the bare receipt, unsigned"
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

/// T30 (SAFETY.6): the provenance receipt rides in `_meta` with subject kind
/// `event`, verifies against the gateway's provenance key when stamping is
/// on, and sits inside the body the webhook signature covers.
#[tokio::test]
async fn provenance_rides_in_meta_and_is_signed() {
    const KEY: &str = "events-provenance-test-key-0123456789";
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut cfg = delivery_config(root.path(), &json!({}));
    cfg["security"]["provenance_stamping"] = json!(true);
    let [cert_file, test_trust] = rx.trust_env();
    let gw = Gateway::start_with_env(
        root.path(),
        cfg,
        &[
            (cert_file.0, &cert_file.1),
            (test_trust.0, &test_trust.1),
            ("GATEWAY_ATTESTATION_SIGNING_KEY", KEY),
            ("GATEWAY_ATTESTATION_KEY_ID", "events-test"),
        ],
    )
    .await;
    gw.event_names(Some(ALICE), Some(EVENT)).await;
    let secret = whsec(32);
    subscribe(&gw, ALICE, &rx.url, &secret, json!({})).await;
    fire(&gw, "d-30", "o/r").await;
    let posts = events_at_least(&rx, 1).await;
    assert!(
        posts[0].signed_by(&secret),
        "the receipt is inside the signed body"
    );
    let stamped = posts[0].json()["_meta"][PROVENANCE].clone();
    assert_eq!(stamped["receipt"]["subject_kind"], "event");
    assert_eq!(stamped["receipt"]["tool"], EVENT);
    let signed: mcp_gateway::trust::SignedResultProvenance =
        serde_json::from_value(stamped).expect("a signed receipt");
    let validator = mcp_gateway::attestation::AttestationValidator::new(
        mcp_gateway::attestation::BnautAttestationSigner::new(
            KEY.as_bytes().to_vec(),
            "events-test",
        )
        .with_audience("test-gateway"),
    );
    assert!(
        validator.verify_result_provenance(&signed),
        "signed with the gateway's provenance key"
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
    fire(&gw, "d-29", "canary-owner/canary-repo").await;
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
        // Attributed: the hashed tenant of the data (MIN.1), never its name.
        assert_eq!(
            record["tenants"],
            json!([mcp_gateway::security::hash_argument(&json!(
                "canary-owner/canary-repo"
            ))]),
            "tenant attribution: {text}"
        );
    }
    // No record of the event, an attempt's or its outcome's, holds the body:
    // scanned once all three outcomes are on the log.
    assert!(
        wait_until(DEADLINE, || {
            audit_mentioning(&root_path, &event_id)
                .iter()
                .filter(|r| r.get("outcome_of_attempt").is_some())
                .count()
                >= 3
        })
        .await,
        "all three outcomes reach the log"
    );
    for record in audit_mentioning(root.path(), &event_id) {
        assert!(
            !record.to_string().contains("canary"),
            "the audit record carries no body: {record}"
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
/// with one `webhook-id`, then one dead letter `exhausted`, and a restart
/// resumes the same record instead of starting over. The crash is placed, not
/// raced: the receiver holds attempt 3 open and the gateway is killed while
/// it is on the wire. An attempt is counted when it is claimed and a restart
/// does not refund it (design F1 and the "at most 5 attempts" budget; pinned
/// at the store by `store::pending::tests::crash`), so the resend after the
/// crash is attempt 4 and the receiver sees exactly five POSTs. The real
/// clock only paces the backoff; the count does not depend on it.
#[tokio::test]
async fn exhausted_retries_dead_letter_within_the_window() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut gw = start(root.path(), &rx, fast_retry()).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    rx.event_default(EventReply::Status(503));
    rx.script([
        EventReply::Status(503),
        EventReply::Status(503),
        EventReply::Hold(DEADLINE, 503),
    ]);
    fire(&gw, "d-32", "o/r").await;
    // Attempt 3 has arrived and is being held: kill the gateway mid-POST.
    events_at_least(&rx, 3).await;
    gw.restart().await;
    let dead = dead_with_reason(root.path(), "exhausted").await;
    assert_eq!(dead.len(), 1, "one dead letter for one occurrence");
    let posts = rx.events();
    assert_eq!(
        posts.len(),
        5,
        "five attempts: the one on the wire at the crash counts, the resend is the fourth"
    );
    assert_eq!(ids(&posts).len(), 1, "the restart kept the webhook-id");
    // The window bound itself is pinned where a clock can pass it:
    // `worker::tests::an_attempt_past_its_bounds_is_overdue_before_it_is_sent`.
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

/// T43 (EVENTS.8): the full chain from a signed inbound webhook into a
/// signature-checking receiver. The route requires `X-Hub-Signature-256`: an
/// unsigned or wrongly keyed POST is refused 401 and delivers nothing. A
/// non-matching filter delivers nothing and unsubscribe stops delivery.
#[tokio::test]
async fn end_to_end_with_a_signature_checking_receiver() {
    const INBOUND_KEY: &str = "events-t43-inbound-hmac-key";
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let cfg = signed_inbound_config(root.path(), &json!({}));
    let gw = start_cfg_env(root.path(), &rx, cfg, &[(INBOUND_SECRET_ENV, INBOUND_KEY)]).await;
    let secret = whsec(32);
    let id = subscribe(&gw, ALICE, &rx.url, &secret, json!({"repo": "o/r"})).await;
    // The refused POSTs carry their own refs, so a leaked one cannot stand in
    // for the accepted delivery.
    assert_eq!(
        gw.webhook("d-43u", &push_ref("o/r", "refused-unsigned"))
            .await,
        401,
        "an unsigned inbound POST is refused"
    );
    assert_eq!(
        fire_signed(
            &gw,
            "d-43w",
            &push_ref("o/r", "refused-wrong-key"),
            "not-the-route-key"
        )
        .await,
        401,
        "a wrongly keyed inbound POST is refused"
    );
    let accepted = fire_signed(&gw, "d-43a", &push_ref("o/r", "accepted"), INBOUND_KEY).await;
    assert!(
        (200..300).contains(&accepted),
        "signed inbound answered {accepted}"
    );
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
    assert_eq!(
        post.json()["data"]["fields"]["ref"],
        "accepted",
        "the delivery is the accepted POST's"
    );
    assert!(!rx.challenges().is_empty(), "the subscribe was verified");
    assert!(
        rx.received().iter().all(|r| r.signed_by(&secret)),
        "every POST the receiver got, verification included, is signed"
    );
    let settle = Duration::from_millis(1500);
    let other = fire_signed(&gw, "d-43b", &push_ref("other/x", "main"), INBOUND_KEY).await;
    assert!(
        (200..300).contains(&other),
        "signed inbound answered {other}"
    );
    tokio::time::sleep(settle).await;
    assert_eq!(
        rx.events().len(),
        1,
        "refused POSTs and a non-matching repo deliver nothing"
    );
    assert_eq!(
        unsubscribe(&gw, ALICE, &rx.url, json!({"repo": "o/r"})).await,
        json!({})
    );
    let after = fire_signed(&gw, "d-43c", &push_ref("o/r", "main"), INBOUND_KEY).await;
    assert!(
        (200..300).contains(&after),
        "signed inbound answered {after}"
    );
    tokio::time::sleep(settle).await;
    assert_eq!(rx.events().len(), 1, "nothing after unsubscribe");
}
