// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7802 (design 3.7): subscribe, refresh, verification, unsubscribe,
//! dead-letter and replay each write one governance record, and an attempt's
//! record names the firewall verdict.
//!
//! Linux-only for `SSL_CERT_FILE`.
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

use delivery::{
    DEADLINE, audit_records, dead_with_reason, delivery_config, events_at_least, fire, start_cfg,
    subscribe, unsubscribe, wait_until,
};
use gateway::{ADMIN, ALICE, EVENT};
use receiver::{EventReply, Receiver, whsec};
use serde_json::{Value, json};

/// The governance records of `action`, once at least one exists.
async fn records_of(root: &std::path::Path, action: &str) -> Vec<Value> {
    let found = wait_until(DEADLINE, || {
        audit_records(root).iter().any(|r| r["action"] == action)
    })
    .await;
    assert!(found, "no {action} record in the audit log");
    audit_records(root)
        .into_iter()
        .filter(|r| r["action"] == action)
        .collect()
}

/// Every lifecycle step writes its record, naming the subscription, the
/// event and the callback host, never the callback path or the secret.
#[tokio::test]
async fn the_subscription_lifecycle_writes_governance_records() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut cfg = delivery_config(root.path(), &json!({}));
    cfg["security"]["firewall"] = json!({"rules": [{"match": "*", "action": "warn"}]});
    let gw = start_cfg(root.path(), &rx, cfg).await;
    let (first, second) = (whsec(32), whsec(32));
    subscribe(&gw, ALICE, &rx.url, &first, json!({})).await;
    let id = records_of(root.path(), "events.subscribe").await[0]["subscription_id"]
        .as_str()
        .expect("subscription id")
        .to_owned();
    subscribe(&gw, ALICE, &rx.url, &second, json!({})).await;
    records_of(root.path(), "events.refresh").await;
    rx.script([EventReply::Status(410)]);
    fire(&gw, "d-7802", "o/r").await;
    let dead = dead_with_reason(root.path(), "gone").await;
    let event_id = dead[0]["event_id"].as_str().expect("event id").to_owned();
    let created = records_of(root.path(), "events.dead_letter").await;
    assert_eq!(created[0]["event_id"], event_id.as_str());
    assert_eq!(created[0]["reason"], "gone");
    let (status, _) = gw
        .admin(
            Some(ADMIN),
            "POST",
            &format!("/ui/api/events/dead-letters/{event_id}/replay"),
        )
        .await;
    assert_eq!(status, 200);
    events_at_least(&rx, 2).await;
    let replayed = records_of(root.path(), "events.replay").await;
    assert_eq!(replayed[0]["event_id"], event_id.as_str());
    // Accountability (MIK-7806): the record names the admin who replayed.
    assert_eq!(replayed[0]["who"]["account"], "admin", "{}", replayed[0]);
    assert_eq!(replayed[0]["who"]["credential_kind"], "api_key");
    assert!(
        replayed[0]["who"]["principal"]
            .as_str()
            .is_some_and(|p| !p.is_empty()),
        "the admin credential's principal is on the record"
    );
    // A bulk replay writes one such record per dead letter it revives.
    rx.script([EventReply::Status(410)]);
    fire(&gw, "d-7806", "o/r").await;
    let second_dead = dead_with_reason(root.path(), "gone").await;
    let second_id = second_dead[0]["event_id"]
        .as_str()
        .expect("event id")
        .to_owned();
    let (status, _) = gw
        .admin(
            Some(ADMIN),
            "POST",
            &format!("/ui/api/events/dead-letters/replay?all=1&subscription={id}"),
        )
        .await;
    assert_eq!(status, 200);
    let bulk = wait_until(DEADLINE, || {
        audit_records(root.path())
            .iter()
            .any(|r| r["action"] == "events.replay" && r["event_id"] == second_id.as_str())
    })
    .await;
    assert!(bulk, "bulk replay writes a record per dead letter");
    for record in audit_records(root.path())
        .iter()
        .filter(|r| r["action"] == "events.replay")
    {
        assert_eq!(record["who"]["account"], "admin", "{record}");
    }
    unsubscribe(&gw, ALICE, &rx.url, json!({})).await;
    records_of(root.path(), "events.unsubscribe").await;
    let verified = records_of(root.path(), "events.verification").await;
    assert_eq!(verified[0]["detail"], "verified");

    for action in [
        "events.subscribe",
        "events.refresh",
        "events.verification",
        "events.unsubscribe",
    ] {
        for record in records_of(root.path(), action).await {
            assert_eq!(record["subscription_id"], id.as_str(), "{action}");
            assert_eq!(record["event_name"], EVENT, "{action}");
            assert_eq!(record["callback_host"], "127.0.0.1", "{action}");
            assert!(record.get("principal").is_some(), "{action} is attributed");
        }
    }
    let text: String = audit_records(root.path())
        .iter()
        .filter(|r| {
            r["action"]
                .as_str()
                .is_some_and(|a| a.starts_with("events."))
        })
        .map(Value::to_string)
        .collect();
    for secret in [&first, &second] {
        let key = secret.trim_start_matches("whsec_");
        assert!(!text.contains(key), "a governance record leaked a secret");
    }
    assert!(!text.contains("/hook"), "never the callback path");
}

/// The attempt record names what the firewall decided about the payload.
#[tokio::test]
async fn an_attempt_record_names_the_firewall_verdict() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut cfg = delivery_config(root.path(), &json!({}));
    cfg["security"]["firewall"] = json!({"rules": [{"match": "*", "action": "warn"}]});
    let gw = start_cfg(root.path(), &rx, cfg).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    fire(&gw, "d-7802v", "o/r").await;
    events_at_least(&rx, 1).await;
    let seen = wait_until(DEADLINE, || {
        audit_records(root.path())
            .iter()
            .any(|r| r.get("attempt").is_some() && r["firewall_verdict"] == "pass")
    })
    .await;
    assert!(seen, "the attempt record carries firewall_verdict pass");
}

/// A payload the firewall redacts is delivered redacted, and its attempt
/// record says `redacted`, not `pass` (MIK-7807).
#[tokio::test]
async fn a_redacted_payload_is_recorded_as_redacted() {
    // Built at run time: a GitHub token shape, 36 characters after the prefix.
    let token = format!("{}_{}", "ghp", "ab".repeat(18));
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut cfg = delivery_config(root.path(), &json!({}));
    cfg["security"]["firewall"] = json!({"rules": [{"match": "*", "action": "warn"}]});
    let gw = start_cfg(root.path(), &rx, cfg).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    fire(&gw, "d-7807", &format!("o/{token}")).await;
    let posts = events_at_least(&rx, 1).await;
    let body = String::from_utf8_lossy(&posts[0].body).into_owned();
    assert!(body.contains("REDACTED"), "delivered redacted: {body}");
    assert!(!body.contains(&token), "the token never leaves: {body}");
    let seen = wait_until(DEADLINE, || {
        audit_records(root.path())
            .iter()
            .any(|r| r.get("attempt").is_some() && r["firewall_verdict"] == "redacted")
    })
    .await;
    assert!(seen, "the attempt record says redacted");
    assert!(
        audit_records(root.path())
            .iter()
            .all(|r| r["firewall_verdict"] != "pass"),
        "no attempt of this event claims pass"
    );
}
