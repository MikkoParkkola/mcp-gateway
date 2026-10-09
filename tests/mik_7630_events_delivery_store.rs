// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630 increment I2: inbound dedupe, projection, outbox and dead-letter
//! bounds, and reload compatibility (design §10: T34, T42b, T45, T49 store
//! clause, T50, T52).
//!
//! Today the inbound route emits nothing and the `event:` block is parsed
//! but never acted on, so each row goes red at its own count or record
//! assertion. Unix; the child trusts the
//! receiver's CA through `Receiver::trust_env` (MIK-8188).
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

use std::path::Path;
use std::time::Duration;

use delivery::{
    DEADLINE, dead_letters, events_at_least, fire, push, records, start, subscribe, wait_until,
};
use gateway::{ALICE, EVENT, Gateway};
use receiver::{EventReply, Receiver, whsec};
use serde_json::{Value, json};

const SETTLE: Duration = Duration::from_millis(1500);

/// Two more routes beside the fixture's: one deduping on the body hash, one
/// with no dedupe at all.
const ACME_CAPABILITY: &str = r#"
name: acme
description: Acme webhooks
schema:
  input: { type: object, properties: {} }
  output: { type: object }
providers: {}
webhooks:
  dedup:
    path: /acme/dedup
    method: POST
    transform:
      event_type: "acme.{action}"
      data: { repo: "{repository.full_name}" }
    event:
      description: "Deduped on the body hash."
      dedupe: body
  plain:
    path: /acme/plain
    method: POST
    transform:
      event_type: "acme.{action}"
      data: { repo: "{repository.full_name}" }
    event:
      description: "No dedupe."
"#;

/// Subscribe alice to `name` with no arguments.
async fn subscribe_to(gw: &Gateway, name: &str, url: &str) {
    let mut p = delivery::params(url, &whsec(32), json!({}));
    p["name"] = json!(name);
    let answer = gw.rpc(Some(ALICE), "events/subscribe", p).await;
    assert!(answer["result"]["id"].is_string(), "{answer}");
}

/// The inbound route accepted the POST.
fn accepted(status: u16) {
    assert!(
        (200..300).contains(&status),
        "inbound webhook answered {status}"
    );
}

/// Event deliveries for `name` so far.
fn count(rx: &Receiver, name: &str) -> usize {
    rx.events()
        .iter()
        .filter(|r| r.json()["name"] == name)
        .count()
}

/// T34 (RELIABLE.2): a `delivery_id_header` route drops a repeated id even
/// when the body is re-serialised, and keeps a new id; a `dedupe: body`
/// route drops the same body; a route with neither keeps both.
#[tokio::test]
async fn inbound_repeats_are_dropped_per_route_key() {
    let root = tempfile::tempdir().expect("root");
    std::fs::create_dir_all(root.path().join("caps")).expect("caps");
    std::fs::write(root.path().join("caps/acme.yaml"), ACME_CAPABILITY).expect("acme");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    let (dedup, plain) = ("webhook.acme.dedup.received", "webhook.acme.plain.received");
    gw.event_names(Some(ALICE), Some(plain)).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    subscribe_to(&gw, dedup, &rx.url).await;
    subscribe_to(&gw, plain, &rx.url).await;

    let compact = push("o/r").to_string();
    let pretty = serde_json::to_string_pretty(&push("o/r")).expect("pretty");
    let path = "/webhooks/github/push";
    for (id, body) in [("same", &compact), ("same", &pretty), ("new", &compact)] {
        accepted(gw.webhook_at(path, Some(id), body).await);
    }
    for path in ["/webhooks/acme/dedup", "/webhooks/acme/plain"] {
        for _ in 0..2 {
            accepted(gw.webhook_at(path, None, &compact).await);
        }
    }
    events_at_least(&rx, 5).await;
    tokio::time::sleep(SETTLE).await;
    assert_eq!(count(&rx, EVENT), 2, "repeated delivery id dropped");
    assert_eq!(count(&rx, dedup), 1, "repeated signed body dropped");
    assert_eq!(count(&rx, plain), 2, "no dedupe keeps both");
}

/// T42b (EVENTS.6): the event never falls back to the raw body. With no
/// mapped key resolving, nothing is delivered and `projection_failed` is
/// counted (read from `/metrics` or the log: the counter's home is the
/// implementation's choice); with one of two resolving, `data.fields` holds
/// only that key.
#[tokio::test]
async fn event_projection_never_falls_back_to_the_raw_body() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    let path = "/webhooks/github/push";
    let none = json!({"action": "opened", "raw_only": "R1"}).to_string();
    let one = json!({"action": "opened", "repository": {"full_name": "o/r"},
                     "raw_only": "R2"})
    .to_string();
    accepted(gw.webhook_at(path, Some("p1"), &none).await);
    accepted(gw.webhook_at(path, Some("p2"), &one).await);
    let posts = events_at_least(&rx, 1).await;
    tokio::time::sleep(SETTLE).await;
    assert_eq!(rx.events().len(), 1, "the unprojectable body emits nothing");
    let data = &posts[0].json()["data"];
    assert_eq!(
        data["fields"],
        json!({"repo": "o/r"}),
        "only the resolved key"
    );
    assert!(!posts[0].json().to_string().contains("raw_only"));
    let metrics = match gw.client.get(format!("{}/metrics", gw.url)).send().await {
        Ok(response) => response.text().await.unwrap_or_default(),
        Err(_) => String::new(),
    };
    assert!(
        metrics.contains("projection_failed") || gw.all_logs().contains("projection_failed"),
        "the dropped occurrence is counted"
    );
}

/// Pending outbox records of subscription `id`.
fn pending_for(root: &Path, id: &str) -> usize {
    records(root, "outbox")
        .iter()
        .filter(|r| r["subscription_id"] == id)
        .count()
}

/// T45 (SAFETY.5): `max_outbox: 10`, `max_outbox_per_subscription: 6`, a
/// receiver that always fails and a 10 min retry base keep records pending.
/// S1's 7th occurrence is dropped while S2 is still written; at 10 in all a
/// new S2 occurrence is dropped too; pending records are never dropped.
#[tokio::test]
async fn outbox_caps_are_hard_and_per_subscription() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(
        root.path(),
        &rx,
        json!({"max_outbox": 10, "max_outbox_per_subscription": 6,
               "retry_base": "10m", "retry_window": "15m"}),
    )
    .await;
    rx.event_default(EventReply::Status(503));
    let s1 = subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({"repo": "a"})).await;
    let s2 = subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({"repo": "b"})).await;
    let root_path = root.path().to_path_buf();
    for n in 0..7 {
        fire(&gw, &format!("a-{n}"), "a").await;
    }
    let six = wait_until(DEADLINE, || pending_for(&root_path, &s1) == 6).await;
    assert!(six, "S1 holds {} pending", pending_for(root.path(), &s1));
    tokio::time::sleep(SETTLE).await;
    assert_eq!(pending_for(root.path(), &s1), 6, "S1's 7th is dropped");
    for n in 0..5 {
        fire(&gw, &format!("b-{n}"), "b").await;
    }
    let four = wait_until(DEADLINE, || pending_for(&root_path, &s2) == 4).await;
    assert!(four, "S2 is written up to the global cap");
    tokio::time::sleep(SETTLE).await;
    assert_eq!(records(root.path(), "outbox").len(), 10, "hard global cap");
    assert_eq!(pending_for(root.path(), &s1), 6, "pending records kept");
}

/// T49 (RELIABLE.3), store clause: a dead letter older than
/// `dead_letter_retention` is swept, a younger one stays. Real clock with a
/// 6 s retention; a restart forces the sweep (assumption: the sweep runs at
/// load as well as periodically, as the subscription expiry sweep does).
#[tokio::test]
async fn dead_letters_are_swept_after_retention() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut gw = start(root.path(), &rx, json!({"dead_letter_retention": "6s"})).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    rx.event_default(EventReply::Status(410));
    fire(&gw, "d-49-old", "o/r").await;
    let old = delivery::dead_with_reason(root.path(), "gone").await[0]["event_id"].clone();
    tokio::time::sleep(Duration::from_secs(4)).await;
    fire(&gw, "d-49-young", "o/r").await;
    let root_path = root.path().to_path_buf();
    assert!(wait_until(DEADLINE, || dead_letters(&root_path).len() == 2).await);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    gw.restart().await;
    let swept = wait_until(DEADLINE, || {
        !dead_letters(&root_path)
            .iter()
            .any(|d| d["event_id"] == old)
    })
    .await;
    assert!(swept, "the old dead letter is swept");
    assert_eq!(dead_letters(root.path()).len(), 1, "the young one stays");
}

/// Bytes of every dead-letter file.
fn dead_bytes(root: &Path) -> u64 {
    std::fs::read_dir(root.join("events/dead")).map_or(0, |d| {
        d.flatten()
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    })
}

/// Six 410s against `events`; the event ids in arrival order.
async fn six_dead_letters(root: &Path, events: Value) -> (Gateway, Vec<String>) {
    let rx = Receiver::start(root).await;
    let gw = start(root, &rx, events).await;
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    rx.event_default(EventReply::Status(410));
    for n in 0..6 {
        fire(&gw, &format!("d-50-{n}"), "o/r").await;
    }
    let posts = events_at_least(&rx, 6).await;
    tokio::time::sleep(SETTLE).await;
    let ids = posts
        .iter()
        .map(|p| p.header("webhook-id").unwrap_or_default())
        .collect();
    (gw, ids)
}

/// T50 (RELIABLE.3): with `dead_letter_max_records: 5` a sixth dead letter
/// evicts the oldest and writes an eviction audit record (assumed to name
/// the evicted event id and contain "evict"); with a byte cap the store stays
/// under it and keeps the newest.
#[tokio::test]
async fn dead_letters_are_capped_by_count_and_bytes() {
    let root = tempfile::tempdir().expect("root");
    let (_gw, ids) = six_dead_letters(root.path(), json!({"dead_letter_max_records": 5})).await;
    let dead: Vec<Value> = dead_letters(root.path());
    assert_eq!(dead.len(), 5, "count cap");
    assert!(
        !dead.iter().any(|d| d["event_id"] == ids[0]),
        "oldest evicted"
    );
    let evictions = delivery::audit_mentioning(root.path(), &ids[0]);
    assert!(
        evictions.iter().any(|r| r.to_string().contains("evict")),
        "the eviction is audited"
    );

    let root = tempfile::tempdir().expect("root");
    let cap = 2500;
    let (_gw, ids) = six_dead_letters(root.path(), json!({"dead_letter_max_bytes": cap})).await;
    let dead = dead_letters(root.path());
    assert!(dead.iter().any(|d| d["event_id"] == ids[5]), "newest kept");
    assert!(dead_bytes(root.path()) <= cap, "byte cap");
}

/// The fixture capability with `ref` removed from filters and mapping.
fn without_ref(yaml: &str) -> String {
    yaml.replace("filters: [repo, ref]", "filters: [repo]")
        .replace(
            r#"data: { repo: "{repository.full_name}", ref: "{ref}" }"#,
            r#"data: { repo: "{repository.full_name}" }"#,
        )
}

/// The event's descriptor as `events/list` shows it to alice.
async fn descriptor(gw: &Gateway) -> Value {
    let answer = gw.rpc(Some(ALICE), "events/list", json!({})).await;
    answer["result"]["events"]
        .as_array()
        .and_then(|e| e.iter().find(|d| d["name"] == EVENT).cloned())
        .unwrap_or(Value::Null)
}

/// T52 (EVENTS.2): a capability reload that removes a filter and a mapped
/// field under the live event name is rejected and the old descriptor stays
/// (watched for 8 s: the watcher polls every 2 s and debounces 500 ms); a
/// reload that only adds a mapped field is accepted. Retyping is not
/// driven: mapped fields are untyped (`{}`) in the payload schema.
#[tokio::test]
async fn reload_rejects_incompatible_schema_changes_under_one_name() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    let file = root.path().join("caps/github.yaml");
    let original = std::fs::read_to_string(&file).expect("fixture capability");
    std::fs::write(&file, without_ref(&original)).expect("incompatible edit");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline {
        let d = descriptor(&gw).await;
        assert!(
            d["inputSchema"]["properties"].get("ref").is_some(),
            "the incompatible reload went live: {d}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let added = original.replace(r#"ref: "{ref}" }"#, r#"ref: "{ref}", sha: "{after}" }"#);
    std::fs::write(&file, added).expect("compatible edit");
    let mut accepted = false;
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while !accepted && tokio::time::Instant::now() < deadline {
        let d = descriptor(&gw).await;
        accepted = d["payloadSchema"]["properties"]["fields"]["properties"]
            .get("sha")
            .is_some();
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(accepted, "an additive change is accepted");
}

/// Poll `events/list` until `done` holds for alice's view of the event.
async fn descriptor_until(gw: &Gateway, done: impl Fn(&Value) -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while tokio::time::Instant::now() < deadline {
        if done(&descriptor(gw).await) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

/// MIK-8038 part 1 (A6): a subscribe held in its callback challenge while
/// its route is removed and restored narrower is refused at its commit. Its
/// `ref` filter is no longer a field the restored route maps, and committing
/// it would leave a subscription that never matches.
#[tokio::test]
async fn a_subscribe_whose_route_narrows_during_its_challenge_is_refused() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    // Under the 10 s challenge timeout, long enough for two reloads (the
    // watcher polls every 2 s and debounces 500 ms).
    rx.reply(receiver::Reply::SlowEcho(Duration::from_secs(9)));
    let file = root.path().join("caps/github.yaml");
    let original = std::fs::read_to_string(&file).expect("fixture capability");
    let params = delivery::params(&rx.url, &whsec(32), json!({"ref": "refs/heads/main"}));
    let narrow = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        std::fs::remove_file(&file).expect("remove the route");
        assert!(
            descriptor_until(&gw, Value::is_null).await,
            "the route went"
        );
        std::fs::write(&file, without_ref(&original)).expect("restore it narrower");
        assert!(
            descriptor_until(&gw, |d| d.is_object()
                && d["inputSchema"]["properties"].get("ref").is_none())
            .await,
            "the narrower route is live"
        );
    };
    let (answer, ()) = tokio::join!(gw.rpc(Some(ALICE), "events/subscribe", params), narrow);
    assert_eq!(
        (&answer["error"]["code"], &answer["error"]["data"]["field"]),
        (&json!(-32602), &json!("arguments")),
        "the commit is refused for its arguments: {answer}"
    );
    assert!(
        records(root.path(), "subs").is_empty(),
        "nothing was stored"
    );
    assert!(
        !rx.challenges().is_empty(),
        "the subscribe passed its first check and was challenged, so the refusal came at commit"
    );
}
