// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7772 under MIK-8057: a restart reconciles stored subscriptions with
//! the catalogue the capability scan then builds. A webhook route removed
//! while the gateway was down holds its subscriptions (nothing is sent, and
//! nothing is deleted on a read); a removed backend takes its subscriptions.
//!
//! Unix; the child trusts the receiver's CA through
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

use std::path::Path;
use std::time::Duration;

use delivery::{DEADLINE, delivery_config, events_at_least, fire, records, subscribe, wait_until};
use gateway::{ADMIN, ALICE, Gateway};
use receiver::{EventReply, Receiver, whsec};
use serde_json::json;

/// Stored subscriptions only: the store rewrites a record through a
/// `.{name}.{n}.tmp` file and a rename, and a count taken mid-rewrite would
/// see that temp file as a second subscription.
fn subs_on_disk(root: &Path) -> usize {
    std::fs::read_dir(root.join("events/subs")).map_or(0, |d| {
        d.flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .count()
    })
}

/// The retry policy of the rows that only need one retry pending: its first
/// retry is seconds away.
fn slow_retry() -> serde_json::Value {
    json!({"retry_base": "30s", "retry_max_attempts": 5, "retry_window": "15m"})
}

/// A subscription with one retry pending, the gateway stopped, then started
/// again with `change` applied to its directory and config. `script` answers
/// the first deliveries (503 after it); the stop waits for `stop_after` POSTs.
async fn restart_after(
    retry: serde_json::Value,
    script: Vec<EventReply>,
    stop_after: usize,
    change: impl FnOnce(&mut Gateway),
) -> (tempfile::TempDir, Receiver, Gateway, usize) {
    let dir = tempfile::tempdir().expect("root");
    let root = dir.path().to_path_buf();
    let rx = Receiver::start(&root).await;
    let cfg = delivery_config(&root, &retry);
    let trust = rx.trust_env();
    let env = trust.each_ref().map(|(k, v)| (*k, v.as_str()));
    let mut gw = Gateway::start_with_env(&root, cfg, &env).await;
    gw.event_names(Some(ALICE), Some(gateway::EVENT)).await;
    rx.event_default(EventReply::Status(503));
    rx.script(script);
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    fire(&gw, "d-7772", "o/r").await;
    let posts = events_at_least(&rx, 1).await.len();
    events_at_least(&rx, stop_after).await;
    assert_eq!(subs_on_disk(&root), 1);
    assert!(
        wait_until(DEADLINE, || !records(&root, "outbox").is_empty()).await,
        "the failed delivery is pending a retry"
    );
    // Down first: a live gateway would reload the change itself.
    gw.stop().await;
    change(&mut gw);
    gw.restart().await;
    (dir, rx, gw, posts)
}

/// AC1, AC3 as amended by MIK-8057: the route is gone when the gateway
/// comes back. The subscription is held, not deleted, and nothing more is
/// posted for it.
#[tokio::test]
async fn a_route_removed_while_down_holds_its_subscription() {
    let (_dir, rx, gw, posts) = restart_after(slow_retry(), Vec::new(), 1, |gw| {
        std::fs::remove_file(gw.root().join("caps/github.yaml")).expect("remove the route");
    })
    .await;
    let root = gw.root().to_path_buf();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(subs_on_disk(&root), 1, "held, not withdrawn");
    assert_eq!(rx.events().len(), posts, "nothing is sent for it");
}

/// MIK-8044.SURF.8: the admin's held listing, served through the route with a
/// subscription really held: its type left with its route, and its failed
/// delivery is still queued. The listing names the type, the count and the
/// queued record (src/events/admin.rs), which only the unit tests saw before.
#[tokio::test]
async fn a_held_subscription_is_listed_with_its_queued_record() {
    let (_dir, _rx, gw, _posts) = restart_after(slow_retry(), Vec::new(), 1, |gw| {
        std::fs::remove_file(gw.root().join("caps/github.yaml")).expect("remove the route");
    })
    .await;
    let deadline = tokio::time::Instant::now() + DEADLINE;
    // A poll: it exits on the listing showing the entry, and asserts after.
    let (status, last) = loop {
        let (status, body) = gw.admin(Some(ADMIN), "GET", "/ui/api/events/held").await;
        let one = status == 200 && body["held"].as_array().is_some_and(|h| h.len() == 1);
        if one || tokio::time::Instant::now() >= deadline {
            break (status, body);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(status, 200, "admin held listing answered {status}: {last}");
    assert_eq!(
        last["held"].as_array().map(Vec::len),
        Some(1),
        "no single held entry appeared: {last}"
    );
    let held = &last["held"][0];
    assert_eq!(held["type"], gateway::EVENT, "{last}");
    assert_eq!(held["count"], 1, "{last}");
    assert_eq!(held["pendingRecords"], 1, "{last}");
}

/// AC1 as amended by MIK-8057: events on with webhooks off offers no webhook
/// event types, so the subscriptions to them are held until they lapse.
#[tokio::test]
async fn webhooks_off_holds_webhook_subscriptions() {
    let (_dir, _rx, gw, _posts) = restart_after(slow_retry(), Vec::new(), 1, |gw| {
        let mut cfg = gw.config().clone();
        cfg["webhooks"]["enabled"] = json!(false);
        gw.rewrite_config(cfg);
    })
    .await;
    let root = gw.root().to_path_buf();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        subs_on_disk(&root),
        1,
        "held, not withdrawn; {}",
        gw.stall_report()
    );
}

/// MIK-7803: a backend removed while the gateway was down takes its
/// `backend.<x>.tools_changed` subscription with it at the next start; a
/// subscription to a retained event type survives the same restart.
#[tokio::test]
async fn a_backend_removed_while_down_takes_its_subscription() {
    let dir = tempfile::tempdir().expect("root");
    let root = dir.path().to_path_buf();
    let rx = Receiver::start(&root).await;
    let mut cfg = delivery_config(&root, &json!({}));
    cfg["backends"] =
        json!({"mock": {"http_url": "http://127.0.0.1:9/mcp", "streamable_http": true}});
    for key in cfg["auth"]["api_keys"].as_array_mut().expect("keys") {
        key["backends"]
            .as_array_mut()
            .expect("backends")
            .push(json!("mock"));
    }
    let trust = rx.trust_env();
    let env = trust.each_ref().map(|(k, v)| (*k, v.as_str()));
    let mut gw = Gateway::start_with_env(&root, cfg.clone(), &env).await;
    let name = "backend.mock.tools_changed";
    gw.event_names(Some(ALICE), Some(name)).await;
    let mut params = delivery::params(&rx.url, &whsec(32), json!({}));
    params["name"] = json!(name);
    let answer = gw.rpc(Some(ALICE), "events/subscribe", params).await;
    assert!(
        answer["result"]["id"].is_string(),
        "backend subscribe: {answer}"
    );
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    assert_eq!(subs_on_disk(&root), 2, "both subscriptions are stored");
    gw.stop().await;
    let mut gone = cfg;
    gone["backends"] = json!({});
    gw.rewrite_config(gone);
    gw.restart().await;
    assert!(
        wait_until(DEADLINE, || subs_on_disk(&root) == 1).await,
        "the removed backend's subscription is withdrawn, the webhook one kept; {}",
        gw.stall_report()
    );
    let names = gw.event_names(Some(ALICE), Some(gateway::EVENT)).await;
    assert!(
        names.iter().all(|n| n != name),
        "the type is gone: {names:?}"
    );
}

/// MIK-8796: a retry the gateway makes before the restart, while the route
/// still exists, is not a send after it. The first reply is held, so the
/// baseline is taken before any retry can be scheduled; the stop waits for
/// the retry itself. Ten attempts at a 1 s base cannot run out first.
#[tokio::test]
async fn a_retry_before_the_restart_is_not_counted_as_sent_after_it() {
    let (_dir, rx, gw, posts) = restart_after(
        json!({"retry_base": "1s", "retry_max_attempts": 10, "retry_window": "15m"}),
        vec![EventReply::Hold(Duration::from_secs(8), 503)],
        2,
        |gw| {
            std::fs::remove_file(gw.root().join("caps/github.yaml")).expect("remove the route");
        },
    )
    .await;
    let root = gw.root().to_path_buf();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(subs_on_disk(&root), 1, "held, not withdrawn");
    assert_eq!(rx.events().len(), posts, "nothing is sent for it");
}
