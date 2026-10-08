// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7772: a restart reconciles stored subscriptions with the catalogue
//! the capability scan then builds, so a route removed while the gateway was
//! down takes its subscriptions and pending retries with it.
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

use std::path::Path;
use std::time::Duration;

use delivery::{DEADLINE, delivery_config, events_at_least, fire, records, subscribe, wait_until};
use gateway::{ALICE, Gateway};
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

/// Debug builds' override of the startup webhook withdraw's grace period.
const GRACE_ENV: &str = "MCP_GATEWAY_TEST_EVENTS_WITHDRAW_GRACE_MS";

/// A subscription with one retry pending, the gateway stopped, then started
/// again with `change` applied to its directory and config.
async fn restart_after(
    change: impl FnOnce(&mut Gateway),
) -> (tempfile::TempDir, Receiver, Gateway, usize) {
    let dir = tempfile::tempdir().expect("root");
    let root = dir.path().to_path_buf();
    let rx = Receiver::start(&root).await;
    let cfg = delivery_config(
        &root,
        &json!({"retry_base": "30s", "retry_max_attempts": 5, "retry_window": "15m"}),
    );
    let (k, v) = rx.trust_env();
    // The startup webhook withdraw waits out no grace period (MIK-8027).
    let env = [(k, v.as_str()), (GRACE_ENV, "0")];
    let mut gw = Gateway::start_with_env(&root, cfg, &env).await;
    gw.event_names(Some(ALICE), Some(gateway::EVENT)).await;
    rx.event_default(EventReply::Status(503));
    subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    fire(&gw, "d-7772", "o/r").await;
    let posts = events_at_least(&rx, 1).await.len();
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

/// AC1, AC3: the route is gone when the gateway comes back. Once the scan
/// has run, the subscription and its pending retry are gone and nothing more
/// is posted.
#[tokio::test]
async fn a_route_removed_while_down_takes_its_subscription_and_retry() {
    let (_dir, rx, gw, posts) = restart_after(|gw| {
        std::fs::remove_file(gw.root().join("caps/github.yaml")).expect("remove the route");
    })
    .await;
    let root = gw.root().to_path_buf();
    assert!(
        wait_until(DEADLINE, || subs_on_disk(&root) == 0).await,
        "the orphaned subscription is withdrawn after the scan; {}",
        gw.stall_report()
    );
    assert!(
        records(&root, "outbox").is_empty(),
        "its pending retry is cancelled"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(rx.events().len(), posts, "nothing is sent for it");
}

/// AC1: events on with webhooks off offers no webhook event types, so the
/// subscriptions to them are withdrawn too.
#[tokio::test]
async fn webhooks_off_withdraws_webhook_subscriptions() {
    let (_dir, _rx, gw, _posts) = restart_after(|gw| {
        let mut cfg = gw.config().clone();
        cfg["webhooks"]["enabled"] = json!(false);
        gw.rewrite_config(cfg);
    })
    .await;
    let root = gw.root().to_path_buf();
    assert!(
        wait_until(DEADLINE, || subs_on_disk(&root) == 0).await,
        "the webhook subscription is withdrawn; {}",
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
    let (k, v) = rx.trust_env();
    let mut gw = Gateway::start_with_env(&root, cfg.clone(), &[(k, &v)]).await;
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
