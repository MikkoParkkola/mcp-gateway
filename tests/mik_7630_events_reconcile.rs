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

fn subs_on_disk(root: &Path) -> usize {
    std::fs::read_dir(root.join("events/subs")).map_or(0, |d| d.flatten().count())
}

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
    let mut gw = Gateway::start_with_env(&root, cfg, &[(k, &v)]).await;
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
        "the orphaned subscription is withdrawn after the scan"
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
        "the webhook subscription is withdrawn"
    );
}
