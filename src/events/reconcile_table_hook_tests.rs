// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reconcile table (Family-fix MIK-7940, design r3 section 6): the webhook
//! hold rows. Each test is one row: an initial state, a change, and the
//! asserted rows (R), started keys (K) and hold stamps (H), with the worker
//! sweep never run. Rows marked PIN hold on base and must stay green; the
//! rest fail on base at their own assertions until the reconcile step lands.
//!
//! Rows here: T11 (non-watch half, red), T19 (retry half, red; its
//! in-memory half is pinned by `a_failed_stamp_write_still_bounds_the_row`),
//! T28 (webhook half, PIN).
//!
//! Rows the reconcile step's hooks must exist for first (R2):
//! - T17: a pause in the staged stamp write, with fan-out to an unaffected
//!   subscription proceeding while 1,000 rows' writes are paused.
//! - T18: a crash between a first hold and its row write; after restart the
//!   hold ends no later than the original end plus downtime plus one pass.
//! - T20: a staged write paused past a newer commit, and past an
//!   unsubscribe; the newer row is kept and the deleted row stays deleted.

use serde_json::json;

use super::*;
use crate::events::types::SourceKind;

/// The webhook keys started now.
async fn webhook_keys(hub: &EventsHub) -> Vec<String> {
    hub.lifecycle
        .lock()
        .await
        .iter()
        .filter(|(kind, _)| *kind == SourceKind::Webhook)
        .map(|(_, key)| key.clone())
        .collect()
}

/// Whether the webhook keys reach `count` within 50 scheduler turns.
async fn keys_settle(hub: &EventsHub, count: usize) -> bool {
    for _ in 0..50 {
        if webhook_keys(hub).await.len() == count {
            return true;
        }
        tokio::task::yield_now().await;
    }
    false
}

/// T11, non-watch half (MIK-8179 STARTED.1, design r3 K rule): a held
/// webhook row keeps no started key, without waiting for a sweep; the route
/// coming back starts it again.
#[tokio::test]
async fn t11_a_held_webhook_row_releases_its_key() {
    let (_dir, hub, registry) = restarted(json!({}), &full()).await;
    let id = id_of(&subscribe(&hub, json!({})).await.expect("refresh"));
    assert_eq!(webhook_keys(&hub).await.len(), 1, "premise: started");
    refresh(&hub, &registry, "");
    assert!(hub.store.held(&id).is_some(), "premise: held");
    // Turns for the posted key reconcile, bounded; no sweep runs.
    assert!(keys_settle(&hub, 0).await, "a held row keeps no key");
    refresh(&hub, &registry, &full());
    assert!(hub.store.held(&id).is_none(), "premise: resumed");
    assert!(keys_settle(&hub, 1).await, "started again");
}

/// T28, webhook half (PIN, #3488): a complete catalogue without the route
/// holds the subscription and deletes nothing; the route coming back
/// resumes it with no subscriber action.
#[tokio::test]
async fn t28_a_dropped_route_holds_the_row_then_resumes() {
    let (_dir, hub, registry) = restarted(json!({}), &full()).await;
    let id = id_of(&subscribe(&hub, json!({})).await.expect("refresh"));
    refresh(&hub, &registry, "");
    assert!(hub.store.get(&id).is_some(), "the row is kept");
    assert!(hub.store.held(&id).is_some(), "held");
    refresh(&hub, &registry, &full());
    assert!(hub.store.held(&id).is_none(), "resumed");
}
