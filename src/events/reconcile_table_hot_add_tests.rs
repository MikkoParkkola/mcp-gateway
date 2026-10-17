// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T03 (MIK-7897 LIFE.2, startup hot-add half): a backend registration and
//! the startup reconcile's snapshot-and-withdraw are serialized, so a backend
//! whose registration completes before the startup withdraw keeps its rows,
//! and none completes between the snapshot and the withdraw.

use std::time::Duration;

use super::*;
use crate::test_pause::{Slot, within};

/// The production backend names (`events_wiring.rs`): the registry's members,
/// read first, then a pause at `snapshot` (when armed) before they return.
fn names_of(
    registry: &Arc<crate::backend::BackendRegistry>,
    snapshot: &Arc<Slot>,
) -> backend_source::BackendNames {
    let (registry, snapshot) = (Arc::clone(registry), Arc::clone(snapshot));
    Arc::new(move || {
        let names: Vec<String> = registry.all().iter().map(|b| b.name.clone()).collect();
        snapshot.pause_blocking();
        names
    })
}

/// A hub whose backend source reads `registry`, as the gateway wires it.
fn hub_on(
    registry: &Arc<crate::backend::BackendRegistry>,
) -> (Arc<EventsHub>, tempfile::TempDir, Arc<Slot>) {
    let (hub, dir) = hub();
    let snapshot = Arc::new(Slot::default());
    let none: backend_source::Ineligible = Arc::new(std::collections::BTreeSet::new);
    hub.install_backend_source_with_upstream(
        names_of(registry, &snapshot),
        Arc::clone(registry),
        none,
    );
    (hub, dir, snapshot)
}

/// Whether `task` finishes within a bounded wait (the shape of
/// `subscribe_order_tests`): read, never asserted while a pause is held.
async fn finishes_soon<T>(task: &tokio::task::JoinHandle<T>) -> bool {
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while !task.is_finished() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    task.is_finished()
}

/// T03a: a remove then re-add of `b` that finishes before the startup
/// snapshot leaves `b` registered, so its rows survive the pass and its key
/// starts at the re-add's announce.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t03a_a_re_add_before_the_startup_snapshot_keeps_its_rows() {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let (hub, _dir, _snapshot) = hub_on(&registry);
    assert!(registry.register(silent_backend()));
    admit_on(&hub, "b", "tools_changed");
    assert!(registry.remove("b"), "premise: b removed");
    assert!(registry.register(silent_backend()), "b re-added");
    let pass = tokio::task::spawn_blocking({
        let hub = Arc::clone(&hub);
        move || hub.reconcile_catalogue(fanout::CatalogueScan::Complete)
    });
    assert!(within("the startup pass", pass).await.expect("join"));
    assert_eq!(hub.store.subscriptions().len(), 1, "b's row kept");
    // What the re-add's announce drives (tools_changed.rs drain).
    hub.backend_tools_changed("b");
    within("b's key starting", async {
        while hub.lifecycle.lock().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert_eq!(hub.store.subscriptions().len(), 1, "still kept");
}

/// T03b: a registration of `b` attempted while the startup pass is between
/// its snapshot and its withdraw does not complete inside that window; it
/// completes after the pass, which judged `b` absent and withdrew its row
/// (removed while the gateway was down, MIK-7803).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t03b_a_registration_waits_for_the_startup_snapshot_and_withdraw() {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let (hub, _dir, snapshot) = hub_on(&registry);
    admit_on(&hub, "b", "tools_changed");
    let (at_snapshot, after_snapshot) = snapshot.arm();
    let (at_withdraw, after_withdraw) = hub.before_withdraw.arm();
    let pass = tokio::task::spawn_blocking({
        let hub = Arc::clone(&hub);
        move || hub.reconcile_catalogue(fanout::CatalogueScan::Complete)
    });
    within("the pass's snapshot", at_snapshot.notified()).await;
    let adding = tokio::task::spawn_blocking({
        let registry = Arc::clone(&registry);
        move || registry.register(silent_backend())
    });
    let added_at_snapshot = finishes_soon(&adding).await;
    after_snapshot.notify_one();
    within("the pass's withdraw", at_withdraw.notified()).await;
    let added_before_withdraw = finishes_soon(&adding).await;
    after_withdraw.notify_one();
    assert!(within("the startup pass", pass).await.expect("join"));
    assert!(
        within("the registration", adding).await.expect("join"),
        "registered"
    );
    assert!(
        !added_at_snapshot,
        "a registration completed while the pass read its snapshot"
    );
    assert!(
        !added_before_withdraw,
        "a registration completed between the snapshot and the withdraw"
    );
    assert!(registry.get("b").is_some(), "b registered after the pass");
    assert!(
        hub.store.subscriptions().is_empty(),
        "the pass ran first: b's row withdrawn as absent at startup"
    );
}
