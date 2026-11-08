// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9379: a plan task's replay snapshot lives in its row, written by the
//! settle that stores the result, and a read rebuilds the in-memory entry
//! from the row it holds; the write that delivers it settles it (MIK-9267's
//! rule). A snapshot this process cannot track is refused under block,
//! decided at the read's start. Rows K1-K26 of the test plan.

use super::super::*;
use super::relay_plan_replay::{OTHER_PROSE, PROSE, Rig, chain, rig};
use super::relay_plan_replay_guards::{committed, state_over_tasks, task_key};
use super::support::*;

use crate::security::firewall::CollusionAction;

/// Publish `action` on the live config the router and Meta-MCP share.
fn publish(rig: &Rig, action: CollusionAction) {
    let mut config = (*rig.state.live_config.get()).clone();
    config.security.firewall.collusion.action = action;
    rig.state.live_config.set(config);
}

/// The in-memory replay entry of `task`'s settled row, if any.
fn entry_held(rig: &Rig, task: &str) -> bool {
    let row = committed(&rig.state, task);
    rig.relay
        .replay_digests(&task_key(task, row.revision))
        .is_some()
}

/// Alice reads `task`; the reply.
async fn read(rig: &Rig, task: &str) -> Value {
    get_task(&rig.state, "key-a", task).await
}

/// K1 and K6: the row that becomes readable already holds the snapshot and
/// nothing is held in memory; alice's first read (receipts aged out) stages
/// it, and bob's relay of the stored answer is refused.
/// Mutants: snapshot written after the result (N1); entry inserted at
/// commit (N2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k1_k6_the_readable_row_holds_its_snapshot_and_a_read_stages_it() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = rig.settle_task("k1", "gateway_execute", chain()).await;
    let row = committed(&rig.state, &task);
    assert!(row.replay_snapshot.is_some(), "the row holds no snapshot");
    assert!(
        !entry_held(&rig, &task),
        "a commit inserted an in-memory entry"
    );
    rig.lapse().await;
    assert!(!rig.refused("key-b", 101, PROSE).await, "premise: lapsed");
    let reply = read(&rig, &task).await;
    assert_eq!(status_of(&reply), "completed", "{reply}");
    assert!(
        rig.refused("key-b", 102, PROSE).await,
        "the read staged nothing from the row"
    );
}

/// K4: steady off; after alice's delivering read nothing is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k4_steady_off_holds_nothing_after_the_read() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    publish(&rig, CollusionAction::Off);
    let task = rig.settle_task("k4", "gateway_execute", chain()).await;
    let reply = read(&rig, &task).await;
    assert_eq!(status_of(&reply), "completed", "{reply}");
    assert!(!entry_held(&rig, &task), "an off delivery kept the entry");
}

/// K5: stored under off, first read under block: kept, bob refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k5_stored_under_off_read_under_block_is_kept() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    publish(&rig, CollusionAction::Off);
    let task = rig.settle_task("k5", "gateway_execute", chain()).await;
    publish(&rig, CollusionAction::Block);
    rig.lapse().await;
    let reply = read(&rig, &task).await;
    assert_eq!(status_of(&reply), "completed", "{reply}");
    assert!(entry_held(&rig, &task), "the block read did not keep it");
    assert!(rig.refused("key-b", 501, PROSE).await);
}

/// K17: off -> block -> read: the off read leaves nothing, the block read
/// rebuilds from the row and is tracked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k17_off_then_block_rebuilds_and_tracks() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    publish(&rig, CollusionAction::Off);
    let task = rig.settle_task("k17", "gateway_execute", chain()).await;
    let _ = read(&rig, &task).await;
    assert!(!entry_held(&rig, &task), "premise: removed after off");
    publish(&rig, CollusionAction::Block);
    rig.lapse().await;
    let _ = read(&rig, &task).await;
    assert!(entry_held(&rig, &task), "the block read rebuilt nothing");
    assert!(rig.refused("key-b", 1701, PROSE).await);
}

/// K18: block -> off -> read: the block read keeps the entry; a later off
/// read leaves the kept entry in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k18_block_then_off_leaves_the_kept_entry() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = rig.settle_task("k18", "gateway_execute", chain()).await;
    let _ = read(&rig, &task).await;
    assert!(entry_held(&rig, &task), "premise: kept by block");
    publish(&rig, CollusionAction::Off);
    let _ = read(&rig, &task).await;
    assert!(entry_held(&rig, &task), "an off read removed a kept entry");
}

/// G32 as changed: a gateway reopened over the same tasks in this process
/// (same epoch) rebuilds the entry from the row: the re-read renews.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g32_a_reopened_gateway_in_the_same_process_renews_from_the_row() {
    let first = rig(PROSE, OTHER_PROSE, None).await;
    let task = first.settle_task("g32", "gateway_execute", chain()).await;
    let Rig {
        state: first_state,
        _store: first_store,
        ..
    } = first;
    drop(first_state);
    let reopened = state_over_tasks(rig(PROSE, OTHER_PROSE, None).await, &first_store).await;
    let reply = get_task(&reopened, "key-a", &task).await;
    assert_eq!(status_of(&reply), "completed", "{reply}");
    assert!(
        super::relay_plan_replay_guards::probe_refused(&reopened, "key-b", 3201, PROSE).await,
        "the re-read did not renew from the persisted snapshot"
    );
}

/// The row of `task` rewritten on disk so its snapshot carries another
/// epoch (a snapshot another process made), then the store reopened.
async fn foreign_epoch(rig: Rig, task: &str) -> Arc<AppState> {
    let Rig {
        state: first_state,
        _store: store,
        ..
    } = rig;
    drop(first_state);
    let record = store.path().join("tasks").join(format!("{task}.json"));
    let mut row: Value =
        serde_json::from_slice(&std::fs::read(&record).expect("the row file: fixture"))
            .expect("the row decodes");
    let epoch = row["replaySnapshot"]["epoch"]
        .as_u64()
        .expect("premise: a snapshot with an epoch");
    row["replaySnapshot"]["epoch"] = json!(epoch.wrapping_add(1));
    std::fs::write(&record, serde_json::to_vec(&row).unwrap()).unwrap();
    state_over_tasks(rig_state().await, &store).await
}

async fn rig_state() -> Rig {
    rig(PROSE, OTHER_PROSE, None).await
}

/// K26b: a snapshot from another epoch: block refuses alice's read with
/// `-32002`; observe and off deliver it. Nothing is rebuilt from it.
/// Mutants: epoch check skipped (N6); untrackable refused under observe (N7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k26_another_epoch_is_refused_under_block_only() {
    for (action, refused) in [
        (CollusionAction::Block, true),
        (CollusionAction::Observe, false),
        (CollusionAction::Off, false),
    ] {
        let first = rig_state().await;
        let task = first.settle_task("k26", "gateway_execute", chain()).await;
        let state = foreign_epoch(first, &task).await;
        let mut config = (*state.live_config.get()).clone();
        config.security.firewall.collusion.action = action;
        state.live_config.set(config);
        let reply = get_task(&state, "key-a", &task).await;
        if refused {
            assert_eq!(reply["error"]["code"], -32002, "{action:?}: {reply}");
        } else {
            assert_eq!(status_of(&reply), "completed", "{action:?}: {reply}");
            assert!(reply.to_string().contains(PROSE), "{action:?}: {reply}");
        }
    }
}

/// The dropped K21 leg, pinned as today's outcome (the stated limit): a
/// read that starts under off is decided then, so an untrackable result is
/// delivered; the refusal is decided at read start only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k21_limit_an_untrackable_read_started_under_off_is_delivered() {
    let first = rig_state().await;
    let task = first.settle_task("k21", "gateway_execute", chain()).await;
    let state = foreign_epoch(first, &task).await;
    let mut config = (*state.live_config.get()).clone();
    config.security.firewall.collusion.action = CollusionAction::Off;
    state.live_config.set(config);
    let reply = get_task(&state, "key-a", &task).await;
    assert_eq!(status_of(&reply), "completed", "{reply}");
}
