// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A plan task's replay snapshot lives in its row, written by the
//! settle that stores the result, and a read rebuilds the in-memory entry
//! from the row it holds; the write that delivers it settles it (the pending-snapshot
//! rule). A snapshot this process cannot track is refused under block,
//! decided at the read's start. Rows K1-K26 of the test plan.

use super::super::*;
use super::relay_plan_replay::{OTHER_PROSE, PROSE, Rig, chain, rig};
use super::relay_plan_replay_guards::{committed, state_over_tasks, task_key};
use super::support::*;

use crate::security::firewall::CollusionAction;
use pretty_assertions::assert_eq;

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

/// Alice's plan task run to its end without any read: the store row is
/// polled and the worker joined, so no tasks/get has rebuilt an entry.
async fn settle_unread(rig: &Rig, key: &str) -> String {
    let call = super::relay_plan_replay::task_call(1, key, "gateway_execute", &chain());
    let created = post(&rig.state, "key-a", call).await;
    let task = task_id(&created);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let status = committed(&rig.state, &task).task.status();
        if status == crate::protocol::tasks::TaskStatus::Completed {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the task never completed: {status:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let joined = rig
        .state
        .task_executor
        .drain(std::time::Duration::from_secs(10))
        .await;
    assert!(joined.is_clean(), "the worker must finish: {joined:?}");
    task
}

/// Alice's tasks/get of `task`, judged and built under the action
/// published now, then `action` published, then its body read: the write
/// (the body's first chunk) commits under `action`.
async fn read_switched_at_write(
    state: &Arc<AppState>,
    task: &str,
    action: CollusionAction,
) -> Value {
    use tower::ServiceExt as _;
    let body = task_method(7_002, "tasks/get", json!({ "taskId": task }));
    let response = create_router(Arc::clone(state))
        .oneshot(http_request(Some("key-a"), &body))
        .await
        .expect("the router must answer");
    let mut config = (*state.live_config.get()).clone();
    config.security.firewall.collusion.action = action;
    state.live_config.set(config);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must read");
    serde_json::from_slice(&bytes).expect("the body is JSON")
}

/// Alice reads `task`; the reply.
async fn read(rig: &Rig, task: &str) -> Value {
    get_task(&rig.state, "key-a", task).await
}

/// K1 and K6: no completed revision of the task is ever published without
/// its snapshot, and none is held in memory before a read; alice's first
/// read (live receipts aged out) stages it, and bob's relay is refused.
/// Mutants: snapshot written in a second write after the result (N1);
/// entry inserted at commit (N2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k1_k6_no_completed_revision_is_readable_without_its_snapshot() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = settle_unread(&rig, "k1").await;
    let published = crate::gateway::task_service::publish_log::of(&task);
    assert!(
        published.iter().any(|(completed, _)| *completed),
        "premise: the completed row was published: {published:?}"
    );
    assert!(
        published
            .iter()
            .all(|(completed, snapshot)| !completed || *snapshot),
        "a completed revision was readable without its snapshot: {published:?}"
    );
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

/// K25: a read judged under off and written under block (a trackable
/// snapshot; the body read after the switch): the write's action decides, the entry is kept, bob refused.
/// Mutant: rebuild only when the read starts under a non-off action.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k25_a_read_judged_under_off_and_written_under_block_is_kept() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = settle_unread(&rig, "k25").await;
    rig.lapse().await;
    publish(&rig, CollusionAction::Off);
    let reply = read_switched_at_write(&rig.state, &task, CollusionAction::Block).await;
    assert_eq!(status_of(&reply), "completed", "{reply}");
    assert!(entry_held(&rig, &task), "the block write did not keep it");
    assert!(rig.refused("key-b", 2501, PROSE).await);
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
/// `-32002`; observe delivers it and counts the relay `untrackable` once;
/// off delivers it and counts nothing. Nothing is rebuilt from it.
/// Mutants: epoch check skipped (N6); refused under observe (N7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k26_another_epoch_is_refused_under_block_only() {
    for (action, refused, counted) in [
        (CollusionAction::Block, true, 1),
        (CollusionAction::Observe, false, 1),
        (CollusionAction::Off, false, 0),
    ] {
        let first = rig_state().await;
        let task = settle_unread(&first, "k26").await;
        let state = foreign_epoch(first, &task).await;
        let mut config = (*state.live_config.get()).clone();
        config.security.firewall.collusion.action = action;
        state.live_config.set(config);
        let measured = get_task(&state, "key-a", &task);
        #[cfg(feature = "metrics")]
        let (reply, count) = crate::gateway::count_relay_reason("untrackable", measured);
        #[cfg(not(feature = "metrics"))]
        let reply = measured.await;
        if refused {
            assert_eq!(reply["error"]["code"], -32002, "{action:?}: {reply}");
        } else {
            assert_eq!(status_of(&reply), "completed", "{action:?}: {reply}");
            assert!(reply.to_string().contains(PROSE), "{action:?}: {reply}");
        }
        #[cfg(feature = "metrics")]
        assert_eq!(count, counted, "{action:?}: untrackable count");
        #[cfg(not(feature = "metrics"))]
        let _ = counted;
    }
}

/// K21-limit, today's outcome of the stated limit (register row 1181): an
/// untrackable read judged under off and written after a switch to block
/// is delivered; the refusal is decided at read start only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k21_limit_an_untrackable_read_switched_to_block_mid_read_is_delivered() {
    let first = rig_state().await;
    let task = settle_unread(&first, "k21").await;
    let state = foreign_epoch(first, &task).await;
    let mut config = (*state.live_config.get()).clone();
    config.security.firewall.collusion.action = CollusionAction::Off;
    state.live_config.set(config);
    let reply = read_switched_at_write(&state, &task, CollusionAction::Block).await;
    assert_eq!(status_of(&reply), "completed", "{reply}");
}

/// Every string leaf of `value`.
fn strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
        Value::Object(map) => map.values().for_each(|v| strings(v, out)),
        _ => {}
    }
}

/// K20 (lead condition 1): the task record on disk holds no text beyond
/// its stored result. Every segment text in the persisted snapshot occurs
/// in the stored result, every server and tool it names is one of the
/// row's targets, and it carries no join text (joins persist as
/// fingerprints). The oracle is general: any pre-redaction or step-only
/// text the snapshot kept would fail it, whatever its source.
/// Mutants: skip the delivered-segment check; skip the join conversion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k20_the_record_holds_no_text_beyond_its_stored_result() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = settle_unread(&rig, "k20").await;
    let Rig { _store: store, .. } = &rig;
    let file = store.path().join("tasks").join(format!("{task}.json"));
    let row: Value = serde_json::from_slice(&std::fs::read(&file).expect("the row file"))
        .expect("the row decodes");
    let snapshot = &row["replaySnapshot"];
    assert!(snapshot.is_object(), "premise: a kept snapshot: {row}");
    let mut stored = Vec::new();
    strings(&row["model"]["task"]["result"], &mut stored);
    let stored = stored.join("\n");
    let targets = committed(&rig.state, &task).targets;
    let names: Vec<&str> = targets
        .iter()
        .flat_map(|t| [t.server.as_str(), t.tool.as_str()])
        .collect();
    let receipts = snapshot["receipts"].as_array().expect("receipts");
    assert!(!receipts.is_empty(), "premise: receipts persisted");
    for receipt in receipts {
        for segment in receipt["segments"].as_array().into_iter().flatten() {
            let text = segment["text"].as_str().expect("segment text");
            assert!(
                stored.contains(text),
                "a persisted segment is not in the stored result: {text:?}"
            );
        }
        // A seam receipt names its contributing `server:tool`s; any other
        // names its own server and tool.
        if let Some(sources) = receipt["seamSources"].as_array() {
            for source in sources {
                let pair = source.as_str().unwrap_or("");
                assert!(
                    targets
                        .iter()
                        .any(|t| format!("{}:{}", t.server, t.tool) == pair),
                    "a persisted seam source is not a target: {pair}"
                );
            }
        } else {
            for name in [&receipt["server"], &receipt["tool"]] {
                assert!(
                    names.contains(&name.as_str().unwrap_or("")),
                    "a persisted name is not a target: {name}"
                );
            }
        }
        assert!(
            receipt["joins"].get("text").is_none(),
            "join text persisted: {receipt}"
        );
    }
}

/// K7: a read under block whose answer is dropped unwritten (its body never
/// read) rebuilds the entry but settles nothing: the entry stays pending,
/// so a later read written under off removes it, which a kept entry would
/// survive.
/// Mutant: settle at judge instead of at the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k7_a_read_dropped_unwritten_settles_nothing() {
    use tower::ServiceExt as _;
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = settle_unread(&rig, "k7").await;
    let body = task_method(7_001, "tasks/get", json!({ "taskId": task }));
    let response = create_router(Arc::clone(&rig.state))
        .oneshot(http_request(Some("key-a"), &body))
        .await
        .expect("the router must answer");
    drop(response);
    assert!(
        entry_held(&rig, &task),
        "premise: the read rebuilt the entry"
    );
    publish(&rig, CollusionAction::Off);
    let reply = read(&rig, &task).await;
    assert_eq!(status_of(&reply), "completed", "{reply}");
    assert!(
        !entry_held(&rig, &task),
        "the dropped read kept the entry it never delivered"
    );
}

/// K29 (P4): the rebuilt entry lives for the task's TTL from the read that
/// inserted it, on the detector's clock: held just before, gone just after.
/// Mutants: a fixed retention; retention from the commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k29_a_rebuilt_entry_lives_for_the_task_ttl_from_its_read() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = settle_unread(&rig, "k29").await;
    let ttl = committed(&rig.state, &task).task.ttl_ms().map_or(
        std::time::Duration::from_secs(crate::idempotency::admission::RETENTION_SECS),
        std::time::Duration::from_millis,
    );
    // Time passes between commit and the first read: the clock is the
    // read's, never the commit's.
    rig.relay
        .advance_collusion_clock_for_test(std::time::Duration::from_secs(60));
    let _ = read(&rig, &task).await;
    let second = std::time::Duration::from_secs(1);
    rig.relay
        .advance_collusion_clock_for_test(ttl.saturating_sub(second));
    assert!(entry_held(&rig, &task), "gone before its TTL");
    rig.relay.advance_collusion_clock_for_test(second * 2);
    assert!(!entry_held(&rig, &task), "held past its TTL");
}
