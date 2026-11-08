// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The pending replay snapshot over stdio, end to end. A keyed chain's
//! answer is captured at judge whatever the action, before settlement makes
//! it replayable. Each write of it (the original, or a replay) keeps the
//! snapshot, unless that write is under `off` and no other delivery of it is
//! outstanding. Frames are judged as the serve loop judges them and written
//! the way the stdout writer does (`OutboundFrame::stdio_written`).

use std::cell::Cell;
use std::rc::Rc;

use super::*;
use crate::gateway::outbound::OutboundFrame;
use crate::gateway::server::{Gateway, StdioClient};

const SESSION: &str = "stdio-replay";

/// The keyed chain over `alpha:a` (one step, [`PROSE`]).
fn chain(id: i64) -> Value {
    keyed_request(
        id,
        "gateway_execute",
        &json!({"chain": [{"tool": "alpha:a", "arguments": {}}]}),
    )
}

/// Publish `action` as the meta's live collusion action.
fn publish(meta: &MetaMcp, action: CollusionAction) {
    let live = meta.live_config().expect("the fixture seeds a live config");
    let mut config = (*live.get()).clone();
    config.security.firewall.collusion.action = action;
    live.set(config);
}

/// Let every live receipt lapse; a stored replay snapshot outlives it.
fn lapse(firewall: &Firewall) {
    firewall.advance_collusion_clock_for_test(Duration::from_secs(WINDOW_SECS + 1));
}

/// `request` dispatched and judged as the serve loop does, unwritten.
async fn judged(meta: &Arc<MetaMcp>, request: Value) -> OutboundFrame {
    let reads = meta.stdio_reads();
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let client = StdioClient {
        session_id: SESSION,
        channel: &crate::gateway::input_bridge::NoClientChannel,
        handshake_capabilities: crate::protocol::meta::Declared::NONE,
        tasks: None,
        serving: crate::gateway::server::stdio_single::ModernServing::Disabled,
        discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
        sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
    };
    let ((answer, staged), hidden) = crate::gateway::outbound::read_scoped(
        reads.guard(),
        Box::pin(Gateway::dispatch_single_staged(
            meta,
            &crate::gateway::authz::default_line(meta),
            &mtls,
            request.clone(),
            client,
        )),
    )
    .await;
    let answer = answer.expect("a request is answered");
    let frame = Gateway::judge_and_commit(
        meta,
        &reads,
        SESSION,
        (answer, request.get("params"), hidden.as_ref()),
        staged,
    )
    .await;
    assert!(frame.delivers_result(), "base: the chain is delivered");
    frame
}

/// r3: judged under `off`, written under `block`: the snapshot is kept, so
/// after the live receipt lapses a replay still records and bob is refused.
/// Mutant killed: m6 (the synchronous capture keeping the off gate).
#[tokio::test]
async fn r3_off_at_judge_block_at_write_keeps_the_snapshot() {
    let (meta, firewall, calls) = stdio_meta(None);
    publish(&meta, CollusionAction::Off);
    let original = judged(&meta, chain(1)).await;
    publish(&meta, CollusionAction::Block);
    original.stdio_written();
    assert!(relayed_by_bob(&firewall, PROSE), "base: the write recorded");
    lapse(&firewall);
    assert!(
        !relayed_by_bob(&firewall, PROSE),
        "premise: the live receipt lapsed"
    );
    let replay = judged(&meta, chain(2)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "premise: served from the retained answer"
    );
    replay.stdio_written();
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the replay renewed the receipt"
    );
}

/// r4: a retry that overtakes the unwritten original, written under
/// `block`, records from the snapshot captured at judge under `off`.
/// Mutants killed: m5 (capture moved to the write), m6.
#[tokio::test]
async fn r4_a_retry_overtaking_the_unwritten_original_records() {
    let (meta, firewall, calls) = stdio_meta(None);
    publish(&meta, CollusionAction::Off);
    let original = judged(&meta, chain(1)).await;
    publish(&meta, CollusionAction::Block);
    let retry = judged(&meta, chain(2)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "premise: the retry was a replay"
    );
    retry.stdio_written();
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the retry's write recorded"
    );
    drop(original);
}

/// r5: the original dropped unwritten (its session ended), then replayed
/// under `block`: the pending snapshot was held, so the replay records.
/// Mutants killed: m5, m6.
#[tokio::test]
async fn r5_dropped_then_replayed_under_block_records() {
    let (meta, firewall, _) = stdio_meta(None);
    publish(&meta, CollusionAction::Off);
    drop(judged(&meta, chain(1)).await);
    publish(&meta, CollusionAction::Block);
    judged(&meta, chain(2)).await.stdio_written();
    assert!(relayed_by_bob(&firewall, PROSE), "the replay recorded");
}

/// r6: the original dropped unwritten, then replayed under `off`: that
/// write was the only delivery and it was under `off`, so the snapshot is
/// gone; a later replay under `block` has nothing to record.
/// Mutant killed: m7 (no removal after an off write).
#[tokio::test]
async fn r6_dropped_then_replayed_under_off_discards() {
    let (meta, firewall, _) = stdio_meta(None);
    publish(&meta, CollusionAction::Off);
    drop(judged(&meta, chain(1)).await);
    judged(&meta, chain(2)).await.stdio_written();
    assert_eq!(
        firewall.replay_entries_for_test(),
        0,
        "nothing delivered under off is held"
    );
    publish(&meta, CollusionAction::Block);
    judged(&meta, chain(3)).await.stdio_written();
    assert!(
        !relayed_by_bob(&firewall, PROSE),
        "no snapshot was left to record"
    );
}

/// r12: when settlement makes the answer replayable, its snapshot already
/// exists, so a retry arriving at that moment finds it.
/// Mutant killed: m11 (capture after settlement).
#[tokio::test(flavor = "current_thread")]
async fn r12_the_snapshot_exists_when_the_answer_becomes_replayable() {
    let (meta, firewall, _) = stdio_meta(None);
    let seen = Rc::new(Cell::new(None));
    let (at, fw) = (Rc::clone(&seen), Arc::clone(&firewall));
    let before = crate::gateway::meta_mcp::admission::publish_hook::reached();
    crate::gateway::meta_mcp::admission::publish_hook::arm(move || {
        at.set(Some(fw.replay_entries_for_test()));
    });
    let original = judged(&meta, chain(1)).await;
    assert_eq!(
        crate::gateway::meta_mcp::admission::publish_hook::reached(),
        before + 1,
        "premise: settlement published the answer once"
    );
    assert_eq!(
        seen.get(),
        Some(1),
        "the snapshot existed when the answer became replayable"
    );
    original.stdio_written();
}
