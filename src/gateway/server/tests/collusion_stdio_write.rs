// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Over stdio a result's relay receipts record when stdout takes its frame,
//! under the generation current at that write, not when the answer is
//! judged. Each row judges an answer, changes the published collusion
//! action while the frame is unwritten, then writes it the way the stdout
//! writer does (`OutboundFrame::stdio_written`, after `stdout` took it).
//! The relay witness here is the firewall's own `block` generation; only
//! the recording side reads the published one.

use super::*;
use crate::gateway::server::Gateway;

/// Publish `action` as the meta's live collusion action.
fn publish(meta: &MetaMcp, action: CollusionAction) {
    let live = meta.live_config().expect("the fixture seeds a live config");
    let mut config = (*live.get()).clone();
    config.security.firewall.collusion.action = action;
    live.set(config);
}

/// One operator read of `text`, judged and handed back unwritten.
async fn judged_unwritten(
    meta: &Arc<MetaMcp>,
    reads: &crate::gateway::outbound::StdioReads,
    cell: &parking_lot::Mutex<String>,
    text: &str,
) -> crate::gateway::outbound::OutboundFrame {
    let (value, hidden, params, staged) = staged_read(meta, reads, cell, text.to_owned()).await;
    let frame = Gateway::judge_and_commit(
        meta,
        reads,
        SESSION,
        (value, params.as_ref(), hidden.as_ref()),
        staged,
    )
    .await;
    assert!(frame.delivers_result(), "base: the read is delivered");
    frame
}

/// s1: judged under `off`, written after `block` is published: recorded,
/// so an HTTP caller relaying the text is refused.
/// Mutant killed: m2 (the generation read when the frame is queued).
#[tokio::test]
async fn s1_a_stdio_answer_records_under_the_generation_at_its_write() {
    let (meta, firewall, cell) = judged_stdio(None);
    let reads = meta.stdio_reads();
    let note = tenant_note("t1", PROSE);
    publish(&meta, CollusionAction::Off);
    let frame = judged_unwritten(&meta, &reads, &cell, &note).await;
    publish(&meta, CollusionAction::Block);
    assert!(
        !http_relay_refused(&firewall, &note),
        "base: nothing is recorded before the write"
    );
    frame.stdio_written();
    assert!(
        http_relay_refused(&firewall, &note),
        "written under block, the answer is recorded"
    );
}

/// s2: a frame dropped unwritten (the session ended with it queued)
/// records nothing.
/// Mutant killed: a commit at judge time.
#[tokio::test]
async fn s2_a_stdio_frame_dropped_unwritten_records_nothing() {
    let (meta, firewall, cell) = judged_stdio(None);
    let reads = meta.stdio_reads();
    let note = tenant_note("t1", PROSE);
    let frame = judged_unwritten(&meta, &reads, &cell, &note).await;
    drop(frame);
    assert!(
        !http_relay_refused(&firewall, &note),
        "a queued frame delivered nothing"
    );
}

/// f1: judged under `block`, written after `off` is published: the write
/// decides, so nothing is recorded.
/// Mutant killed: m2 (the generation read when the frame is queued).
#[tokio::test]
async fn f1_a_block_to_off_flip_before_the_write_records_nothing() {
    let (meta, firewall, cell) = judged_stdio(None);
    let reads = meta.stdio_reads();
    let note = tenant_note("t1", PROSE);
    let frame = judged_unwritten(&meta, &reads, &cell, &note).await;
    publish(&meta, CollusionAction::Off);
    frame.stdio_written();
    assert!(
        !http_relay_refused(&firewall, &note),
        "written under off, nothing is recorded"
    );
}

/// The frames of a two-item batch of operator reads, `first` then
/// `second`, judged and unwritten.
async fn batch_unwritten(
    meta: &Arc<MetaMcp>,
    reads: &crate::gateway::outbound::StdioReads,
    cell: &parking_lot::Mutex<String>,
    first: &str,
) -> Vec<crate::gateway::outbound::OutboundFrame> {
    *cell.lock() = first.to_owned();
    let read = |id: u64| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
               "params": {"name": "gateway_invoke",
                          "arguments": {"server": "alpha", "tool": "read", "arguments": {}}}})
    };
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    Gateway::dispatch_batch_read(
        meta,
        &crate::gateway::authz::default_line(meta),
        &mtls,
        json!([read(1), read(2)]),
        (
            SESSION,
            crate::gateway::server::stdio_single::InputSanitizing::Off,
            crate::gateway::server::stdio_single::ModernServing::Disabled,
        ),
        reads,
    )
    .await
}

/// s3: each batch item records when the batch frame is written, under the
/// generation then.
/// Mutant killed: m1 (batch items not committed at the write).
#[tokio::test]
async fn s3_batch_items_record_at_the_batch_write() {
    let (meta, firewall, cell) = judged_stdio(None);
    let reads = meta.stdio_reads();
    let note = tenant_note("t1", PROSE);
    publish(&meta, CollusionAction::Off);
    let frames = batch_unwritten(&meta, &reads, &cell, &note).await;
    assert!(
        frames
            .iter()
            .all(crate::gateway::outbound::OutboundFrame::delivers_result),
        "base: both reads are delivered"
    );
    publish(&meta, CollusionAction::Block);
    crate::gateway::outbound::StdioReads::batch_of(frames).stdio_written();
    assert!(
        http_relay_refused(&firewall, &note),
        "the items were recorded at the batch write"
    );
}

/// s4: a batch frame written twice (a sink retrying its bookkeeping)
/// records each item once: the second write finds every commit taken. The
/// detector's debug assertion against a digest recorded twice would fire.
/// Mutant killed: an item commit that is not taken out of its slot.
#[tokio::test]
async fn s4_a_batch_records_each_item_once() {
    let (meta, firewall, cell) = judged_stdio(None);
    let reads = meta.stdio_reads();
    let note = tenant_note("t1", PROSE);
    let frames = batch_unwritten(&meta, &reads, &cell, &note).await;
    let batch = crate::gateway::outbound::StdioReads::batch_of(frames);
    batch.stdio_written();
    batch.stdio_written();
    assert!(
        http_relay_refused(&firewall, &note),
        "recorded once, at the first write"
    );
}

/// r24: a keyed chain whose delivery record fails (fail-closed audit) is
/// replaced by the audit refusal and not retained, so no replay snapshot
/// survives it: the pending capture is never taken for an answer that does
/// not deliver, and settlement retains nothing to discard. A pin: an
/// earlier capture would still be discarded when settlement retains nothing
/// (E1), which r17 kills at the store.
#[tokio::test]
async fn r24_an_audit_failure_leaves_no_replay_snapshot() {
    let (log, _dir) = failing_audit();
    let (meta, firewall, cell) = judged_stdio(Some(log));
    let reads = meta.stdio_reads();
    *cell.lock() = tenant_note("t1", PROSE);
    let request = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "gateway_execute",
                   "arguments": {"chain": [{"tool": "alpha:read", "arguments": {}}]},
                   "_meta": {"io.mcp-gateway/idempotency-key": "r24"}}});
    let (value, hidden, params, staged) = staged_request(&meta, &reads, request).await;
    let frame = Gateway::judge_and_commit(
        &meta,
        &reads,
        SESSION,
        (value, params.as_ref(), hidden.as_ref()),
        staged,
    )
    .await;
    assert!(
        !frame.delivers_result(),
        "base: the failed delivery record replaces the answer"
    );
    frame.stdio_written();
    assert_eq!(
        firewall.replay_entries_for_test(),
        0,
        "an audit-withheld answer leaves no replay snapshot"
    );
}

/// s1w: s1 through the real stdout writer. The frame is queued to
/// `run_stdout_writer` over a 64-byte pipe nobody reads yet, so stdout
/// cannot take it; `block` is published while it waits; the client then
/// reads the line and the writer finishes. Nothing is recorded before
/// stdout took the frame, and it is recorded after.
/// Mutant killed: m2 (the generation read when the frame is queued).
#[tokio::test]
async fn s1w_the_stdout_writer_records_when_stdout_takes_the_frame() {
    use tokio::io::AsyncBufReadExt as _;
    let (meta, firewall, cell) = judged_stdio(None);
    let reads = meta.stdio_reads();
    let note = tenant_note("t1", PROSE);
    publish(&meta, CollusionAction::Off);
    let frame = judged_unwritten(&meta, &reads, &cell, &note).await;
    let (sink, client) = tokio::io::duplex(64);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let writer = tokio::spawn(Gateway::run_stdout_writer(sink, rx));
    tx.send(frame).await.expect("the writer takes the queue");
    tokio::task::yield_now().await;
    publish(&meta, CollusionAction::Block);
    assert!(
        !http_relay_refused(&firewall, &note),
        "base: nothing is recorded while stdout has not taken the frame"
    );
    let mut line = String::new();
    let mut reader = tokio::io::BufReader::new(client);
    tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut line))
        .await
        .expect("the frame is written within 30 s")
        .expect("read the frame");
    assert!(
        line.contains("orchard ledger"),
        "base: the answer was written"
    );
    drop(tx);
    tokio::time::timeout(Duration::from_secs(30), writer)
        .await
        .expect("the writer ends once its queue closes")
        .expect("the writer task");
    assert!(
        http_relay_refused(&firewall, &note),
        "taken by stdout under block, the answer is recorded"
    );
}
