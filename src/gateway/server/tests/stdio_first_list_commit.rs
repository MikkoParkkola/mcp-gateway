// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9309 R14 (C1): the first-list flag is committed by the enqueue
//! itself, so once a first list's answer is queued no later list can read
//! the flag unset and wait again. Checked at the enqueue, with no timing:
//! the moment `send_unless_cancelled` returns, the flag must be set.

use serde_json::json;
use tokio::sync::{mpsc, oneshot};

use super::super::first_list_wait::{FirstList, mark_waited_for_test};
use super::super::stdio_dispatches::StdioDispatches;
use crate::gateway::outbound::OutboundFrame;
use crate::protocol::RequestId;

#[tokio::test]
async fn r14_a_queued_first_answer_has_committed_the_flag() {
    let dispatches = StdioDispatches::default();
    let (writer, mut stdout) = mpsc::channel::<OutboundFrame>(4);
    let first = FirstList::default();
    let probe = first.clone();
    let cancelled = dispatches.cancelled();
    let (report, reported) = oneshot::channel::<bool>();
    let id: RequestId = serde_json::from_value(json!(2)).expect("a request id");
    tokio::spawn(first.scope(async move {
        mark_waited_for_test();
        let permit = writer.reserve().await.expect("the writer is open");
        cancelled.send_unless_cancelled(
            Some(&id),
            permit,
            OutboundFrame::gateway_stdio(json!({"jsonrpc": "2.0", "id": 2, "result": {}})),
        );
        // What a later list would read now, before this task goes on.
        report
            .send(probe.answered_for_test())
            .expect("the row awaits the report");
    }));
    let committed = reported.await.expect("the dispatch reported");
    assert!(
        stdout.recv().await.is_some(),
        "premise: the answer was queued"
    );
    assert!(
        committed,
        "the answer was queued while the first-list flag was still unset"
    );
}

/// R14b: a send outside any ticket (a batch, a direct dispatch) still queues
/// its answer, and commits nothing.
#[tokio::test]
async fn r14b_a_send_outside_a_ticket_queues_and_commits_nothing() {
    let dispatches = StdioDispatches::default();
    let (writer, mut stdout) = mpsc::channel::<OutboundFrame>(4);
    let cancelled = dispatches.cancelled();
    let id: RequestId = serde_json::from_value(json!(5)).expect("a request id");
    tokio::spawn(async move {
        let permit = writer.reserve().await.expect("the writer is open");
        cancelled.send_unless_cancelled(
            Some(&id),
            permit,
            OutboundFrame::gateway_stdio(json!({"jsonrpc": "2.0", "id": 5, "result": {}})),
        );
    })
    .await
    .expect("the send ran outside a ticket");
    assert!(stdout.recv().await.is_some(), "the answer was not queued");
}
