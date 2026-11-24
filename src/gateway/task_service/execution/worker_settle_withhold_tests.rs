// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settlement commits no relay receipt for a row that withholds its outcome:
//! no reader is ever served that output, so nothing of it was relayed. The
//! vouched twins, completed and failed by the peer, still commit one.

use serde_json::json;

use super::stored_backend_output;
use crate::gateway::task_service::{CommittedTask, ErrorAuthor, Vouching};
use crate::protocol::JsonRpcError;
use crate::protocol::tasks::Task;

fn stored(task: Task, vouching: Vouching, error_author: Option<ErrorAuthor>) -> CommittedTask {
    CommittedTask {
        task,
        revision: 1,
        targets: Vec::new(),
        targets_recorded: true,
        output_free: false,
        error_author,
        owner_digest: Box::default(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
        vouching,
        replay_snapshot: None,
    }
}

#[test]
fn a_withheld_row_commits_no_settlement_receipt() {
    for vouching in [Vouching::Vouched, Vouching::Unvouched] {
        let mut done = Task::create("gateway_invoke").expect("the clock reads after 1970");
        done.complete(&json!({"content": [{"type": "text", "text": "answer"}], "isError": false}))
            .expect("a live task completes");
        let mut failed = Task::create("gateway_invoke").expect("the clock reads after 1970");
        failed
            .fail(&JsonRpcError {
                code: -32001,
                message: "the peer's own error".to_owned(),
                data: None,
            })
            .expect("a live task fails");
        let expected = vouching == Vouching::Vouched;
        assert_eq!(
            stored_backend_output(&stored(done, vouching, None)),
            expected,
            "{vouching:?} completed"
        );
        assert_eq!(
            stored_backend_output(&stored(failed, vouching, Some(ErrorAuthor::Peer))),
            expected,
            "{vouching:?} failed by the peer"
        );
    }
}
