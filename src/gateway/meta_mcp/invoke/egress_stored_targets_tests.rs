// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored read is judged under the calls planned or attempted for the task,
//! whoever wrote its answer: a call the gateway refused before its backend
//! stays a target, so the response firewall judges a later read of it under
//! that call's own rules, exactly as before the gateway recorded itself as
//! the answer's author.

use serde_json::json;

use super::stored_targets;
use crate::gateway::task_service::{CommittedTask, ErrorAuthor, Target};
use crate::protocol::tasks::Task;

fn row(task: Task, author: Option<ErrorAuthor>) -> CommittedTask {
    CommittedTask {
        task,
        revision: 1,
        targets: vec![Target {
            server: "beta".into(),
            tool: "echo".into(),
        }],
        targets_recorded: true,
        output_free: false,
        error_author: author,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
    }
}

/// The refused call's planned target is the judged target, the same with
/// the gateway as the answer's author as without.
#[test]
fn a_refused_call_is_still_judged_under_its_planned_target() {
    let mut task = Task::create("gateway_invoke").expect("the clock reads after 1970");
    task.complete(&json!({"content": [{"type": "text", "text": "no such tool"}], "isError": true}))
        .expect("a live task completes");
    let authored = stored_targets(&row(task.clone(), Some(ErrorAuthor::Gateway)));
    let plain = stored_targets(&row(task, None));
    let pairs = |targets: &[crate::security::response_policy::ResponsePolicyTarget]| {
        targets
            .iter()
            .map(|t| (t.server.clone(), t.tool.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        pairs(&authored),
        vec![("beta".to_owned(), "echo".to_owned())]
    );
    assert_eq!(pairs(&authored), pairs(&plain));
}
