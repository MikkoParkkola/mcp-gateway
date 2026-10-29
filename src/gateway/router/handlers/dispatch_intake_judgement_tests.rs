// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 PERF.11: the intake judges an anonymous task submit without
//! allocating. With authentication off, a `tools/call` carrying `params.task`
//! is left to the task path right after one lookup, so the call's allocations
//! are that lookup's. A JSON-pointer lookup allocated per segment.

use serde_json::json;

use super::run::intake_judgement;
use crate::gateway::alloc_meter::measure;
use crate::gateway::router::tests::test_router_app_state;

/// Mutant: the `params.task` lookup taken by `pointer` again.
#[tokio::test]
async fn an_anonymous_task_submit_is_judged_without_allocating() {
    let (state, _store) = test_router_app_state().await;
    assert!(
        !state.live_config.generation().auth().enabled,
        "premise: authentication is off"
    );
    let request = json!({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "gateway_invoke", "task": {"ttl": 60000}, "arguments": {}},
    });
    let task_caller = super::super::tasks::owner::TaskCaller {
        verified_identity: None,
        agent: None,
        subject: None,
        cert: None,
        client: None,
    };
    let owners = super::super::tasks::owner::TaskOwners {
        task: String::new(),
        events: String::new(),
        admission: String::new(),
    };
    let (verdict, measured) = measure(|| intake_judgement(&state, &request, &task_caller, &owners));
    assert!(
        verdict.is_none(),
        "a task submit with auth off is left to the task path"
    );
    assert_eq!(
        measured.calls, 0,
        "judging an anonymous task submit allocated {} times ({} B) (MIK-8014 PERF.11)",
        measured.calls, measured.bytes
    );
}
