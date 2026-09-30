// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.PARENT.6 (test 4, end to end): a task whose backend result claims
//! `"cacheScope": "public"` runs to completion, and `tasks/get` over the router
//! returns the retained result as `private`.
//!
//! The backend tool is surfaced, so the worker's dispatch returns the backend's
//! envelope as it came, top-level `cacheScope` included; through
//! `gateway_invoke` the envelope is wrapped into text and the key would never
//! reach the retained result.

use std::sync::Arc;

use serde_json::{Value, json};

use super::http::{keyed, modern, post_against, public_mcp_auth, state_from_with, task_id_of};
use crate::fixture::{self, CountedBackend};
use mcp_gateway::transport::Transport;

/// `tasks/get` as `key-a` until the task is terminal, bounded by [`fixture::BOUND`].
async fn poll_terminal(
    state: &Arc<mcp_gateway::gateway::test_helpers::AppState>,
    id: &str,
) -> Value {
    let mut last = Value::Null;
    tokio::time::timeout(fixture::BOUND, async {
        let mut request_id = 80;
        loop {
            let (_, body) = post_against(
                Arc::clone(state),
                "key-a",
                modern(request_id, "tasks/get", json!({ "taskId": id }), true),
            )
            .await;
            request_id += 1;
            if let Some("completed" | "failed" | "cancelled") =
                body.pointer("/result/status").and_then(Value::as_str)
            {
                return body;
            }
            last = body;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("'{id}' never reached a terminal status: {last}"))
}

#[tokio::test]
async fn tasks_get_returns_a_retained_public_claim_as_private() {
    // The fixture really claims `public`: asked on a separate instance so the
    // counted backend under test still sees exactly one dispatch.
    let probe = CountedBackend::claiming_public();
    let raw = Transport::request(probe.as_ref(), "tools/call", None)
        .await
        .expect("the fixture answers");
    assert_eq!(raw.result.expect("a result")["cacheScope"], "public");

    let fx = state_from_with(public_mcp_auth(), CountedBackend::claiming_public()).await;
    let create = keyed(
        modern(
            70,
            "tools/call",
            json!({ "name": fixture::TOOL, "arguments": {}, "task": {} }),
            true,
        ),
        "mik-7211-p6-task-scope",
    );
    let (_, created) = post_against(Arc::clone(&fx.state), "key-a", create).await;
    let task_id = task_id_of(&created);
    fx.backend.wait_for_calls(1).await;

    let done = poll_terminal(&fx.state, &task_id).await;

    assert_eq!(
        done.pointer("/result/status"),
        Some(&json!("completed")),
        "{done}"
    );
    assert_eq!(
        done.pointer("/result/result/structuredContent/marker"),
        Some(&json!(fixture::MARKER)),
        "the retained result is the backend's own: {done}"
    );
    assert_eq!(
        done.pointer("/result/result/cacheScope"),
        Some(&json!("private")),
        "{done}"
    );
}
