// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8407: a followed upstream job whose handle the store refused still
//! settles the bindings its dispatch ran under.
//!
//! The peer answers the task-augmented call with a handle one byte over what
//! `mark_upstream` accepts, so the capture is refused and nothing about the
//! dispatch is on the row before the follow settles it. Only the settlement
//! can then write the bindings.
use super::super::*;
use super::support::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::gateway::task_service::{
    CancelDelivery, UpstreamAnswer, UpstreamHandle, UpstreamRecovery,
};

/// One byte over `MAX_UPSTREAM_HANDLE_BYTES` (512).
fn oversized_handle() -> String {
    "h".repeat(513)
}

/// Answers a task-augmented `tools/call` with the oversized handle.
struct Peer;

#[async_trait::async_trait]
impl Transport for Peer {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let body = match method {
            "initialize" => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock", "version": "0" }
            }),
            "tools/list" => json!({
                "tools": [{ "name": TOOL, "description": "d", "inputSchema": { "type": "object" } }]
            }),
            _ => json!({}),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), body))
    }

    async fn request_with_task_capability(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "tools/call" {
            let handle = json!({
                "resultType": "task",
                "taskId": oversized_handle(),
                "status": "working"
            });
            return Ok(JsonRpcResponse::success(RequestId::Number(1), handle));
        }
        self.request(method, params).await
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Claims the fixture backend, answers the follow with a completed result,
/// and counts the queries that named the oversized handle.
struct Recovery(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl UpstreamRecovery for Recovery {
    async fn cancel(&self, _handle: &UpstreamHandle, _deadline: Duration) -> CancelDelivery {
        CancelDelivery::Confirmed
    }

    async fn claims(&self, backend: &str) -> bool {
        backend == BACKEND
    }

    async fn query(&self, handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        if handle.handle == oversized_handle() {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        UpstreamAnswer::Completed(json!({ "content": [{ "type": "text", "text": "done" }] }))
    }
}

/// Mutant: `settle_followed` settles an empty binding list (the round-2
/// defect: a refused capture lost the bindings).
#[tokio::test]
async fn a_refused_capture_still_settles_the_dispatch_bindings() {
    let (state, _store) = fixture_state(&two_principal_auth()).await;
    let backend = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Peer));
    std::assert!(state.backends.register(backend));
    let followed = Arc::new(AtomicUsize::new(0));
    std::assert!(
        state
            .task_executor
            .install_recovery(Arc::new(Recovery(Arc::clone(&followed))))
    );

    let created = post(
        &state,
        "key-a",
        task_invoke(1, "refused-capture", json!({})),
    )
    .await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    // Settled by the follow (the only caller of `settle_followed`): the
    // peer was queried with the refused handle, and the row holds the
    // follow's answer, not the submission's working stub.
    std::assert!(
        followed.load(Ordering::SeqCst) >= 1,
        "the follow never queried the held handle"
    );
    std::assert_eq!(
        settled.pointer("/result/result/content/0/text"),
        Some(&json!("done")),
        "{settled}"
    );
    std::assert!(
        state
            .task_executor
            .durable_upstream_for_test(&task)
            .is_none(),
        "precondition: the oversized handle was refused, not made durable"
    );
    let (recorded, bindings) = state.task_executor.bindings_for_test(&task);
    std::assert!(recorded, "the row is at BINDING_VERSION");
    std::assert_eq!(
        bindings,
        vec![(BACKEND.to_owned(), TOOL.to_owned(), None)],
        "the settlement dropped the dispatch's bindings"
    );
}
