// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The worker's hold on an upstream job's handle, from capture to the row's
//! one upstream cancel (MIK-7642): capture it, follow it, and when the capture
//! was refused, offer it to the cancel claim however the follow ended.

use std::sync::Arc;

use tokio::sync::watch;

use super::super::upstream::CancelSend;
use super::super::{TaskExecutor, UpstreamCapture};
use super::follow_handle;

/// Own one live upstream job: make its handle durable, follow it within a
/// bounded budget, and settle what it eventually says.
///
/// Order matters. The handle is made durable BEFORE anything else is done with
/// it — a row is recoverable only once its handle is on disk, and the window
/// between the peer's answer and that write stays `unknown`. A refusal there
/// does not stop the job, which is why the follow below still runs.
pub(super) async fn follow_upstream_job(
    executor: &Arc<TaskExecutor>,
    state: &crate::gateway::task_service::host::LiveHost,
    principal: &str,
    id: &str,
    revision: u64,
    dispatched: (
        crate::gateway::meta_mcp::upstream::DirectJob,
        String,
        crate::gateway::meta_mcp::invoke::relay::RelayKey<'_>,
    ),
    cancel_rx: &mut watch::Receiver<bool>,
) {
    let (job, handle, relay) = dispatched;
    let captured = capture_handle(executor, (principal, id, revision), &job, &handle).await;
    let followed = (&job, handle.clone(), relay, captured);
    follow_handle(
        executor,
        state,
        (principal, id, revision),
        followed,
        cancel_rx,
    )
    .await;
    // A refused capture (the row cancelled meanwhile, or a failed write) left
    // the handle held here as the only one. A cancel commits before it
    // signals, so the follow may have ended any way at all without seeing it:
    // offer the handle once, now. The claim is a no-op unless the row is
    // cancelled and unclaimed (MIK-7642).
    if !captured {
        cancel_held_upstream(executor, principal, id, &job, handle).await;
    }
}

/// Make `handle` durable, before anything else is done with it. A refusal
/// does not stop the job: it is followed either way, and once the follow ends
/// the held handle is offered to the row's one cancel claim
/// (`follow_upstream_job`; design r8 R8.4, the capture-side case).
async fn capture_handle(
    executor: &Arc<TaskExecutor>,
    (principal, id, revision): (&str, &str, u64),
    job: &crate::gateway::meta_mcp::upstream::DirectJob,
    handle: &str,
) -> bool {
    executor
        .notify_observer(super::super::CommitStage::BeforeCapture, id)
        .await;
    let capture = UpstreamCapture {
        backend: job.server.clone(),
        tool: job.tool.clone(),
        arguments: job.arguments.clone(),
        handle: handle.to_owned(),
    };
    executor
        .capture_upstream(principal, id, revision, capture)
        .await
}

/// Offer a handle this worker holds, for a row cancelled under it, to the
/// row's one durable cancel claim; send it here if this worker wins. `false`
/// when the row is not cancelled, another sender claimed, or nothing could be
/// read.
pub(super) async fn cancel_held_upstream(
    executor: &Arc<TaskExecutor>,
    principal: &str,
    id: &str,
    job: &crate::gateway::meta_mcp::upstream::DirectJob,
    handle: String,
) -> bool {
    let Ok(owner) = executor.service.owner(principal) else {
        return false;
    };
    let Some(offer) = executor.offered_descriptor(owner.as_digest(), id, job, handle) else {
        return false;
    };
    executor
        .cancel_upstream_once(owner.as_digest(), id, Some(offer), CancelSend::Inline)
        .await
}
