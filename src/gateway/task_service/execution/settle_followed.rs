// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7887.RECEIPT.1/.4: a followed upstream job's settlement and the relay
//! receipt it commits: built from what is stored, attributed to the peer only
//! when the committed error is the peer's own.

use std::sync::Arc;

use super::TaskExecutor;
use crate::gateway::meta_mcp::invoke::relay::{AnswerShape, GatewayStamps};
use crate::gateway::task_service::ErrorAuthor;
use crate::protocol::tasks::TaskTransition;

/// Stage a followed upstream result for `relay` under `target`, as stored: the
/// backend's own value, never a `gateway_invoke` wrapper (MIK-7887.RECEIPT.4).
pub(super) fn stage_followed_result(
    state: &crate::gateway::task_service::host::LiveHost,
    relay: crate::gateway::meta_mcp::invoke::relay::RelayKey<'_>,
    target: (&str, &str),
    stored: &serde_json::Value,
) {
    state
        .meta_mcp()
        .stage_upstream_result(relay, target, stored);
    rebuild_task_receipt(state, stored, AnswerShape::Literal);
}

/// MIK-7887.RECEIPT.4: a task's receipt describes its result as stored and
/// served: `stored` has settlement's marker strip applied, and the rebuild
/// leaves out the scope the serializer clamps and the gateway's chain.
pub(super) fn rebuild_task_receipt(
    state: &crate::gateway::task_service::host::LiveHost,
    stored: &serde_json::Value,
    shape: AnswerShape,
) {
    state
        .meta_mcp()
        .rebuild_receipt_from_final(Some(stored), GatewayStamps::Legacy, shape);
}

/// The followed job a settlement belongs to.
pub(super) struct FollowedJob<'a> {
    pub(super) job: &'a crate::gateway::meta_mcp::upstream::DirectJob,
    pub(super) relay: crate::gateway::meta_mcp::invoke::relay::RelayKey<'a>,
    pub(super) id: &'a str,
    pub(super) principal: &'a str,
    pub(super) revision: u64,
}

/// Audit, attribute and settle a followed job's outcome. `screened` says who
/// wrote a `Fail` event's error before the audit; the audit can still replace
/// the outcome with the gateway's own refusal, and says so. The error is the
/// peer's only when both left it as the peer wrote it (MIK-7887.RECEIPT.1).
/// Only then is its receipt staged in place of the working stub; otherwise
/// the stub is dropped.
pub(super) async fn settle_followed(
    executor: &Arc<TaskExecutor>,
    state: &crate::gateway::task_service::host::LiveHost,
    followed: &FollowedJob<'_>,
    ((event, screened), writes): (
        (TaskTransition, ErrorAuthor),
        crate::gateway::gateway_writes::WriteRecord,
    ),
    notes: &crate::gateway::meta_mcp::invoke::audit::DispatchNotes,
) {
    let (job, id) = (followed.job, followed.id);
    // Recorded before the commit, still under the lease, as a live call is
    // recorded before its result is stored.
    let task = crate::gateway::meta_mcp::invoke::audit::SettledTask {
        server: &job.server,
        tool: &job.tool,
        id,
    };
    let (event, kept) = (state.meta_mcp())
        .audit_settlement_kept(task, event, notes, followed.principal)
        .await;
    let author = committed_author(screened, kept);
    if let TaskTransition::Fail(error) = &event {
        let target = (job.server.as_str(), job.tool.as_str());
        (state.meta_mcp()).stage_followed_error(followed.relay, target, error, author);
    }
    let stored = executor
        .settle_cas_by(
            followed.principal,
            id,
            followed.revision,
            (event, None),
            author,
            writes,
        )
        .await;
    state.meta_mcp().commit_staged_relay(stored);
}

/// A peer's failure screened by the reader's error policy, with the screen's
/// own verdict on who wrote what it returns.
pub(super) fn screened_peer_failure(
    state: &crate::gateway::task_service::host::LiveHost,
    job: &crate::gateway::meta_mcp::upstream::DirectJob,
    id: &str,
    error: crate::protocol::JsonRpcError,
) -> (TaskTransition, ErrorAuthor) {
    let peer = super::settlement::strip_http_status(error);
    let (screened, author) =
        (state.meta_mcp()).recover_task_error_with(&job.server, &job.tool, None, id, peer);
    (TaskTransition::Fail(screened), author)
}

/// Who wrote a committed error: the screen's verdict, unless the audit
/// replaced the outcome, which makes it the gateway's.
pub(super) fn committed_author(screened: ErrorAuthor, kept: bool) -> ErrorAuthor {
    if kept { screened } else { ErrorAuthor::Gateway }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MIK-7887.RECEIPT.1: an error is the peer's only when the screen passed
    /// it and the audit kept it.
    #[test]
    fn only_a_screened_and_kept_peer_error_is_the_peers() {
        assert_eq!(committed_author(ErrorAuthor::Peer, true), ErrorAuthor::Peer);
        assert_eq!(
            committed_author(ErrorAuthor::Peer, false),
            ErrorAuthor::Gateway
        );
        assert_eq!(
            committed_author(ErrorAuthor::Gateway, true),
            ErrorAuthor::Gateway
        );
        assert_eq!(
            committed_author(ErrorAuthor::Gateway, false),
            ErrorAuthor::Gateway
        );
    }
}
