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

/// Audit, attribute and settle a followed job's outcome; `peer` is the peer's
/// own error when the job failed with one. The error is the peer's only when
/// the committed error is that error unchanged by every screen and by the
/// audit, which can replace any outcome (MIK-7887.RECEIPT.1). Only then is its
/// receipt staged in place of the working stub; otherwise the stub is dropped.
pub(super) async fn settle_followed(
    executor: &Arc<TaskExecutor>,
    state: &crate::gateway::task_service::host::LiveHost,
    followed: &FollowedJob<'_>,
    (event, peer): (TaskTransition, Option<crate::protocol::JsonRpcError>),
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
    let event = (state.meta_mcp())
        .audit_settlement(task, event, notes, followed.principal)
        .await;
    let author = error_author(&event, peer.as_ref());
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
        )
        .await;
    state.meta_mcp().commit_staged_relay(stored);
}

/// `Peer` only when `event` fails with exactly the peer's own error.
pub(super) fn error_author(
    event: &TaskTransition,
    peer: Option<&crate::protocol::JsonRpcError>,
) -> ErrorAuthor {
    let same = |a: &crate::protocol::JsonRpcError, b: &crate::protocol::JsonRpcError| {
        serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
    };
    match (event, peer) {
        (TaskTransition::Fail(error), Some(peer)) if same(error, peer) => ErrorAuthor::Peer,
        _ => ErrorAuthor::Gateway,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::JsonRpcError;
    use serde_json::json;

    fn peer() -> JsonRpcError {
        JsonRpcError {
            code: -32042,
            message: "the peer's words".to_owned(),
            data: Some(json!({"row": 7})),
        }
    }

    /// MIK-7887.RECEIPT.1: only the peer's own error, unchanged by every
    /// screen and by the audit, is the peer's. A rewrite, a replacement, any
    /// other outcome, or no peer error at all is the gateway's.
    #[test]
    fn only_an_unchanged_peer_error_is_the_peers() {
        let unchanged = TaskTransition::Fail(peer());
        assert_eq!(error_author(&unchanged, Some(&peer())), ErrorAuthor::Peer);

        let mut rewritten = peer();
        rewritten.message = "withheld by the gateway".to_owned();
        let rewritten = TaskTransition::Fail(rewritten);
        assert_eq!(
            error_author(&rewritten, Some(&peer())),
            ErrorAuthor::Gateway
        );

        let mut data_dropped = peer();
        data_dropped.data = None;
        let data_dropped = TaskTransition::Fail(data_dropped);
        assert_eq!(
            error_author(&data_dropped, Some(&peer())),
            ErrorAuthor::Gateway
        );

        let completed = TaskTransition::Complete(json!({"content": []}));
        assert_eq!(
            error_author(&completed, Some(&peer())),
            ErrorAuthor::Gateway
        );

        assert_eq!(error_author(&unchanged, None), ErrorAuthor::Gateway);
    }
}
