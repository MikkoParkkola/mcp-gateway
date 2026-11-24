// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T4: a continuation this gateway will not redeem is a single-use token the
//! replay guard turned away. Its refusal notes `replay_guard`, whatever the
//! cause, and is answered with the one client sentence and -32602.

use crate::gateway::meta_mcp::invoke::audit::{take_refusal_kind, with_route_scope};
use crate::gateway::meta_mcp::invoke::continuation::rejected_continuation;
use crate::protocol::continuation::ContinuationError;

#[tokio::test]
async fn t4_an_unredeemable_continuation_notes_replay_guard() {
    for reason in [ContinuationError::NotAuthentic, ContinuationError::Expired] {
        let (error, kind) =
            with_route_scope(async { (rejected_continuation(&reason), take_refusal_kind()) }).await;
        assert_eq!(error.to_rpc_code(), -32602, "{reason:?}: {error}");
        assert_eq!(
            serde_json::to_value(kind).expect("a kind serializes"),
            serde_json::json!("replay_guard"),
            "{reason:?}"
        );
    }
}
