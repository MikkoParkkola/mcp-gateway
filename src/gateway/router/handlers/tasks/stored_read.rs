// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The account pre-pass of a stored task read on HTTP (MIK-8392): who the
//! read is judged as, and filling its account outcomes before the route's
//! synchronous delivery check reads them.

use std::sync::Arc;

use serde_json::Value;

use super::RecoveryCaller;
use crate::gateway::router::AppState;

/// The caller a stored read is judged as, built as [`with_policy_caller`](super::with_policy_caller)
/// builds its context: the verified identity, and the credential's provenance.
pub(super) fn stored_read_caller<'a>(
    caller: &RecoveryCaller<'a>,
) -> crate::identity_propagation::CallerProof<'a> {
    crate::identity_propagation::CallerProof::new(
        caller.verified_identity,
        crate::identity_propagation::CallerProvenance::classify(
            caller.client.map(|client| client.principal.as_str()),
        ),
    )
}

/// Fill the request's account outcomes for the named task's recorded
/// targets (MIK-8392). An owner-scoped read: a task this caller does not own,
/// or that is absent, is left to the route's own answer.
pub(super) async fn prepare_stored_read(
    state: &Arc<AppState>,
    owner: &str,
    params: Option<&Value>,
    caller: &RecoveryCaller<'_>,
) {
    let Some(task_id) = crate::gateway::task_route::task_id_param(params) else {
        return;
    };
    if let Ok(stored) = state.tasks.get(owner, task_id) {
        state
            .meta_mcp
            .prepare_stored_read(&stored, stored_read_caller(caller))
            .await;
    }
}
