// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The deferred task's secret check: a query polls, and its answer is
//! settled, only while what the dispatch injected is still what the backend
//! injects now, in this process. Both settlement sites (the worker's follow
//! and the owner's recovery read) take their answers from the query, so the
//! check runs here, before the poll and again on its terminal answer.

use crate::backend::Backend;
use crate::error::rpc_codes::INTERNAL_ERROR;
use crate::gateway::task_service::{UpstreamAnswer, UpstreamHandle};
use crate::protocol::JsonRpcError;

/// What a withheld task says, and nothing of its result.
pub(crate) const WITHHELD: &str =
    "the backend's injected credential changed since this task was dispatched";

/// `None` when the task may be polled or settled: its stored fingerprint
/// equals what the backend's rules resolve to now, and the values the
/// dispatch sent are renewed in the backend's redaction set, so an echo of
/// an unchanged secret is still removed. Otherwise the withheld answer: the
/// gateway's own words, settled as the task's end, never retried.
pub(super) fn withheld(backend: &Backend, handle: &UpstreamHandle) -> Option<UpstreamAnswer> {
    if backend.vouch_and_renew(
        &handle.tool,
        &handle.arguments,
        handle.fingerprint.as_deref(),
    ) {
        return None;
    }
    tracing::warn!(
        backend = %handle.backend,
        "a deferred upstream task was withheld: the backend's injected credential changed since its dispatch"
    );
    Some(UpstreamAnswer::Substituted(JsonRpcError {
        code: INTERNAL_ERROR,
        message: WITHHELD.into(),
        data: None,
    }))
}

#[cfg(test)]
#[path = "upstream_secrets_tests.rs"]
mod tests;
