// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a refused or missed call's invocation record says: the code a gate
//! kept for it, and the dispatch's miss of a backend the gate found absent.

use serde_json::Value;

use crate::Result;
use crate::gateway::meta_mcp::visible::memo::{denial_code, note_denial_code, take_gate_absent};
use crate::security::decision_record::DecisionKind;

/// The dispatch's miss for `server`: the plain `BackendNotFound` the caller
/// always got. When the gate also found the backend unregistered, it is the
/// gateway's own answer to a name that matches nothing, so the invocation
/// record names `not_found` with the miss's code. A backend the gate saw and a
/// reload then removed records the plain error, as before.
pub(super) fn backend_miss(server: &str, tool: &str) -> crate::Error {
    if take_gate_absent(server, tool) {
        note_denial_code(server, tool, -32001, Some((DecisionKind::NotFound, None)));
    }
    crate::Error::BackendNotFound(server.to_string())
}

/// The meta denial count for `result`, and the one record per call:
/// the answer to a requested target the route stage or the gate refused is
/// counted once and recorded `denied` with the refusal's own code (the
/// returned outcome), whatever it reads as to the caller (the missing name's
/// answer). The log is the operator's, so the real reason there tells the
/// caller nothing. `None` for every other call, classed by its result.
pub(super) fn count_meta_denial(
    args: &Value,
    result: &Result<Value>,
) -> Option<crate::security::audit::AuditOutcome> {
    use crate::security::security_metrics::{DenialRoute, denied, meta_denial, meta_refused};
    let code = args
        .get("server")
        .and_then(Value::as_str)
        .zip(args.get("tool").and_then(Value::as_str))
        .and_then(|(server, tool)| denial_code(server, tool));
    if let Some(code) = code {
        meta_refused(code);
        return Some(crate::security::audit::AuditOutcome::Denied(code));
    }
    if let Some(reason) = meta_denial(result) {
        denied(DenialRoute::Meta, reason);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::meta_mcp::visible::memo::{
        clear_gate_absent, mark_gate_absent, with_visibility_memo,
    };

    /// A miss the gate marked keeps `not_found`'s code; one it did not keeps
    /// none; both answer the same plain error, and the mark is used up.
    #[tokio::test]
    async fn the_miss_records_not_found_only_after_a_gate_miss() {
        with_visibility_memo(async {
            mark_gate_absent("gone", "t");
            let marked = backend_miss("gone", "t");
            assert_eq!(denial_code("gone", "t"), Some(-32001), "marked");
            let unmarked = backend_miss("lost", "t");
            assert_eq!(denial_code("lost", "t"), None, "unmarked");
            assert_eq!(marked.to_string(), "Backend not found: gone");
            assert_eq!(unmarked.to_string(), "Backend not found: lost");
            assert!(!take_gate_absent("gone", "t"), "the mark was taken");
        })
        .await;
    }

    /// Marks are per target: clearing or taking one leaves another's.
    #[tokio::test]
    async fn a_mark_is_kept_per_target() {
        with_visibility_memo(async {
            mark_gate_absent("a", "t");
            mark_gate_absent("b", "t");
            clear_gate_absent("a", "t");
            assert!(!take_gate_absent("a", "t"), "a was cleared");
            assert!(take_gate_absent("b", "t"), "b's mark survives a's clear");
        })
        .await;
    }
}
