// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a refused or missed call's invocation record says: the code a gate
//! kept for it, and the dispatch's miss of a backend the gate found absent.

use serde_json::Value;

use crate::Result;
use crate::gateway::meta_mcp::visible::memo::{denial_code, take_gate_absent};
use crate::security::decision_record::DecisionKind;

/// The dispatch's miss for `server`: the plain `BackendNotFound` the caller
/// always got. When the gate also found the backend unregistered, it is the
/// gateway's own answer to a name that matches nothing, so the invocation
/// record names `not_found` with the miss's code. A backend the gate saw and a
/// reload then removed records the plain error, as before.
pub(super) fn backend_miss(server: &str, tool: &str) -> crate::Error {
    // Noted on this call only: a later call on the same name in the same
    // request (a chain, after a reload) records its own outcome.
    if take_gate_absent(server, tool) {
        super::audit::note_refused_by(DecisionKind::NotFound, None);
        super::audit::note_not_found();
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
    not_found: bool,
) -> Option<crate::security::audit::AuditOutcome> {
    use crate::security::security_metrics::{DenialRoute, denied, meta_denial, meta_refused};
    let code = args
        .get("server")
        .and_then(Value::as_str)
        .zip(args.get("tool").and_then(Value::as_str))
        .and_then(|(server, tool)| denial_code(server, tool));
    // A code a gate kept first stands; else this call's own missing backend.
    if let Some(code) = code.or(not_found.then_some(-32001)) {
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

    /// A marked miss and an unmarked one answer the same plain error, and
    /// the mark is used up by the miss that took it.
    #[tokio::test]
    async fn a_miss_answers_the_same_and_uses_up_its_mark() {
        with_visibility_memo(async {
            mark_gate_absent("gone", "t");
            let marked = backend_miss("gone", "t");
            let unmarked = backend_miss("lost", "t");
            assert_eq!(marked.to_string(), "Backend not found: gone");
            assert_eq!(unmarked.to_string(), "Backend not found: lost");
            assert!(!take_gate_absent("gone", "t"), "the mark was taken");
            assert_eq!(denial_code("gone", "t"), None, "nothing kept request-wide");
        })
        .await;
    }

    /// This call's missing backend is a denial with -32001; without it the
    /// same answer is classed by its result, and no request-wide code is kept.
    #[tokio::test]
    async fn the_call_s_own_miss_is_its_denial() {
        with_visibility_memo(async {
            let args = serde_json::json!({"server": "gone", "tool": "t"});
            let missed: Result<Value> = Err(crate::Error::BackendNotFound("gone".into()));
            assert_eq!(
                count_meta_denial(&args, &missed, true),
                Some(crate::security::audit::AuditOutcome::Denied(-32001))
            );
            assert_eq!(count_meta_denial(&args, &missed, false), None);
            assert_eq!(denial_code("gone", "t"), None, "nothing request-wide");
        })
        .await;
    }

    /// A code a gate kept first wins over this call's own missing backend.
    #[tokio::test]
    async fn a_kept_code_wins_over_the_call_s_miss() {
        with_visibility_memo(async {
            crate::gateway::meta_mcp::visible::memo::note_denial_code("gone", "t", -32003, None);
            let args = serde_json::json!({"server": "gone", "tool": "t"});
            let missed: Result<Value> = Err(crate::Error::BackendNotFound("gone".into()));
            assert_eq!(
                count_meta_denial(&args, &missed, true),
                Some(crate::security::audit::AuditOutcome::Denied(-32003))
            );
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
