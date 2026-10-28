// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The settlement inspection of a native task result, and the task's
//! settlement record when the inspection refused or rewrote the answer.

use crate::error::rpc_codes::INVALID_REQUEST;
use crate::gateway::meta_mcp::invoke::relay::AnswerShape;

use super::{TaskCall, rebuild_task_receipt};

/// The response firewall on a native task result, under the targets the
/// synchronous call would use (#2351): a refusal is what the task settles on.
fn inspect_settled(
    state: &crate::gateway::task_service::host::LiveHost,
    call: &TaskCall,
    id: &str,
    response: crate::protocol::JsonRpcResponse,
) -> (crate::protocol::JsonRpcResponse, Option<Decided>) {
    // A surfaced task's result is inspected as the recorded server's answer:
    // a reload that moved the name during the call must not lend it the new
    // server's targets.
    crate::gateway::meta_mcp::MetaMcp::with_surfaced_pin_sync(
        &call.tool,
        call.surfaced_server.as_ref(),
        || inspect_settled_pinned(state, call, id, response),
    )
}

/// What a settlement's inspection decided about the answer, when it refused
/// or rewrote it, and the target it was inspected as.
struct Decided {
    refused: bool,
    server: String,
    tool: String,
}

/// The settlement inspection with its record. A terminal answer the inspection
/// refused or rewrote writes the task's settlement record before it commits,
/// in a cell of its own; the record's trace is the dispatch's invocation
/// trace, taken before a refusal replaces the response. Under fail-closed a
/// failed write withholds the answer (`-32005`, no content).
pub(in crate::gateway::task_service::execution) async fn inspect_and_record(
    state: &crate::gateway::task_service::host::LiveHost,
    call: &TaskCall,
    (principal, id): (&str, &str),
    response: crate::protocol::JsonRpcResponse,
) -> crate::protocol::JsonRpcResponse {
    crate::gateway::delivery_facts::scope(async move {
        let trace = response.invocation_trace.clone();
        let (settled, decided) = inspect_settled(state, call, id, response);
        // Read after the inspection: an input request it refused is replaced
        // by an error, which ends the task, so that refusal is recorded.
        let interim = settled.result.as_ref().is_some_and(|result| {
            crate::protocol::mrtr::InputRequired::claims_input_required(result)
        });
        let Some(decided) = decided.filter(|_| !interim) else {
            return settled;
        };
        if !decided.refused {
            crate::gateway::delivery_facts::raise(
                crate::gateway::delivery_facts::ResponseEffect::Rewritten,
            );
        }
        let task = crate::gateway::meta_mcp::invoke::audit::SettledTask {
            server: &decided.server,
            tool: &decided.tool,
            id,
        };
        let trace_id = trace.as_deref().unwrap_or(id);
        let kept = state
            .meta_mcp()
            .record_task_settlement(
                task,
                (trace_id, principal),
                decided.refused,
                settled.result.as_ref(),
            )
            .await;
        if kept {
            return settled;
        }
        let withheld = crate::Error::AuditUnavailable;
        crate::protocol::JsonRpcResponse::error(
            settled.id,
            withheld.to_rpc_code(),
            withheld.to_string(),
        )
    })
    .await
}

fn inspect_settled_pinned(
    state: &crate::gateway::task_service::host::LiveHost,
    call: &TaskCall,
    id: &str,
    mut response: crate::protocol::JsonRpcResponse,
) -> (crate::protocol::JsonRpcResponse, Option<Decided>) {
    if response.error.is_some() || response.egress_scanned {
        return (response, None);
    }
    let Some(result) = response.result.as_mut() else {
        return (response, None);
    };
    let backend = crate::gateway::router::backend_tool_targets_for_call(
        state.meta_mcp(),
        &call.tool,
        &call.arguments,
        crate::gateway::meta_mcp::visible::TargetView::Dispatched,
    );
    #[cfg(test)]
    crate::gateway::meta_mcp::visible::seams::inspected_under(
        backend.iter().map(|target| target.server.clone()).collect(),
    );
    let targets =
        crate::gateway::meta_mcp::response_security::meta_response_targets(&call.tool, &backend);
    let snapshot = state.meta_mcp().relay_snapshot(result);
    // Compared after the inspection, so a redaction is seen whether or not a
    // relay snapshot was taken.
    let before = result.clone();
    let refused = state
        .meta_mcp()
        .inspect_task_result(&targets, id, result)
        .is_err();
    let rewritten = !refused && *result != before;
    let decided = (refused || rewritten).then(|| Decided {
        refused,
        server: targets
            .first()
            .map(|t| t.server.clone())
            .unwrap_or_default(),
        tool: targets
            .first()
            .map_or_else(|| call.tool.clone(), |t| t.tool.clone()),
    });
    // A redaction changed what the task will deliver: its receipt is rebuilt
    // from it. A task holds the backend's native result, never a wrapper.
    state
        .meta_mcp()
        .restage_if_changed(snapshot, Some(&*result), AnswerShape::Literal);
    // A task stores the backend's native result, never a `gateway_invoke`
    // wrapper, whatever tool started it.
    rebuild_task_receipt(
        state,
        &crate::gateway::task_service::execution::settlement::stored_result(result.clone()),
        AnswerShape::Literal,
    );
    if refused {
        response = crate::protocol::JsonRpcResponse::delivery_refusal_error(
            response.id,
            INVALID_REQUEST,
            "Response blocked by security firewall",
        );
    }
    (response, decided)
}
