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

/// A worker dispatch run in a cell of its own: its response, and whether a
/// gateway refusal was raised inside it (see [`dispatch_refusal`]). Each
/// dispatch gets a fresh cell, so a discarded attempt's flag goes with it.
/// The dispatch is boxed before the cell's future is built: inline, its state
/// machine deepens every worker path's stack by a whole dispatch.
pub(in crate::gateway::task_service::execution) fn dispatched_in_cell<T>(
    dispatch: impl std::future::Future<Output = T>,
) -> impl std::future::Future<Output = (T, Option<bool>)> {
    let dispatch = Box::pin(dispatch);
    crate::gateway::delivery_facts::scope(async move {
        let dispatched = dispatch.await;
        let facts = crate::gateway::delivery_facts::snapshot();
        (dispatched, dispatch_refusal(facts.as_ref()))
    })
}

/// Whether the dispatch cell holds a gateway refusal. `None` with no cell to
/// read: the settlement then records nothing, never a false not-refused.
pub(in crate::gateway::task_service::execution) fn dispatch_refusal(
    facts: Option<&crate::gateway::delivery_facts::DeliveryFacts>,
) -> Option<bool> {
    facts.map(crate::gateway::delivery_facts::DeliveryFacts::refused)
}

/// The settlement inspection with its record. One record per settlement: the
/// inspection's own decision when it refused or rewrote the answer, else a
/// gateway refusal raised inside the dispatch (`dispatch_refused`), for a
/// single-target task. A composite's steps run in cells of their own and are
/// not recorded here. The record is written before the transition commits,
/// in a cell of its own; its trace is the dispatch's invocation trace, taken
/// before a refusal replaces the response. Under fail-closed a failed write
/// withholds the answer (`-32005`, no content).
pub(in crate::gateway::task_service::execution) async fn inspect_and_record(
    state: &crate::gateway::task_service::host::LiveHost,
    call: &TaskCall,
    (principal, id): (&str, &str),
    (response, dispatch_refused): (crate::protocol::JsonRpcResponse, Option<bool>),
) -> crate::protocol::JsonRpcResponse {
    crate::gateway::delivery_facts::scope(async move {
        let trace = response.invocation_trace.clone();
        let (settled, decided) = inspect_settled(state, call, id, response);
        // Read after the inspection: an input request it refused is replaced
        // by an error, which ends the task, so that refusal is recorded.
        let interim = settled.result.as_ref().is_some_and(|result| {
            crate::protocol::mrtr::InputRequired::claims_input_required(result)
        });
        let firewall = crate::Error::ResponseFirewallRefused.to_rpc_code();
        let recorded = match decided.filter(|_| !interim) {
            // A redaction raised `rewritten` in this cell already, where the
            // firewall decided it (`egress::firewall_result`); it is not raised twice.
            Some(decided) => Some((
                decided.server,
                decided.tool,
                decided.refused.then_some(firewall),
            )),
            None if !interim && !crate::gateway::meta_mcp::is_composite_meta_tool(&call.tool) => {
                dispatch_refusal_code(dispatch_refused, &settled).map(|code| {
                    let (server, tool) = dispatch_target(state, call);
                    (server, tool, Some(code))
                })
            }
            None => None,
        };
        let Some((server, tool, refused)) = recorded else {
            return settled;
        };
        let task = crate::gateway::meta_mcp::invoke::audit::SettledTask {
            server: &server,
            tool: &tool,
            id,
        };
        let trace_id = trace.as_deref().unwrap_or(id);
        let kept = state
            .meta_mcp()
            .record_task_settlement(
                task,
                (trace_id, principal),
                refused,
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

/// The code a dispatch refusal is recorded with, or `None` when the cell
/// holds no refusal (or there was no cell). It is the code the task settles
/// with; a refusal delivered as a withheld (`isError`) result carries the
/// firewall's, as the inspection's does. Never read from the code alone: a
/// backend's own error with a refusal's code is not a refusal. A dispatch
/// that still delivered a clean answer is not recorded as refused.
fn dispatch_refusal_code(
    dispatch_refused: Option<bool>,
    settled: &crate::protocol::JsonRpcResponse,
) -> Option<i32> {
    if dispatch_refused != Some(true) {
        return None;
    }
    if let Some(error) = &settled.error {
        return Some(error.code);
    }
    let withheld = settled
        .result
        .as_ref()
        .and_then(|result| result.get("isError"));
    (withheld == Some(&serde_json::Value::Bool(true)))
        .then(|| crate::Error::ResponseFirewallRefused.to_rpc_code())
}

/// The target a dispatch refusal is recorded under: the call's first
/// dispatched target, as the settlement inspection records its own, read
/// under the recorded surfaced name.
fn dispatch_target(
    state: &crate::gateway::task_service::host::LiveHost,
    call: &TaskCall,
) -> (String, String) {
    crate::gateway::meta_mcp::MetaMcp::with_surfaced_pin_sync(
        &call.tool,
        call.surfaced_server.as_ref(),
        || {
            let backend = crate::gateway::router::backend_tool_targets_for_call(
                state.meta_mcp(),
                &call.tool,
                &call.arguments,
                crate::gateway::meta_mcp::visible::TargetView::Dispatched,
            );
            let targets = crate::gateway::meta_mcp::response_security::meta_response_targets(
                &call.tool, &backend,
            );
            // With no target resolved (a readmission refused before any),
            // the call's own surfaced server and tool name it.
            targets.first().map_or_else(
                || {
                    let server = call
                        .surfaced_server
                        .as_ref()
                        .map_or_else(|| "gateway".to_owned(), |target| target.server.clone());
                    (server, call.tool.clone())
                },
                |t| (t.server.clone(), t.tool.clone()),
            )
        },
    )
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

#[cfg(test)]
mod tests {
    use super::{dispatch_refusal, dispatch_refusal_code, dispatched_in_cell};
    use crate::gateway::delivery_facts;
    use crate::protocol::{JsonRpcResponse, RequestId};

    fn refused_error() -> JsonRpcResponse {
        JsonRpcResponse::error(Some(RequestId::Number(0)), -32603, "refused")
    }

    /// A backend's own failure as the task receives it: an `isError` result,
    /// not a JSON-RPC error (`dispatch_error_result`).
    fn is_error_result() -> JsonRpcResponse {
        JsonRpcResponse::success(
            RequestId::Number(0),
            serde_json::json!({"isError": true, "content": []}),
        )
    }

    /// A refusal is recorded with the code the task settles with, and one
    /// delivered as a withheld `isError` result with the firewall's.
    #[test]
    fn a_refusal_is_recorded_in_either_shape() {
        assert_eq!(
            dispatch_refusal_code(Some(true), &refused_error()),
            Some(-32603)
        );
        assert_eq!(
            dispatch_refusal_code(Some(true), &is_error_result()),
            Some(crate::Error::ResponseFirewallRefused.to_rpc_code())
        );
    }

    /// Paired control: a refusal's code is not a refusal. With the cell clean,
    /// or no cell, neither shape is recorded.
    #[test]
    fn the_code_alone_records_nothing() {
        for settled in [refused_error(), is_error_result()] {
            assert_eq!(dispatch_refusal_code(Some(false), &settled), None);
            assert_eq!(dispatch_refusal_code(None, &settled), None);
        }
    }

    /// A dispatch that still delivered a clean answer is not recorded as
    /// refused, whatever its cell holds: no false refusal in the audit trail.
    #[test]
    fn a_clean_answer_records_no_refusal() {
        for result in [
            serde_json::json!({"content": []}),
            serde_json::json!({"isError": false, "content": []}),
        ] {
            let settled = JsonRpcResponse::success(RequestId::Number(0), result);
            assert_eq!(dispatch_refusal_code(Some(true), &settled), None);
        }
    }

    /// With no cell to read, nothing is recorded.
    #[test]
    fn no_cell_reads_as_unknown() {
        assert_eq!(dispatch_refusal(None), None);
    }

    /// A dispatch reads the refusal raised in its own cell and only that:
    /// neither an earlier attempt's refusal nor an enclosing cell's.
    #[tokio::test]
    async fn each_dispatch_reads_its_own_cell() {
        let ((), refused) = dispatched_in_cell(async {
            delivery_facts::refused(());
        })
        .await;
        assert_eq!(refused, Some(true));
        let ((), clean) = dispatched_in_cell(async {}).await;
        assert_eq!(clean, Some(false));
        let ((), inner) = delivery_facts::scope(async {
            delivery_facts::refused(());
            dispatched_in_cell(async {}).await
        })
        .await;
        assert_eq!(inner, Some(false));
    }
}
