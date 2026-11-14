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
) -> impl std::future::Future<Output = (T, Option<CellRefusal>)> {
    let dispatch = Box::pin(dispatch);
    crate::gateway::delivery_facts::scope(async move {
        let dispatched = dispatch.await;
        let facts = crate::gateway::delivery_facts::snapshot();
        (dispatched, dispatch_refusal(facts.as_ref()))
    })
}

/// What a dispatch cell says about a gateway refusal raised in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::gateway::task_service::execution) struct CellRefusal {
    /// A gateway refusal was raised in the cell.
    pub(in crate::gateway::task_service::execution) refused: bool,
    /// The code the latest refusal the gateway answered as a tool result was
    /// built with: the refusing gate's own, which the settlement records
    /// rather than one guessed from the result's shape.
    pub(in crate::gateway::task_service::execution) withheld_code: Option<i32>,
    /// The record trace of the step a composite ended refused on, which its
    /// settlement joins (`joined_by: step_trace`). `None` for a single-target
    /// dispatch, and for a composite with no usable step trace, whose record
    /// then joins by task id (`joined_by: task_id`).
    pub(in crate::gateway::task_service::execution) ended_on: Option<std::sync::Arc<str>>,
}

/// Whether the dispatch cell holds a gateway refusal, and the gateway fold's
/// code. `None` with no cell to read: the settlement then records nothing,
/// never a false not-refused.
pub(in crate::gateway::task_service::execution) fn dispatch_refusal(
    facts: Option<&crate::gateway::delivery_facts::DeliveryFacts>,
) -> Option<CellRefusal> {
    facts.map(|facts| CellRefusal {
        refused: facts.refused(),
        withheld_code: facts.withheld_code(),
        ended_on: facts.ended_on(),
    })
}

/// The settlement inspection with its record. One record per settlement: the
/// inspection's own decision when it refused or rewrote the answer, else a
/// gateway refusal raised inside the dispatch (`dispatch_refused`): a
/// single-target task's under its dispatched target, a composite's under the
/// gateway and its own tool, joined to the step its plan ended refused on
/// ([`composite_join`]). The record is written before the transition commits,
/// in a cell of its own; its trace is the dispatch's invocation trace, taken
/// before a refusal replaces the response. Under fail-closed a failed write
/// withholds the answer (`-32005`, no content).
pub(in crate::gateway::task_service::execution) async fn inspect_and_record(
    state: &crate::gateway::task_service::host::LiveHost,
    call: &TaskCall,
    (principal, id): (&str, &str),
    (response, dispatch_refused): (crate::protocol::JsonRpcResponse, Option<CellRefusal>),
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
        let composite = crate::gateway::meta_mcp::is_composite_meta_tool(&call.tool);
        let recorded = match decided.filter(|_| !interim) {
            // A redaction raised `rewritten` in this cell already, where the
            // firewall decided it (`egress::firewall_result`); it is not raised twice.
            Some(decided) => Some((
                (decided.server, decided.tool),
                decided.refused.then_some(firewall),
                None,
            )),
            None if !interim && !composite => {
                dispatch_refusal_code(dispatch_refused.as_ref(), &settled)
                    .map(|code| (dispatch_target(state, call), Some(code), None))
            }
            // A composite names itself: its plan may reach several backends.
            None if !interim => {
                let refusal = dispatch_refused.as_ref();
                composite_refusal_code(refusal, &settled).map(|code| {
                    let target = ("gateway".to_owned(), call.tool.clone());
                    (target, Some(code), Some(composite_join(refusal)))
                })
            }
            None => None,
        };
        let Some(((server, tool), refused, join)) = recorded else {
            return settled;
        };
        let task = crate::gateway::meta_mcp::invoke::audit::SettledTask {
            server: &server,
            tool: &tool,
            id,
        };
        // A composite joins its ended-on step, else the task id; a
        // single-target record keeps the dispatch's trace.
        let trace_id = match &join {
            Some(step) => step.as_deref().unwrap_or(id),
            None => trace.as_deref().unwrap_or(id),
        };
        let joined_by = join.as_ref().map(|step| {
            use crate::gateway::meta_mcp::invoke::audit::SettlementJoin;
            if step.is_some() {
                SettlementJoin::StepTrace
            } else {
                SettlementJoin::TaskId
            }
        });
        let kept = state
            .meta_mcp()
            .record_task_settlement(
                task,
                (trace_id, principal),
                (refused, joined_by),
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
/// with. A refusal delivered as a withheld (`isError`) result carries the
/// code the refusing gate folded it with (a whole withhold `-32600`, a
/// malformed round `-32603`, an undeclared key `-32602`, ...), and the
/// firewall's only when no gateway fold was noted. Never read from the code
/// alone: a backend's own error with a refusal's code is not a refusal. A
/// dispatch that still delivered a clean answer is not recorded as refused.
fn dispatch_refusal_code(
    dispatch: Option<&CellRefusal>,
    settled: &crate::protocol::JsonRpcResponse,
) -> Option<i32> {
    let dispatch = dispatch.filter(|cell| cell.refused)?;
    if let Some(error) = &settled.error {
        return Some(error.code);
    }
    let withheld = settled
        .result
        .as_ref()
        .and_then(|result| result.get("isError"));
    (withheld == Some(&serde_json::Value::Bool(true))).then(|| {
        dispatch
            .withheld_code
            .unwrap_or_else(|| crate::Error::ResponseFirewallRefused.to_rpc_code())
    })
}

/// The code a composite's refusal is recorded with: the refusing gate's own
/// code, carried up from the step the plan ended on (the cell's
/// `withheld_code`), over the plan's wrapper error (`settled.error.code`),
/// over [`dispatch_refusal_code`]'s fallback. Recorded only when that
/// function records one: never without a refusal, never for a clean answer.
fn composite_refusal_code(
    dispatch: Option<&CellRefusal>,
    settled: &crate::protocol::JsonRpcResponse,
) -> Option<i32> {
    let code = dispatch_refusal_code(dispatch, settled)?;
    Some(dispatch.and_then(|cell| cell.withheld_code).unwrap_or(code))
}

/// The step trace a composite's settlement record joins: the step the plan
/// ended refused on, or `None` when the cell kept no usable trace from it,
/// and the record then joins by task id.
fn composite_join(dispatch: Option<&CellRefusal>) -> Option<std::sync::Arc<str>> {
    dispatch.and_then(|cell| cell.ended_on.clone())
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
    if response.error.is_some() || response.wire_meta.egress_scanned {
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
        // Task settlement: the published generation alone.
        .inspect_task_result((&targets, id), None, result)
        .is_err();
    let rewritten = !refused && *result != before;
    let decided = (refused || rewritten).then(|| Decided {
        refused,
        server: targets.first().map_or_default(|t| t.server.clone()),
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
    use super::{
        CellRefusal, composite_join, composite_refusal_code, dispatch_refusal,
        dispatch_refusal_code, dispatched_in_cell,
    };
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

    /// A cell read: whether it holds a refusal, and the gateway fold's code.
    fn cell(refused: bool, withheld_code: Option<i32>) -> CellRefusal {
        CellRefusal {
            refused,
            withheld_code,
            ended_on: None,
        }
    }

    /// A refusal is recorded with the code the task settles with, and one
    /// delivered as a withheld `isError` result with the firewall's when no
    /// gateway fold was noted.
    #[test]
    fn a_refusal_is_recorded_in_either_shape() {
        assert_eq!(
            dispatch_refusal_code(Some(&cell(true, None)), &refused_error()),
            Some(-32603)
        );
        assert_eq!(
            dispatch_refusal_code(Some(&cell(true, None)), &is_error_result()),
            Some(crate::Error::ResponseFirewallRefused.to_rpc_code())
        );
    }

    /// A withheld result carries the code the refusing gate folded it with,
    /// not the firewall's: each gate's own code is what the task settles with.
    #[test]
    fn a_withheld_result_carries_the_gates_own_code() {
        for code in [-32603, -32602, -32003, -32001] {
            assert_eq!(
                dispatch_refusal_code(Some(&cell(true, Some(code))), &is_error_result()),
                Some(code)
            );
        }
        // An error frame's own code still wins over any fold.
        assert_eq!(
            dispatch_refusal_code(Some(&cell(true, Some(-32602))), &refused_error()),
            Some(-32603)
        );
    }

    /// Only the gateway's own fold is read: a backend's failure folded into
    /// the cell leaves the firewall's code, and a gateway fold outranks it.
    #[tokio::test]
    async fn only_the_gateways_fold_is_read() {
        use crate::gateway::health_metrics::{Origin, RpcError};
        let ((), backend) = dispatched_in_cell(async {
            delivery_facts::folded(RpcError {
                code: -32010,
                origin: Origin::Backend,
            });
            delivery_facts::refused(());
        })
        .await;
        assert_eq!(backend, Some(cell(true, None)));
        let ((), gateway) = dispatched_in_cell(async {
            delivery_facts::folded(RpcError {
                code: -32010,
                origin: Origin::Backend,
            });
            delivery_facts::gateway_folded(-32603);
            delivery_facts::refused(());
        })
        .await;
        assert_eq!(gateway, Some(cell(true, Some(-32603))));
    }

    /// Paired control: a refusal's code is not a refusal. With the cell clean,
    /// or no cell, neither shape is recorded.
    #[test]
    fn the_code_alone_records_nothing() {
        for settled in [refused_error(), is_error_result()] {
            assert_eq!(
                dispatch_refusal_code(Some(&cell(false, Some(-32603))), &settled),
                None
            );
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
            assert_eq!(
                dispatch_refusal_code(Some(&cell(true, Some(-32603))), &settled),
                None
            );
        }
    }

    /// The latest gateway fold is the one recorded: an earlier gate's fold,
    /// even a worse-ranked one, never lends its code to a later withhold, and a
    /// backend failure folded afterwards does not displace it.
    #[tokio::test]
    async fn the_latest_gateway_fold_is_recorded() {
        use crate::gateway::health_metrics::{Origin, RpcError};
        let ((), later) = dispatched_in_cell(async {
            delivery_facts::gateway_folded(-32603);
            delivery_facts::gateway_folded(-32602);
            delivery_facts::refused(());
        })
        .await;
        assert_eq!(later, Some(cell(true, Some(-32602))));
        let ((), backend_after) = dispatched_in_cell(async {
            delivery_facts::gateway_folded(-32603);
            delivery_facts::folded(RpcError {
                code: -32010,
                origin: Origin::Backend,
            });
            delivery_facts::refused(());
        })
        .await;
        assert_eq!(backend_after, Some(cell(true, Some(-32603))));
    }

    /// A composite records the refusing gate's carried code over the plan's
    /// wrapper error, then that error's code, then the firewall's on a
    /// withheld result; never a refusal for a clean answer or a clean cell.
    #[test]
    fn a_composite_prefers_the_carried_gate_code() {
        let clean = JsonRpcResponse::success(RequestId::Number(0), serde_json::json!({}));
        let cases = [
            (cell(true, Some(-32003)), refused_error(), Some(-32003)),
            (cell(true, None), refused_error(), Some(-32603)),
            (
                cell(true, None),
                is_error_result(),
                Some(crate::Error::ResponseFirewallRefused.to_rpc_code()),
            ),
            (cell(true, Some(-32003)), clean, None),
            (cell(false, Some(-32003)), refused_error(), None),
        ];
        for (cell, settled, want) in cases {
            assert_eq!(
                composite_refusal_code(Some(&cell), &settled),
                want,
                "{cell:?}"
            );
        }
        assert_eq!(composite_refusal_code(None, &refused_error()), None);
    }

    /// A composite joins the step trace its cell kept, and the task id
    /// (`None`) when the cell kept none or there is no cell.
    #[test]
    fn a_composite_joins_only_the_step_trace_its_cell_kept() {
        let traced = CellRefusal {
            ended_on: Some("step-trace".into()),
            ..cell(true, Some(-32003))
        };
        let cases = [
            (Some(&traced), Some("step-trace")),
            (Some(&cell(true, Some(-32003))), None),
            (None, None),
        ];
        for (dispatch, want) in cases {
            assert_eq!(composite_join(dispatch).as_deref(), want, "{dispatch:?}");
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
            delivery_facts::gateway_folded(-32603);
            delivery_facts::refused(());
        })
        .await;
        assert_eq!(refused, Some(cell(true, Some(-32603))));
        // A later attempt inherits neither the refusal nor its withheld code.
        let ((), clean) = dispatched_in_cell(async {}).await;
        assert_eq!(clean, Some(cell(false, None)));
        // Nor does a dispatch inside a cell that already holds both.
        let ((), inner) = delivery_facts::scope(async {
            delivery_facts::gateway_folded(-32602);
            delivery_facts::refused(());
            dispatched_in_cell(async {}).await
        })
        .await;
        assert_eq!(inner, Some(cell(false, None)));
    }
}
