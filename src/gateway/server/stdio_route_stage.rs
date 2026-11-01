// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The route stage stdio runs before admission, in `/mcp`'s order
//! (route-check-parity P3; MIK-8149, MIK-8160, MIK-8326): authorize every
//! target, scan it with the request firewall, then X14 for a task-augmented
//! call. A refusal here has taken no idempotency key, lease or task. The
//! signing nonce is admitted before this stage (a bad nonce stays cheap to
//! refuse, MIK-7377.SIGNING.5 row 40), and the caller gives it back when this
//! stage answers (lead ruling, P3). The dispatch chokepoint re-runs
//! authorization and the stateless content scan at send time, as it does for
//! every route.

use serde_json::Value;

use super::{Gateway, StdioClient};
use crate::gateway::meta_mcp::refund_witness::RefundWitness;
use crate::gateway::meta_mcp::{
    MetaMcp, MetaMcpCallerContext, TaskConfirmation, TaskConfirmationRequest,
    error_response_preserving_status,
};
use crate::protocol::mrtr::RetryFields;
use crate::protocol::{JsonRpcResponse, RequestId};

/// What the route stage decided for one stdio `tools/call`.
pub(super) enum RouteStage {
    /// Admit the call. `Some` carries X14's granted retry fields, with the
    /// confirmation metadata stripped, for admission to key on.
    Proceed(Option<RetryFields>),
    /// Answer with this and admit nothing.
    Answer(JsonRpcResponse),
    /// Every requested target is one this caller cannot see (MIK-8361):
    /// dispatch it unadmitted, past X14 and the task gate, to the gate that
    /// answers it as a missing name.
    Absent,
}

impl Gateway {
    /// Run the route stage for one stdio `tools/call` of `tool_name` with its
    /// merged `arguments` and its `task` member, if any. `witness` comes back
    /// on every outcome that acted on nothing (MIK-8353): the checks act on
    /// nothing, and X14 hands it back unless it spent a grant.
    pub(super) async fn stdio_route_stage(
        meta_mcp: &MetaMcp,
        id: &RequestId,
        (tool_name, arguments, task): (&str, &Value, Option<&Value>),
        caller: &MetaMcpCallerContext<'_>,
        client: StdioClient<'_>,
        witness: Option<RefundWitness>,
    ) -> (RouteStage, Option<RefundWitness>) {
        let session_id = client.session_id;
        let scope = caller.scope();
        let mut targets = crate::gateway::router::backend_tool_targets_for_call(
            meta_mcp,
            tool_name,
            arguments,
            crate::gateway::meta_mcp::visible::TargetView::Caller(scope, Some(session_id)),
        );
        // A playbook's steps are known from its definition, not the request:
        // appended after the request's own targets so they are authorized and
        // scanned with them, before any step runs (MIK-8362).
        let request_targets = targets.len();
        targets.extend(meta_mcp.playbook_step_targets(tool_name, arguments));
        // Authorize every target before scanning any, so a refused later
        // target charges no earlier one's budget.
        if let Some(answer) = authorize_targets(
            meta_mcp,
            (scope, session_id),
            (&targets, request_targets),
            id,
        ) {
            return (RouteStage::Answer(answer), witness);
        }
        // The stateful controls key on the one client this process serves; an
        // empty identity would refuse every call unscored.
        #[cfg(feature = "firewall")]
        for (index, target) in targets.iter().enumerate() {
            let checked = target.as_target();
            let kind = if index < request_targets {
                crate::gateway::meta_mcp::invoke::ScanTarget::Request
            } else {
                crate::gateway::meta_mcp::invoke::ScanTarget::Step
            };
            if let Some(refusal) = meta_mcp.route_request_scan(
                session_id,
                (checked.server, checked.tool, checked.arguments),
                (
                    super::STDIO_CREDENTIAL_PRINCIPAL,
                    super::STDIO_CREDENTIAL_PRINCIPAL,
                    kind,
                ),
            ) {
                let answer = error_response_preserving_status(id.clone(), &refusal);
                return (RouteStage::Answer(answer), witness);
            }
        }
        // The caller verdict (MIK-8356 R5.1), after authorize and the
        // firewall and before X14, task intent and admission: as on `/mcp`.
        // A refusal or a failed fill is answered by the dispatch. A verdict
        // that acted spends the witness, so the nonce stays spent (MIK-8353).
        let witness = meta_mcp
            .caller_verdicts(&targets, tool_name, (caller, Some(session_id)), witness)
            .await;
        // MIK-8361, as on `/mcp`: recorded, so the gate answers it absent.
        let (invisible, witness) = meta_mcp
            .invisible_call(
                tool_name,
                (&targets, request_targets),
                caller,
                (Some(session_id), witness),
            )
            .await;
        if invisible {
            return (RouteStage::Absent, witness);
        }
        // X14 decides a task-augmented call, so it needs the session's task
        // store; without one the call is synchronous and X14 has nothing to say.
        let Some(tasks) = client.tasks else {
            return (RouteStage::Proceed(None), witness);
        };
        let (confirmation, witness) = meta_mcp
            .confirm_destructive_task_with(
                &TaskConfirmationRequest {
                    id: id.clone(),
                    tool_name,
                    arguments,
                    task,
                    retry: caller.retry,
                    verified_identity: None,
                    // The derivation continuations bind stdio by (`Stdio { nonce }`),
                    // so a grant and a continuation name one caller one way.
                    principal: crate::protocol::mrtr::source_fingerprint(
                        caller.principal_source(None),
                    ),
                    // This process's one share of the continuation pool (MIK-8293).
                    quota: caller.quota_key(),
                    // The caller's own owner, the one `stdio_tasks::intent` admits
                    // under (the local operator for a stdio caller). A context wired
                    // to the wrong caller has none, so it fails closed: re-challenged.
                    owner: caller.owner_principal().unwrap_or_default(),
                    scope,
                    session_id: Some(session_id),
                    input_capabilities: caller.input_capabilities,
                    is_modern: caller.is_modern,
                    admission: tasks.service.admission(),
                },
                witness,
            )
            .await;
        let stage = match confirmation {
            TaskConfirmation::NotRequired => RouteStage::Proceed(None),
            TaskConfirmation::Granted(granted) => {
                // A granted confirmation was spent: veto every give-back.
                caller.signing.inspect(|signing| signing.mark_spent());
                RouteStage::Proceed(Some(granted))
            }
            TaskConfirmation::Answer(answer) => RouteStage::Answer(*answer),
        };
        (stage, witness)
    }
}

/// The one route-stage authorize `/mcp` also runs, over every target: the
/// answer of the first it refuses. A surfaced name withheld from this caller
/// is not a target (MIK-8340), so neither the firewall nor X14 can confirm it
/// exists. A requested target the caller cannot see takes the missing name's
/// path (MIK-8361); a step's target keeps the strict authorize, and its
/// refusal is neutral, as the step is operator-defined (A3).
fn authorize_targets(
    meta_mcp: &MetaMcp,
    (scope, session_id): (crate::gateway::meta_mcp::InvokeScope<'_>, &str),
    (targets, request_targets): (&[crate::gateway::authz::CallTarget<'_>], usize),
    id: &RequestId,
) -> Option<JsonRpcResponse> {
    targets.iter().enumerate().find_map(|(index, target)| {
        let checked = target.as_target();
        let (server_tool, arguments) = ((checked.server, checked.tool), checked.arguments);
        let routed = if index < request_targets {
            // Its record names the route's own refusal code, as on `/mcp`.
            meta_mcp
                .authorize_requested_target(scope, server_tool, arguments, Some(session_id))
                .map(|withheld| {
                    if let Some(withheld) = withheld {
                        // A lone target answered as absent is the gateway's
                        // refusal, as on `/mcp`.
                        if targets.len() == 1 {
                            crate::gateway::delivery_facts::raise(
                                crate::gateway::delivery_facts::ResponseEffect::Refused,
                            );
                        }
                        crate::gateway::meta_mcp::visible::memo::note_denial_code(
                            checked.server,
                            checked.tool,
                            withheld.to_rpc_code(),
                            crate::gateway::meta_mcp::invoke::audit::take_refusal_kind(),
                        );
                    }
                })
        } else {
            meta_mcp
                .authorize_route_target(scope, server_tool, arguments)
                .map_err(|_| crate::gateway::meta_mcp::step_not_permitted())
        };
        routed.err().map(|error| {
            // The route stage's refusal answers the whole request: a refused
            // step, the route authorization, or a profile withhold, whatever
            // the target count. A grant record that cannot be written is not
            // a policy refusal.
            if index >= request_targets
                || matches!(
                    error,
                    crate::Error::Forbidden { .. } | crate::Error::ToolNotFound(_)
                )
            {
                crate::gateway::delivery_facts::raise(
                    crate::gateway::delivery_facts::ResponseEffect::Refused,
                );
            }
            error_response_preserving_status(id.clone(), &error)
        })
    })
}

#[cfg(test)]
#[path = "stdio_route_stage_tests.rs"]
mod tests;
