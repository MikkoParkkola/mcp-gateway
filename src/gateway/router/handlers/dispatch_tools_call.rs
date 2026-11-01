// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `tools/call` arm of `meta_mcp_dispatch` (MIK-8143), moved verbatim.
//!
//! An answer that leaves through the dispatcher's tail (shaped, finalized and
//! serialized like every other response) is `Ok`; a refusal that already
//! carries the status it must be sent with is `Err`, returned unchanged.

use crate::error::rpc_codes::INVALID_REQUEST;
use crate::gateway::delivery_facts::{self, ResponseEffect};
use std::sync::Arc;

use axum::http::StatusCode;

use super::dispatch_intake::Intake;
use super::tasks;
use crate::gateway::meta_mcp::InvokeScope;
use crate::gateway::meta_mcp::admission::SyncLease;
use crate::gateway::meta_mcp::signing::SigningInvocationContext;
use crate::gateway::router::AppState;
use crate::gateway::router::authorization::{
    RouterAuthorizer, backend_tool_targets_for_call, is_admin_meta_tool, require_admin_tool_access,
};
use crate::gateway::router::helpers::{
    build_error_response, build_error_response_with_data, build_response,
    extract_tools_call_params_ref, merge_client_meta_ref,
};
use crate::gateway::router::meta_refusal_audit::Refused;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::response_policy::ResponsePolicyTarget;

mod route_stage;
#[cfg(test)]
mod route_stage_order_tests;

/// The `tools/call` arm. Writes the response targets and the owned execution
/// the dispatcher's tail reads, and the signing context it prepares.
#[expect(
    clippy::too_many_lines,
    reason = "the arm's remaining stages: verdicts, the withheld-call gate, X14, task intent, signing and admission"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the dispatcher hands this arm its intake, scope, signing and response slots"
)]
#[expect(
    clippy::result_large_err,
    reason = "Err is the refusal response, already carrying its status"
)]
pub(super) async fn tools_call(
    state: &Arc<AppState>,
    intake: &Intake<'_>,
    id: RequestId,
    router_authorizer: &RouterAuthorizer<'_>,
    invoke_scope: InvokeScope<'_>,
    signing_context: &mut Option<SigningInvocationContext>,
    response_targets: &mut Vec<ResponsePolicyTarget>,
    execution: &mut Option<SyncLease>,
) -> Result<JsonRpcResponse, axum::response::Response> {
    // The prelude's facts under the names this arm was written with.
    let (client, cert_identity, grant_subject) =
        (&intake.client, &intake.cert_identity, &intake.grant_subject);
    let (oauth_agent_identity, verified_identity) =
        (&intake.oauth_agent_identity, &intake.verified_identity);
    // Only for a tool this gateway exposes: a hidden one keeps the ordinary
    // unknown-tool answer, so the refusal reveals nothing.
    if let Some(refusal) = intake
        .degraded_session_tool_refusal()
        .filter(|_| state.meta_mcp.exposes_meta_tool(intake.external_tool()))
    {
        // Same code and shape the meta layer's no-session refusal uses.
        return Ok(JsonRpcResponse::error(
            Some(id),
            INVALID_REQUEST,
            refusal.to_string(),
        ));
    }
    let (session_id, owner, admission_owner) =
        (&intake.session_id, &intake.owner, &intake.admission_owner);
    let protocol_revision_owned = &intake.protocol_revision_owned;
    let (is_modern, declared_capabilities, surface_request) = (
        intake.is_modern,
        intake.declared_capabilities,
        intake.surface_request,
    );
    let params = intake.params();
    let (tool_name, arguments) = extract_tools_call_params_ref(params);
    let empty_arguments = serde_json::Value::Object(serde_json::Map::new());
    // A conforming client's `_meta` is a sibling of `arguments`, and
    // the meta layer reads it off the argument object it is handed.
    // Meta-tool path only -- the direct backend route runs before the
    // meta-tool match and must stay byte-identical.
    // Borrowed from the request (MIK-8014): copied only where `_meta` is
    // merged in, or where a task stores the call.
    let arguments = merge_client_meta_ref(
        arguments.unwrap_or(&empty_arguments),
        params,
        state.meta_mcp.exposes_meta_tool(tool_name),
    );

    // A task-augmented call used to be answered HERE, with a handle
    // minted from a volatile store before anything was authorized. That
    // return is gone. A handle is a promise that work is under way, and
    // this site is upstream of every gate that decides whether the work
    // may happen at all — so it promised dispatch to callers the
    // authorization loop, the firewall and the destructive-confirmation
    // gate were about to refuse, and it did so without a durable record
    // behind the handle. The intent is built below, after those gates,
    // and travels on the caller context that the dispatch chokepoint
    // takes once the call is cleared to run.

    // A multi-round-trip retry carries `inputResponses` and
    // `requestState` as siblings of `name` and `arguments` (MIK-7212).
    // They are read here and travel to the invoke funnel on the caller
    // context, which is the only scope that can act on them: redeeming
    // the continuation reproduces the digest sealed at mint time, and
    // that digest is over the *backend's* server, tool and argument
    // object. Here `tool_name` is the gateway-facing name and
    // `arguments` the wrapper carrying them, so a binding check
    // attempted at this site would refuse every honest retry.
    //
    // What cannot wait is the malformed shape, refused below before
    // anything dispatches.
    let retry = crate::protocol::mrtr::RetryFields::from_params(params);
    // A refusal below is written to the chain as the meta layer would (#2420).
    let refused = Refused::of(
        &arguments,
        client.as_ref(),
        grant_subject.as_ref(),
        session_id,
        state.live_config.generation().auth().record_key(),
    );
    if retry.is_malformed() {
        // Neither a usable retry nor a fresh call. Running it as a fresh
        // call would repeat whatever the first attempt already did, and
        // for a destructive tool that is the whole risk.
        let message = format!("malformed request fields: {}", retry.malformed.join(", "));
        return Err(refused.answer_malformed(state, id, message).await);
    }
    // Exposure decides before admin does, here as well as in the
    // dispatcher. The dispatcher orders these two correctly for its own
    // callers, and this pre-check runs earlier still, so on the HTTP
    // path an unexposed admin tool used to be answered by an admin
    // refusal -- which confirms the tool exists to exactly the caller
    // the allow-list hides it from, while stdio answered with the
    // unrecognised-tool refusal. Declining to pre-check what we will
    // not confirm leaves the dispatcher the single owner of that
    // refusal instead of asking two sites to word one answer alike.
    if state.meta_mcp.exposes_meta_tool(tool_name)
        && is_admin_meta_tool(tool_name)
        && let Err(e) = require_admin_tool_access(
            state.transparency_log.as_ref(),
            client.as_ref(),
            grant_subject.as_ref(),
            tool_name,
            state.live_config.generation().auth().record_key(),
        )
        .await
    {
        delivery_facts::raise(ResponseEffect::Refused);
        return Err(build_error_response(
            Some(id),
            e.code,
            e.message,
            session_id,
            e.status,
        ));
    }

    let mut backend_targets = backend_tool_targets_for_call(
        &state.meta_mcp,
        tool_name,
        &arguments,
        crate::gateway::meta_mcp::visible::TargetView::Caller(
            invoke_scope,
            Some(session_id.as_str()),
        ),
    );
    // Computed once (MIK-8014): the firewall's per-caller controls and the
    // caller context below key on the same caller.
    let caller_key = crate::gateway::router::identity::caller_key(
        grant_subject.as_ref(),
        cert_identity.as_ref(),
        client.as_ref(),
    );
    *response_targets = crate::gateway::meta_mcp::response_security::meta_response_targets(
        tool_name,
        &backend_targets,
    );
    // A playbook's steps come from its definition, not the request. They join
    // the targets after the response targets are fixed, so response handling
    // is unchanged, and are authorized and scanned before any step runs
    // (MIK-8362).
    let request_targets = backend_targets.len();
    if request_targets == 1 {
        delivery_facts::lone_target();
    }
    backend_targets.extend(state.meta_mcp.playbook_step_targets(tool_name, &arguments));
    // The route stages: authorize every target, then scan them (one order,
    // pinned by `route_stage_order_tests`).
    let route = route_stage::RouteStage {
        state,
        intake,
        id: &id,
        tool_name,
        targets: &backend_targets,
        request_targets,
        invoke_scope,
    };
    let (withheld_trace, refused) = match route.authorize_call_targets(refused).await {
        Ok(cleared) => cleared,
        Err(end) => return *end,
    };
    #[cfg(feature = "firewall")]
    if let Err(refusal) = route.scan_targets(refused, &caller_key).await {
        return Err(*refusal);
    }
    #[cfg(not(feature = "firewall"))]
    let _ = refused;
    // The route stage is done; the window a catalogue change must not reach
    // (MIK-8340, one judgement per request).
    #[cfg(test)]
    crate::gateway::meta_mcp::visible::seams::route_stage_done();

    let mut caller =
        route_stage::caller_context(state, intake, router_authorizer, &retry, &caller_key);
    // The caller's own facts the task intent below is built with.
    let (api_key_name, agent_id, agent_declared) =
        (caller.api_key_name, caller.agent_id, caller.agent_declared);

    // The caller verdict (MIK-8356 R5.1): after route authorize and the
    // firewall, before X14, the task gate and admission. On a per-user
    // backend it records the caller's own answer in the request's memo, so
    // every reader below sees it and a name the caller's catalogue withholds
    // or lacks answers as absent; its resolution is carried to dispatch.
    // Nothing has acted before it (MIK-8353, r4 H1): the witness is minted
    // here, and a verdict that acted spends it, so the nonce stays spent.
    let witness = state
        .meta_mcp
        .caller_verdicts(
            &backend_targets,
            tool_name,
            (&caller, Some(session_id.as_str())),
            Some(crate::gateway::meta_mcp::refund_witness::RefundWitness::at_capture()),
        )
        .await;
    // A name the verdict withheld answers -32601 under the target an absent
    // name gets, never its backend's (MIK-8356).
    *response_targets = crate::gateway::meta_mcp::response_security::without_withheld(
        tool_name,
        std::mem::take(response_targets),
    );
    // MIK-8361: a call every requested target of which this caller cannot
    // see is answered by the gate as a missing name is, before X14, the task
    // gate, signing and admission act on it. The judgement is recorded, so
    // the gate answers it absent whatever the catalogue does next.
    #[cfg(test)]
    crate::gateway::meta_mcp::withheld_gate::seams::gate_start();
    let (invisible, witness) = state
        .meta_mcp
        .invisible_call(
            tool_name,
            (&backend_targets, request_targets),
            &caller,
            (Some(session_id.as_str()), witness),
        )
        .await;
    // The gate has judged; the window a catalogue change must not reach
    // (MIK-8361, one judgement per request).
    #[cfg(test)]
    crate::gateway::meta_mcp::withheld_gate::seams::gate_done();
    if invisible {
        // A backend-wide refusal (kill switch) is answered as admission
        // answers it for a missing name: the same 400.
        // MIK-8387: an absent target (recorded or live) is never judged by
        // name here, so a kill switch cannot single out a registered one.
        let scoped = state
            .meta_mcp
            .scoped(caller.scope().authorizer.backend_grant());
        if let Some(refusal) = backend_targets
            .iter()
            .filter(|target| !scoped.absent_step(&target.server, &target.tool))
            .find_map(|target| state.meta_mcp.admit_backend_wide(&target.server).err())
        {
            delivery_facts::outlet(&refusal);
            return Err(build_error_response(
                Some(id),
                refusal.to_rpc_code(),
                refusal.to_string(),
                session_id,
                StatusCode::BAD_REQUEST,
            ));
        }
        let session = Some(session_id.as_str());
        let answer = state
            .meta_mcp
            .handle_tools_call_ref(id, tool_name, arguments, session, caller);
        let answer = Box::pin(answer).await;
        // The withheld target's record is this call's one invocation record.
        return Ok(match withheld_trace {
            Some(trace) if answer.invocation_trace.is_none() => {
                answer.with_invocation_trace(trace.into())
            }
            _ => answer,
        });
    }

    // The modern destructive gate (X14). Every authorization, admin and
    // firewall check above has already run, and nothing below has yet
    // acted: a challenge mints no task, reserves no idempotency key and
    // reaches no backend, and neither does a refusal.
    // X14 hands the witness back only if it spent no grant, and admission
    // gives the nonce back only with it.
    let (confirmation, witness) = state
        .meta_mcp
        .confirm_destructive_task_with(
            &crate::gateway::meta_mcp::TaskConfirmationRequest {
                id: id.clone(),
                // The outer name the client called, never a wrapper's
                // target, and the same `arguments` binding that reaches
                // `task_intent_for_call` — that value is both the admission
                // operation's `arguments` and its representation, so the
                // grant must digest what admission will key on.
                tool_name,
                arguments: &arguments,
                task: params.and_then(|p| p.get("task")),
                retry: &retry,
                verified_identity: verified_identity.as_ref(),
                principal: crate::protocol::mrtr::source_fingerprint(caller.principal_source(None)),
                quota: caller.quota_key(),
                // The owner `task_intent_for_call` admits under below.
                owner,
                // A surfaced name this caller may not invoke is not classified
                // (MIK-8326).
                scope: invoke_scope,
                session_id: Some(session_id.as_str()),
                input_capabilities: declared_capabilities,
                is_modern,
                admission: state.task_executor.service.admission(),
            },
            witness,
        )
        .await;
    let granted = match confirmation {
        crate::gateway::meta_mcp::TaskConfirmation::NotRequired => None,
        // Confirmed: dispatch the original call, with the confirmation
        // metadata removed. The grant was spent: veto every give-back.
        crate::gateway::meta_mcp::TaskConfirmation::Granted(granted) => {
            signing_context
                .as_ref()
                .inspect(|signing| signing.mark_spent());
            Some(granted)
        }
        // The challenge, or the refusal of a grant that does not
        // authorise this call. Answered here because there is nothing
        // below to run.
        crate::gateway::meta_mcp::TaskConfirmation::Answer(answer) => {
            // Out through the tail, not around it. A challenge is a
            // client-visible result like any other: it needs this
            // revision's metadata shaped onto it *before* the response
            // security finalizer runs, and it needs that finalizer —
            // whose `PreserveInputRequired` policy is what leaves the
            // challenge's own discriminator alone, and whose signing
            // step is the only one entitled to sign what goes out.
            // Serialization then follows the request's own era, so a
            // legacy caller still gets its session header. The status
            // is re-derived there from this same response, by the same
            // `refusal_status` call, so a refusal keeps its code.
            //
            // Nothing has been admitted at this point — no lease, no
            // task, no backend — so the tail's execution settlement has
            // nothing to settle, which is the honest state for a call
            // that was stopped at the gate.
            return Ok(*answer);
        }
    };
    // The fields the call goes on with: the grant's cleared copy when the
    // gate confirmed it, else the request's own.
    let retry = granted.as_ref().unwrap_or(&retry);
    caller.retry = retry;

    // Authorization is handed to the dispatch chokepoint rather than
    // applied here, so the shapes an edge cannot see — a playbook
    // step, whose targets are not in the request — face it too. The
    // authorizer is the one derived above, before the method match.

    // The background-task intent, or a refusal, or nothing at all.
    //
    // Built here — after the authorization loop, the firewall scan and
    // the admin pre-check, and before the dispatch chokepoint that owns
    // the destructive-confirmation gate — because a handle must not be
    // minted for a call that is about to be refused. Only a request that
    // actually carries a `task` member is offered to the builder: an
    // ordinary `tools/call` must reach the synchronous path unchanged,
    // and the builder's own refusals (no verified owner, no idempotency
    // key) are conditions on asking for a task, not on calling a tool.
    let task_intent = if params.is_some_and(|p| p.get("task").is_some()) {
        match tasks::task_intent_for_call(
            state,
            id.clone(),
            tasks::TaskIntentRequest {
                tool_name,
                arguments: &arguments,
                is_modern,
                retry,
                verified_identity: verified_identity.as_ref(),
                owner,
                client: client.as_ref(),
                oauth_agent_identity: oauth_agent_identity.as_ref(),
                cert_identity: cert_identity.as_ref(),
                api_key_name,
                agent_id,
                agent_declared,
                grant_subject: grant_subject.clone(),
                is_admin: client.as_ref().is_some_and(|c| c.admin),
                scope: invoke_scope,
                input_capabilities: declared_capabilities,
                session_id: Some(session_id.as_str()),
                protocol_revision: protocol_revision_owned.as_deref(),
                surface_request,
            },
        ) {
            Ok(intent) => intent,
            Err(refusal) => {
                return Err(build_response(
                    *refusal,
                    session_id,
                    StatusCode::BAD_REQUEST,
                ));
            }
        }
    } else {
        None
    };

    // One request owns admission through dispatch and secured delivery.
    // A route change may conflict on representation, never create a
    // second owner for the same verified principal and explicit key.
    // The A/B arm and the prefetch hints key on the caller (G4). Its
    // reclaim deadline is renewed here, in every build, because those
    // entries have no session end to reclaim them.
    if let Some(ref lifecycle) = state.session_lifecycle
        && !caller_key.is_empty()
    {
        lifecycle.renew(caller_key.clone());
    }
    // Built above, after every gate that can still refuse, and only
    // carried here: the dispatch chokepoint is what hands it over.
    caller.task = task_intent;
    if let Some(context) = signing_context.as_mut()
        && let Err(error) = state.meta_mcp.prepare_signing_for_call(
            context,
            tool_name,
            &arguments,
            Some(session_id),
            &caller,
        )
    {
        delivery_facts::outlet(&error);
        return Err(build_error_response(
            Some(id),
            error.to_rpc_code(),
            crate::gateway::meta_mcp::signing::wire_error_message(&error),
            session_id,
            StatusCode::BAD_REQUEST,
        ));
    }
    caller.signing = signing_context.as_ref();
    let admission = state.meta_mcp.admit_meta_sync(
        crate::gateway::meta_mcp::AdmissionOwner::routed(admission_owner),
        &caller,
        tool_name,
        &arguments,
        Some(session_id),
        &id,
        witness,
    );
    let (owned_execution, replay) = match admission {
        Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Owned(lease)) => (Some(lease), None),
        Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Replay(
            response,
            audit,
            target,
            dispatched,
            bindings,
        )) => {
            // STORED.2 site 1: a retained single-call result is served only
            // on proven liveness; otherwise the call proceeds as Unprotected
            // and the lift serves it after a live proof. A plan replay is
            // served only with every executed step's account proven, else it
            // answers that step's live refusal (MIK-8406).
            match state
                .meta_mcp
                .defer_or_serve_replay(
                    tool_name,
                    &arguments,
                    &caller,
                    target,
                    (dispatched, bindings),
                    (response, audit),
                )
                .await
            {
                Some(replay) => (None, Some(replay)),
                None => (None, None),
            }
        }
        Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Unprotected) => (None, None),
        Err(error) => {
            delivery_facts::outlet(&error);
            let status = match &error {
                crate::Error::Forbidden { status, .. } => {
                    StatusCode::from_u16(*status).unwrap_or(StatusCode::FORBIDDEN)
                }
                _ if error.to_rpc_code() == 409 => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
            };
            // MIK-8747: an admission refusal that carries gateway-authored
            // data (the cross-era replay refusal) keeps it on the wire.
            if let crate::Error::JsonRpc {
                data: Some(data), ..
            } = &error
            {
                return Err(build_error_response_with_data(
                    Some(id),
                    error.to_rpc_code(),
                    error.to_string(),
                    data.clone(),
                    session_id,
                    status,
                ));
            }
            return Err(build_error_response(
                Some(id),
                error.to_rpc_code(),
                error.to_string(),
                session_id,
                status,
            ));
        }
    };
    *execution = owned_execution;
    caller.execution = execution.as_ref();
    // Screened at delivery, in `finalize_content`, with every other frame.
    let response = if let Some((response, audit)) = replay {
        // #2472: a replay is a delivered call, recorded as its first run was.
        let session = Some(session_id.as_str());
        (state.meta_mcp)
            .audit_replay(tool_name, &arguments, session, &caller, response, audit)
            .await
    } else {
        Box::pin(state.meta_mcp.handle_tools_call_ref(
            id,
            tool_name,
            arguments,
            Some(session_id.as_str()),
            caller,
        ))
        .await
    };
    Ok(response)
}
