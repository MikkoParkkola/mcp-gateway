// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `tools/call` arm of `meta_mcp_dispatch` (MIK-8143), moved verbatim.
//!
//! An answer that leaves through the dispatcher's tail (shaped, finalized and
//! serialized like every other response) is `Ok`; a refusal that already
//! carries the status it must be sent with is `Err`, returned unchanged.

use std::sync::Arc;

use axum::http::StatusCode;
#[cfg(feature = "firewall")]
use tracing::warn;

use super::dispatch_intake::Intake;
use super::tasks;
use crate::gateway::meta_mcp::admission::SyncLease;
use crate::gateway::meta_mcp::signing::SigningInvocationContext;
use crate::gateway::meta_mcp::{InvokeScope, MetaMcpCallerContext};
use crate::gateway::router::AppState;
use crate::gateway::router::authorization::{
    RouterAuthorizer, authorize_tool_target, backend_tool_targets_for_call, is_admin_meta_tool,
    refusal_principal, require_admin_tool_access,
};
use crate::gateway::router::helpers::{
    build_error_response, build_response, extract_tools_call_params_ref, merge_client_meta_ref,
};
use crate::gateway::router::meta_refusal_audit::Refused;
use crate::gateway::session_lifecycle;
use crate::protocol::{JsonRpcResponse, RequestId};
#[cfg(feature = "firewall")]
use crate::security::firewall::FirewallAction;
use crate::security::response_policy::ResponsePolicyTarget;

/// The `tools/call` arm. Writes the response targets and the owned execution
/// the dispatcher's tail reads, and the signing context it prepares.
#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::result_large_err
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
    let (oauth_agent_identity, verified_identity, agent_identity) = (
        &intake.oauth_agent_identity,
        &intake.verified_identity,
        &intake.agent_identity,
    );
    let (session_id, owner, admission_owner) =
        (&intake.session_id, &intake.owner, &intake.admission_owner);
    #[cfg(feature = "firewall")]
    let existing_session_id = &intake.existing_session_id;
    let protocol_revision_owned = &intake.protocol_revision_owned;
    let (era, is_modern, declared_capabilities, surface_request) = (
        intake.era,
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
        )
        .await
    {
        return Err(build_error_response(
            Some(id),
            e.code,
            e.message,
            session_id,
            e.status,
        ));
    }

    let backend_targets = backend_tool_targets_for_call(&state.meta_mcp, tool_name, &arguments);
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
    for target in &backend_targets {
        // A surfaced name this caller could not invoke is answered by
        // the meta layer exactly as an unknown name is (`-32601`), and
        // audited there: a 403 here would confirm the backend (A3).
        if state.meta_mcp.surfaced_tool_server(tool_name).is_some()
            && state
                .meta_mcp
                .may_invoke(
                    &target.server,
                    &target.tool,
                    invoke_scope,
                    Some(session_id.as_str()),
                )
                .is_err()
        {
            continue;
        }
        if let Err(e) = authorize_tool_target(
            state.as_ref(),
            client.as_ref(),
            oauth_agent_identity.as_ref(),
            cert_identity.as_ref(),
            target.as_target(),
        ) {
            // This gate returns without entering the meta layer, so the
            // chokepoint's emitter never fires for a shape the router
            // covers. Both gates call the one helper, or HTTP scope
            // denials — the ones most worth seeing — go unrecorded.
            crate::gateway::authz::audit_refusal(
                crate::gateway::authz::Transport::Http,
                refusal_principal(
                    client.as_ref(),
                    oauth_agent_identity.as_ref(),
                    cert_identity.as_ref(),
                )
                .as_deref(),
                &target.server,
                &target.tool,
                &e.message,
            );
            return Err(refused
                .answer(state, target.as_target(), id, e.code, e.message, e.status)
                .await);
        }

        // Firewall: pre-invocation request scan
        #[cfg(feature = "firewall")]
        if let Some(ref fw) = state.firewall {
            let target = target.as_target();
            let caller_name = client.as_ref().map_or("anonymous", |c| c.name.as_str());
            // The key the per-caller controls score on (MIK-7971):
            // never the display name, which every anonymous caller
            // shares. Empty is no identity: refused.
            let control_identity = crate::gateway::router::identity::control_identity(
                caller_key.clone(),
                session_id,
                existing_session_id.as_deref(),
            );
            // Renew the reclaim deadline on every call (`IDLE_TTL`). An
            // empty identity holds no per-identity state: not tracked.
            if let Some(ref lifecycle) = state.session_lifecycle
                && !control_identity.is_empty()
            {
                lifecycle.track(
                    control_identity.clone(),
                    session_lifecycle::now_unix() + session_lifecycle::IDLE_TTL.as_secs(),
                );
            }
            let verdict = fw.check_request(
                session_id,
                target.server,
                target.tool,
                target.arguments,
                caller_name,
                &control_identity,
            );
            if verdict.action == FirewallAction::Warn {
                warn!(
                    server = target.server,
                    tool = target.tool,
                    findings = verdict.findings.len(),
                    "Firewall: request warning"
                );
            }
            if !verdict.allowed {
                // OWASP ASI10 (Rogue Agents): anomaly blocks use -32002;
                // all other firewall blocks use -32600 (invalid request).
                let (code, reason) = if verdict.is_asi10_block() {
                    let desc = verdict.findings.first().map_or(
                        "Anomaly detection triggered: unusual tool sequence blocked",
                        |f| f.description.as_str(),
                    );
                    (-32002_i32, format!("Anomaly detection blocked: {desc}"))
                } else {
                    let desc = verdict
                        .findings
                        .first()
                        .map_or("Security firewall blocked this request", |f| {
                            f.description.as_str()
                        });
                    (-32600_i32, format!("Firewall blocked: {desc}"))
                };
                return Err(refused
                    .answer(state, target, id, code, reason, StatusCode::BAD_REQUEST)
                    .await);
            }
        }
    }

    let api_key_name = client.as_ref().map(|c| c.name.as_str());
    // Authorization reads the PROVEN principal. This value reaches
    // `IdentityGrantRequest.agent_id` -> `GrantAgent::matches`, which
    // is a bare string compare: before this change it carried the
    // header-first conflated id, so a grant scoped to `agent-a` was
    // satisfied by anyone sending `X-Agent-ID: agent-a`. That path has
    // no `agent_identity.enabled` gate, so the escalation was reachable
    // on shipped defaults.
    //
    // Cost attribution wants the caller's own tag instead
    // (`AgentIdentity::attribution_id`). Routing the two apart needs
    // separate fields on `MetaMcpCallerContext` and
    // `TaskIntentRequest`; until those carry both, authorization
    // correctness wins the single field.
    let agent_id = agent_identity.proven_agent_id();
    // Audit and cost attribution read the caller's own tag. It travels
    // beside the proven principal, never instead of it.
    let agent_declared = agent_identity.declared_agent_label();

    // Destructive-action confirmation is decided at the dispatcher,
    // for every transport. What this edge owns is the one fact the
    // dispatcher cannot see: which era the request was written
    // against, and therefore what to do when nobody can be asked.
    // Handed over finished, so the shape is read once, here. Hardened
    // gives a legacy caller the modern answer: refuse what nobody can
    // confirm (GH1942.HARDEN.1 row 11).
    let confirmation_policy = if is_modern
        || state.live_config.running().security.posture
            == crate::security::SecurityPosture::Hardened
    {
        crate::gateway::destructive_confirmation::ConfirmationPolicy::for_modern()
    } else {
        crate::gateway::destructive_confirmation::ConfirmationPolicy::for_legacy()
    };

    // The caller, built before the task gate so the gate binds its grant
    // through this caller's own `principal_source` — the one binding every
    // continuation reads (MIK-8137) — rather than a second spelling of
    // who it is. Its task intent and final retry fields are filled in
    // below, once the gate has decided.
    let mut caller = MetaMcpCallerContext {
        task: None,
        execution: None,
        signing: None,
        is_modern,
        protocol_revision: protocol_revision_owned.as_deref(),
        credential_principal: client.as_ref().map(|client| client.principal.as_str()),
        authentication: crate::gateway::meta_mcp::Authentication::of(client.as_ref()),
        credential_kind: crate::security::audit::CredentialKind::of(client.as_ref()),
        authorizer: router_authorizer,
        api_key_name,
        agent_id,
        agent_declared,
        grant_subject: grant_subject.clone(),
        stdio_nonce: None,
        caller_key: Some(caller_key.as_str()).filter(|key| !key.is_empty()),
        verified_identity: verified_identity.as_ref(),
        is_admin: client.as_ref().is_some_and(|c| c.admin),
        surface_request,
        input_capabilities: declared_capabilities,
        retry: &retry,
        // Already derived at the top of this handler from the
        // same classification `initialize` advertises against;
        // re-deriving it here is the drift `classify_request`
        // exists to prevent.
        era,
        // HTTP holds the multiplexer, so this caller really can
        // be sent a request of the gateway's own.
        channel: state.proxy_manager.as_ref(),
        // Era decides who can be asked. A modern caller has no
        // session to hold an elicitation open, so it is asked
        // in-band and bound to its answer by a continuation.
        //
        // A legacy caller always gets `Elicit`, including when no
        // session was presented. HTTP can carry an asker; whether
        // one answered is what `policy` decides. Mapping a
        // sessionless request to `Unavailable` would refuse the
        // legacy caller this path deliberately still warns.
        confirmation: match era {
            crate::protocol::meta::Era::Modern => {
                crate::gateway::destructive_confirmation::ConfirmationChannel::InBand {
                    continuation: &state.continuation,
                }
            }
            crate::protocol::meta::Era::Legacy => {
                crate::gateway::destructive_confirmation::ConfirmationChannel::Elicit {
                    proxy: &state.proxy_manager,
                    policy: confirmation_policy,
                }
            }
        },
    };

    // The modern destructive gate (X14). Every authorization, admin and
    // firewall check above has already run, and nothing below has yet
    // acted: a challenge mints no task, reserves no idempotency key and
    // reaches no backend, and neither does a refusal.
    let confirmation = state
        .meta_mcp
        .confirm_destructive_task(&crate::gateway::meta_mcp::TaskConfirmationRequest {
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
            input_capabilities: declared_capabilities,
            is_modern,
            admission: state.task_executor.service.admission(),
        })
        .await;
    let granted = match confirmation {
        crate::gateway::meta_mcp::TaskConfirmation::NotRequired => None,
        // Confirmed: dispatch the original call, with the confirmation
        // metadata removed.
        crate::gateway::meta_mcp::TaskConfirmation::Granted(granted) => Some(granted),
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
        lifecycle.track(
            caller_key.clone(),
            session_lifecycle::now_unix() + session_lifecycle::IDLE_TTL.as_secs(),
        );
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
    );
    let (owned_execution, replay) = match admission {
        Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Owned(lease)) => (Some(lease), None),
        Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Replay(response, audit)) => {
            (None, Some((response, audit)))
        }
        Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Unprotected) => (None, None),
        Err(error) => {
            let status = match &error {
                crate::Error::Forbidden { status, .. } => {
                    StatusCode::from_u16(*status).unwrap_or(StatusCode::FORBIDDEN)
                }
                _ if error.to_rpc_code() == 409 => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
            };
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
