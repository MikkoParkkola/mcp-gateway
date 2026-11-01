// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `tools_call`'s route stages, moved verbatim: authorize every target, then
//! scan them, then build the caller the dispatch chokepoint receives.
//!
//! Each stage's early exit is exactly what `tools_call` returned there, so
//! the call site returns it unchanged.

use std::sync::Arc;

use axum::http::StatusCode;
#[cfg(feature = "firewall")]
use tracing::warn;

use super::super::dispatch_intake::Intake;
use crate::gateway::authz::CallTarget;
use crate::gateway::delivery_facts::{self, ResponseEffect};
use crate::gateway::meta_mcp::{
    InvokeScope, MetaMcpCallerContext, STEP_NOT_PERMITTED, STEP_NOT_PERMITTED_CODE,
    STEP_NOT_PERMITTED_STATUS, error_response_preserving_status, invoke::audit, visible::memo,
};
use crate::gateway::router::AppState;
use crate::gateway::router::authorization::RouterAuthorizer;
use crate::gateway::router::meta_refusal_audit::Refused;
use crate::protocol::mrtr::RetryFields;
use crate::protocol::{JsonRpcResponse, RequestId};
#[cfg(feature = "firewall")]
use crate::security::{firewall::FirewallAction, response_policy::RuleTarget};

/// What a stage hands back when the call ends there: exactly what
/// `tools_call` returns (`Ok` leaves through the dispatcher's tail, `Err` is
/// a refusal already carrying its status).
pub(super) type StageEnd = Result<JsonRpcResponse, axum::response::Response>;

/// The facts the two route stages share, borrowed for one call.
pub(super) struct RouteStage<'a> {
    pub(super) state: &'a Arc<AppState>,
    pub(super) intake: &'a Intake<'a>,
    pub(super) id: &'a RequestId,
    pub(super) tool_name: &'a str,
    pub(super) targets: &'a [CallTarget<'a>],
    pub(super) request_targets: usize,
    pub(super) invoke_scope: InvokeScope<'a>,
}

/// Each stage takes the call's [`Refused`] by value: an answering branch
/// consumes it and ends the call, and a stage that clears every target
/// hands it back for the next.
impl<'a> RouteStage<'a> {
    /// Authorize every target before scanning any, so a target refused with
    /// `Err` charges no earlier one's budget. A withheld target is recorded
    /// and answered later as a missing name, after the earlier targets were
    /// scanned: deliberate for a scoped key, whose missing name
    /// (`Absence::Unregistered`) takes the same path, so the scan charge
    /// cannot reveal that a backend exists.
    ///
    /// `Ok` carries the withheld target's trace (its record is this call's
    /// invocation record, and the invisible call's answer carries it) and
    /// `refused`, handed back. `Err` is boxed for `clippy::result_large_err`,
    /// not for behaviour.
    pub(super) async fn authorize_call_targets(
        &self,
        refused: Refused<'a>,
    ) -> Result<(Option<String>, Refused<'a>), Box<StageEnd>> {
        let (state, invoke_scope) = (self.state, self.invoke_scope);
        let session_id = &self.intake.session_id;
        let mut withheld_trace = None;
        for (index, target) in self.targets.iter().enumerate() {
            // The one route-stage authorize /mcp and stdio share (P3). A surfaced
            // name withheld from this caller is not a target: the meta
            // layer answers it as a name that matches no tool.
            let checked = target.as_target();
            // A requested target the caller cannot see takes the missing name's
            // path; a step's target keeps the strict authorize.
            let routed = if index < self.request_targets {
                match state.meta_mcp.authorize_requested_target(
                    invoke_scope,
                    (checked.server, checked.tool),
                    checked.arguments,
                    Some(session_id.as_str()),
                ) {
                    // Its record names the real reason; the answer is the
                    // missing name's, later.
                    Ok(Some(withheld)) => {
                        let code = match &withheld {
                            crate::Error::Forbidden { code, .. } => *code,
                            other => other.to_rpc_code(),
                        };
                        // A lone target answered as absent is the gateway's
                        // refusal; a withheld step in a call that still delivers
                        // is not.
                        if self.targets.len() == 1 {
                            delivery_facts::raise(ResponseEffect::Refused);
                        }
                        // One record per call: an invoked target's answer writes
                        // it, as a missing target's does; a surfaced name's
                        // missing twin writes none, so the route records it.
                        if state.meta_mcp.exposes_meta_tool(self.tool_name) {
                            let kind = audit::take_refusal_kind();
                            memo::note_denial_code(checked.server, checked.tool, code, kind);
                        } else {
                            let trace = refused.note_withheld(state, checked, code).await;
                            // Only a call with no other target is answered for
                            // this record alone.
                            if self.targets.len() == 1 {
                                withheld_trace = trace;
                            }
                        }
                        Ok(())
                    }
                    Ok(None) => Ok(()),
                    Err(refusal) => Err(refusal),
                }
            } else {
                state.meta_mcp.authorize_route_target(
                    invoke_scope,
                    (checked.server, checked.tool),
                    checked.arguments,
                )
            };
            // A step's target is operator-defined: any refusal of it is neutral (A3).
            if index >= self.request_targets && routed.is_err() {
                return Err(Box::new(Err(refused
                    .answer(
                        state,
                        target.as_target(),
                        self.id.clone(),
                        STEP_NOT_PERMITTED_CODE,
                        STEP_NOT_PERMITTED.to_string(),
                        StatusCode::from_u16(STEP_NOT_PERMITTED_STATUS)
                            .unwrap_or(StatusCode::FORBIDDEN),
                    )
                    .await)));
            }
            match routed {
                Ok(()) => {}
                Err(crate::Error::Forbidden {
                    code,
                    status,
                    message,
                }) => {
                    // Answered here, not in the meta layer, so the refusal keeps
                    // the route's own answer (its HTTP status included).
                    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
                    return Err(Box::new(Err(refused
                        .answer(
                            state,
                            target.as_target(),
                            self.id.clone(),
                            code,
                            message,
                            status,
                        )
                        .await)));
                }
                // Any other refusal (an unwritable grant record) is answered as
                // the meta layer answers it.
                Err(other) => {
                    // A requested target the session profile withholds ends the
                    // whole request: refused, whatever the target count.
                    if matches!(other, crate::Error::ToolNotFound(_)) {
                        delivery_facts::raise(ResponseEffect::Refused);
                    }
                    return Err(Box::new(Ok(error_response_preserving_status(
                        self.id.clone(),
                        &other,
                    ))));
                }
            }
        }
        Ok((withheld_trace, refused))
    }

    /// Firewall: the pre-invocation request scan. Runs only after
    /// [`Self::authorize_call_targets`] cleared every target, and consumes
    /// `refused`. `Err` is the refusal, boxed for `clippy::result_large_err`.
    #[cfg(feature = "firewall")]
    pub(super) async fn scan_targets(
        &self,
        refused: Refused<'a>,
        caller_key: &str,
    ) -> Result<(), Box<axum::response::Response>> {
        let (state, intake, session_id) = (self.state, self.intake, &self.intake.session_id);
        let client = &intake.client;
        for (index, target) in self.targets.iter().enumerate() {
            if let Some(ref fw) = state.firewall {
                let target = target.as_target();
                let caller_name = client.as_ref().map_or("anonymous", |c| c.name.as_str());
                // The key the per-caller controls score on:
                // never the display name, which every anonymous caller
                // shares. Empty is no identity: refused.
                let control_identity = crate::gateway::router::identity::control_identity(
                    caller_key.to_string(),
                    session_id,
                    intake.existing_session_id.as_deref(),
                    intake.session_degraded,
                );
                // Renew the reclaim deadline on every call (`IDLE_TTL`). An
                // empty identity holds no per-identity state: not tracked.
                if let Some(ref lifecycle) = state.session_lifecycle
                    && !control_identity.is_empty()
                {
                    lifecycle.renew(control_identity.clone());
                }
                let verdict = fw.check_request_keyed(
                    intake.generation.firewall_policy(),
                    session_id,
                    RuleTarget::routed(target.server, target.tool, client.as_ref()),
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
                if let Some((code, reason)) = verdict.request_refusal() {
                    use crate::security::decision_record::DecisionKind;
                    audit::note_refused_by(DecisionKind::Firewall, None);
                    // A content finding about a step names the definition: it
                    // answers as every other step refusal does (A3).
                    if index >= self.request_targets && verdict.refusal_words_content() {
                        return Err(Box::new(
                            refused
                                .firewall()
                                .answer(
                                    state,
                                    target,
                                    self.id.clone(),
                                    STEP_NOT_PERMITTED_CODE,
                                    STEP_NOT_PERMITTED.to_string(),
                                    StatusCode::from_u16(STEP_NOT_PERMITTED_STATUS)
                                        .unwrap_or(StatusCode::FORBIDDEN),
                                )
                                .await,
                        ));
                    }
                    return Err(Box::new(
                        refused
                            .firewall()
                            .answer(
                                state,
                                target,
                                self.id.clone(),
                                code,
                                reason,
                                StatusCode::BAD_REQUEST,
                            )
                            .await,
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The caller, built before the task gate so the gate binds its grant
/// through this caller's own `principal_source` — the one binding every
/// continuation reads — rather than a second spelling of who it
/// is. Its task intent and final retry fields are filled in by `tools_call`,
/// once the gate has decided. Pure: it reads, and acts on nothing.
pub(super) fn caller_context<'a>(
    state: &'a AppState,
    intake: &'a Intake<'_>,
    authorizer: &'a RouterAuthorizer<'_>,
    retry: &'a RetryFields,
    caller_key: &'a str,
) -> MetaMcpCallerContext<'a> {
    let client = &intake.client;
    let (era, is_modern) = (intake.era, intake.is_modern);
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
    let agent_id = intake.agent_identity.proven_agent_id();
    // Audit and cost attribution read the caller's own tag. It travels
    // beside the proven principal, never instead of it.
    let agent_declared = intake.agent_identity.declared_agent_label();

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

    MetaMcpCallerContext {
        task: None,
        execution: None,
        signing: None,
        is_modern,
        protocol_revision: intake.protocol_revision_owned.as_deref(),
        credential_principal: client
            .as_ref()
            .map(|client| client.principal.storage_form()),
        record_principal: crate::gateway::auth::AuthenticatedClient::record_principal_of(
            client.as_ref(),
            state.live_config.generation().auth().record_key(),
        ),
        authentication: crate::gateway::meta_mcp::Authentication::of(client.as_ref()),
        credential_kind: crate::security::audit::CredentialKind::of(client.as_ref()),
        authorizer,
        api_key_name: client.as_ref().map(|c| c.name.as_str()),
        agent_id,
        agent_declared,
        grant_subject: intake.grant_subject.clone(),
        stdio_nonce: None,
        caller_key: Some(caller_key).filter(|key| !key.is_empty()),
        verified_identity: intake.verified_identity.as_ref(),
        is_admin: client.as_ref().is_some_and(|c| c.admin),
        surface_request: intake.surface_request,
        input_capabilities: intake.declared_capabilities,
        retry,
        // Already derived at the top of the handler from the
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
    }
}
