// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2420: the invocation record for a meta-route `tools/call` the router
//! refuses before the meta layer runs. The meta layer's writer (D1-d) never
//! sees these calls, so without this the scope pre-check and the request
//! firewall refused on `/mcp` without a trace in the chain, while the same
//! refusals on `/mcp/{name}` were recorded (D2-a).

use crate::error::rpc_codes::INVALID_PARAMS;
use std::collections::BTreeSet;

use axum::http::StatusCode;
use serde_json::Value;

use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::authz::ToolTarget;
use crate::gateway::meta_mcp::invoke::audit::DispatchNotes;
use crate::identity_grants::GrantSubject;
use crate::protocol::RequestId;
use crate::security::audit::{
    AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho, InvocationRoute, InvocationTarget,
};
use crate::security::transparency_log::CorrelationKey;

use super::AppState;
use super::helpers::build_error_response;

/// A meta-route call about to be refused before dispatch.
pub(super) struct Refused<'a> {
    /// The `tools/call` arguments as sent: the object the meta writer hashes
    /// (D1-d.1), so a refused and an admitted call hash alike.
    arguments: &'a Value,
    /// Built as the meta layer builds it (`AuditWho::from_caller`): the same
    /// credential kind, principal, key name and verified subject.
    who: AuditWho,
    session_id: &'a str,
    /// The request firewall refused it, for the web UI's counters.
    firewall: bool,
}

/// What a refusal records: its outcome and the target resolved before it.
struct Refusal<'t> {
    outcome: AuditOutcome,
    server: &'t str,
    tool: Option<&'t str>,
    tenants: BTreeSet<String>,
    /// The kind of a refusal decided before any gate could note one; `None`
    /// when a gate decides it, so an unnoted one records `unrecorded`.
    unnoted: Option<crate::security::decision_record::DecisionKind>,
}

impl<'a> Refused<'a> {
    pub(super) fn of(
        arguments: &'a Value,
        client: Option<&AuthenticatedClient>,
        grant_subject: Option<&GrantSubject>,
        session_id: &'a str,
        record_key: &crate::gateway::record_principal::RecordPrincipalKey,
    ) -> Self {
        Self {
            arguments,
            who: AuditWho::from_request(client, grant_subject, record_key),
            session_id,
            firewall: false,
        }
    }

    /// Mark this refusal as the request firewall's.
    #[cfg(feature = "firewall")]
    pub(super) const fn firewall(mut self) -> Self {
        self.firewall = true;
        self
    }

    /// Record the refusal of `target` as `denied` with `code`, then answer it; under
    /// [`AuditFailurePolicy::FailClosed`] a failed write answers 503 instead
    /// (D1-f).
    pub(super) async fn answer(
        self,
        state: &AppState,
        target: ToolTarget<'_>,
        id: RequestId,
        code: i32,
        message: String,
        status: StatusCode,
    ) -> axum::response::Response {
        // Every caller answers the whole request with this refusal: the
        // route authorization, the request firewall, a refused step.
        crate::gateway::delivery_facts::raise(
            crate::gateway::delivery_facts::ResponseEffect::Refused,
        );
        // MIK-7116.MIN.1: the tenants the refused request named; nothing was
        // fetched, so there is no response side and no data class.
        let tenants = state.meta_mcp.request_tenants(target.arguments);
        let refusal = Refusal {
            outcome: AuditOutcome::Denied(code),
            server: target.server,
            tool: Some(target.tool),
            tenants,
            unnoted: None,
        };
        self.record(state, refusal, id, code, message, status).await
    }

    /// MIK-7660 AC3: record a call refused for malformed retry fields as
    /// `invalid`, then answer it -32602/400. It is refused before any target
    /// is resolved, so the record names no server, no tool and no tenant.
    pub(super) async fn answer_malformed(
        self,
        state: &AppState,
        id: RequestId,
        message: String,
    ) -> axum::response::Response {
        let refusal = Refusal {
            outcome: AuditOutcome::Invalid(INVALID_PARAMS),
            server: "",
            tool: None,
            tenants: BTreeSet::new(),
            unnoted: Some(crate::security::decision_record::DecisionKind::Syntax),
        };
        self.record(
            state,
            refusal,
            id,
            INVALID_PARAMS,
            message,
            StatusCode::BAD_REQUEST,
        )
        .await
    }

    /// MIK-8382: record a keyed call with no execution principal refused at
    /// the `/mcp` intake as `invalid` with the error's code (the direct
    /// route's D2-a record of the same refusal), then answer it with HTTP 400.
    /// The intake runs before any target is mapped, so the record names the
    /// target as the request spells it: `gateway_invoke`'s server and tool,
    /// else no server and the called name.
    pub(super) async fn answer_intake(
        self,
        state: &AppState,
        (server, tool): (&str, &str),
        id: Option<RequestId>,
        error: &crate::Error,
    ) -> axum::response::Response {
        let code = error.to_rpc_code();
        let refusal = Refusal {
            outcome: AuditOutcome::Invalid(code),
            server,
            tool: Some(tool),
            tenants: BTreeSet::new(),
            // No execution principal: the caller's identity standing, which no
            // kind names yet (MIK-8914.API2A.13), so recorded as unrecorded.
            unnoted: Some(crate::security::decision_record::DecisionKind::Unrecorded),
        };
        // The predicate needs an `id` member; an unrecognised one is still
        // answered, with no id, and recorded.
        let Some(id) = id else {
            crate::security::security_metrics::meta_refused(code);
            if let Some(Err(error)) = self.write(state, refusal).await {
                tracing::warn!(%error, "Transparency log write failed (non-fatal)");
            }
            return build_error_response(
                None,
                code,
                error.to_string(),
                self.session_id,
                StatusCode::BAD_REQUEST,
            );
        };
        self.record(
            state,
            refusal,
            id,
            code,
            error.to_string(),
            StatusCode::BAD_REQUEST,
        )
        .await
    }

    /// MIK-8361: record a requested target the caller may not see, refused
    /// by `code` at the route, which then takes the missing name's path. The
    /// record names the real reason, as every refusal's does; it is written
    /// best-effort (a failed write is counted, never answered), so an outage
    /// cannot tell a withheld name from a missing one (D3-a narrowed).
    ///
    /// The written record's trace, for the answer's delivery record.
    pub(super) async fn note_withheld(
        &self,
        state: &AppState,
        target: ToolTarget<'_>,
        code: i32,
    ) -> Option<String> {
        let tenants = state.meta_mcp.request_tenants(target.arguments);
        let refusal = Refusal {
            outcome: AuditOutcome::Denied(code),
            server: target.server,
            tool: Some(target.tool),
            tenants,
            unnoted: None,
        };
        crate::security::security_metrics::meta_refused(code);
        let error = match self.write(state, refusal).await? {
            Ok(trace) => return Some(trace),
            Err(error) => error,
        };
        // Counted by the log's own `mcp_audit_append_failures_total`;
        // named here with its trace id so the operator sees the gap.
        let trace_id = crate::gateway::trace::current().unwrap_or_default();
        tracing::warn!(
            %error,
            trace_id,
            server = target.server,
            tool = target.tool,
            "withheld-target refusal record write failed (counted, not answered)"
        );
        None
    }

    async fn record(
        self,
        state: &AppState,
        refusal: Refusal<'_>,
        id: RequestId,
        code: i32,
        message: String,
        status: StatusCode,
    ) -> axum::response::Response {
        // D4: every meta-route refusal decided before dispatch is counted
        // here, with or without a log; the meta layer never sees it.
        crate::security::security_metrics::meta_refused(code);
        let Some(written) = self.write(state, refusal).await else {
            return build_error_response(Some(id), code, message, self.session_id, status);
        };
        let failure_policy = state
            .transparency_log
            .as_ref()
            .map(|log| log.failure_policy());
        match written {
            Ok(trace) => {
                let mut response =
                    build_error_response(Some(id), code, message, self.session_id, status);
                super::helpers::trace_error_frame(&mut response, trace);
                response
            }
            Err(error) if failure_policy == Some(AuditFailurePolicy::FailClosed) => {
                tracing::error!(%error, "meta-route refusal audit write failed; answering 503");
                let error = crate::Error::AuditUnavailable;
                build_error_response(
                    Some(id),
                    error.to_rpc_code(),
                    error.to_string(),
                    self.session_id,
                    StatusCode::SERVICE_UNAVAILABLE,
                )
            }
            Err(error) => {
                tracing::warn!(%error, "Transparency log write failed (non-fatal)");
                build_error_response(Some(id), code, message, self.session_id, status)
            }
        }
    }

    /// The refusal record, written under the returned trace; `None` with no
    /// transparency log.
    async fn write(
        &self,
        state: &AppState,
        refusal: Refusal<'_>,
    ) -> Option<Result<String, crate::Error>> {
        // Every router refusal is written here, with or without a
        // log, so the web UI's counters move here once per refused call.
        state.meta_mcp.count_call(
            refusal.server,
            refusal.tool,
            &self.who,
            crate::counters::Outcome::Audited {
                outcome: refusal.outcome,
                firewall: self.firewall,
                cache_hit: false,
            },
        );
        let log = state.transparency_log.as_ref()?;
        let otel_trace_id = self
            .arguments
            .get("_meta")
            .and_then(crate::protocol::trace::TraceContext::from_meta)
            .and_then(|tc| tc.trace_id().map(str::to_string));
        let trace_id =
            crate::gateway::trace::current().unwrap_or_else(crate::gateway::trace::generate);
        let envelope = AuditEnvelope {
            trace_id: Some(trace_id.clone()),
            otel_trace_id: otel_trace_id.clone(),
            outcome: refusal.outcome,
            who: self.who.clone(),
        };
        let request_hash = format!(
            "sha256:{}",
            crate::hashing::canonical_json_sha256(self.arguments)
        );
        let server = refusal.server.to_string();
        let tool = refusal.tool.map(str::to_string);
        let attribution =
            DispatchNotes::default().attribution(&state.meta_mcp, refusal.tenants, None);
        let mut noted = crate::gateway::meta_mcp::invoke::audit::take_route_noted();
        if !noted.has_refusal()
            && let Some(kind) = refusal.unnoted
        {
            noted.refused(kind, None);
        }
        let decision = Box::new(noted.decision(
            crate::security::decision_record::Decided::Fresh,
            crate::security::decision_record::Refused::of(refusal.outcome),
            state.meta_mcp.live_config().as_deref(),
        ));
        let session = self.session_id.to_string();
        let recorded = trace_id.clone();
        // The meta writer's correlation ladder; a modern call's session is
        // `""`, so it falls to the minted trace id (MIK-7640).
        let written = log
            .append_bounded(move |log| {
                let key =
                    CorrelationKey::ladder(otel_trace_id.as_deref(), Some(&session), &trace_id);
                log.log_invocation_attributed(
                    key,
                    &envelope,
                    InvocationTarget {
                        route: InvocationRoute::Meta,
                        server: &server,
                        tool: tool.as_deref(),
                    },
                    &request_hash,
                    None,
                    attribution,
                    Some(decision.as_ref()),
                )
            })
            .await;
        Some(written.map(|()| recorded).map_err(Into::into))
    }
}

#[cfg(test)]
#[path = "meta_refusal_audit_tests.rs"]
mod tests;
