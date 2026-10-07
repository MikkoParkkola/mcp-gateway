// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2420: the invocation record for a meta-route `tools/call` the router
//! refuses before the meta layer runs. The meta layer's writer (D1-d) never
//! sees these calls, so without this the scope pre-check and the request
//! firewall refused on `/mcp` without a trace in the chain, while the same
//! refusals on `/mcp/{name}` were recorded (D2-a).

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
}

/// What a refusal records: its outcome and the target resolved before it.
struct Refusal<'t> {
    outcome: AuditOutcome,
    server: &'t str,
    tool: Option<&'t str>,
    tenants: BTreeSet<String>,
}

impl<'a> Refused<'a> {
    pub(super) fn of(
        arguments: &'a Value,
        client: Option<&AuthenticatedClient>,
        grant_subject: Option<&GrantSubject>,
        session_id: &'a str,
    ) -> Self {
        Self {
            arguments,
            who: AuditWho::from_request(client, grant_subject),
            session_id,
        }
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
        // MIK-7116.MIN.1: the tenants the refused request named; nothing was
        // fetched, so there is no response side and no data class.
        let tenants = state.meta_mcp.request_tenants(target.arguments);
        let refusal = Refusal {
            outcome: AuditOutcome::Denied(code),
            server: target.server,
            tool: Some(target.tool),
            tenants,
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
            outcome: AuditOutcome::Invalid(-32602),
            server: "",
            tool: None,
            tenants: BTreeSet::new(),
        };
        self.record(state, refusal, id, -32602, message, StatusCode::BAD_REQUEST)
            .await
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
        let Some(log) = state.transparency_log.as_ref() else {
            return build_error_response(Some(id), code, message, self.session_id, status);
        };
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
            who: self.who,
        };
        let request_hash = format!(
            "sha256:{}",
            crate::hashing::canonical_json_sha256(self.arguments)
        );
        let server = refusal.server.to_string();
        let tool = refusal.tool.map(str::to_string);
        let attribution =
            DispatchNotes::default().attribution(&state.meta_mcp, refusal.tenants, None);
        let session = self.session_id.to_string();
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
                )
            })
            .await;
        match written {
            Ok(()) => build_error_response(Some(id), code, message, self.session_id, status),
            Err(error) if log.failure_policy() == AuditFailurePolicy::FailClosed => {
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
}

#[cfg(test)]
#[path = "meta_refusal_audit_tests.rs"]
mod tests;
