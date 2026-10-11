// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's idempotency stage (7a), moved out of `direct_dispatch`
//! unchanged.

use axum::http::StatusCode;

use super::super::helpers::build_http_error_response;
use super::direct_caller::{Envelope, Rejection};
use super::direct_dispatch::Scope;
use super::direct_preflight::{Preflight, Propagation};

/// MIK-7272.SUB.4: the bypass re-enforces the idempotency guard locally, the
/// same shape as the isolation guard. A broken stream forces re-issue with a
/// NEW request id, so without this the duplicate side effect lands twice on
/// the one route that never reaches `invoke_tool_traced`.
pub(super) fn idempotency_outcome(
    scope: Scope<'_>,
    envelope: &Envelope,
    preflight: &Preflight,
    propagation: &Propagation,
) -> Result<Option<crate::idempotency::GuardOutcome>, Rejection> {
    if envelope.method != "tools/call" {
        return Ok(None);
    }
    let caller = scope.caller;
    match scope.state.meta_mcp.direct_route_idempotency(
        preflight.retry.idempotency_key.as_deref(),
        scope.name,
        propagation.identity_key.as_deref(),
        caller.verified_identity.as_ref(),
        caller.grant_subject.as_ref(),
        caller
            .client
            .as_ref()
            .map(|client| client.principal.as_str()),
        crate::gateway::meta_mcp::Authentication::of(caller.client.as_ref()),
        envelope.params.as_ref(),
    ) {
        Ok(outcome) => Ok(outcome),
        Err(e) => {
            let code = e.to_rpc_code();
            let status = u16::try_from(code)
                .ok()
                .and_then(|c| StatusCode::from_u16(c).ok())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            Err(build_http_error_response(
                Some(scope.id.clone()),
                code,
                e.to_string(),
                status,
            ))
        }
    }
}
