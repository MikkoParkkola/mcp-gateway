// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's checks before the caller's credential (MIK-8361
//! ORACLE.3/.4): authorize, the request firewall and the withheld gate.

use super::BackendAuthContext;
use super::direct_caller::{Envelope, Rejection};
use super::direct_dispatch::Scope;
use super::direct_failure::DirectFailure;

/// What the checks before the credential decided for a `tools/call`.
pub(super) enum Guarded {
    /// Nothing to answer: the call goes on to its credential.
    Clear,
    /// A name the caller cannot see, answered as a name the catalogue lacks.
    Withheld(Rejection),
    /// The same, for a caller with no view of this per-user backend: a
    /// missing name meets the account's credential step, so the route runs
    /// it for the withheld name too (MIK-8361 ruling B).
    WithheldNoView(Rejection),
}

/// MIK-8361 ORACLE.3/.4: a `tools/call`'s authorize, request firewall and
/// withheld gate, run before the caller's credential is resolved, so a call
/// they refuse or answer resolves none. A withheld name is answered here as
/// a name the catalogue lacks.
pub(super) async fn guard_before_credential(
    scope: Scope<'_>,
    envelope: &Envelope,
) -> Result<Guarded, Rejection> {
    if envelope.method != "tools/call" {
        return Ok(Guarded::Clear);
    }
    let caller = scope.caller;
    let client = caller.client.as_ref();
    let auth = BackendAuthContext {
        generation: &caller.generation,
        client,
        oauth_agent_identity: caller.oauth_agent_identity.as_ref(),
        cert_identity: caller.cert_identity.as_ref(),
        #[cfg(feature = "firewall")]
        grant_subject: caller.grant_subject.as_ref(),
    };
    // No credential yet: a failure answered here refreshes none.
    let failed = DirectFailure {
        state: scope.state,
        name: scope.name,
        id: scope.id.clone(),
        client,
        generation: &caller.generation,
        identity: caller.verified_identity.as_ref(),
        managed: None,
    };
    let withheld = super::guard_tool_call(
        scope.state,
        scope.name,
        auth,
        (envelope.params.as_ref(), scope.id, scope.route.session_id),
        (&scope.route.backend, &failed),
    )
    .await?;
    let backend = &scope.route.backend;
    let no_principal = backend.keeps_per_user_catalogues()
        && scope
            .state
            .meta_mcp
            .lacks_principal_on_required(backend, caller.proof());
    // A withheld name from a caller with no principal falls through to the
    // missing name's answer below, built by the same code: it never meets
    // the credential step a no-view caller's withheld name meets.
    if let Some(absent) = withheld
        && !no_principal
    {
        let no_view = backend.keeps_per_user_catalogues()
            && scope
                .state
                .meta_mcp
                .caller_lacks_view(backend, caller.proof())
                .await;
        return Ok(if no_view {
            Guarded::WithheldNoView(absent)
        } else {
            Guarded::Withheld(absent)
        });
    }
    // A caller with no principal on a required per-user backend can hold no
    // slot there: it lacks every tool, -32601 as on every other entry
    // (MIK-8356 R3.7), before any credential is resolved for it.
    if no_principal {
        scope.state.meta_mcp.warn_lacked_principal(
            &backend.name,
            Some(caller.spend_key.as_str()).filter(|key| !key.is_empty()),
        );
        let tool = envelope
            .params
            .as_ref()
            .and_then(|params| params.get("name"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let absent = crate::gateway::meta_mcp::visible::absent::absent_name(tool);
        let response =
            crate::gateway::meta_mcp::response_security::error_response_preserving_status(
                scope.id.clone(),
                &absent,
            );
        return Err(super::super::helpers::build_http_response(
            &crate::gateway::meta_mcp::invoke::egress::Egressed::gateway_own(response),
            axum::http::StatusCode::OK,
        ));
    }
    Ok(Guarded::Clear)
}
