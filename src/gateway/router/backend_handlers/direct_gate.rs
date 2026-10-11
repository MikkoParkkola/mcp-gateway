// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's checks before the caller's credential (MIK-8361
//! ORACLE.3/.4): authorize, the request firewall and the withheld gate.

use super::BackendAuthContext;
use super::direct_caller::{Envelope, Rejection};
use super::direct_dispatch::Scope;
use super::direct_failure::DirectFailure;

/// MIK-8361 ORACLE.3/.4: a `tools/call`'s authorize, request firewall and
/// withheld gate, run before the caller's credential is resolved, so a call
/// they refuse or answer resolves none. A withheld name is answered here as
/// a name the catalogue lacks.
pub(super) async fn guard_before_credential(
    scope: Scope<'_>,
    envelope: &Envelope,
) -> Result<(), Rejection> {
    if envelope.method != "tools/call" {
        return Ok(());
    }
    let caller = scope.caller;
    let client = caller.client.as_ref();
    let auth = BackendAuthContext {
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
        identity: caller.verified_identity.as_ref(),
        managed: None,
    };
    super::guard_tool_call(
        scope.state,
        scope.name,
        auth,
        (envelope.params.as_ref(), scope.id, scope.route.session_id),
        (&scope.route.backend, &failed),
    )
    .await?;
    Ok(())
}
