// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The binding a chain step's continuation is minted under, kept out of
//! `invoke.rs`'s size baseline.

use crate::Result;
use crate::gateway::meta_mcp::MetaMcp;
use crate::identity_propagation::CallerProof;

impl MetaMcp {
    /// Who a continuation minted by a call to `server:tool` is bound to, for
    /// `caller`: `principal_source` over the call's dispatch binding, exactly
    /// as the call's own mint derives it (MIK-8137). A chain resume reads this
    /// for the step its handle is pending at, so the resume opens the handle
    /// under the binding the step minted with rather than a second spelling.
    ///
    /// Resolving the binding mints the caller's propagated or account
    /// credential, as the step's own dispatch does; a refusal returns here.
    pub(in crate::gateway::meta_mcp) async fn step_fingerprint(
        &self,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        (server, tool): (&str, &str),
    ) -> Result<Option<String>> {
        // A resolution the caller verdict carried for this step is the one
        // its dispatch will use: derive from it, with no second mint (fold F6).
        if let Some(binding) = super::super::visible::memo::with_carried(server, tool, |carried| {
            carried.resolved.binding.clone()
        }) {
            return Ok(crate::protocol::mrtr::source_fingerprint(
                caller.principal_source(binding.as_deref()),
            ));
        }
        // So is any resolution ERROR it carried (a mint-time Busy among
        // them): request-local, taken once, after the step's policy check,
        // and answered here with no second mint or audit (MIK-8428 Case E).
        if let Some(error) = super::super::visible::memo::take_resolution_error(server, tool) {
            return Err(error);
        }
        let backend = self
            .scoped(caller.scope().authorizer.backend_grant())
            .scoped_get(server);
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        let resolved = self
            .resolve_dispatch(
                (server, tool),
                backend.as_deref(),
                proof,
                caller.verified_identity,
            )
            .await?;
        let fingerprint = crate::protocol::mrtr::source_fingerprint(
            caller.principal_source(resolved.binding.as_deref()),
        );
        // A resume runs no caller verdict (its step is known only at run
        // time): this resolution is the step's, carried to its invocation so
        // the resume resolves once (MIK-8356 C13).
        if let Some(backend) = backend {
            super::super::visible::memo::carry_dispatch(
                server,
                tool,
                super::super::visible::memo::Carried {
                    backend,
                    resolved,
                    fill_error: None,
                },
            );
        }
        Ok(fingerprint)
    }
}
