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
        let backend = self.backends.get(server);
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        let resolved = self
            .resolve_dispatch(
                (server, tool),
                backend.as_deref(),
                proof,
                caller.verified_identity,
            )
            .await?;
        Ok(crate::protocol::mrtr::source_fingerprint(
            caller.principal_source(resolved.binding.as_deref()),
        ))
    }
}
