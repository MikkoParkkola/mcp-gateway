// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Liveness proofs for stored replays (MIK-8392 STORED.2).
//!
//! Site 5 proves every recorded target before serving a repeated task call:
//! a live resolution is the proof, and a carried fill failure is answered as
//! the failed dispatch answers it. Both run what a live call runs, so a
//! repeated call is answered exactly as its live dispatch would answer it.

use crate::identity_propagation::CallerProof;

impl crate::gateway::meta_mcp::MetaMcp {
    /// Prove `(server, tool)` live for `caller` by resolving what its
    /// dispatch would resolve, and dropping the credential: a successful
    /// resolution is the proof. A refusal answers as the live call's own
    /// resolution refusal, offer included.
    pub(crate) async fn prove_target_live(
        &self,
        (server, tool): (&str, &str),
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> crate::Result<()> {
        let backend = self.backends.get(server);
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        self.resolve_dispatch(
            (server, tool),
            backend.as_deref(),
            proof,
            caller.verified_identity,
        )
        .await
        .map(|_| ())
    }

    /// The answer a failed dispatch gives for a carried fill failure (E4),
    /// as `dispatch_resolution`'s Break arm answers it: the connect offer
    /// when the failure is a marked refusal, else the refused-fill tool
    /// result. `Ok` shapes as the live arm would; `Err` answers directly.
    pub(crate) async fn refused_fill_outcome(
        &self,
        (server, tool): (&str, &str),
        error: crate::Error,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> crate::Result<serde_json::Value> {
        if crate::personal_accounts::refusal::marked(&error).is_some() {
            return self.with_connect_offer(Err(error), caller.verified_identity).await;
        }
        let surface = self.hint_surface(caller);
        Ok(self.account_refused_fill(server, tool, &error, (std::time::Instant::now(), surface)))
    }
}
