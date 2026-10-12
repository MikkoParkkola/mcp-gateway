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

    /// E9 (MIK-8392): a repeated task call whose target is hidden ONLY because
    /// its account cannot be read right now answers as the live call does.
    ///
    /// The trigger is narrow: the catalogue verdict is `Lacked` (the caller's
    /// own per-user catalogue does not list it) AND the account outcome is
    /// `Unavailable` (custody failing). Then the withholding is a symptom of
    /// the outage, not lost access, and the live call's resolution answers
    /// (retryable). A Schema, Descriptor or Refused verdict, a `NoView`
    /// (revoked) or `Live` account, or no open memo (outcome `None`) leaves
    /// the catalogue refusal in place, so a hidden or revoked tool still
    /// answers as a missing name. Run before `refuse_stored_repeat`.
    pub(crate) async fn unavailable_repeat_answer(
        &self,
        id: &crate::protocol::RequestId,
        stored: &crate::gateway::task_service::CommittedTask,
        session: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Option<crate::protocol::JsonRpcResponse> {
        use crate::gateway::meta_mcp::visible::{
            self, AccountOutcome, Visibility, Withholding,
        };
        let targets: Vec<(&str, &str)> = stored
            .targets
            .iter()
            .map(|target| (target.server.as_str(), target.tool.as_str()))
            .collect();
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        self.fill_account_outcomes(&targets, proof).await;
        for &(server, tool) in &targets {
            let Some(account) = self.target_account(server, tool) else {
                continue;
            };
            if visible::account_outcome(server, &account) != Some(AccountOutcome::Unavailable) {
                continue;
            }
            if self.stored_target_view(server, tool, caller.scope(), session)
                != Some(Visibility::Withheld(Withholding::Lacked))
            {
                continue;
            }
            if let Err(error) = self.prove_target_live((server, tool), caller).await {
                return Some(
                    crate::gateway::meta_mcp::response_security::error_response_preserving_status(
                        id.clone(),
                        &error,
                    ),
                );
            }
        }
        None
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
