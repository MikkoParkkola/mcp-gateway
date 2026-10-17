// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Liveness proofs for stored replays (MIK-8392 STORED.2).
//!
//! Site 5 proves every recorded target before serving a repeated task call:
//! a live resolution is the proof, and a carried fill failure is answered as
//! the failed dispatch answers it. Both run what a live call runs, so a
//! repeated call is answered exactly as its live dispatch would answer it.

use crate::identity_propagation::CallerProof;

/// What `invoke_tool_traced` answered (MIK-8392 STORED.2 D8): a live value,
/// or the lift's already-shaped stored answer.
pub(super) enum TracedOutcome {
    /// A live dispatch's guarded value, through the ordinary path.
    Live(super::GuardedValue),
    /// The lift's stored answer, already passed through `audit_replay`:
    /// shaped, audited and receipted, so every later layer delivers it
    /// unchanged, never re-wrapped.
    Stored(crate::protocol::JsonRpcResponse),
}

/// What `invoke_tool_sourced` answered (MIK-8392 STORED.2 D8): a live value
/// to shape, or the lift's already-shaped stored answer, delivered unchanged.
pub(crate) enum SourcedOutcome {
    /// A live dispatch's sourced value, through the ordinary path.
    Live(crate::gateway::meta_mcp::response_security::Sourced),
    /// The lift's stored answer: no invocation record, no shaping.
    Stored(crate::protocol::JsonRpcResponse),
}

/// Whether `resolved` minted something that proves the caller's account: a
/// dispatch binding, from a propagation mint or an account credential. It is
/// the discriminator the response and retry caches namespace on, so "proven"
/// and "keyed per user" never disagree. An optional (`required: false`)
/// propagation backend's failed mint falls back to static credentials with no
/// binding (IDP.5). That fallback is not a proof: the stored output was
/// produced under a per-user credential (MIK-8392 STORED.2 FIX 1).
fn minted_proof(resolved: &super::ResolvedDispatch) -> bool {
    resolved.binding.is_some()
}

/// The refusal an unminted proof answers with, at site 5 and at the lift: a
/// retryable `-32603`, nothing sent.
fn unminted_refusal(server: &str) -> crate::Error {
    crate::Error::Config(format!(
        "identity propagation minted no credential for backend '{server}'; \
         a stored result is not served without one"
    ))
}

/// A deferred entry the lift dropped because resolution minted nothing
/// (FIX 1b). The call may still be answered by the idempotency cache, when
/// the first run was unminted too and wrote its result under the same static
/// principal; otherwise it must not dispatch, or a keyed retry of a write
/// would run it a second time under static credentials (at most once).
pub(super) struct UnprovenReplay;

/// Refuse a call whose deferred entry was dropped unproven, once the
/// idempotency lookup has missed (FIX 1b); `Ok` for any other call.
pub(super) fn refuse_unproven(dropped: Option<UnprovenReplay>, server: &str) -> crate::Result<()> {
    dropped.map_or(Ok(()), |UnprovenReplay| Err(unminted_refusal(server)))
}

impl crate::gateway::meta_mcp::MetaMcp {
    /// The lift (MIK-8392 STORED.2): the route stage deferred this
    /// invocation's retained result to a live dispatch, and resolution has
    /// just proven the account live, so the stored answer is served without
    /// dispatching. The entry is keyed by this invocation's own key and taken
    /// once, so a nested invocation never meets it (L3). A delivered call:
    /// the signing nonce stays spent and nothing is sent (`Break`).
    /// `Continue(None)` for an unkeyed call or one with nothing deferred.
    /// For a resolution that minted nothing (FIX 1b) the entry is dropped,
    /// never served, and `Continue(Some(_))` makes the caller fail closed
    /// unless its idempotency lookup, keyed by the unminted principal, hits.
    pub(super) async fn lift_deferred(
        &self,
        (server, tool): (&str, &str),
        resolved: &super::ResolvedDispatch,
        witness: &mut super::nonce_settle::Witnessed<'_, '_>,
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> std::ops::ControlFlow<crate::protocol::JsonRpcResponse, Option<UnprovenReplay>> {
        use crate::gateway::meta_mcp::visible;
        use std::ops::ControlFlow::{Break, Continue};
        let Some(deferred) = visible::deferred_replay_key(server, tool, caller.retry)
            .and_then(|key| visible::take_deferred_replay(&key))
        else {
            return Continue(None);
        };
        if !minted_proof(resolved) {
            return Continue(Some(UnprovenReplay));
        }
        witness.spend();
        super::nonce_settle::mark_dispatched(caller, (server, tool));
        Break(
            self.audit_replay(
                &deferred.tool_name,
                &deferred.arguments,
                session_id,
                caller,
                deferred.response,
                deferred.audit,
            )
            .await,
        )
    }

    /// Prove `(server, tool)` live for `caller` through the dispatch's own
    /// resolution step, `dispatch_resolution`: it consumes what the route
    /// stage already met in this request (a busy custody, a failed
    /// resolution, a carried credential or a carried failed fill) before it
    /// resolves, so a repeat costs and records exactly what the live call
    /// does (T12r). `Ok(None)` is proven, `Ok(Some(value))` is a carried
    /// failed fill's tool answer (E4), and `Err` is the live refusal, connect
    /// offer included. The credential is dropped.
    pub(crate) async fn prove_target_live(
        &self,
        (server, tool): (&str, &str),
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> crate::Result<Option<serde_json::Value>> {
        // A permanent refusal this request's repeat pre-pass already met is
        // the live answer (#3892 Ub-repeat): resolving again would write a
        // second refusal record for one call.
        if let Some(account) = self.target_account(server, tool)
            && let Some(refusal) =
                crate::gateway::meta_mcp::visible::take_account_refusal(server, &account)
        {
            return Err(refusal);
        }
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        let mut witness = super::nonce_settle::Witnessed::take(caller);
        let proven = self
            .dispatch_resolution(
                (server, tool),
                (proof, caller.verified_identity, caller.caller_key),
                self.hint_surface(caller),
                &mut witness,
            )
            .await;
        // A busy custody refused this call before its backend: ask for the
        // nonce back, as the live call's busy answer does (invoke.rs), so the
        // same signed repeat is judged on its merits after recovery (R5n).
        if let Err(error) = &proven
            && crate::personal_accounts::refusal::transient_data(error).is_some()
        {
            super::nonce_settle::ask_refund(caller);
        }
        Ok(match proven? {
            // A task repeat has no live path (its row holds the key), so an
            // unminted resolution fails closed (FIX 1).
            std::ops::ControlFlow::Continue((_, resolved)) if !minted_proof(&resolved) => {
                return Err(unminted_refusal(server));
            }
            std::ops::ControlFlow::Continue(_) => None,
            std::ops::ControlFlow::Break(answer) => Some(answer.into_parts().0),
        })
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
        (tool_name, session): (&str, Option<&str>),
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Option<crate::protocol::JsonRpcResponse> {
        use crate::gateway::meta_mcp::visible::{self, AccountOutcome, Visibility, Withholding};
        let targets: Vec<(&str, &str)> = stored
            .targets
            .iter()
            .map(|target| (target.server.as_str(), target.tool.as_str()))
            .collect();
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        // A repeat's fill (#3892): outcomes recorded, a busy custody writes
        // no transient `idp_refuse` (R5).
        self.fill_account_outcomes(
            &targets,
            proof,
            crate::gateway::meta_mcp::account_outcome::AccountWrites::PermanentOnly,
        )
        .await;
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
            match self.prove_target_live((server, tool), caller).await {
                Ok(None) => {}
                Ok(Some(value)) => {
                    return Some(self.shape_repeat_fill(id.clone(), tool_name, value, caller));
                }
                Err(error) => {
                    return Some(
                        crate::gateway::meta_mcp::response_security::error_response_preserving_status(
                            id.clone(),
                            &error,
                        ),
                    );
                }
            }
        }
        None
    }
}

#[cfg(test)]
#[path = "stored_proof_tests.rs"]
mod tests;
