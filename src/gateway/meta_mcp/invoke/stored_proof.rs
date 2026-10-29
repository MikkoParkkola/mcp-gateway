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

/// `invoke_tool_sourced`'s answer and whether the invocation was refused
/// before its backend. Must be used: a caller that drops `pre_send` records a
/// refused invocation as a call.
#[must_use]
pub(crate) struct Invoked {
    pub(crate) outcome: crate::Result<SourcedOutcome>,
    pub(crate) pre_send: crate::gateway::meta_mcp::dispatch_log::PreSend,
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

/// The refusal an unminted proof answers with, at site 5, at the lift and on
/// the direct route's stored replay (MIK-8434): a `-32603` that is not
/// retryable, nothing sent.
pub(super) fn unminted_refusal(server: &str) -> crate::Error {
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
        // MIK-8407: every dispatch passes here once its credential is
        // resolved, so the binding it runs under is noted here, from the
        // resolution it uses, before anything is replayed or sent.
        super::nonce_settle::note_binding(caller, (server, tool), resolved.account.as_deref());
        let Some(deferred) = visible::deferred::deferred_replay_key(server, tool, caller.retry)
            .and_then(|key| visible::memo::take_deferred_replay(&key))
        else {
            return Continue(None);
        };
        if !minted_proof(resolved) {
            return Continue(Some(UnprovenReplay));
        }
        // MIK-8407: judged again at the serving point, against the account
        // this resolution just proved, so a reload since admission cannot
        // pass another account's proof off as the recorded one's. Nothing is
        // sent; the stored output never goes out.
        // Both the account this resolution proved and the target's account
        // now must be the recorded one.
        let view = self.scoped(caller.scope().authorizer.backend_grant());
        let judged = crate::gateway::meta_mcp::stored_binding::judge(&deferred.bindings, |s, t| {
            if (s, t) == (server, tool) {
                resolved.account.clone()
            } else {
                self.current_binding(&view, s, t)
            }
        })
        .and_then(|()| self.judge_bindings(&view, &deferred.bindings));
        if let Err(error) = judged {
            // Refused at the serving point: nothing replayed, nothing sent.
            super::audit::note_pre_send(crate::gateway::meta_mcp::dispatch_log::PreSend::Refused);
            return Break(crate::protocol::JsonRpcResponse::error(
                deferred.response.id.clone(),
                error.to_rpc_code(),
                error.to_string(),
            ));
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
                super::super::admission::ReplayFacts {
                    audit: deferred.audit,
                    server: deferred.audit_server,
                },
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
        if let Some(account) = self.target_account(
            &self.scoped(caller.scope().authorizer.backend_grant()),
            server,
            tool,
        ) && let Some(refusal) =
            crate::gateway::meta_mcp::visible::memo::take_account_refusal(server, &account)
        {
            return Err(refusal);
        }
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        let mut witness = super::nonce_settle::Witnessed::take(caller);
        let proven = self
            .dispatch_resolution(
                &self.scoped(caller.scope().authorizer.backend_grant()),
                (server, tool),
                (proof, caller.verified_identity, caller.caller_key),
                self.hint_surface(caller),
                &mut witness,
            )
            .await;
        // A busy custody refused this call before its backend: ask for the
        // nonce back, as the live call's busy answer does (invoke.rs), so the
        // same signed repeat is judged on its merits after recovery (R5n).
        if let Err(error) = &proven {
            super::nonce_settle::ask_if_transient(caller, error);
        }
        Ok(match proven? {
            // A task repeat has no live path (its row holds the key), so an
            // unminted resolution fails closed (FIX 1).
            std::ops::ControlFlow::Continue((_, resolved)) if !minted_proof(&resolved) => {
                return Err(unminted_refusal(server));
            }
            // A minted (or refreshed) binding is an effect: the witness is
            // spent, so a later refusal in the same walk cannot give the
            // nonce back (MIK-8406 G1).
            std::ops::ControlFlow::Continue(_) => {
                witness.spend();
                None
            }
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
        use crate::gateway::meta_mcp::visible::{
            self, Visibility, Withholding, memo::AccountOutcome,
        };
        let targets = crate::gateway::task_service::Target::pairs(&stored.targets);
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        // A repeat's fill (#3892): outcomes recorded, a busy custody writes
        // no transient `idp_refuse` (R5).
        self.fill_account_outcomes(
            &self.scoped(caller.scope().authorizer.backend_grant()),
            &targets,
            proof,
            crate::gateway::meta_mcp::account_outcome::AccountWrites::PermanentOnly,
        )
        .await;
        for &(server, tool) in &targets {
            let Some(account) = self.target_account(
                &self.scoped(caller.scope().authorizer.backend_grant()),
                server,
                tool,
            ) else {
                continue;
            };
            if visible::memo::account_outcome(server, &account) != Some(AccountOutcome::Unavailable)
            {
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
#[path = "stored_proof_nonce_tests.rs"]
mod nonce_tests;
#[cfg(test)]
#[path = "stored_proof_tests.rs"]
mod tests;
