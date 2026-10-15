// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each target account's liveness for this caller, judged without a mint and
//! recorded once per request (MIK-8392). The async pre-pass fills the memo's
//! account outcomes; the synchronous sites after it only read them
//! ([`visible::account_outcome`]), and fail closed when one is missing.
//!
//! The account is the one the dispatch would use: an identity-propagation
//! backend's managed `account`, or a capability's `auth.account`. A target
//! with neither binds no per-user account, so it has nothing to judge here.

use crate::identity_propagation::CallerProof;
use crate::personal_accounts::ViewBinding;

use super::MetaMcp;
use super::visible::{self, AccountKey, AccountOutcome};

/// What a mint-free account judgement writes besides its outcome.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AccountWrites {
    /// A stored read's fill: a busy custody writes its one transient
    /// `idp_refuse` (the record the live call writes for the same state).
    All,
    /// A repeated task call's fill (#3892 review finding 6): the outcome is
    /// still recorded, so an unbindable caller's permanent refusal is kept,
    /// but a busy custody writes no `idp_refuse`: the repeat serves its
    /// stored output and refused nothing.
    PermanentOnly,
    /// Task intake for a capability account (MIK-8428): as `All`, and the
    /// transient is also carried in the request memo so the intake answers it.
    AllAndCarry,
}

impl MetaMcp {
    /// The account `server`'s `tool` dispatches under, if any.
    pub(crate) fn target_account(&self, server: &str, tool: &str) -> Option<AccountKey> {
        if let Some(backend) = self.backends.get(server)
            && backend.identity_propagation_config().is_some()
            && let Some(descriptor) = backend.account_descriptor_id()
        {
            return Some(AccountKey(descriptor.to_owned()));
        }
        let capabilities = self.get_capabilities()?;
        if server != capabilities.name {
            return None;
        }
        let account = capabilities.get(tool)?.auth.account.clone()?;
        Some(AccountKey(account))
    }

    /// Record each target's account outcome in the open request's memo.
    /// Infallible and idempotent: an outcome already recorded is not read
    /// again, and a failure to read custody is an outcome
    /// ([`AccountOutcome::Unavailable`]), never an error.
    pub(super) async fn fill_account_outcomes(
        &self,
        targets: &[(&str, &str)],
        caller: CallerProof<'_>,
        writes: AccountWrites,
    ) {
        for &(server, tool) in targets {
            let Some(account) = self.target_account(server, tool) else {
                continue;
            };
            if visible::account_outcome(server, &account).is_some() {
                continue;
            }
            // s2-d3 E5: a CLEAN resolution this request already holds (the
            // route stage's caller verdict, carried to the dispatch) proves
            // the account live; reading custody again would be a second read.
            // A carried resolution whose fill failed is no proof (E4): the
            // account is judged by its own read below.
            if visible::with_carried(server, tool, |carried| carried.fill_error.is_none())
                == Some(true)
            {
                visible::record_account_outcome(server, &account, AccountOutcome::Live);
                continue;
            }
            let outcome = self
                .judge_account((server, tool), &account, caller, writes)
                .await;
            visible::record_account_outcome(server, &account, outcome);
        }
    }

    /// Task intake for a capability account (MIK-8428): a capability
    /// target has no per-user backend, so the route stage's caller
    /// verdict never reads its account view (`caller_verdict` proceeds
    /// for a server without per-user catalogues). For a task-augmented
    /// call only, judge each such target's account mint-free here, after
    /// admission and before any task or key exists, so a busy custody is
    /// recorded through the same transient carrier the verdict uses and
    /// `task_intake_transient` answers it at intake. A target with a
    /// registry backend keeps its verdict and is skipped; a sync call
    /// never calls this, so it gains no extra read.
    pub(super) async fn judge_capability_accounts_for_task(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        caller: &super::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) {
        let scope = caller.scope();
        let targets = crate::gateway::router::backend_tool_targets_for_call(
            self,
            tool_name,
            arguments,
            visible::TargetView::Caller(scope, session_id),
        );
        for target in &targets {
            let target = target.as_target();
            let (server, tool) = (target.server, target.tool);
            if self.backends.get(server).is_some() {
                continue;
            }
            let Some(account) = self.target_account(server, tool) else {
                continue;
            };
            if visible::account_outcome(server, &account).is_some() {
                continue;
            }
            let outcome = self
                .judge_account(
                    (server, tool),
                    &account,
                    scope.caller,
                    AccountWrites::AllAndCarry,
                )
                .await;
            visible::record_account_outcome(server, &account, outcome);
        }
    }

    /// One account's outcome, read through the vault's mint-free view;
    /// `writes` selects what a busy custody also writes ([`AccountWrites`]).
    /// Only the task intake carries a transient into the request memo's
    /// transient slot (as the caller verdict records a view Busy); a stored
    /// read's fill does not, as nothing in that request dispatches.
    async fn judge_account(
        &self,
        (server, tool): (&str, &str),
        account: &AccountKey,
        caller: CallerProof<'_>,
        writes: AccountWrites,
    ) -> AccountOutcome {
        let Some(view) = self
            .account_strategies
            .view_binding_classified(&account.0, caller)
            .await
        else {
            return AccountOutcome::Unjudged;
        };
        if let ViewBinding::Bound(binding) = &view {
            visible::record_account_binding(server, account, binding);
        }
        let outcome = view_outcome(&view, |binding| {
            // A binding the isolation guard or the per-user slot rule would
            // refuse is no view either (as `has_no_view_for`). Only an
            // identity-propagation backend has those rules; a capability
            // account has none.
            self.backends.get(server).is_some_and(|backend| {
                backend.identity_propagation_config().is_some()
                    && (self.meta_route_isolation_refused_for_caller(&backend, Some(binding))
                        || !backend.fetch_carries_caller_identity(Some(binding)))
            })
        });
        // The stored read's one audit write for a busy custody, through the
        // same helper the live call uses (MIK-8392 Busy parity, gap-4).
        if outcome == AccountOutcome::Transient
            && writes != AccountWrites::PermanentOnly
            && let ViewBinding::Transient(error) = &view
        {
            if writes == AccountWrites::AllAndCarry {
                visible::record_account_transient(server, tool, error.to_string());
            }
            self.account_strategies
                .audit_transient_refusal(
                    self.transparency_logger.as_ref(),
                    &account.0,
                    caller,
                    &error.to_string(),
                )
                .await;
        }
        outcome
    }
}

/// A mint-free view read's outcome. A refusal a connect journey fixes
/// (absent, revoked, reconnect required, a changed descriptor) is no view;
/// a busy custody is transient; any other failure (shutting down, a store
/// error) proves nothing either way, so it is unavailable. `slot_refuses`
/// judges a binding the vault did hand back.
fn view_outcome(view: &ViewBinding, slot_refuses: impl FnOnce(&String) -> bool) -> AccountOutcome {
    match view {
        ViewBinding::Bound(binding) if slot_refuses(binding) => AccountOutcome::NoView,
        ViewBinding::Bound(_) => AccountOutcome::Live,
        ViewBinding::NoView(_) => AccountOutcome::NoView,
        ViewBinding::Transient(_) => AccountOutcome::Transient,
        ViewBinding::Unavailable(_) => AccountOutcome::Unavailable,
    }
}

#[cfg(test)]
#[path = "account_outcome_tests.rs"]
mod tests;
