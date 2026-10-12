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

use crate::identity_propagation::{CallerProof, PropagationError};

use super::MetaMcp;
use super::visible::{self, AccountKey, AccountOutcome};

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
    pub(crate) async fn fill_account_outcomes(
        &self,
        targets: &[(&str, &str)],
        caller: CallerProof<'_>,
    ) {
        for &(server, tool) in targets {
            let Some(account) = self.target_account(server, tool) else {
                continue;
            };
            if visible::account_outcome(server, &account).is_some() {
                continue;
            }
            let outcome = self.judge_account(server, &account, caller).await;
            visible::record_account_outcome(server, &account, outcome);
        }
    }

    /// One account's outcome, read through the vault's mint-free view.
    async fn judge_account(
        &self,
        server: &str,
        account: &AccountKey,
        caller: CallerProof<'_>,
    ) -> AccountOutcome {
        let Some(view) = self
            .account_strategies
            .view_binding_checked(&account.0, caller)
            .await
        else {
            return AccountOutcome::Unjudged;
        };
        match view {
            Ok(binding) => {
                // A binding the isolation guard or the per-user slot rule
                // would refuse is no view either (as `has_no_view_for`). Only
                // an identity-propagation backend has those rules; a
                // capability account has none.
                let refused = self.backends.get(server).is_some_and(|backend| {
                    backend.identity_propagation_config().is_some()
                        && (self.meta_route_isolation_refused_for_caller(&backend, Some(&binding))
                            || !backend.fetch_carries_caller_identity(Some(&binding)))
                });
                if refused {
                    AccountOutcome::NoView
                } else {
                    AccountOutcome::Live
                }
            }
            Err(
                PropagationError::AccountNotConnected(_)
                | PropagationError::AccountReconnectRequired(_),
            ) => AccountOutcome::NoView,
            Err(_) => AccountOutcome::Unavailable,
        }
    }
}
