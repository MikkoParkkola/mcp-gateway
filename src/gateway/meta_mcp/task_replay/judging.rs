// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a stored task result is judged before delivery: visibility, accounts,
//! provenance and current policy. Moved out of the parent to keep it under
//! the file-size ceiling; the bodies are unchanged, and `refuse_stored` is
//! `pub(super)` so the parent's two callers still reach it.

use serde_json::json;

use super::super::visible::{self, memo::AccountOutcome};
use super::super::{MetaMcp, MetaMcpCallerContext, error_response_preserving_status};
use super::{
    StoredAnswer, StoredEffect, StoredRead, StoredVisibility, StoredWithheld, retry_later,
};
use crate::gateway::task_service::CommittedTask;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result};

impl MetaMcp {
    pub(super) fn refuse_stored(
        &self,
        id: &RequestId,
        stored: &CommittedTask,
        (attestation, session): (Option<&str>, Option<&str>),
        caller: &MetaMcpCallerContext<'_>,
        read: StoredRead,
    ) -> Option<StoredAnswer> {
        let refused = |error: &Error| {
            StoredAnswer::new(
                StoredEffect::Refused,
                error_response_preserving_status(id.clone(), error),
            )
        };
        let unrecorded = |response| StoredAnswer::new(StoredEffect::Unrecorded, response);
        if !stored.serves_backend_output() {
            return None;
        }
        // A stored target whose backend is absent for a scoped
        // key answers as the live call does, the same for all three cells:
        // -32001 carrying the live call's own text, which
        // for an absent backend is the catalogue's miss text. An out-of-scope
        // one first writes the scope refusal the stored policy check writes
        // (an audit line only, no log record).
        let scoped = self.scoped(caller.scope().authorizer.backend_grant());
        for target in &stored.targets {
            let Some(absence) = scoped.absence(&target.server) else {
                continue;
            };
            // Out of the key's scope is a policy refusal; unregistered, a miss.
            let effect = if absence == super::super::scoped_backends::Absence::OutOfScope {
                let args = json!({"server": target.server, "tool": target.tool, "arguments": {}});
                let _ = self.check_visible_policy(&args, session, caller);
                StoredEffect::Refused
            } else {
                StoredEffect::Unrecorded
            };
            let missing = crate::backend::text_absent(&target.tool);
            return Some(StoredAnswer::new(
                effect,
                JsonRpcResponse::error(Some(id.clone()), -32001, missing),
            ));
        }
        // Visibility first, as on the live path: a Descriptor, Schema or Lacked
        // target answers as absent even where policy would also refuse.
        // A Refused target falls through to the policy check;
        // a cold one defers its retry until after policy and accounts, as the
        // live path fills a cold slot only after route policy.
        let (cold, caller_catalogue) = match self.judge_stored_visibility(stored, session, caller) {
            Err((error, effect)) => {
                return Some(StoredAnswer::new(
                    effect,
                    error_response_preserving_status(id.clone(), &error),
                ));
            }
            Ok(judged) => judged,
        };
        // Policy before accounts, as on the live path: route authorize before
        // caller verdicts, and the dispatch policy before its resolution.
        if let Err(error) = self.authorize_stored(stored, attestation, session, caller) {
            return Some(refused(&error));
        }
        // A removed backend answers as the live call does
        // (`BackendNotFound`, the invoke path's answer for an unknown
        // server), after policy, as the live call refuses on policy before
        // it dispatches.
        if let Some(error) = self.unknown_server_refusal(
            &self.scoped(caller.scope().authorizer.backend_grant()),
            stored,
        ) {
            return Some(unrecorded(error_response_preserving_status(
                id.clone(),
                &error,
            )));
        }
        // The stored output only under the bindings that produced
        // it, judged for a read and a repeat alike (a repeat's site-5 proof
        // proves the CURRENT account, never the recorded one).
        // A stored output the gateway will not serve under today's bindings
        // is its refusal.
        if let Err(error) = self.judge_stored_provenance(stored, caller) {
            return Some(refused(&error));
        }
        if let Err(withheld) = self.judge_stored_accounts(
            &self.scoped(caller.scope().authorizer.backend_grant()),
            stored,
            read,
        ) {
            // An account that cannot be used is availability, not policy.
            return Some(unrecorded(match withheld {
                StoredWithheld::Retry(after) => retry_later(id, after),
                StoredWithheld::Refused(error) => {
                    error_response_preserving_status(id.clone(), &error)
                }
            }));
        }
        // The caller's own catalogue is judged after its account, as the
        // live caller verdict resolves the credential before it reads the
        // caller's slot.
        if let Some((error, effect)) = caller_catalogue {
            return Some(StoredAnswer::new(
                effect,
                error_response_preserving_status(id.clone(), &error),
            ));
        }
        if let Some(after) = cold {
            return Some(unrecorded(retry_later(id, after)));
        }
        // The error-rate cooldown of a per-user tool is met last,
        // as on the live call (it waits for the credential step): a caller
        // with no view of the tool has already been answered as a missing
        // name above, so the cooldown cannot tell it the tool exists. A
        // repeat never judges accounts and is answered by site 5.
        if read == StoredRead::Read && self.deferred_cooldown_refuses(stored, session, caller) {
            return Some(unrecorded(retry_later(id, None)));
        }
        // COLLUDE.1 §13.3: a stored result or pending prompt delivered again
        // renews the reader's receipt; the delivery owner commits it.
        self.stage_stored_receipt(caller.relay_caller(session), caller.api_key_name, stored);
        None
    }

    /// Each recorded target against this caller's current catalogue:
    /// through the one judgement [`MetaMcp::stored_target_view`], refused
    /// through the one guard [`visible::memo::absent_if_withheld`], except a Refused
    /// view, which falls through to [`Self::authorize_stored`]. A cold view
    /// defers its retry until after policy and accounts; the first cold lease,
    /// if any, is returned for the caller to answer then.
    fn judge_stored_visibility(
        &self,
        stored: &CommittedTask,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> std::result::Result<StoredVisibility, (Error, StoredEffect)> {
        let scope = caller.scope();
        let mut cold: Option<Option<std::time::Duration>> = None;
        let mut caller_catalogue: Option<(Error, StoredEffect)> = None;
        for target in &stored.targets {
            let (server, tool) = (target.server.as_str(), target.tool.as_str());
            let Some(judged) = self.stored_target_view(server, tool, scope, session) else {
                if cold.is_none() {
                    cold = Some(self.cold_lease_remaining(server, caller));
                }
                continue;
            };
            // A Refused view is policy, not visibility: it falls through to
            // `authorize_stored`, so the read refuses as the live call does
            // and writes its record.
            if judged == visible::Visibility::Withheld(visible::Withholding::Refused) {
                continue;
            }
            // A per-user backend's Lacked or Schema verdict is the caller's
            // own catalogue's: the live caller verdict reads it only after
            // the account resolves, so it is answered after the account
            // judgement. A descriptor block, or a shared catalogue's verdict,
            // is answered now, before policy (T12).
            let own_catalogue = self.keeps_per_user_catalogues(server)
                && matches!(
                    judged,
                    visible::Visibility::Withheld(
                        visible::Withholding::Lacked | visible::Withholding::Schema
                    )
                );
            if own_catalogue {
                if caller_catalogue.is_none() {
                    caller_catalogue = visible::memo::absent_if_withheld(Some(judged), tool)
                        .err()
                        .map(|error| (error, StoredEffect::of(judged)));
                }
                continue;
            }
            visible::memo::absent_if_withheld(Some(judged), tool)
                .map_err(|error| (error, StoredEffect::of(judged)))?;
        }
        Ok((cold, caller_catalogue))
    }

    /// The live call's answer for a target whose server is neither a
    /// registered backend nor the capability provider offering that tool:
    /// `BackendNotFound`, the invoke path's answer for an
    /// unknown server (`dispatch.rs` answers it when no backend was
    /// captured). A capability tool still judges through the catalogue and
    /// policy path; a personal-account backend that was removed answers
    /// here too, as its live call does.
    fn unknown_server_refusal(
        &self,
        view: &crate::gateway::meta_mcp::scoped_backends::ScopedBackends<'_>,
        stored: &CommittedTask,
    ) -> Option<Error> {
        for target in &stored.targets {
            let (server, tool) = (target.server.as_str(), target.tool.as_str());
            if view.scoped_get(server).is_some() {
                continue;
            }
            let offered = self
                .get_capabilities()
                .is_some_and(|cap| cap.name == server && cap.get(tool).is_some());
            if !offered {
                return Some(Error::BackendNotFound(server.to_string()));
            }
        }
        None
    }

    /// Each recorded target's account (task reads only) as the pre-pass
    /// recorded it. Runs after [`Self::authorize_stored`], as the
    /// live path refuses on policy before the account/caller verdict: route
    /// authorize before caller verdicts, and the dispatch policy before its
    /// resolution.
    fn judge_stored_accounts(
        &self,
        view: &crate::gateway::meta_mcp::scoped_backends::ScopedBackends<'_>,
        stored: &CommittedTask,
        read: StoredRead,
    ) -> std::result::Result<(), StoredWithheld> {
        if read != StoredRead::Read {
            return Ok(());
        }
        for target in &stored.targets {
            let (server, tool) = (target.server.as_str(), target.tool.as_str());
            let Some(account) = self.target_account(view, server, tool) else {
                continue;
            };
            let outcome = visible::memo::account_outcome(server, &account);
            if outcome.is_none() {
                self.unfilled_outcome_read(server);
            }
            match outcome {
                // Unfilled: the pre-pass never ran for it. Fail closed,
                // and retryable: nothing about the grant was learned.
                None | Some(AccountOutcome::Unavailable) => {
                    return Err(visible::memo::take_account_refusal(server, &account)
                        .map_or(StoredWithheld::Retry(None), StoredWithheld::Refused));
                }
                // A busy custody: the same retryable answer the live call
                // gives, never a permanent refusal.
                Some(AccountOutcome::Transient) => {
                    return Err(StoredWithheld::Retry(None));
                }
                Some(AccountOutcome::NoView) => {
                    return Err(StoredWithheld::Refused(visible::absent::absent_name(tool)));
                }
                Some(AccountOutcome::Live | AccountOutcome::Unjudged) => {}
            }
        }
        Ok(())
    }

    /// A row written before bindings were recorded has no provenance, so its
    /// backend output is refused (design r4 E4); the row and its key stay
    /// held. Any other row: each recorded binding against the target's now.
    fn judge_stored_provenance(
        &self,
        stored: &CommittedTask,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Result<()> {
        if !stored.bindings_recorded {
            let server = stored
                .targets
                .first()
                .map_or(stored.task.tool(), |target| target.server.as_str());
            return Err(super::super::stored_binding::Refusal::Legacy.error(server));
        }
        self.judge_bindings(
            &self.scoped(caller.scope().authorizer.backend_grant()),
            &stored.bindings,
        )
    }

    fn authorize_stored(
        &self,
        stored: &CommittedTask,
        attestation: Option<&str>,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Result<()> {
        if stored.targets.is_empty() {
            // A recording gateway's empty list means nothing was planned or
            // attempted (`Record::targets`).
            // An older row's empty list means it has no upstream descriptor to
            // name its call (`CommittedTask::of`): `task.tool()` is the meta
            // tool, and the backend's current list is no record of what ran, so
            // nothing can prove the caller may read it. Refused, plan or not:
            // fail closed.
            return if stored.targets_recorded {
                Ok(())
            } else {
                Err(Error::Forbidden {
                    code: -32003,
                    status: 403,
                    message: "stored task result has no recorded provenance".to_owned(),
                })
            };
        }
        // A poll that meets the same decision again is not written
        // again inside the window (`grant_audit` module docs).
        // Explicit identity fields, JSON-encoded so no value can
        // forge a separator. A subject's label is display only, so it is not
        // part of the caller; a Debug rendering would carry it.
        let task_and_caller = json!([
            stored.task.id(),
            caller.api_key_name,
            caller
                .grant_subject
                .as_ref()
                .map(|s| [s.authority.as_str(), s.subject.as_str()]),
            caller.agent_id.map(|a| (a.as_str(), a.proof())),
        ])
        .to_string();
        super::super::grant_audit::in_repeat_scope(&self.grant_repeats, task_and_caller, || {
            // Names only: no current policy reads a target's arguments.
            for target in &stored.targets {
                let args = super::super::upstream::recovery_policy_args(
                    &target.server,
                    &target.tool,
                    &json!({}),
                    attestation,
                );
                self.check_visible_policy(&args, session, caller)?;
            }
            Ok(())
        })
    }
}
