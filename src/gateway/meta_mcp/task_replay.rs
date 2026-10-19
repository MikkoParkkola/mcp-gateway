// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored task result is re-authorized before it is delivered (#2450).
//!
//! `tasks/get` and a repeated task-augmented call both hand back a result the
//! caller already owns. Neither may do so once current policy blocks the calls
//! that produced it, the way a synchronous replay is refused (#2445).

mod receipts;

use serde_json::json;

use super::visible::{self, AccountOutcome};
use super::{MetaMcp, MetaMcpCallerContext, error_response_preserving_status};
use crate::gateway::task_service::CommittedTask;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result};

impl MetaMcp {
    /// The refusal for delivering `stored` on a task read (tasks/get, a
    /// notification frame), or `None` when it may go out.
    ///
    /// A terminal task's output and a parked task's pending input requests
    /// (#2466) are both backend output, so both are checked. A working or
    /// cancelled task delivers none. `attestation` is the token this request
    /// presents. The request's account outcomes must already be filled by
    /// [`Self::prepare_stored_read`] (MIK-8392); a missing one answers
    /// retryable, never the output.
    pub(crate) fn refuse_stored_delivery(
        &self,
        id: &RequestId,
        stored: &CommittedTask,
        attestation: Option<&str>,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        self.refuse_stored(id, stored, (attestation, session), caller, StoredRead::Read)
    }

    /// [`Self::refuse_stored_delivery`] for a repeated task-augmented call
    /// (`BeginOutcome::Existing`). Its catalogue is judged here; its accounts
    /// are not: a call has a live path, so an account that is not live is
    /// answered by that call's own resolution after this returns `None`
    /// (MIK-8392 site-5 split, lead ruling 2026-10-12).
    pub(crate) fn refuse_stored_repeat(
        &self,
        id: &RequestId,
        stored: &CommittedTask,
        attestation: Option<&str>,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        self.refuse_stored(
            id,
            stored,
            (attestation, session),
            caller,
            StoredRead::RepeatedCall,
        )
    }

    /// Fill this request's account outcomes for `stored`'s targets, the
    /// async half of a stored read (MIK-8392): every read entry awaits this
    /// inside the request's memo, then judges synchronously. `scope` is this
    /// request's live policy caller, so a cold claim already refused without
    /// the caller's catalogue is skipped before it resolves (F4).
    pub(crate) async fn prepare_stored_read(
        &self,
        stored: &CommittedTask,
        scope: super::visibility::InvokeScope<'_>,
        session_id: Option<&str>,
    ) {
        self.prepare_stored_read_kind(stored, scope, session_id, StoredRead::Read)
            .await;
    }

    /// The repeat's pre-pass: its accounts are judged live and
    /// [`Self::judge_stored_accounts`] skips a `RepeatedCall`, so the account
    /// fill still runs (one custody read, so an unbindable caller's permanent
    /// refusal is kept) but with `AccountWrites::PermanentOnly`: a busy
    /// custody writes no transient `idp_refuse`. The catalogue refresh below
    /// it still runs, as the repeat's visibility judgement reads it.
    pub(super) async fn prepare_repeated_call(
        &self,
        stored: &CommittedTask,
        scope: super::visibility::InvokeScope<'_>,
        session_id: Option<&str>,
    ) {
        self.prepare_stored_read_kind(stored, scope, session_id, StoredRead::RepeatedCall)
            .await;
    }

    async fn prepare_stored_read_kind(
        &self,
        stored: &CommittedTask,
        scope: super::visibility::InvokeScope<'_>,
        session_id: Option<&str>,
        read: StoredRead,
    ) {
        if !stored.serves_backend_output() {
            return;
        }
        let caller = scope.caller;
        let targets = crate::gateway::task_service::Target::pairs(&stored.targets);
        #[cfg(test)]
        let targets: Vec<(&str, &str)> = targets
            .into_iter()
            .filter(|(server, _)| {
                self.backends.for_test().get(server).is_none_or(|backend| {
                    !backend
                        .skip_account_prepass
                        .load(std::sync::atomic::Ordering::SeqCst)
                })
            })
            .collect();
        // A target policy already refuses without any catalogue is never
        // account-judged (MIK-8392 seat finding 1): no custody read and no
        // audit write for it, as the live Step 0 does neither. Its answer
        // comes from the policy layers in `refuse_stored`, before accounts.
        // A repeat still fills (so an unbindable caller's permanent refusal
        // below is kept, Ub-repeat) but writes no busy `idp_refuse` here: a
        // busy account is answered by site 5's live resolution, which writes
        // the live call's one record (MIK-8392 STORED.2, R5).
        let writes = if read == StoredRead::RepeatedCall {
            super::account_outcome::AccountWrites::PermanentOnly
        } else {
            super::account_outcome::AccountWrites::All
        };
        let judged: Vec<(&str, &str)> = targets
            .iter()
            .copied()
            .filter(|&(server, tool)| {
                !self.target_refused_without_catalogue((server, tool), scope, session_id)
            })
            .collect();
        let view = self.scoped(scope.authorizer.backend_grant());
        self.fill_account_outcomes(&view, &judged, caller, writes)
            .await;
        for &(server, tool) in &targets {
            self.keep_permanent_refusal(&view, server, tool, caller)
                .await;
            self.settle_caller_view(server, tool, scope, session_id)
                .await;
            self.settle_shared_view((server, tool), scope, session_id)
                .await;
        }
    }

    /// An account that read unavailable because this caller can never bind
    /// it is refused for good: keep the live call's own answer, so the read
    /// answers it rather than "retry" (MIK-8392, lead ruling 2026-10-12).
    /// Busy, shutting-down and store failures stay retryable.
    async fn keep_permanent_refusal(
        &self,
        view: &crate::gateway::meta_mcp::scoped_backends::ScopedBackends<'_>,
        server: &str,
        tool: &str,
        caller: crate::identity_propagation::CallerProof<'_>,
    ) {
        let Some(account) = self.target_account(view, server, tool) else {
            return;
        };
        if visible::account_outcome(server, &account) != Some(AccountOutcome::Unavailable)
            || !self.account_strategies.unbindable(&account.0, caller)
        {
            return;
        }
        if let Some(refusal) = self.live_refusal(view, (server, tool), caller).await {
            visible::record_account_refusal(server, &account, refusal);
        }
    }

    /// The per-user half of a stored read (MIK-8392 B' and touch-on-read):
    /// a caller's live slot is touched so reading it keeps it from idle
    /// eviction; a cold one is re-established by the one reader that claims
    /// it, and only while its account reads live. Every other reader answers
    /// retryable until the lease ends.
    async fn settle_caller_view(
        &self,
        server: &str,
        tool: &str,
        scope: super::visibility::InvokeScope<'_>,
        session_id: Option<&str>,
    ) {
        let caller = scope.caller;
        let Some(backend) = self
            .scoped(scope.authorizer.backend_grant())
            .scoped_get(server)
        else {
            return;
        };
        if !backend.keeps_per_user_catalogues() {
            return;
        }
        // A Passthrough view can never warm (`remember_caller_slot` skips it)
        // and the stored read judges the shared catalogue for it: nothing to
        // claim or publish here.
        if backend.identity_propagation_config().is_some_and(|idp| {
            matches!(
                idp.strategy,
                crate::identity_propagation::PropagationStrategyKind::Passthrough
            )
        }) {
            return;
        }
        let Some(principal) = self.principal_for(&backend, caller) else {
            return;
        };
        let id = principal.stable_actor_id();
        if let Some(held) = backend.caller_slot_held(&id) {
            // d0 warm: revalidate against the binding the pre-pass's own
            // view read gave (no second vault read). A mismatch (a rotated
            // grant) forgets the entry, but only while it is still the one
            // seen here, so a lease claimed meanwhile survives.
            let current = self
                .target_account(&self.scoped(scope.authorizer.backend_grant()), server, tool)
                .and_then(|account| visible::account_binding(server, &account));
            if current.is_none_or(|current| current == held.binding()) {
                // MIK-8392 F2: a held catalogue past its TTL is stale, by
                // the same rule the live fill uses. Treat the view as cold:
                // forget, claim the lease and refresh through `warm_cold_view`
                // (one resolution per lease window), retryable meanwhile,
                // exactly as a cold view. A fresh catalogue touches and
                // stays warm: no extra resolution (C1, K1).
                if backend.has_cached_tools_for(Some(held.binding())) {
                    backend.touch_caller_slot(held.binding());
                    return;
                }
                backend.forget_caller_held(&id, &held);
            } else {
                #[cfg(test)]
                backend.after_warm_capture.pause().await;
                backend.forget_caller_held(&id, &held);
            }
        }
        let account = self
            .target_account(&self.scoped(scope.authorizer.backend_grant()), server, tool)
            .map(|account| visible::account_outcome(server, &account));
        // Only a live grant may re-establish a view (d1): a NoView entry is
        // reclaimed only on Live, and nothing is claimed while the account
        // is not proven (NoView, Unavailable, unfilled).
        let account_live = matches!(account, None | Some(Some(AccountOutcome::Live)));
        if !matches!(
            account,
            None | Some(Some(AccountOutcome::Live | AccountOutcome::Unjudged))
        ) {
            return;
        }
        if self.refused_without_catalogue(&backend, (server, tool), scope, session_id) {
            return;
        }
        if let crate::backend::ColdClaim::Won(generation) =
            backend.claim_cold_view(&id, COLD_RETRY_BACKOFF, account_live)
        {
            self.warm_cold_view((server, tool), &backend, caller, generation)
                .await;
        }
    }

    /// The shared half of a stored read (MIK-8392 F2): a shared catalogue
    /// past its TTL is refreshed through the live call's catalogue fill,
    /// under the gateway's credentials and no caller credential, before the
    /// read judges it — so a stored read can serve a withdrawn shared tool
    /// for at most one TTL. Only a stale HELD list refreshes: a
    /// never-populated shared catalogue keeps T9c (judged on the other
    /// reasons, no fill), and a cleared one keeps F5 (retryable, no fill).
    /// A failed refresh leaves the list stale, and the sync judgement
    /// answers retryable.
    async fn settle_shared_view(
        &self,
        (server, tool): (&str, &str),
        scope: super::visibility::InvokeScope<'_>,
        session_id: Option<&str>,
    ) {
        let Some(backend) = self
            .scoped(scope.authorizer.backend_grant())
            .scoped_get(server)
        else {
            return;
        };
        // Only backends whose stored read judges the shared catalogue:
        // those without per-user catalogues, plus Passthrough, which is
        // never indexed and judges shared (P1).
        let passthrough = backend.identity_propagation_config().is_some_and(|idp| {
            matches!(
                idp.strategy,
                crate::identity_propagation::PropagationStrategyKind::Passthrough
            )
        });
        if backend.keeps_per_user_catalogues() && !passthrough {
            return;
        }
        let (cached, _, _, fresh) = backend.cached_tools_view(None);
        if cached.is_none() || fresh {
            return;
        }
        // The same F4 guard as a cold claim: a read already refused without
        // the catalogue causes no gateway-credentialed listing.
        if self.refused_without_catalogue(&backend, (server, tool), scope, session_id) {
            return;
        }
        let _ = backend.tools_for_check(None, &[], true).await;
    }

    /// [`Self::refused_without_catalogue`] for any stored target, a
    /// capability-provider one with no registry backend included (seat
    /// finding 3): only the descriptor block needs the backend itself;
    /// `may_invoke` and dispatch admission decide from the name alone.
    fn target_refused_without_catalogue(
        &self,
        (server, tool): (&str, &str),
        scope: super::visibility::InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> bool {
        if let Some(backend) = self
            .scoped(scope.authorizer.backend_grant())
            .scoped_get(server)
        {
            self.refused_without_catalogue(&backend, (server, tool), scope, session_id)
        } else {
            if self.may_invoke(server, tool, scope, session_id).is_err() {
                return true;
            }
            let call = super::invoke::dispatch_guards::BackendCall {
                server,
                tool,
                session_id,
                api_key_name: scope.api_key_name,
                cost_key: None,
                trace_id: "",
                caller_key: None,
            };
            // MIK-8475: an account-bearing capability waits for the
            // credential step too.
            let view = self.scoped(scope.authorizer.backend_grant());
            if self.defers_error_rate_cooldown(&view, server, tool) {
                self.admit_named_target(&call).is_err()
            } else {
                self.admit_target(&call).is_err()
            }
        }
    }

    /// Whether a recorded target whose cooldown waits for the credential
    /// step is refused by the dispatch admission (the error-rate cooldown
    /// included, auto-recovery with it).
    fn deferred_cooldown_refuses(
        &self,
        stored: &CommittedTask,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> bool {
        let view = self.scoped(caller.scope().authorizer.backend_grant());
        stored.targets.iter().any(|target| {
            self.defers_error_rate_cooldown(&view, &target.server, &target.tool)
                && self
                    .admit_target(&super::invoke::dispatch_guards::BackendCall {
                        server: &target.server,
                        tool: &target.tool,
                        session_id,
                        api_key_name: caller.api_key_name,
                        cost_key: caller.cost_key(),
                        trace_id: "",
                        caller_key: None,
                    })
                    .is_err()
        })
    }

    /// MIK-8392 F4: whether `server`'s `tool` is refused for this caller
    /// without reading any catalogue: descriptor-blocked, refused by the
    /// invocation policy (the silent check the name judgement uses), or by
    /// the dispatch admission (the kill switch). A read so refused triggers
    /// no credential resolution and no backend listing; the sync judgement
    /// still answers it, with its audit record.
    fn refused_without_catalogue(
        &self,
        backend: &crate::backend::Backend,
        (server, tool): (&str, &str),
        scope: super::visibility::InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> bool {
        if backend.is_blocked_tool(tool)
            || self.may_invoke(server, tool, scope, session_id).is_err()
        {
            return true;
        }
        let call = super::invoke::dispatch_guards::BackendCall {
            server,
            tool,
            session_id,
            api_key_name: scope.api_key_name,
            cost_key: None,
            trace_id: "",
            caller_key: None,
        };
        // MIK-8474: on a per-user backend the error-rate cooldown waits for
        // the credential step, as the live call's policy has it (MIK-8439).
        // Skipping the target for it left it unfilled, so a caller with no
        // view got "retry" where a missing name gets "absent". The read
        // answers the cooldown last (`deferred_cooldown_refuses`).
        let view = self.scoped(scope.authorizer.backend_grant());
        if self.defers_error_rate_cooldown(&view, server, tool) {
            self.admit_named_target(&call).is_err()
        } else {
            self.admit_target(&call).is_err()
        }
    }

    /// A stored read found no account outcome for `server`'s target: every
    /// read entry runs the pre-pass first, so this is a broken invariant
    /// (MIK-8392 N0). It still fails closed; tests observe it by count.
    ///
    /// The registry is read only in test builds, for the count: production
    /// reports the invariant and reads nothing (MIK-8387 PR-B commit 3).
    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "the registry is read only in test builds"
        )
    )]
    fn unfilled_outcome_read(&self, server: &str) {
        #[cfg(test)]
        if let Some(backend) = self.backends.for_test().get(server) {
            backend
                .unfilled_outcome_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        tracing::error!(server, "stored read without the account pre-pass");
    }

    /// What is left of `caller`'s running cold lease on `server`, if one runs.
    fn cold_lease_remaining(
        &self,
        server: &str,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<std::time::Duration> {
        let backend = self
            .scoped(caller.scope().authorizer.backend_grant())
            .scoped_get(server)?;
        let proof = crate::identity_propagation::CallerProof::new(
            caller.verified_identity,
            caller.provenance(),
        );
        let principal = self.principal_for(&backend, proof)?;
        backend.cold_lease_remaining(&principal.stable_actor_id())
    }

    fn refuse_stored(
        &self,
        id: &RequestId,
        stored: &CommittedTask,
        (attestation, session): (Option<&str>, Option<&str>),
        caller: &MetaMcpCallerContext<'_>,
        read: StoredRead,
    ) -> Option<JsonRpcResponse> {
        if !stored.serves_backend_output() {
            return None;
        }
        // MIK-8387 S7: a stored target whose backend is absent for a scoped
        // key answers as the live call does, the same for all three cells:
        // -32001 carrying the live call's own text (MIK-8392 F1 ruling), which
        // for an absent backend is the catalogue's miss text. An out-of-scope
        // one first writes the scope refusal the stored policy check writes
        // (an audit line only, no log record).
        let scoped = self.scoped(caller.scope().authorizer.backend_grant());
        for target in &stored.targets {
            let Some(absence) = scoped.absence(&target.server) else {
                continue;
            };
            if absence == super::scoped_backends::Absence::OutOfScope {
                let args = json!({"server": target.server, "tool": target.tool, "arguments": {}});
                let _ = self.check_visible_policy(&args, session, caller);
            }
            let missing = crate::backend::text_absent(&target.tool);
            return Some(JsonRpcResponse::error(Some(id.clone()), -32001, missing));
        }
        // Visibility first, as on the live path: a Descriptor, Schema or Lacked
        // target answers as absent even where policy would also refuse
        // (MIK-8392 T12). A Refused target falls through to the policy check;
        // a cold one defers its retry until after policy and accounts, as the
        // live path fills a cold slot only after route policy.
        let (cold, caller_catalogue) = match self.judge_stored_visibility(stored, session, caller) {
            Err(error) => return Some(error_response_preserving_status(id.clone(), &error)),
            Ok(judged) => judged,
        };
        // Policy before accounts, as on the live path: route authorize before
        // caller verdicts, and the dispatch policy before its resolution.
        if let Err(error) = self.authorize_stored(stored, attestation, session, caller) {
            return Some(error_response_preserving_status(id.clone(), &error));
        }
        // MIK-8392 F1: a removed backend answers as the live call does
        // (`BackendNotFound`, the invoke path's answer for an unknown
        // server), after policy, as the live call refuses on policy before
        // it dispatches.
        if let Some(error) = self.unknown_server_refusal(
            &self.scoped(caller.scope().authorizer.backend_grant()),
            stored,
        ) {
            return Some(error_response_preserving_status(id.clone(), &error));
        }
        if let Err(withheld) = self.judge_stored_accounts(
            &self.scoped(caller.scope().authorizer.backend_grant()),
            stored,
            read,
        ) {
            return Some(match withheld {
                StoredWithheld::Retry(after) => retry_later(id, after),
                StoredWithheld::Refused(error) => {
                    error_response_preserving_status(id.clone(), &error)
                }
            });
        }
        // The caller's own catalogue is judged after its account, as the
        // live caller verdict resolves the credential before it reads the
        // caller's slot (MIK-8392 Ub).
        if let Some(error) = caller_catalogue {
            return Some(error_response_preserving_status(id.clone(), &error));
        }
        if let Some(after) = cold {
            return Some(retry_later(id, after));
        }
        // MIK-8474: the error-rate cooldown of a per-user tool is met last,
        // as on the live call (it waits for the credential step): a caller
        // with no view of the tool has already been answered as a missing
        // name above, so the cooldown cannot tell it the tool exists. A
        // repeat never judges accounts and is answered by site 5.
        if read == StoredRead::Read && self.deferred_cooldown_refuses(stored, session, caller) {
            return Some(retry_later(id, None));
        }
        // COLLUDE.1 §13.3: a stored result or pending prompt delivered again
        // renews the reader's receipt; the delivery owner commits it.
        self.stage_stored_receipt(caller.relay_caller(session), caller.api_key_name, stored);
        None
    }

    /// Each recorded target against this caller's current catalogue (MIK-8392):
    /// through the one judgement [`MetaMcp::stored_target_view`], refused
    /// through the one guard [`visible::absent_if_withheld`], except a Refused
    /// view, which falls through to [`Self::authorize_stored`]. A cold view
    /// defers its retry until after policy and accounts; the first cold lease,
    /// if any, is returned for the caller to answer then.
    fn judge_stored_visibility(
        &self,
        stored: &CommittedTask,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> std::result::Result<StoredVisibility, Error> {
        let scope = caller.scope();
        let mut cold: Option<Option<std::time::Duration>> = None;
        let mut caller_catalogue: Option<Error> = None;
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
            // and writes its record (MIK-8392 lead ruling 2026-10-12).
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
                    caller_catalogue = visible::absent_if_withheld(Some(judged), tool).err();
                }
                continue;
            }
            visible::absent_if_withheld(Some(judged), tool)?;
        }
        Ok((cold, caller_catalogue))
    }

    /// The live call's answer for a target whose server is neither a
    /// registered backend nor the capability provider offering that tool:
    /// `BackendNotFound` (MIK-8392 F1), the invoke path's answer for an
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
    /// recorded it (MIK-8392). Runs after [`Self::authorize_stored`], as the
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
            let outcome = visible::account_outcome(server, &account);
            if outcome.is_none() {
                self.unfilled_outcome_read(server);
            }
            match outcome {
                // Unfilled: the pre-pass never ran for it. Fail closed,
                // and retryable: nothing about the grant was learned.
                None | Some(AccountOutcome::Unavailable) => {
                    return Err(visible::take_account_refusal(server, &account)
                        .map_or(StoredWithheld::Retry(None), StoredWithheld::Refused));
                }
                // A busy custody: the same retryable answer the live call
                // gives (MIK-8392 Busy parity), never a permanent refusal.
                Some(AccountOutcome::Transient) => {
                    return Err(StoredWithheld::Retry(None));
                }
                Some(AccountOutcome::NoView) => {
                    return Err(StoredWithheld::Refused(visible::absent_name(tool)));
                }
                Some(AccountOutcome::Live | AccountOutcome::Unjudged) => {}
            }
        }
        Ok(())
    }

    fn authorize_stored(
        &self,
        stored: &CommittedTask,
        attestation: Option<&str>,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Result<()> {
        if stored.targets.is_empty() {
            // A recording gateway's empty list means nothing was dispatched.
            // An older row's empty list means it has no upstream descriptor to
            // name its call (`CommittedTask::of`): `task.tool()` is the meta
            // tool, and the backend's current list is no record of what ran, so
            // nothing can prove the caller may read it. Refused, plan or not
            // (MIK-7686, fail closed).
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
        // MIK-7692: a poll that meets the same decision again is not written
        // again inside the window (`grant_audit` module docs).
        // MIK-7826: explicit identity fields, JSON-encoded so no value can
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
        super::grant_audit::in_repeat_scope(&self.grant_repeats, task_and_caller, || {
            // Names only: no current policy reads a target's arguments.
            for target in &stored.targets {
                let args = super::upstream::recovery_policy_args(
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

/// How long a claimed attempt to re-establish a cold view holds before
/// another reader may try (MIK-8392 B'): the idle reaper's own sweep, so a
/// cold state outlasts eviction by at most one sweep, and an outage costs at
/// most one resolution per caller per backend per minute.
const COLD_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);

/// Which stored delivery is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoredRead {
    /// A task read: tasks/get or a notification frame.
    Read,
    /// A repeated task-augmented call: its accounts are judged live.
    RepeatedCall,
}

/// A stored read's visibility verdict that is answered later: the first cold
/// view's remaining lease (retry), and the first refusal by the caller's own
/// per-user catalogue (answered after the account judgement).
type StoredVisibility = (Option<Option<std::time::Duration>>, Option<Error>);

/// Why a stored delivery does not go out.
enum StoredWithheld {
    /// Its target is withheld from this caller: the absent answer.
    Refused(Error),
    /// This caller's view is not settled yet: retry, never terminal. While
    /// a cold lease runs, what is left of it.
    Retry(Option<std::time::Duration>),
}

/// The retryable answer (MIK-8392 s1-d1, Busy parity): built through the
/// one sealed transient builder the live call also uses, converted the
/// same way, so the two error objects are byte-equal apart from the id.
/// It carries no output.
fn retry_later(id: &RequestId, after: Option<std::time::Duration>) -> JsonRpcResponse {
    error_response_preserving_status(
        id.clone(),
        &crate::personal_accounts::refusal::transient_retry_error(after),
    )
}

#[cfg(test)]
#[path = "stored_read_prepass_tests.rs"]
mod prepass_tests;
