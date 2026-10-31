// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The caller verdict on a per-user backend (MIK-8356 design R5): a call is
//! judged by the caller's own catalogue slot, never by the shared one, and a
//! name that slot withholds or lacks answers as an absent name.
//!
//! Taken once per request and recorded in the visibility memo, so every
//! reader after the firewall (confirmation, chain refusal, admission, task
//! routing) sees the caller's own answer. Its credential resolution is
//! carried to the dispatch, so a call resolves once.

use crate::backend::{Backend, CatalogueVerdict};
use crate::identity_propagation::CallerProof;

use super::super::refund_witness::RefundWitness;

use super::super::visible::{self, Visibility, Withholding, memo};
use super::super::{MetaMcp, MetaMcpCallerContext};

/// What a caller verdict decided.
#[derive(Debug)]
pub(crate) enum CallerVerdict {
    /// Not a per-user target, policy or the descriptor already decides it,
    /// or this caller's catalogue offers it (or cannot vouch either way):
    /// the call proceeds and the existing checks answer.
    Proceed,
    /// The caller's catalogue withholds or lacks it: answer as absent.
    Absent,
    /// The fill under the caller's credential failed. The resolution is
    /// carried; the dispatch's own check answers the failure as a failed
    /// dispatch (backend unavailable, with managed-401 recovery).
    Unavailable,
    /// The mint-free view read met a busy custody (MIK-8392 Busy parity):
    /// the busy is carried in the request memo and the dispatch answers
    /// the one retryable transient answer, with no second custody read.
    Transient,
}

/// How a call named its per-user target. It decides what a caller with no
/// view of the backend is told (MIK-6745 consent-journey design, section 9.2,
/// predicate D).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetNaming {
    /// A surfaced tool called by its own name: no backend is named, so a
    /// caller with no view lacks it and the call answers as absent.
    SurfacedName,
    /// `gateway_invoke`, a chain step or a playbook step naming the backend:
    /// the dispatch keeps the account's connect offer, the same for every
    /// tool name on it.
    ExplicitBackend,
}

impl TargetNaming {
    /// How the request named `server`'s `tool`: a surfaced name when the
    /// call's own name is that surfaced tool.
    pub(crate) fn of(meta: &MetaMcp, tool_name: &str, (server, tool): (&str, &str)) -> Self {
        if tool == tool_name && meta.surfaced_server_unscoped(tool_name) == Some(server) {
            Self::SurfacedName
        } else {
            Self::ExplicitBackend
        }
    }
}

/// What [`MetaMcp::judge_caller_slot`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SlotJudgement {
    Offered,
    Absent,
    Unknown,
}

impl MetaMcp {
    /// The request half of re-establishing a cold view (MIK-8392 B', d1):
    /// resolve the caller's own credential and binding for the won claim
    /// `attempt`, so the fill can run inline or as its own task. `None` when
    /// nothing resolves: the attempt settles, the lease stays as the retry
    /// backoff and the view stays cold.
    pub(in crate::gateway::meta_mcp) async fn resolve_cold_view(
        &self,
        (server, tool): (&str, &str),
        attempt: ColdAttempt,
        caller: CallerProof<'_>,
    ) -> Option<ColdFill> {
        #[cfg(test)]
        attempt.backend.cold_winner.pause().await;
        let resolved = self
            .resolve_dispatch(
                (server, tool),
                Some(attempt.backend.as_ref()),
                caller,
                caller.verified(),
            )
            .await
            .ok()?;
        Some(ColdFill {
            binding: resolved.binding?,
            headers: resolved.caller_credential.lent(),
            attempt,
        })
    }

    /// The live call's own refusal for `caller` on `(server, tool)`: the
    /// error `resolve_dispatch` answers, or `None` when it resolves. A stored
    /// read uses it for a refusal that never changes (MIK-8392, lead ruling
    /// 2026-10-12), so it answers exactly what the live call answers. It runs
    /// what a live call runs, including the refusal's audit record.
    pub(in crate::gateway::meta_mcp) async fn live_refusal(
        &self,
        view: &crate::gateway::meta_mcp::scoped_backends::ScopedBackends<'_>,
        (server, tool): (&str, &str),
        caller: CallerProof<'_>,
    ) -> Option<crate::Error> {
        let backend = view.scoped_get(server);
        self.resolve_dispatch(
            (server, tool),
            backend.as_deref(),
            caller,
            caller.verified(),
        )
        .await
        .err()
    }

    /// The caller verdict for `(server, tool)`, taken right after route
    /// authorize and the firewall (R5.1). Idempotent within a request: a
    /// recorded answer is returned as is.
    ///
    /// `witness` is the call's refund witness (MIK-8353). It comes back only
    /// from an arm that contacted nothing: a memo hit, Step 0, no principal, or
    /// no view (each reads in-process state or the vault's stored grant, with
    /// no provider call and no durable write). A busy custody comes back too:
    /// a call refused before its backend was reached gives its nonce back
    /// (`invoke/nonce_settle.rs:27-31`), and an `idp_refuse` audit append is
    /// not an effect a replay would repeat, so it does not spend the witness.
    /// A resolution (which may mint, refresh or lease), a catalogue fill or a
    /// 401 refresh spends it, so a later refusal keeps the nonce spent.
    ///
    /// # Errors
    ///
    /// The credential resolution's own refusal (a connect offer, an
    /// unbound account backend).
    pub(crate) async fn caller_verdict(
        &self,
        (server, tool): (&str, &str),
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
        naming: TargetNaming,
        witness: Option<RefundWitness>,
    ) -> crate::Result<(CallerVerdict, Option<RefundWitness>)> {
        let Some(backend) = self
            .scoped(caller.scope().authorizer.backend_grant())
            .scoped_get(server)
            .filter(|backend| backend.keeps_per_user_catalogues())
        else {
            return Ok((CallerVerdict::Proceed, witness));
        };
        match memo::recorded_visibility(server, tool) {
            Some(Visibility::Visible) => return Ok((CallerVerdict::Proceed, witness)),
            Some(Visibility::Withheld(_)) => return Ok((CallerVerdict::Absent, witness)),
            None => {}
        }
        // Step 0 (R5.2): descriptor and policy first, with no fill and no
        // resolution. A name they withhold is answered by the existing
        // checks, which read the same judgement.
        if self.tool_visible_to(server, tool, caller.scope(), session_id) != Visibility::Visible {
            return Ok((CallerVerdict::Proceed, witness));
        }
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        // No principal on a required backend: no slot can hold this caller's
        // catalogue, so it lacks the tool, answered before any resolution.
        if self.lacks_principal_on_required(&backend, proof) {
            self.warn_lacked_principal(server, caller.caller_key);
            memo::record_visibility(server, tool, Visibility::Withheld(Withholding::Lacked));
            return Ok((CallerVerdict::Absent, witness));
        }
        // A managed account with no current grant has no view (R3.7). Nothing
        // is resolved here: resolving would create a consent journey. The
        // marker makes every later listing withhold the backend at once. A call
        // by surfaced name names no backend, so it lacks the tool and every
        // reader after this answers as absent; a dispatch naming the backend
        // proceeds to that account's connect offer, the same for every tool
        // name (MIK-6745 section 9.2, predicate D).
        // The route verdict's acting resolution already failed for this
        // target in this request (MIK-8392 G1a twin): a memo hit. The
        // dispatch answers the carried error; resolving here would read
        // custody and audit a second time.
        if memo::has_resolution_error(server, tool) {
            return Ok((CallerVerdict::Proceed, witness));
        }
        // A busy custody already met in this request (the route stage's
        // verdict, read again on a surfaced route): no second custody read
        // and no second audit record (MIK-8392 Busy parity).
        if memo::account_transient(server, tool).is_some() {
            return Ok((CallerVerdict::Transient, witness));
        }
        let no_view = match self.has_no_view_for_classified(&backend, proof).await {
            Ok(no_view) => no_view,
            Err(error) => {
                // A busy custody is not "no view": no marker is recorded,
                // nothing proceeds to the acting resolution. The witness
                // is kept, as on the no-view arm: this call reaches no
                // backend and its answer is retryable, so its nonce is
                // given back (`invoke/nonce_settle.rs:27-31`); the
                // `idp_refuse` append below is not an effect a replay
                // would repeat. The busy is carried request-local and
                // consumed once at the dispatch.
                let reason = error.to_string();
                memo::record_account_transient(server, tool, reason.clone());
                if let Some(account) = self.target_account(
                    &self.scoped(caller.scope().authorizer.backend_grant()),
                    server,
                    tool,
                ) {
                    memo::record_account_outcome(server, &account, memo::AccountOutcome::Transient);
                }
                if let Some(descriptor) = backend.account_descriptor_id() {
                    self.account_strategies
                        .audit_transient_refusal(
                            self.transparency_logger.as_ref(),
                            descriptor,
                            proof,
                            &reason,
                        )
                        .await;
                }
                return Ok((CallerVerdict::Transient, witness));
            }
        };
        if no_view {
            if let Some(principal) = self.principal_for(&backend, proof) {
                backend.record_no_view(&principal.stable_actor_id());
            }
            let verdict = match naming {
                TargetNaming::SurfacedName => {
                    memo::record_visibility(
                        server,
                        tool,
                        Visibility::Withheld(Withholding::Lacked),
                    );
                    CallerVerdict::Absent
                }
                TargetNaming::ExplicitBackend => CallerVerdict::Proceed,
            };
            return Ok((verdict, witness));
        }
        // Everything below may act: the resolution may mint, refresh or lease
        // the caller's credential, and the judgement fills the catalogue.
        // The witness is spent once the outcome is known, below: a sealed
        // transient (a busy custody at the view or the mint) released
        // nothing, so it alone returns the witness unspent for the nonce
        // refund (`nonce_settle.rs:27-31`); spending is only consuming the
        // token, so deferring it past the acting half changes nothing else.
        // Boxed: the acting half's state (resolution, fill, refresh) would
        // otherwise sit inline in every dispatch future that awaits a verdict,
        // refusals included (MIK-8400's allocation caps). It is allocated only
        // when a per-user call gets this far.
        match Box::pin(self.caller_verdict_acting(
            (server, tool),
            backend,
            proof,
            caller.verified_identity,
        ))
        .await
        {
            Ok(verdict) => {
                if let Some(witness) = witness {
                    witness.spend();
                }
                Ok((verdict, None))
            }
            // A sealed transient resolution error (MIK-8428 mint Busy):
            // carried to the dispatch here, witness unspent, so the call
            // is answered once and its nonce refunded like a view Busy.
            Err(error) if crate::personal_accounts::refusal::transient_data(&error).is_some() => {
                memo::record_resolution_error(server, tool, error);
                Ok((CallerVerdict::Proceed, witness))
            }
            Err(error) => {
                if let Some(witness) = witness {
                    witness.spend();
                }
                Err(error)
            }
        }
    }

    /// The caller verdict for each of one request's `targets`, in order, as
    /// the route stages take it (R5.1), threading the call's refund witness:
    /// it comes back only if no verdict acted. A refusal or a failed fill is
    /// answered by the dispatch.
    pub(crate) async fn caller_verdicts(
        &self,
        targets: &[crate::gateway::authz::CallTarget<'_>],
        tool_name: &str,
        (caller, session_id): (&MetaMcpCallerContext<'_>, Option<&str>),
        mut witness: Option<RefundWitness>,
    ) -> Option<RefundWitness> {
        for target in targets {
            let target = target.as_target();
            let (server, tool) = (target.server, target.tool);
            let naming = TargetNaming::of(self, tool_name, (server, tool));
            witness = match self
                .caller_verdict((server, tool), caller, session_id, naming, witness)
                .await
            {
                Ok((_, witness)) => witness,
                Err(error) => {
                    // The acting resolution failed (MIK-8392 G1a): carry
                    // its error to the dispatch so it answers without
                    // resolving (and auditing) again in this request.
                    // The witness stays spent, as the verdict spent it:
                    // the resolution may have minted.
                    memo::record_resolution_error(server, tool, error);
                    None
                }
            };
        }
        witness
    }

    /// The resolution an invocation dispatches under (MIK-8356 R5.2): the one
    /// a caller verdict taken earlier in this request carried (its backend
    /// instance and resolution, consumed by this invocation only), or a fresh
    /// one. `Break` is the call's answer. A carried resolution, failed fill or
    /// not, means the verdict acted, and a fresh resolution may mint or refresh
    /// before it fails: each spends `witness` (MIK-8353 3a). The no-principal
    /// arm resolves nothing and keeps it.
    pub(super) async fn dispatch_resolution(
        &self,
        view: &crate::gateway::meta_mcp::scoped_backends::ScopedBackends<'_>,
        (server, tool): (&str, &str),
        (caller_proof, verified_identity, caller_key): (
            CallerProof<'_>,
            Option<&crate::key_server::oidc::VerifiedIdentity>,
            Option<&str>,
        ),
        surface: crate::gateway::recovery::MetaSurface,
        witness: &mut super::nonce_settle::Witnessed<'_, '_>,
    ) -> crate::Result<
        std::ops::ControlFlow<
            super::GuardedValue,
            (Option<std::sync::Arc<Backend>>, super::ResolvedDispatch),
        >,
    > {
        use std::ops::ControlFlow::{Break, Continue};
        #[cfg(test)]
        dispatch_seam::dispatch_resolution_starts();
        // The verdict's busy custody, consumed once: the one retryable
        // transient answer, with no acting resolution and no mint — and
        // no second custody read in this request (MIK-8392 Busy parity).
        // The witness is kept: nothing reached the backend, so the nonce
        // is given back (`nonce_settle.rs:27-31`); the invoke asks for the
        // refund as it returns this error.
        if memo::take_account_transient(server, tool).is_some() {
            return Err(crate::personal_accounts::refusal::transient_retry_error(
                None,
            ));
        }
        // The verdict's acting resolution already failed in this request
        // (MIK-8392 G1a): answer its error, consumed once, without
        // resolving a second time. The witness is spent, as on the fresh
        // resolution's failure: that resolution may have minted. A sealed
        // transient is the one exception (MIK-8428): its mint-time Busy
        // released nothing, so the witness stays for the nonce refund.
        if let Some(error) = memo::take_resolution_error(server, tool) {
            if crate::personal_accounts::refusal::transient_data(&error).is_none() {
                witness.spend();
            }
            return Err(error);
        }
        match memo::take_carried(server, tool) {
            // The verdict's fill failed: answered as a failed dispatch is,
            // with nothing filled or sent again (F13, A11-c).
            Some(memo::Carried {
                fill_error: Some(error),
                ..
            }) => {
                witness.spend();
                let checked = (std::time::Instant::now(), surface);
                let value = self.account_refused_fill(server, tool, &error, checked);
                if crate::personal_accounts::refusal::marked(&error).is_some() {
                    return self.with_connect_offer(Err(error), verified_identity).await;
                }
                Ok(Break(super::GuardedValue::sealed_by_guard(value)))
            }
            Some(carried) => {
                witness.spend();
                Ok(Continue((Some(carried.backend), carried.resolved)))
            }
            None => {
                let backend = view.scoped_get(server);
                // No principal on a required per-user backend: an absent name,
                // answered before any resolution (lead ruling 2026-10-11).
                if backend
                    .as_deref()
                    .is_some_and(|b| self.lacks_principal_on_required(b, caller_proof))
                {
                    self.warn_lacked_principal(server, caller_key);
                    return Err(visible::absent::absent_name(tool));
                }
                let resolved = self
                    .resolve_dispatch(
                        (server, tool),
                        backend.as_deref(),
                        caller_proof,
                        verified_identity,
                    )
                    .await;
                // A failed resolution may have minted or refreshed before
                // it failed, so it spends the witness — except a sealed
                // transient (MIK-8428), whose busy custody released
                // nothing: the witness stays for the nonce refund.
                let resolved = match resolved {
                    Ok(resolved) => resolved,
                    Err(error) => {
                        if crate::personal_accounts::refusal::transient_data(&error).is_none() {
                            witness.spend();
                        }
                        return Err(error);
                    }
                };
                Ok(Continue((backend, resolved)))
            }
        }
    }

    /// The half of [`Self::caller_verdict`] that may act: resolve the
    /// caller's credential, judge the caller's slot (a fill), and carry the
    /// resolution to the dispatch.
    async fn caller_verdict_acting(
        &self,
        (server, tool): (&str, &str),
        backend: std::sync::Arc<Backend>,
        proof: CallerProof<'_>,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
    ) -> crate::Result<CallerVerdict> {
        let resolved = self
            .resolve_dispatch((server, tool), Some(&backend), proof, verified_identity)
            .await?;
        let judged = self
            .judge_caller_slot(
                (server, tool),
                &backend,
                resolved.binding.as_deref(),
                resolved.caller_credential.lent(),
                proof,
            )
            .await;
        let (verdict, fill_error) = match judged {
            Ok(SlotJudgement::Absent) => return Ok(CallerVerdict::Absent),
            Ok(_) => (CallerVerdict::Proceed, None),
            // A 401 on a managed credential forces its one refresh here, as
            // the dispatch's fill would (A11-c). The failure is carried: the
            // dispatch answers it as a failed dispatch, without a second fill.
            Err(error) => {
                let error = match resolved.caller_credential.managed.as_ref() {
                    Some(managed)
                        if crate::security::http_diagnostics::is_upstream_unauthorized(&error) =>
                    {
                        managed.after_upstream_401(error).await
                    }
                    _ => error,
                };
                (CallerVerdict::Unavailable, Some(error))
            }
        };
        memo::carry_dispatch(
            server,
            tool,
            memo::Carried {
                backend,
                resolved,
                fill_error,
            },
        );
        Ok(verdict)
    }

    /// Judge `tool` on the slot `binding` selects, record the answer in the
    /// request's memo and index the caller's slot. `Unknown` records nothing:
    /// the argument-key check decides, as before.
    ///
    /// # Errors
    ///
    /// The fill's error when the slot could not be listed.
    pub(super) async fn judge_caller_slot(
        &self,
        (server, tool): (&str, &str),
        backend: &Backend,
        binding: Option<&str>,
        headers: crate::transport::LentCredential,
        proof: CallerProof<'_>,
    ) -> crate::Result<SlotJudgement> {
        let verdict = backend.catalogue_verdict(binding, headers, tool).await;
        self.remember_caller_slot(backend, proof, binding).await;
        let (recorded, judgement) = match verdict? {
            CatalogueVerdict::Offers => (Some(Visibility::Visible), SlotJudgement::Offered),
            CatalogueVerdict::Withholds => {
                let reason = if backend.is_unselected(tool) {
                    Withholding::Unselected
                } else if backend.is_blocked_tool(tool) {
                    Withholding::Descriptor
                } else {
                    Withholding::Schema
                };
                (Some(Visibility::Withheld(reason)), SlotJudgement::Absent)
            }
            CatalogueVerdict::Lacks => (
                Some(Visibility::Withheld(Withholding::Lacked)),
                SlotJudgement::Absent,
            ),
            CatalogueVerdict::Unknown => (None, SlotJudgement::Unknown),
        };
        // First judgement wins: an answer recorded meanwhile stands.
        Ok(
            match recorded.map(|judged| memo::record_visibility(server, tool, judged)) {
                Some(Visibility::Visible) => SlotJudgement::Offered,
                Some(Visibility::Withheld(_)) => SlotJudgement::Absent,
                None => judgement,
            },
        )
    }
}

#[cfg(test)]
#[path = "caller_verdict_outcome_tests.rs"]
mod outcome_tests;

/// Test-only hook between the invocation policy and the dispatch's
/// resolution, for the MIK-8439 rows that change state in that window (a
/// cooldown, a reload, a profile). Compiled out of non-test builds. The hook
/// is thread-local, so its rows run on the default current-thread tokio
/// runtime: on a multi-thread one the dispatch may resolve on another
/// thread and never fire it.
#[cfg(test)]
mod dispatch_seam {
    use std::cell::RefCell;

    thread_local! {
        static BEFORE_DISPATCH_RESOLUTION: RefCell<Option<Box<dyn FnOnce()>>> =
            RefCell::new(None);
    }

    /// Clears an unfired hook when dropped, so it cannot fire in a later
    /// test on the same thread.
    pub(super) struct Armed;

    impl Drop for Armed {
        fn drop(&mut self) {
            BEFORE_DISPATCH_RESOLUTION.with(|slot| slot.borrow_mut().take());
        }
    }

    /// Run `hook` once, the next time a dispatch on this thread starts its
    /// resolution, until the returned guard drops.
    #[must_use]
    pub(super) fn before_dispatch_resolution(hook: impl FnOnce() + 'static) -> Armed {
        BEFORE_DISPATCH_RESOLUTION.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        Armed
    }

    /// Called where a dispatch starts its resolution.
    pub(super) fn dispatch_resolution_starts() {
        if let Some(hook) = BEFORE_DISPATCH_RESOLUTION.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }
}

#[cfg(test)]
#[path = "noview_cooldown_tests.rs"]
mod noview_cooldown_tests;

/// A won cold claim, from the claim until its fill ends. While it lives a
/// listing may wait on the claim's lease. Dropped without a publish (a failed
/// lookup or fetch, a panic, or a request cut short mid-lookup), it settles
/// the lease to a plain retry backoff and wakes those waiters, so none waits
/// out a backoff nothing will fill.
pub(in crate::gateway::meta_mcp) struct ColdAttempt {
    backend: std::sync::Arc<Backend>,
    principal_id: String,
    generation: u64,
    /// What the publish gate reads the grant with, captured when the claim
    /// was won; `None` on a backend with no managed account.
    gate: Option<crate::gateway::meta_mcp::publish_gate::GateInputs>,
}

impl ColdAttempt {
    /// `principal_id`'s claim `generation` on `backend`, just won.
    pub(in crate::gateway::meta_mcp) fn new(
        backend: std::sync::Arc<Backend>,
        principal_id: String,
        generation: u64,
        gate: Option<crate::gateway::meta_mcp::publish_gate::GateInputs>,
    ) -> Self {
        Self {
            backend,
            principal_id,
            generation,
            gate,
        }
    }

    /// Whether the publish gate lets `binding` be indexed now: a fresh
    /// custody read must still give it. No gate inputs, nothing to read. A
    /// result the grant has moved past also drops the claim's lease, so the
    /// next reader fills under the current grant instead of waiting out a
    /// backoff.
    async fn gate_allows(&self, binding: &str) -> bool {
        use crate::gateway::meta_mcp::publish_gate::Publish;
        let Some(gate) = &self.gate else {
            return true;
        };
        let judged = gate.judge(&self.backend, binding).await;
        if judged == Publish::Superseded {
            self.backend
                .release_cold_attempt(&self.principal_id, self.generation);
        }
        judged == Publish::Allow
    }
}

impl Drop for ColdAttempt {
    fn drop(&mut self) {
        self.backend
            .settle_cold_attempt(&self.principal_id, self.generation);
    }
}

/// A claimed cold view's fill, resolved in the request and owning everything
/// it needs, so it runs inline (a stored read) or as its own task (a listing)
/// with no borrowed request context to lose.
pub(in crate::gateway::meta_mcp) struct ColdFill {
    attempt: ColdAttempt,
    binding: String,
    headers: crate::transport::LentCredential,
}

impl ColdFill {
    /// The fill bound of the backend this fill runs on.
    pub(in crate::gateway::meta_mcp) fn backend_bound(&self) -> std::time::Duration {
        self.attempt.backend.tools_fill_bound()
    }

    /// Fill the caller's own slot, within the backend's own fetch bound, then
    /// publish it over the claim's lease. The credential headers are dropped
    /// as soon as the fetch returns, so a hung backend holds none past it.
    /// The attempt settles as it drops; after a publish there is nothing left
    /// to settle.
    pub(in crate::gateway::meta_mcp) async fn run(self) {
        let Self {
            attempt,
            binding,
            headers,
        } = self;
        let backend = &attempt.backend;
        backend.extend_cold_lease(
            &attempt.principal_id,
            attempt.generation,
            backend.tools_fill_bound(),
        );
        let filled = backend
            .tools_for_check(Some(&binding), headers, false)
            .await;
        if filled.is_ok() && attempt.gate_allows(&binding).await {
            backend.publish_cold_view(&attempt.principal_id, attempt.generation, &binding);
        }
    }
}
