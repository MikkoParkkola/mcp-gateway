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

use super::super::visible::{self, Visibility, Withholding};
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
    /// Re-establish `caller`'s cold per-user view of `server` for a stored
    /// read that won the claim (MIK-8392 B'): resolve the caller's credential
    /// and fill the caller's own slot, which indexes it. One resolution per
    /// claimed attempt. A failure leaves the lease to expire; the slot was
    /// evicted, so no stale cached list can stand in for a failed fill.
    pub(in crate::gateway::meta_mcp) async fn warm_cold_view(
        &self,
        (server, tool): (&str, &str),
        backend: &Backend,
        caller: CallerProof<'_>,
    ) {
        let Ok(resolved) = self
            .resolve_dispatch((server, tool), Some(backend), caller, caller.verified())
            .await
        else {
            return;
        };
        let _ = self
            .judge_caller_slot(
                (server, tool),
                backend,
                resolved.binding.as_deref(),
                &resolved.caller_credential.headers,
                caller,
            )
            .await;
    }

    /// The caller verdict for `(server, tool)`, taken right after route
    /// authorize and the firewall (R5.1). Idempotent within a request: a
    /// recorded answer is returned as is.
    ///
    /// `witness` is the call's refund witness (MIK-8353). It comes back only
    /// from an arm that contacted nothing: a memo hit, Step 0, no principal, or
    /// no view (each reads in-process state or the vault's stored grant, with
    /// no provider call and no durable write). A resolution (which may mint,
    /// refresh or lease), a catalogue fill or a 401 refresh spends it, so a
    /// later refusal keeps the nonce spent.
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
            .backends
            .get(server)
            .filter(|backend| backend.keeps_per_user_catalogues())
        else {
            return Ok((CallerVerdict::Proceed, witness));
        };
        match visible::recorded_visibility(server, tool) {
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
            visible::record_visibility(server, tool, Visibility::Withheld(Withholding::Lacked));
            return Ok((CallerVerdict::Absent, witness));
        }
        // A managed account with no current grant has no view (R3.7). Nothing
        // is resolved here: resolving would create a consent journey. The
        // marker makes every later listing withhold the backend at once. A call
        // by surfaced name names no backend, so it lacks the tool and every
        // reader after this answers as absent; a dispatch naming the backend
        // proceeds to that account's connect offer, the same for every tool
        // name (MIK-6745 section 9.2, predicate D).
        if self.has_no_view_for(&backend, proof).await {
            if let Some(principal) = self.principal_for(&backend, proof) {
                backend.record_no_view(&principal.stable_actor_id());
            }
            let verdict = match naming {
                TargetNaming::SurfacedName => {
                    visible::record_visibility(
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
        if let Some(witness) = witness {
            witness.spend();
        }
        // Boxed: the acting half's state (resolution, fill, refresh) would
        // otherwise sit inline in every dispatch future that awaits a verdict,
        // refusals included (MIK-8400's allocation caps). It is allocated only
        // when a per-user call gets this far.
        Box::pin(self.caller_verdict_acting(
            (server, tool),
            backend,
            proof,
            caller.verified_identity,
        ))
        .await
        .map(|verdict| (verdict, None))
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
            let target = (target.server, target.tool);
            let naming = TargetNaming::of(self, tool_name, target);
            witness = self
                .caller_verdict(target, caller, session_id, naming, witness)
                .await
                .ok()
                .and_then(|(_, witness)| witness);
        }
        witness
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
                &resolved.caller_credential.headers,
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
        visible::carry_dispatch(
            server,
            tool,
            visible::Carried {
                backend,
                resolved,
                fill_error,
            },
        );
        Ok(verdict)
    }

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
    ) -> crate::Result<Option<String>> {
        // A resolution the caller verdict carried for this step is the one
        // its dispatch will use: derive from it, with no second mint (fold F6).
        if let Some(binding) =
            visible::with_carried(server, tool, |carried| carried.resolved.binding.clone())
        {
            return Ok(crate::protocol::mrtr::source_fingerprint(
                caller.principal_source(binding.as_deref()),
            ));
        }
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
        let fingerprint = crate::protocol::mrtr::source_fingerprint(
            caller.principal_source(resolved.binding.as_deref()),
        );
        // A resume runs no caller verdict (its step is known only at run
        // time): this resolution is the step's, carried to its invocation so
        // the resume resolves once (MIK-8356 C13).
        if let Some(backend) = backend {
            visible::carry_dispatch(
                server,
                tool,
                visible::Carried {
                    backend,
                    resolved,
                    fill_error: None,
                },
            );
        }
        Ok(fingerprint)
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
        headers: &[(String, String)],
        proof: CallerProof<'_>,
    ) -> crate::Result<SlotJudgement> {
        let verdict = backend.catalogue_verdict(binding, headers, tool).await;
        self.remember_caller_slot(backend, proof, binding);
        let (recorded, judgement) = match verdict? {
            CatalogueVerdict::Offers => (Some(Visibility::Visible), SlotJudgement::Offered),
            CatalogueVerdict::Withholds => {
                let reason = if backend.is_blocked_tool(tool) {
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
            match recorded.map(|judged| visible::record_visibility(server, tool, judged)) {
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
