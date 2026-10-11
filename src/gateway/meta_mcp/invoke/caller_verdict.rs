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

/// What [`MetaMcp::judge_caller_slot`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SlotJudgement {
    Offered,
    Absent,
    Unknown,
}

impl MetaMcp {
    /// The caller verdict for `(server, tool)`, taken right after route
    /// authorize and the firewall (R5.1). Idempotent within a request: a
    /// recorded answer is returned as is.
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
    ) -> crate::Result<CallerVerdict> {
        let Some(backend) = self
            .backends
            .get(server)
            .filter(|backend| backend.keeps_per_user_catalogues())
        else {
            return Ok(CallerVerdict::Proceed);
        };
        match visible::recorded_visibility(server, tool) {
            Some(Visibility::Visible) => return Ok(CallerVerdict::Proceed),
            Some(Visibility::Withheld(_)) => return Ok(CallerVerdict::Absent),
            None => {}
        }
        // Step 0 (R5.2): descriptor and policy first, with no fill and no
        // resolution. A name they withhold is answered by the existing
        // checks, which read the same judgement.
        if self.tool_visible_to(server, tool, caller.scope(), session_id) != Visibility::Visible {
            return Ok(CallerVerdict::Proceed);
        }
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        let resolved = self
            .resolve_dispatch(
                (server, tool),
                Some(&backend),
                proof,
                caller.verified_identity,
            )
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
            visible::Carried {
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
        headers: &[(String, String)],
        proof: CallerProof<'_>,
    ) -> crate::Result<SlotJudgement> {
        let verdict = backend.catalogue_verdict(binding, headers, tool).await;
        self.remember_caller_slot(backend, proof, binding);
        let (recorded, judgement) = match verdict? {
            CatalogueVerdict::Offers => (Some(Visibility::Visible), SlotJudgement::Offered),
            CatalogueVerdict::Withholds => (
                Some(Visibility::Withheld(Withholding::Schema)),
                SlotJudgement::Absent,
            ),
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
