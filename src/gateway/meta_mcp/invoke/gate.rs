// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 design r4: the meta-layer half of the terminal withheld gate.
//!
//! A name the caller may not see takes the missing name's path. Before the
//! invocation policy, signing, idempotency, the credential resolution and the
//! dispatch, a name this caller cannot see (withheld for any reason, or not
//! in the backend's catalogue) is answered here, by the same F13 check and
//! the same sealing a missing name gets, so the two answers are one by
//! construction. A name the caller may see and the catalogue lists passes on
//! untouched.

use serde_json::{Value, json};

use super::{GuardedValue, MetaMcp};
use crate::backend::{Backend, CatalogueVerdict, Lens};
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::gateway::meta_mcp::refund_witness::{RefundWitness, schema_effect};
use crate::gateway::meta_mcp::scoped_backends::Absence;
use crate::gateway::meta_mcp::visible::{
    Visibility, Withholding, absent::absent_name, memo::note_denial_code, memo::record_visibility,
    memo::recorded_visibility,
};
use crate::identity_propagation::CallerProof;
use crate::security::decision_record::DecisionKind;
use crate::{Error, Result};

#[path = "gate_as_undefined.rs"]
mod as_undefined;
mod fill_marks;

/// What a shared catalogue says about a name the caller's policy allows.
enum Shared {
    /// Listed with a valid schema: the call goes on.
    Offered,
    /// Withheld (descriptor or schema), or lacked by a complete list.
    Withheld(Withholding),
    /// Nothing proven: F13's table answers it.
    Unproven,
}

impl MetaMcp {
    /// Whether a `gateway_invoke` target on a registered backend is one the
    /// gate answers as absent: refused by the caller's invocation rules,
    /// withheld by its descriptor or schema, or on a per-user backend whose
    /// caller slot this request has not judged visible (MIK-8433). An
    /// unregistered backend is not (MIK-8387). Signing skips the policy for
    /// it (amendment A1), so a refusal that names the tool, such as the
    /// error-rate cooldown, is met only once the route stage has judged it.
    pub(crate) fn withheld_invoke_target(
        &self,
        arguments: &Value,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> bool {
        let (Ok(server), Ok(tool)) = (
            crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "server"),
            crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "tool"),
        ) else {
            return false;
        };
        self.scoped(caller.scope().authorizer.backend_grant())
            .scoped_get(server)
            .is_some_and(|backend| {
                self.may_invoke(server, tool, caller.scope(), session)
                .is_err()
                || backend.blocked_tool_refusal(None, tool).is_some()
                // Signing cannot read a per-user caller's slot before the
                // route stage judges it (stdio). Until the request holds a
                // visible verdict, the target is the route stage's, as a
                // missing name is. No cooldown read: the dispatch meets it.
                || (backend.keeps_per_user_catalogues()
                    && recorded_visibility(server, tool) != Some(Visibility::Visible))
            })
    }

    /// What `backend`'s shared catalogue says about `tool`, filled once if
    /// cold (F13's single-flight fill, the gateway's own login).
    async fn shared_verdict(
        &self,
        backend: &Backend,
        tool: &str,
        headers: &[(String, String)],
    ) -> Shared {
        // Under `off` no call lists the catalogue: judged from what is held.
        let verdict = if backend.checks_membership() {
            backend
                .catalogue_verdict(
                    None,
                    crate::transport::LentCredential::unchecked(headers),
                    tool,
                )
                .await
        } else {
            Ok(backend.held_verdict(None, tool))
        };
        match verdict {
            Ok(CatalogueVerdict::Offers) => Shared::Offered,
            Ok(CatalogueVerdict::Withholds) if backend.is_unselected(tool) => {
                Shared::Withheld(Withholding::Unselected)
            }
            Ok(CatalogueVerdict::Withholds) if backend.is_blocked_tool(tool) => {
                Shared::Withheld(Withholding::Descriptor)
            }
            Ok(CatalogueVerdict::Withholds) => Shared::Withheld(Withholding::Schema),
            Ok(CatalogueVerdict::Lacks) => Shared::Withheld(Withholding::Lacked),
            Ok(CatalogueVerdict::Unknown) | Err(_) => Shared::Unproven,
        }
    }

    /// Whether a whole `tools/call` is answered by the gate: a
    /// `gateway_invoke` or `gateway_execute` whose request names at least
    /// one target, every one of which this caller cannot see, and that runs
    /// no playbook step (`targets` beyond `requested`). Such a call takes the
    /// missing name's path at once, past X14, the task gate, signing and
    /// admission. Anything else goes on, and each step meets the gate.
    pub(crate) async fn invisible_call(
        &self,
        tool_name: &str,
        (targets, requested): (&[crate::gateway::authz::CallTarget<'_>], usize),
        caller: &MetaMcpCallerContext<'_>,
        (session_id, witness): (Option<&str>, Option<RefundWitness>),
    ) -> (bool, Option<RefundWitness>) {
        if !matches!(tool_name, "gateway_invoke" | "gateway_execute")
            || requested == 0
            || targets.len() != requested
        {
            return (false, witness);
        }
        // The judgement may fill a cold catalogue: an effect, so the nonce
        // stays spent (MIK-8353 3a).
        let servers = || targets.iter().map(|target| target.server.as_str());
        let marks = self.fill_marks(servers());
        let mut invisible = true;
        for target in targets {
            let named = (target.server.as_str(), target.tool.as_str());
            if !self.invisible_at_route(named, caller, session_id).await {
                invisible = false;
                break;
            }
        }
        let filled = schema_effect(self.filled_since(&marks, servers()));
        (invisible, RefundWitness::carry(witness, filled))
    }

    /// The route stage's judgement of one requested backend target: whether
    /// the caller cannot see it (withheld, or lacked by a complete list).
    /// Recorded in the request's memo, so the meta gate answers it absent
    /// whatever the catalogue does next. `false` for a capability (the route
    /// authorize answers those), a per-user backend's allowed name that its
    /// caller verdict did not withhold (MIK-8356's check owns it), a
    /// backend-wide refusal and anything unproven.
    pub(crate) async fn invisible_at_route(
        &self,
        (server, tool): (&str, &str),
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> bool {
        // MIK-8387 S2: an absent name (recorded by S1, or absent now) is
        // invisible. Recorded upgrade-only: this answer skips signing and
        // admission, so S3 must keep it absent even if a reload restores the
        // backend before it asks.
        if self
            .scoped(caller.scope().authorizer.backend_grant())
            .absent_step(server, tool)
        {
            crate::gateway::meta_mcp::visible::memo::record_absent(server, tool);
            return true;
        }
        let Some(backend) = self
            .scoped(caller.scope().authorizer.backend_grant())
            .scoped_get(server)
        else {
            return false;
        };
        let refused = self
            .may_invoke(server, tool, caller.scope(), session_id)
            .is_err();
        let reason = if refused {
            // Whatever the backend-wide checks say: the gate answers them
            // for this name as for a missing one.
            Withholding::Refused
        } else if backend.keeps_per_user_catalogues() {
            // MIK-8356's caller verdict records what the caller's own slot
            // withholds or lacks, and leaves a descriptor-withheld name to
            // this gate (its step 0): either takes the path a refused one
            // takes, answered by the same layer, with the same status.
            match self.tool_visible_to(server, tool, caller.scope(), session_id) {
                Visibility::Withheld(reason) => reason,
                Visibility::Visible => return false,
            }
        } else if self.admit_backend_wide(server).is_err() {
            return false;
        } else {
            match self
                .shared_verdict(&backend, tool, backend.gate_headers())
                .await
            {
                // Under `off` the held list never reports a lacked name (it
                // is unproven, so forwarded): `Lacked` comes only from a
                // checked membership, which the gate answers.
                Shared::Withheld(reason) => reason,
                Shared::Offered | Shared::Unproven => return false,
            }
        };
        // First judgement wins: an earlier one in this request stands.
        record_visibility(server, tool, Visibility::Withheld(reason)) != Visibility::Visible
    }

    /// MIK-8361: a name this caller cannot see is answered as missing, before
    /// the policy, signing, idempotency, credential or dispatch; a policy
    /// refusal of a target the caller cannot see is answered so too
    /// ([`Self::backstop`]). `None` lets the call go on.
    pub(super) async fn gated(
        &self,
        args: &Value,
        target: (&str, &str),
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Option<Result<GuardedValue>> {
        // The refund witness (MIK-8353 3a): a catalogue fill the gate causes
        // is an effect, so the nonce stays spent; whatever survives goes back
        // to the call on drop, for its settle or the dispatch's own steps.
        let marks = self.fill_marks(std::iter::once(target.0));
        let mut witness = super::nonce_settle::Witnessed::take(caller);
        let answer = match self.withheld_gate(target, caller, session_id).await {
            Some(answer) => Some(answer),
            None => match self.check_or_stamp(args, session_id, caller, target) {
                Ok(()) => None,
                Err(refusal) => Some(self.backstop(target, caller, session_id, refusal).await),
            },
        };
        witness.carry(schema_effect(
            self.filled_since(&marks, std::iter::once(target.0)),
        ));
        answer
    }

    /// The gate for one `gateway_invoke` target or chain step. `Some` is the
    /// call's answer; `None` lets it go on to the invocation policy and the
    /// dispatch.
    pub(super) async fn withheld_gate(
        &self,
        (server, tool): (&str, &str),
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Option<Result<GuardedValue>> {
        #[cfg(test)]
        if crate::gateway::meta_mcp::withheld_gate::seams::gate_skipped() {
            return None;
        }
        // A playbook step's target is the definition's, not the caller's: it
        // keeps the neutral step refusal (A3, MIK-8362).
        if crate::playbook::current_step().is_some() {
            return None;
        }
        let answer = self.gate_answer((server, tool), caller, session_id).await?;
        // Answered before anything acted: the signing nonce is given back, as
        // for a name that matches no tool (MIK-8340 A4).
        super::nonce_settle::settle_pre_send(caller, super::nonce_settle::PreSendExit::AskRefund);
        Some(answer)
    }

    /// The dispatch-time backstop (design r2 item 4): a refusal the policy
    /// check gives a name that slipped past the gate is answered as the gate
    /// would answer it, the absent name's answer, never by its reason. Any
    /// other refusal stands.
    pub(super) async fn backstop(
        &self,
        (server, tool): (&str, &str),
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
        refusal: Error,
    ) -> Result<GuardedValue> {
        if crate::playbook::current_step().is_some() {
            // A decision about the caller the gate, judging the name alone,
            // let through: the step records it (see is_authorization_refusal).
            if is_authorization_refusal(&refusal) {
                crate::gateway::delivery_facts::refused_while_vouched();
            }
            // A playbook step keeps its neutral refusal (A3) and asks, as a
            // chain step does: the witness decides (MIK-8353 3d-2).
            super::nonce_settle::settle_pre_send(
                caller,
                super::nonce_settle::PreSendExit::AskRefund,
            );
            return Err(refusal);
        }
        if let Some(answer) = self.gate_answer((server, tool), caller, session_id).await {
            super::nonce_settle::settle_pre_send(
                caller,
                super::nonce_settle::PreSendExit::AskRefund,
            );
            answer
        } else {
            // The policy's own refusal at dispatch, before anything this
            // step does acts: the witness decides (MIK-8353 3d).
            super::nonce_settle::settle_pre_send(
                caller,
                super::nonce_settle::PreSendExit::AskRefund,
            );
            Err(refusal)
        }
    }

    /// The answer a scoped key gets for an absent name: the one a registered
    /// backend outside its scope got before (the catalogue's miss text, as an
    /// `isError` result), so the three cells are equal by construction. The
    /// record keeps the scope refusal's code for an out-of-scope name; on a
    /// task worker this is the only note (MIK-8387 W1).
    async fn absent_answer(
        &self,
        (server, tool): (&str, &str),
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Result<GuardedValue> {
        crate::gateway::meta_mcp::visible::memo::record_absent(server, tool);
        let scoped = self.scoped(caller.scope().authorizer.backend_grant());
        if scoped.absence(server) == Some(Absence::OutOfScope) {
            note_denial_code(
                server,
                tool,
                -32003,
                Some((DecisionKind::BackendScope, None)),
            );
            // Outside the key's scope: refused, not merely missing.
            crate::gateway::delivery_facts::withheld();
            crate::gateway::delivery_facts::gateway_folded(-32003);
        } else {
            // Not out of scope: the name matches nothing, the gateway's own
            // refusal, recorded as an unscoped caller's missing backend is.
            super::audit::note_refused_by(DecisionKind::NotFound, None);
            super::audit::note_not_found();
            crate::gateway::delivery_facts::gateway_folded(-32001);
        }
        self.record_withheld(server, tool, Withholding::Absent, caller, session_id)
            .await;
        let miss = json!({"content": [{"type": "text", "text": crate::backend::text_absent(tool)}],
                          "isError": true});
        let sealed = self
            .seal_key_refusal(
                (caller, session_id),
                (server, tool),
                Ok(Some(miss)),
                (None, caller.verified_identity, std::time::Instant::now()),
                &mut None,
            )
            .await;
        match sealed {
            Ok(Some(answer)) => Ok(answer),
            Ok(None) => Err(absent_name(tool)),
            Err(refusal) => Err(refusal),
        }
    }

    async fn gate_answer(
        &self,
        (server, tool): (&str, &str),
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Option<Result<GuardedValue>> {
        // First, before every early return: a provisional miss belongs to the
        // invocation that judged it, never to a later one on the same name.
        crate::gateway::meta_mcp::visible::memo::clear_gate_absent(server, tool);
        // MIK-8387 S3: an absent name is answered before any name-keyed check
        // (policy, capability, kill switch, catalogue), from the record first,
        // so a reload since the route stage cannot reach a dispatch.
        if self
            .scoped(caller.scope().authorizer.backend_grant())
            .absent_step(server, tool)
        {
            return Some(self.absent_answer((server, tool), caller, session_id).await);
        }
        self.named_gate_answer((server, tool), caller, session_id)
            .await
    }

    /// [`Self::named_gate_answer`] on a backend that keeps a catalogue per
    /// caller: `None` hands the name to MIK-8356's caller-slot check.
    async fn per_user_withheld_answer(
        &self,
        (server, tool): (&str, &str),
        backend: &Backend,
        refused: bool,
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Option<Result<GuardedValue>> {
        let scope = caller.scope();
        // Lead ruling (8356 x 8361): a policy- or descriptor-withheld name
        // answers -32601 at once, with no fill and no credential; every
        // other name is MIK-8356's caller-slot check's.
        let reason = if refused {
            Withholding::Refused
        } else {
            match self.tool_visible_to(server, tool, scope, session_id) {
                Visibility::Withheld(reason) if reason.is_backend_gate() => reason,
                _ => return None,
            }
        };
        self.record_withheld(server, tool, reason, caller, session_id)
            .await;
        withheld_for(reason);
        // Ruling B (A5): a caller with no view of this backend cannot
        // tell names apart, so a withheld name it names gets the connect
        // offer a missing one gets; -32601 at once is for a caller with a
        // view. Resolution mints nothing without a grant.
        let proof = CallerProof::new(caller.verified_identity, caller.provenance());
        if self.has_no_view_for(backend, proof).await
            && let Err(offer) = self
                .resolve_dispatch(
                    (server, tool),
                    Some(backend),
                    proof,
                    caller.verified_identity,
                )
                .await
        {
            return Some(Err(offer));
        }
        Some(Err(absent_name(tool)))
    }

    /// The lens the key check reads a named tool under: withheld when the
    /// gate judged it so (recorded, and raised for a policy reason); as
    /// listed for a miss or a fill that failed, which the check below meets
    /// and answers as F13 does.
    async fn gate_lens(
        &self,
        judged: Option<Withholding>,
        (server, tool): (&str, &str),
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Lens {
        let Some(reason) = judged else {
            return Lens::Catalogue;
        };
        if reason != Withholding::Lacked {
            self.record_withheld(server, tool, reason, caller, session_id)
                .await;
        }
        withheld_for(reason);
        Lens::Withheld
    }

    /// [`Self::gate_answer`] for a name that is not absent.
    async fn named_gate_answer(
        &self,
        (server, tool): (&str, &str),
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Option<Result<GuardedValue>> {
        let scope = caller.scope();
        // Policy, profile, admin rule, grants: known without a catalogue.
        let refused = self
            .may_invoke_explained(server, tool, scope, session_id)
            .inspect_err(|(error, refusal)| {
                // The call's one record names it (MIK-8361); a code the route
                // stage kept first stands.
                note_denial_code(server, tool, error.to_rpc_code(), Some(refusal.clone()));
            })
            .is_err();
        if let Some(cap) = self.caller_capabilities()
            && server == cap.name
        {
            // A capability the caller may not reach answers as one that is
            // not defined: the same `ToolNotFound` the grant check gives it.
            let by_rule = self.capability_rule_refusal(
                (server, tool),
                scope,
                caller.admin != crate::gateway::authz::AdminStanding::None,
            );
            if !refused || by_rule.is_none() {
                return None;
            }
            self.record_withheld(server, tool, Withholding::Refused, caller, session_id)
                .await;
            withheld_for(Withholding::Refused);
            return Some(Err(Error::ToolNotFound(tool.to_string())));
        }
        let Some(backend) = self
            .scoped(caller.scope().authorizer.backend_grant())
            .scoped_get(server)
        else {
            // Unregistered for this caller, provisionally: the dispatch records
            // `not_found` only if it misses too (a reload may register it first).
            crate::gateway::meta_mcp::visible::memo::mark_gate_absent(server, tool);
            return None;
        };
        // Not existence-sensitive: answered alike for every name, before any
        // fill (K2).
        if let Err(refusal) = self.admit_backend_wide(server) {
            return Some(Err(refusal));
        }
        if backend.keeps_per_user_catalogues() {
            return self
                .per_user_withheld_answer((server, tool), &backend, refused, caller, session_id)
                .await;
        }
        let headers = backend.gate_headers();
        // One judgement per request: a verdict the route stage recorded
        // stands, so a catalogue refill since cannot turn an answered-absent
        // name into a dispatch (MIK-8340's rule).
        let judged = match recorded_visibility(server, tool) {
            Some(Visibility::Withheld(reason)) => Some(reason),
            _ if refused => Some(Withholding::Refused),
            _ => match self.shared_verdict(&backend, tool, headers).await {
                Shared::Offered => return None,
                // A name the list lacks is judged by F13's own table below,
                // which knows the mode (`off` forwards it).
                Shared::Withheld(Withholding::Lacked) | Shared::Unproven => None,
                Shared::Withheld(reason) => Some(reason),
            },
        };
        let lens = self
            .gate_lens(judged, (server, tool), caller, session_id)
            .await;
        let checked_at = std::time::Instant::now();
        let refusal = self
            .undeclared_key_refusal_through(
                (server, Some(&backend)),
                tool,
                // Never read: the gate checks only names the list lacks.
                &Value::Null,
                (None, crate::transport::LentCredential::unchecked(headers)),
                (scope, session_id),
                lens,
            )
            .await
            .map(|checked| checked.map(|checked| checked.answer));
        let mut unreserved = None;
        let sealed = self
            .seal_key_refusal(
                (caller, session_id),
                (server, tool),
                refusal,
                (None, caller.verified_identity, checked_at),
                &mut unreserved,
            )
            .await;
        match sealed {
            // A miss the mode forwards (`standard` on a list that proves
            // nothing, `off`): the stated residual, as before.
            Ok(None) => None,
            Ok(Some(answer)) => Some(Ok(answer)),
            Err(refusal) => Some(Err(refusal)),
        }
    }
}

#[cfg(test)]
#[path = "gate_fill_tests.rs"]
mod fill_tests;

#[cfg(test)]
#[path = "gate_call_level_tests.rs"]
mod call_level_tests;

#[cfg(test)]
#[path = "gate_refusal_kind_tests.rs"]
mod refusal_kind_tests;

/// Whether `error` is the gateway's own decision about the caller, wherever
/// it was built (`Forbidden`, as `delivery_facts::outlet` reads it): a
/// dispatch-time policy refusal, the per-user lender's refusal of a send, a
/// refused shared slot. Such a refusal is answered as the refusal it is,
/// never folded into a backend error result, and never sampled against the
/// backend's error budget; a playbook step answers it neutrally. An audit
/// failure, an undefined capability or an absent name is not one.
pub(super) fn is_authorization_refusal(error: &Error) -> bool {
    matches!(error, Error::Forbidden { .. })
}

/// A name the gate answers as absent for `reason`: a policy reason (the
/// caller may not invoke it, or its schema or description failed a check) is
/// the gateway's refusal; a name a caller's own catalogue lacks is not.
fn withheld_for(reason: Withholding) {
    if reason.is_policy() {
        crate::gateway::delivery_facts::withheld();
    }
}
