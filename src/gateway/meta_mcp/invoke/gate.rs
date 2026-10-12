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

use serde_json::Value;

use super::{GuardedValue, MetaMcp};
use crate::backend::{Backend, CatalogueVerdict, Lens};
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::gateway::meta_mcp::refund_witness::{RefundWitness, schema_effect};
use crate::gateway::meta_mcp::visible::{
    Visibility, Withholding, absent_name, note_denial_code, record_visibility, recorded_visibility,
};
use crate::{Error, Result};

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
    /// gate answers as absent: refused by the caller's invocation rules, or
    /// withheld by its descriptor or schema. An unregistered backend is not
    /// (MIK-8387). Signing skips the policy for it (amendment A1).
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
        self.backends.get(server).is_some_and(|backend| {
            self.may_invoke(server, tool, caller.scope(), session)
                .is_err()
                || backend.blocked_tool_refusal(None, tool).is_some()
        })
    }

    /// What signing still judges for a target it skipped the policy for: what
    /// a missing name meets there that its existence does not decide, the
    /// name's form and the call's attestation, in the policy's order. Only
    /// the refusals that name it are skipped (amendment A1).
    ///
    /// # Errors
    ///
    /// The policy's own refusal of a malformed name or a missing attestation.
    pub(crate) fn check_call_level_policy(
        &self,
        arguments: &Value,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Result<()> {
        let tool = crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "tool")?;
        if let Err(reason) = crate::security::validate_tool_name(tool) {
            return Err(Error::Protocol(format!(
                "Invalid tool name '{tool}': {reason}"
            )));
        }
        self.check_attestation(
            arguments,
            caller.agent_id.map(crate::security::ProvenAgentId::as_str),
            "gateway_invoke",
        )
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
            backend.catalogue_verdict(None, headers, tool).await
        } else {
            Ok(backend.held_verdict(None, tool))
        };
        match verdict {
            Ok(CatalogueVerdict::Offers) => Shared::Offered,
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

    /// Each named backend's fill count plus the registry's membership epoch,
    /// for [`Self::filled_since`], read in one call under the registry's
    /// membership lock. No instance is held: the lock serializes the marks
    /// against every add, replace or remove, so an unmoved epoch means every
    /// target is the same instance as at the mark and its count compares
    /// soundly.
    fn fill_marks<'s>(&self, servers: impl Iterator<Item = &'s str>) -> (u64, Vec<Option<u64>>) {
        self.backends.with_membership(|membership| {
            let fills = servers
                .map(|server| {
                    self.backends
                        .get(server)
                        .map(|backend| backend.list_fills())
                })
                .collect();
            (membership, fills)
        })
    }

    /// Whether a named backend filled since `marks`: any count changed OR
    /// the epoch changed counts as a fill, so the nonce stays spent. The
    /// counts and the epoch are read in one call under the registry's
    /// membership lock, so the snapshot and the final read agree with the
    /// map; only reloads pay this, and equal marks prove nothing acted.
    fn filled_since<'s>(
        &self,
        (membership, marks): &(u64, Vec<Option<u64>>),
        servers: impl Iterator<Item = &'s str>,
    ) -> bool {
        self.backends.with_membership(|epoch| {
            let counts_changed = marks.iter().zip(servers).any(|(mark, server)| {
                self.backends
                    .get(server)
                    .map(|backend| backend.list_fills())
                    != *mark
            });
            counts_changed || epoch != *membership
        })
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
        let Some(backend) = self.backends.get(server) else {
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
        } else if self.admit_backend_wide(server, tool).is_err() {
            return false;
        } else {
            match self
                .shared_verdict(&backend, tool, backend.gate_headers())
                .await
            {
                // Under `off` a lacked name is forwarded: not the gate's.
                Shared::Withheld(Withholding::Lacked) if !backend.checks_membership() => {
                    return false;
                }
                Shared::Withheld(reason) => reason,
                Shared::Offered | Shared::Unproven => return false,
            }
        };
        // First judgement wins: an earlier one in this request stands.
        matches!(
            record_visibility(server, tool, Visibility::Withheld(reason)),
            Visibility::Withheld(_)
        )
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
        caller.signing.inspect(|signing| signing.want_refund());
        Some(answer)
    }

    /// The session profile's refusal of `(server, tool)`, if it refuses it:
    /// the error the meta path's own check gives it. A reason a listing hides
    /// it (R6), read by the direct route, whose authorize ignores profiles.
    pub(crate) fn profile_refusal(
        &self,
        server: &str,
        tool: &str,
        session_id: Option<&str>,
    ) -> Option<Error> {
        self.active_profile(session_id)
            .check(server, tool)
            .err()
            .map(Error::Protocol)
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
            return Err(refusal);
        }
        match self.gate_answer((server, tool), caller, session_id).await {
            Some(answer) => {
                caller.signing.inspect(|signing| signing.want_refund());
                answer
            }
            None => Err(refusal),
        }
    }

    async fn gate_answer(
        &self,
        (server, tool): (&str, &str),
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Option<Result<GuardedValue>> {
        let scope = caller.scope();
        // Policy, profile, admin rule, grants: known without a catalogue.
        let refusal = self.may_invoke(server, tool, scope, session_id).err();
        let refused = refusal.is_some();
        if let Some(refusal) = &refusal {
            // The call's one record names it (MIK-8361); a code the route
            // stage kept first stands.
            note_denial_code(server, tool, refusal.to_rpc_code());
        }
        if let Some(cap) = self.get_capabilities()
            && server == cap.name
        {
            // A capability the caller may not reach answers as one that is
            // not defined: the same `ToolNotFound` the grant check gives it.
            if !(refused && cap.has_capability(tool)) {
                return None;
            }
            self.record_withheld(server, tool, Withholding::Refused, caller, session_id)
                .await;
            return Some(Err(Error::ToolNotFound(tool.to_string())));
        }
        let backend = self.backends.get(server)?;
        // Not existence-sensitive: answered alike for every name, before any
        // fill (K2).
        if let Err(refusal) = self.admit_backend_wide(server, tool) {
            return Some(Err(refusal));
        }
        if backend.keeps_per_user_catalogues() {
            // Lead ruling (8356 x 8361): a policy- or descriptor-withheld name
            // answers -32601 at once, with no fill and no credential; every
            // other name is MIK-8356's caller-slot check's.
            let reason = if refused {
                Withholding::Refused
            } else {
                match self.tool_visible_to(server, tool, scope, session_id) {
                    Visibility::Withheld(Withholding::Descriptor) => Withholding::Descriptor,
                    _ => return None,
                }
            };
            self.record_withheld(server, tool, reason, caller, session_id)
                .await;
            // Ruling B (A5): a caller with no view of this backend cannot
            // tell names apart, so a withheld name it names gets the connect
            // offer a missing one gets; -32601 at once is for a caller with a
            // view. Resolution mints nothing without a grant.
            let proof = crate::identity_propagation::CallerProof::new(
                caller.verified_identity,
                caller.provenance(),
            );
            if self.has_no_view_for(&backend, proof).await
                && let Err(offer) = self
                    .resolve_dispatch(
                        (server, tool),
                        Some(&backend),
                        proof,
                        caller.verified_identity,
                    )
                    .await
            {
                return Some(Err(offer));
            }
            return Some(Err(absent_name(tool)));
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
        let lens = match judged {
            Some(reason) => {
                if reason != Withholding::Lacked {
                    self.record_withheld(server, tool, reason, caller, session_id)
                        .await;
                }
                Lens::Withheld
            }
            // A miss, or a fill that failed: the check below meets the same
            // state and answers it as F13 does.
            None => Lens::Catalogue,
        };
        let checked_at = std::time::Instant::now();
        let refusal = self
            .undeclared_key_refusal_through(
                (server, Some(&backend)),
                tool,
                // Never read: the gate checks only names the list lacks.
                &Value::Null,
                (None, headers),
                (scope, session_id),
                lens,
            )
            .await;
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

/// D4's meta denial count for `result`, and MIK-8361's one record per call:
/// the answer to a requested target the route stage or the gate refused is
/// counted once and recorded `denied` with the refusal's own code (the
/// returned outcome), whatever it reads as to the caller (the missing name's
/// answer). The log is the operator's, so the real reason there tells the
/// caller nothing. `None` for every other call, classed by its result.
pub(super) fn count_meta_denial(
    args: &Value,
    result: &Result<Value>,
) -> Option<crate::security::audit::AuditOutcome> {
    use crate::security::security_metrics::{DenialRoute, denied, meta_denial, meta_refused};
    let code = args
        .get("server")
        .and_then(Value::as_str)
        .zip(args.get("tool").and_then(Value::as_str))
        .and_then(|(server, tool)| crate::gateway::meta_mcp::visible::denial_code(server, tool));
    if let Some(code) = code {
        meta_refused(code);
        return Some(crate::security::audit::AuditOutcome::Denied(code));
    }
    if let Some(reason) = meta_denial(result) {
        denied(DenialRoute::Meta, reason);
    }
    None
}

#[cfg(test)]
#[path = "gate_fill_tests.rs"]
mod fill_tests;
