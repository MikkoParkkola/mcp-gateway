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

use crate::error::rpc_codes::INVALID_REQUEST;
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
            let server =
                crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "server")?;
            // Every authorizer passes an empty server or tool, so the policy's
            // own name check answers it, as it did before A1.
            if server.is_empty() || tool.is_empty() {
                return Err(Error::Protocol(format!(
                    "Invalid tool name '{tool}': {reason}"
                )));
            }
            // As every authorizer refuses a malformed name, and as
            // `authorize_invocation` answers and audits it: the policy this
            // call skipped would have, and so does a missing name.
            let refusal = Error::Forbidden {
                code: INVALID_REQUEST,
                status: axum::http::StatusCode::FORBIDDEN.as_u16(),
                message: reason,
            };
            let authorizer = caller.authorizer;
            crate::gateway::authz::audit_refusal(
                authorizer.transport(),
                authorizer.caller_name(),
                server,
                tool,
                &refusal.to_string(),
            );
            return Err(refusal);
        }
        self.check_attestation(
            arguments,
            caller.agent_id.map(crate::security::ProvenAgentId::as_str),
            "gateway_invoke",
        )?;
        // The kill switch says nothing about the name: a missing name meets
        // it in the policy, right after the attestation, so a skipped one
        // meets it here (H3). A disabled capability names the tool and is
        // not met for a name the caller cannot see (#3872 review C).
        let server = crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "server")?;
        self.admit_backend_wide(server)
    }
    /// The invocation policy as the caller may see it: a capability the
    /// caller may not reach answered as the undefined one is
    /// ([`Self::as_undefined_capability`]). Signing runs it for a target it
    /// does not skip (H2), and a stored read runs it so it answers what the
    /// live call answers (MIK-8392 D-POLICY under MIK-8361).
    ///
    /// # Errors
    ///
    /// The policy's refusal, so mapped.
    pub(crate) fn check_visible_policy(
        &self,
        arguments: &Value,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Result<()> {
        self.check_invocation_policy(arguments, session, caller)
            .map_err(|refusal| self.as_undefined_capability(arguments, caller, refusal))
    }

    /// The policy's refusal of a capability the caller may not reach (admin
    /// rule, identity grant), as the undefined twin is answered: it meets the
    /// same authorizer, then the grant check's `ToolNotFound`. The two rules
    /// are re-read silently, with no second authorizer decision; a refusal
    /// they did not give (the authorizer's, a later step's) is the undefined
    /// twin's too and is kept.
    fn as_undefined_capability(
        &self,
        arguments: &Value,
        caller: &MetaMcpCallerContext<'_>,
        refusal: Error,
    ) -> Error {
        let (Ok(server), Ok(tool)) = (
            crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "server"),
            crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "tool"),
        ) else {
            return refusal;
        };
        match self.capability_rule_refusal((server, tool), caller.scope(), caller.is_admin) {
            Some(rule) if rule.to_string() == refusal.to_string() => {
                Error::ToolNotFound(tool.to_string())
            }
            _ => refusal,
        }
    }

    /// [`Self::profile_refusal_as_undefined`] at a site that delivers it: a
    /// profile refusal answered as an absent name is the gateway's refusal,
    /// raised for a one-target call (`delivery_facts::withheld`). Never
    /// called from the decision functions themselves, so a discarded policy
    /// probe raises nothing.
    pub(super) fn withheld_as_undefined(
        &self,
        named: (&str, &str),
        session_id: Option<&str>,
        refusal: Error,
    ) -> Error {
        let answered = self.profile_refusal_as_undefined(named, session_id, refusal);
        // Only the profile refusal maps to `ToolNotFound` here; every other
        // refusal of `admit_target` passes through unchanged.
        if matches!(answered, Error::ToolNotFound(_)) {
            crate::gateway::delivery_facts::withheld();
        }
        answered
    }

    /// `refusal`, unless the session's routing profile excludes a defined
    /// capability: then the undefined capability's answer (MIK-8361), as
    /// [`Self::profile_withheld_capability`] gives it. Any other refusal (kill
    /// switch, a backend tool's profile refusal) is kept.
    pub(super) fn profile_refusal_as_undefined(
        &self,
        named: (&str, &str),
        session_id: Option<&str>,
        refusal: Error,
    ) -> Error {
        self.profile_withheld_capability(named, session_id)
            .unwrap_or(refusal)
    }

    /// `ToolNotFound` for a defined capability the session's routing profile
    /// excludes, as the undefined twin is answered at the route stage before
    /// any profile is read: the profile's refusal would confirm the capability
    /// exists (MIK-8361). It writes nothing: a profile refusal leaves no
    /// invocation record, before this mapping and after it. `None` for any
    /// other target.
    pub(super) fn profile_withheld_capability(
        &self,
        (server, tool): (&str, &str),
        session_id: Option<&str>,
    ) -> Option<Error> {
        let defined = self
            .caller_capabilities()
            .is_some_and(|cap| server == cap.name && cap.has_capability(tool));
        self.active_profile(session_id)
            .check(server, tool)
            .err()
            .filter(|_| defined)
            .map(|_| Error::ToolNotFound(tool.to_string()))
    }

    /// The refusal a defined capability gets from a rule that depends on it
    /// existing: the admin rule or the identity grant, re-read silently with
    /// no authorizer decision. `None` for an undefined capability, any other
    /// server, or a capability both rules admit. The gate and
    /// [`Self::check_visible_policy`] both answer such a refusal as the
    /// undefined capability, through this one predicate (MIK-8361).
    fn capability_rule_refusal(
        &self,
        (server, tool): (&str, &str),
        scope: crate::gateway::meta_mcp::visibility::InvokeScope<'_>,
        is_admin: bool,
    ) -> Option<Error> {
        let defined = self
            .caller_capabilities()
            .is_some_and(|cap| server == cap.name && cap.has_capability(tool));
        if !defined {
            return None;
        }
        self.admin_capability_rule(server, tool, is_admin)
            .and_then(|()| {
                self.identity_grant_rule(server, tool, scope, crate::gateway::authz::Emit::Silent)
            })
            .err()
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

    /// Each named backend's fill count plus the registry's membership epoch,
    /// for [`Self::filled_since`], read in one call under the registry's
    /// membership lock. No instance is held: the lock serializes the marks
    /// against every add, replace or remove, so an unmoved epoch means every
    /// target is the same instance as at the mark and its count compares
    /// soundly.
    fn fill_marks<'s>(&self, servers: impl Iterator<Item = &'s str>) -> (u64, Vec<Option<u64>>) {
        self.backends.membership_for(
            crate::gateway::meta_mcp::scoped_backends::Unscoped::Discovery,
            |membership| {
                let fills = servers
                    .map(|server| {
                        self.backends
                            .get_for(
                                crate::gateway::meta_mcp::scoped_backends::Unscoped::Discovery,
                                server,
                            )
                            .map(|backend| backend.list_fills())
                    })
                    .collect();
                (membership, fills)
            },
        )
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
        self.backends.membership_for(
            crate::gateway::meta_mcp::scoped_backends::Unscoped::Discovery,
            |epoch| {
                let counts_changed = marks.iter().zip(servers).any(|(mark, server)| {
                    self.backends
                        .get_for(
                            crate::gateway::meta_mcp::scoped_backends::Unscoped::Discovery,
                            server,
                        )
                        .map(|backend| backend.list_fills())
                        != *mark
                });
                counts_changed || epoch != *membership
            },
        )
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
            note_denial_code(server, tool, -32003);
            // Outside the key's scope: refused, not merely missing.
            crate::gateway::delivery_facts::withheld();
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
        let refusal = self.may_invoke(server, tool, scope, session_id).err();
        let refused = refusal.is_some();
        if let Some(refusal) = &refusal {
            // The call's one record names it (MIK-8361); a code the route
            // stage kept first stands.
            note_denial_code(server, tool, refusal.to_rpc_code());
        }
        if let Some(cap) = self.caller_capabilities()
            && server == cap.name
        {
            // A capability the caller may not reach answers as one that is
            // not defined: the same `ToolNotFound` the grant check gives it.
            let by_rule = self.capability_rule_refusal((server, tool), scope, caller.is_admin);
            if !refused || by_rule.is_none() {
                return None;
            }
            self.record_withheld(server, tool, Withholding::Refused, caller, session_id)
                .await;
            withheld_for(Withholding::Refused);
            return Some(Err(Error::ToolNotFound(tool.to_string())));
        }
        let backend = self
            .scoped(caller.scope().authorizer.backend_grant())
            .scoped_get(server)?;
        // Not existence-sensitive: answered alike for every name, before any
        // fill (K2).
        if let Err(refusal) = self.admit_backend_wide(server) {
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
        .and_then(|(server, tool)| {
            crate::gateway::meta_mcp::visible::memo::denial_code(server, tool)
        });
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

#[cfg(test)]
#[path = "gate_call_level_tests.rs"]
mod call_level_tests;

#[cfg(test)]
#[path = "gate_refusal_kind_tests.rs"]
mod refusal_kind_tests;

/// Whether a refusal the dispatch-time policy check gave is an authorization
/// decision about the caller (`Forbidden`, which a playbook step answers
/// neutrally); an audit failure, an undefined capability or an absent name is
/// not.
fn is_authorization_refusal(error: &Error) -> bool {
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
