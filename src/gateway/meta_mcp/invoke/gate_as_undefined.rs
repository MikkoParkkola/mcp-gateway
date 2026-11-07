// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gate's policy half: a refusal by the caller's invocation rules,
//! profile or capability rule, answered as the undefined capability, so a
//! refused name and a missing one answer alike. Moved from
//! `gate.rs` unchanged; the invisible-name gate itself stays there.

use crate::error::rpc_codes::INVALID_REQUEST;
use serde_json::Value;

use super::super::MetaMcp;
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::{Error, Result};

impl MetaMcp {
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
        self.check_visible_policy_explained(arguments, session, caller)
            .map_err(super::super::audit::noted)
    }

    /// [`Self::check_visible_policy`], with the refusing check's pair and no
    /// note. The undefined twin's answer maps only the error: the
    /// pair is the refusing check's.
    pub(crate) fn check_visible_policy_explained(
        &self,
        arguments: &Value,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> crate::security::decision_record::Explained {
        self.check_invocation_policy_explained(arguments, session, caller)
            .map_err(|(refusal, pair)| {
                (
                    self.as_undefined_capability(arguments, caller, refusal),
                    pair,
                )
            })
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
        match self.capability_rule_refusal(
            (server, tool),
            caller.scope(),
            caller.admin != crate::gateway::authz::AdminStanding::None,
        ) {
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
    pub(in crate::gateway::meta_mcp::invoke) fn withheld_as_undefined(
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
    pub(in crate::gateway::meta_mcp::invoke) fn profile_refusal_as_undefined(
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
    pub(in crate::gateway::meta_mcp::invoke) fn profile_withheld_capability(
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
    pub(super) fn capability_rule_refusal(
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

    /// The session profile's refusal of `(server, tool)`, if it refuses it:
    /// the error the meta path's own check gives it. A reason a listing hides
    /// it (R6), read by the direct route, whose authorize ignores profiles.
    pub(crate) fn profile_refusal(
        &self,
        server: &str,
        tool: &str,
        session_id: Option<&str>,
    ) -> Option<Error> {
        self.caller_profile_check(session_id, (server, tool)).err()
    }
}
