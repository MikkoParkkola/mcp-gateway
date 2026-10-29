// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8137 P1-route-b1: the dispatch chokepoint (design r2.2 C1'; firewall
//! rescan per design note `design-b1-rescan.md` r2).
//!
//! Every backend send in the meta layer passes [`MetaMcp::chokepoint`]
//! immediately before it is marked dispatched, whoever asked for it: a
//! `gateway_invoke`, a surfaced tool, a playbook or chain step, a task worker,
//! a continuation retry or a bridged input round. It re-checks, against the
//! policy in force now and on the bytes the send carries:
//! - target authorization, identity grants and the admin-capability rule,
//!   silently on allow (the route already wrote this call's allow record) and
//!   with the route's own audit rows on refusal;
//! - the request firewall's stateless content scan and rules
//!   ([`crate::security::firewall::Firewall::rescan`]), never the stateful
//!   guards, which judged the logical call once at its route scan.
//!
//! A refusal is `Error::Forbidden`: nothing was sent, so the caller gives back
//! what it took (nonce, idempotency key). A pass mints the [`Permit`] that
//! `accounted_dispatch` takes by value: only this module can construct one, so
//! a send that skipped the chokepoint does not compile (MX).

#[cfg(feature = "firewall")]
use crate::error::rpc_codes::{INVALID_PARAMS, INVALID_REQUEST};
use serde_json::Value;

use crate::gateway::authz::{Emit, ToolTarget};
use crate::gateway::meta_mcp::scoped_backends::Absence;
use crate::gateway::meta_mcp::{InvokeScope, MetaMcp};
use crate::{Error, Result};

#[cfg(test)]
#[path = "chokepoint_tests.rs"]
mod chokepoint_tests;

/// Proof that one send passed the chokepoint, consumed by that send.
#[must_use = "a permit is consumed by the send it was minted for"]
pub(super) struct Permit(());

/// Where a send came from, for the chokepoint's records (never content).
#[derive(Clone, Copy)]
pub(super) enum Source {
    /// A call's own send: `gateway_invoke`, a surfaced tool, a chain step.
    Invoke,
    /// A playbook step.
    Step,
    /// A continuation retry carrying the client's redeemed answers.
    Retry,
    /// A bridged input round (legacy client) carrying its answers.
    Bridged,
    /// A `tools/call` on the direct per-backend route, its answers included
    /// on a redeemed retry (MIK-8351).
    Direct,
}

impl Source {
    /// The source of a send from `invoke_tool_traced`.
    pub(super) fn of_call(answers: Option<&Value>) -> Self {
        if answers.is_some() {
            Self::Retry
        } else if crate::playbook::current_step().is_some() {
            Self::Step
        } else {
            Self::Invoke
        }
    }

    #[cfg(feature = "firewall")]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Invoke => "invoke",
            Self::Step => "step",
            Self::Retry => "retry",
            Self::Bridged => "bridged",
            Self::Direct => "direct",
        }
    }
}

/// The caller-controlled bytes one send carries: the tool arguments and, on a
/// retry or a bridged round, the client's answers. Operator-injected secrets
/// are added after the chokepoint and are not caller input (note r2, item 2).
pub(in crate::gateway) struct Outbound<'a> {
    pub(in crate::gateway) arguments: &'a Value,
    pub(in crate::gateway) answers: Option<&'a Value>,
    /// The instance that sends: the folder check classifies it, never a
    /// fresh lookup (a reload between the route scan and the send cannot
    /// split the checked backend from the sending one).
    pub(in crate::gateway) backend: Option<&'a crate::backend::Backend>,
}

/// Proof that one direct-route `tools/call` passed the chokepoint (MIK-8351).
///
/// The only way the direct route can send a `tools/call`: its send takes one
/// by value, and only [`MetaMcp::direct_send_permit`] here can build one, so
/// a direct send that skipped the chokepoint does not compile, as for the
/// meta route's [`Permit`].
#[must_use = "a permit is consumed by the send it was minted for"]
pub(in crate::gateway) struct DirectPermit(Permit);

/// Whose target a route-stage scan is looking at.
#[cfg(feature = "firewall")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanTarget {
    /// A target the request names.
    Request,
    /// A playbook step the definition names, not the request.
    Step,
}

#[cfg(test)]
impl DirectPermit {
    /// A permit for a send whose test is not about the chokepoint. Test builds
    /// only: production can mint one solely through the chokepoint.
    pub(in crate::gateway) fn for_test() -> Self {
        Self(Permit(()))
    }
}

impl MetaMcp {
    /// Pass or refuse one send. See the module documentation.
    pub(super) fn chokepoint(
        &self,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
        (server, tool): (&str, &str),
        outbound: &Outbound<'_>,
        source: Source,
    ) -> Result<Permit> {
        // Callers pass the parsed object they dispatch (`parse_tool_arguments`),
        // the value the route judged through `judged_arguments` (kimi i1).
        debug_assert!(
            outbound.arguments.is_object(),
            "the chokepoint judges dispatched objects"
        );
        self.recheck_target(scope, (server, tool), outbound.arguments, Emit::Silent)?;
        #[cfg(feature = "firewall")]
        self.rescan_outbound(scope, session_id, (server, tool), outbound, source)?;
        #[cfg(not(feature = "firewall"))]
        let _ = (session_id, source, outbound.answers, outbound.backend);
        Ok(Permit(()))
    }

    /// Pass or refuse one direct-route `tools/call` (MIK-8351, MIK-8154 SAN.3):
    /// the same re-check the meta route's sends get, on the bytes the direct
    /// route is about to send, its redeemed answers included.
    ///
    /// # Errors
    /// The chokepoint's refusal: nothing was sent, so the caller gives back
    /// what it took.
    pub(in crate::gateway) fn direct_send_permit(
        &self,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
        (server, tool): (&str, &str),
        outbound: &Outbound<'_>,
    ) -> Result<DirectPermit> {
        self.chokepoint(scope, session_id, (server, tool), outbound, Source::Direct)
            .map(DirectPermit)
    }

    /// The single route-stage authorize that `/mcp` and stdio both run, before
    /// the request firewall, X14 and admission (route-check-parity P3). Every
    /// target is authorized as the dispatch chokepoint will re-check it, with
    /// the route's allow record. A surfaced name withheld from this caller
    /// never reaches here: it resolves to no target (MIK-8340), and the meta
    /// direct route answers it as a name that matches no tool.
    ///
    /// # Errors
    /// The authorization refusal.
    pub(crate) fn authorize_route_target(
        &self,
        scope: InvokeScope<'_>,
        (server, tool): (&str, &str),
        arguments: &Value,
    ) -> Result<()> {
        self.recheck_target(scope, (server, tool), arguments, Emit::Audit)
    }

    /// [`Self::authorize_route_target`] for a target the request names
    /// (MIK-8361). Every refusal here is one a listing also applies, so the
    /// caller cannot see the target: it takes the missing name's path. On a
    /// backend, a missing name passes this stage, so the withheld one does
    /// too (its refusal record is written all the same) and the gate answers
    /// it absent after the firewall. On the capability backend a missing
    /// name is refused here as not found, so the withheld one is too.
    ///
    /// `Ok(Some(refusal))` is a withheld target that passes, with the refusal
    /// its record names; `Ok(None)` a target the caller may see.
    ///
    /// # Errors
    /// `ToolNotFound` for a capability the caller may not reach, its routing
    /// profile included.
    pub(crate) fn authorize_requested_target(
        &self,
        scope: InvokeScope<'_>,
        (server, tool): (&str, &str),
        arguments: &Value,
        session_id: Option<&str>,
    ) -> Result<Option<Error>> {
        // MIK-8387 S1: for a scoped key, a backend outside its scope and one
        // that is not registered are one absent name. Recorded first, before
        // the caller verdict and the response-target filter read the memo, so
        // every later site answers all three alike. An unregistered name has
        // nothing to authorize, so the name-keyed route rules (a tool scope
        // among them) never single it out; an out-of-scope one keeps the
        // scope refusal for the call's record.
        if let Some(absence) = self
            .scoped(scope.authorizer.backend_grant())
            .absence(server)
        {
            crate::gateway::meta_mcp::visible::memo::record_absent(server, tool);
            return Ok(match absence {
                Absence::OutOfScope => self
                    .authorize_route_target(scope, (server, tool), arguments)
                    .err(),
                Absence::Unregistered => None,
            });
        }
        let Err(refusal) = self.authorize_route_target(scope, (server, tool), arguments) else {
            // The route authorize reads no session, so no routing profile: a
            // defined capability the profile excludes is refused here, as the
            // undefined one is, not later by admission for its reason.
            return self
                .profile_withheld_capability((server, tool), session_id)
                .map_or(Ok(None), Err);
        };
        // MIK-8441: an empty grant reaches no backend, so every name, the
        // capability backend's included, keeps the grant refusal. It is
        // decided before any lookup, so it tells no name from another.
        if matches!(
            scope.authorizer.backend_grant(),
            crate::gateway::authz::BackendGrant::Empty
        ) {
            return Err(refusal);
        }
        match self.get_capabilities() {
            // Even an unwritable record answers so: the call dispatches
            // nothing (D3-a narrowed, lead ruling 2026-10-11).
            Some(cap) if cap.name == server => Err(Error::ToolNotFound(tool.to_string())),
            // No gate answers a backend that is not registered: for a caller
            // with no scoped grant its refusal stays the strict one, recorded
            // fail-closed (a scoped key's absent names are S1's, above).
            _ if self
                .scoped(scope.authorizer.backend_grant())
                .scoped_get(server)
                .is_none() =>
            {
                Err(refusal)
            }
            _ => {
                // Recorded before every later reader (MIK-8356's caller
                // verdict included), so a policy-refused target resolves no
                // credential (R5.1) and the gate answers it absent.
                let withheld = crate::gateway::meta_mcp::visible::Visibility::Withheld(
                    crate::gateway::meta_mcp::visible::Withholding::Refused,
                );
                crate::gateway::meta_mcp::visible::memo::record_visibility(server, tool, withheld);
                Ok(Some(refusal))
            }
        }
    }

    /// The route-stage request scan on this Meta-MCP's own firewall, for the
    /// transport that has no firewall of its own (stdio; route-check-parity
    /// P3, MIK-8149.REQFW.1): the content scan and the stateful controls
    /// (anomaly, tenant guard, budget) `check_request` runs once per logical
    /// call, with its request audit row. `None` passes; `Some` is the shared
    /// refusal every route answers. The dispatch rescan stays stateless.
    ///
    /// A [`ScanTarget::Step`] is a playbook step the definition names, not the
    /// request: a content finding about it is answered with the neutral step
    /// refusal, as a step's authorization refusal is (A3). A stateful control's
    /// refusal (budget, tenant, anomaly) keeps its count-only firewall wording.
    #[cfg(feature = "firewall")]
    pub(crate) fn route_request_scan(
        &self,
        session_id: &str,
        (server, tool, arguments): (&str, &str, &Value),
        (caller, control_identity, target): (&str, &str, ScanTarget),
    ) -> Option<Error> {
        let firewall = self.firewall.as_deref()?;
        // stdio only: no API keys on that transport.
        let rule_target = crate::security::response_policy::RuleTarget {
            server: crate::security::response_policy::ServerOf::Backend(server),
            tool,
            key: crate::security::response_policy::KeyOf::NoKey,
        };
        let verdict = firewall.check_request_keyed(
            session_id,
            rule_target,
            arguments,
            caller,
            control_identity,
            None,
        );
        if verdict.action == crate::security::firewall::FirewallAction::Warn {
            tracing::warn!(
                server,
                tool,
                findings = verdict.findings.len(),
                "Firewall: request warning"
            );
        }
        let (code, message) = verdict.request_refusal()?;
        if target == ScanTarget::Step && verdict.refusal_words_content() {
            return Some(crate::gateway::meta_mcp::step_not_permitted());
        }
        Some(Error::Forbidden {
            code,
            status: 400,
            message,
        })
    }

    /// Target authorization, identity grants and the admin-capability rule,
    /// against the policy in force now. `on_allow` says whether an allow writes
    /// its record: the route stage writes it, the dispatch recheck is silent
    /// (the route already wrote it). A refusal writes the rows a route-layer
    /// refusal writes. Never skipped for a call signing prepared: a grant
    /// revoked since then is refused here (F5).
    fn recheck_target(
        &self,
        scope: InvokeScope<'_>,
        (server, tool): (&str, &str),
        arguments: &Value,
        on_allow: Emit,
    ) -> Result<()> {
        let authorizer = scope.authorizer;
        let target = ToolTarget {
            server,
            tool,
            arguments,
        };
        let decision = authorizer.decide(target);
        let refusal = if decision.verdict.is_err() {
            decision.emit(Emit::Audit).map_err(|e| Error::Forbidden {
                code: e.code,
                status: e.status.as_u16(),
                message: e.message,
            })
        } else {
            // Allowed: the record, when this stage owns it, then the admin rule.
            let _allowed = decision.emit(on_allow);
            self.admin_capability_rule(server, tool, scope.is_admin)
        };
        if let Err(e) = refusal {
            let (transport, name) = (authorizer.transport(), authorizer.caller_name());
            crate::gateway::authz::audit_refusal(transport, name, server, tool, &e.to_string());
            return Err(e);
        }
        if self
            .identity_grant_rule(server, tool, scope, Emit::Silent)
            .is_err()
        {
            // Re-run to write the refusal's own record, as the route would.
            return self.identity_grant_rule(server, tool, scope, Emit::Audit);
        }
        Ok(())
    }

    /// The request firewall's content scan and rules over every
    /// caller-controlled part of the send, as one verdict: Allow sends with no
    /// record; Warn sends with one warning and one audit row; Block refuses
    /// with one audit row and the route's own code and message.
    #[cfg(feature = "firewall")]
    fn rescan_outbound(
        &self,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
        (server, tool): (&str, &str),
        outbound: &Outbound<'_>,
        source: Source,
    ) -> Result<()> {
        use crate::security::firewall::FirewallAction;
        let Some(firewall) = self.firewall.as_deref() else {
            return Ok(());
        };
        // The content scan reads objects. Arguments always are (parsing
        // refuses anything else before dispatch); answers that are not cannot
        // be judged, so they are refused rather than sent unscanned.
        if outbound.answers.is_some_and(|answers| !answers.is_object()) {
            return Err(Error::Forbidden {
                code: INVALID_PARAMS,
                status: 400,
                message: "inputResponses must be an object".to_owned(),
            });
        }
        // The proven key when the scope carries one; otherwise not known, never
        // "no key": an internal scope (`unscoped`, `allow_all`) has no caller
        // to prove it, and not known can only fail closed.
        let target = crate::security::response_policy::RuleTarget {
            server: crate::security::response_policy::ServerOf::Backend(server),
            tool,
            key: scope.grant_key.map_or(
                crate::security::response_policy::KeyOf::NotKnown,
                crate::security::response_policy::KeyOf::Key,
            ),
        };
        let mut verdict = firewall.rescan(
            target,
            outbound.arguments,
            crate::security::firewall::ScanSubject::Arguments,
            outbound.backend,
        );
        if let Some(answers) = outbound.answers {
            let answered = firewall.rescan(
                target,
                answers,
                crate::security::firewall::ScanSubject::Answers,
                outbound.backend,
            );
            if rank(answered.action) > rank(verdict.action) {
                verdict.action = answered.action;
            }
            verdict.findings.extend(answered.findings);
        }
        verdict.allowed = verdict.action != FirewallAction::Block;
        if verdict.action == FirewallAction::Allow {
            return Ok(());
        }
        let labels = crate::security::response_policy::ResponseCorrelation {
            session_id: session_id.unwrap_or(""),
            caller: scope.authorizer.caller_name().unwrap_or("anonymous"),
            external_server: server,
            external_tool: tool,
            subject: None,
            trace_id: None,
            key: crate::security::response_policy::KeyOf::NotKnown,
        };
        firewall.audit_dispatch(&labels, outbound.arguments, &verdict, source.as_str());
        if verdict.allowed {
            tracing::warn!(
                server,
                tool,
                source = source.as_str(),
                findings = verdict.findings.len(),
                "Firewall: dispatch warning"
            );
            return Ok(());
        }
        // The stateless rescan has no anomaly findings, so this is the
        // `-32600` arm of the one shared wording.
        let (code, message) = verdict.request_refusal().unwrap_or_else(|| {
            (
                INVALID_REQUEST,
                "Firewall blocked: Security firewall blocked this request".to_owned(),
            )
        });
        // The call history counts this refusal as a firewall catch.
        super::audit::counting::note_request_firewall();
        Err(Error::Forbidden {
            code,
            status: 400,
            message,
        })
    }
}

/// Strength order of a firewall action, for combining a send's parts.
#[cfg(feature = "firewall")]
const fn rank(action: crate::security::firewall::FirewallAction) -> u8 {
    use crate::security::firewall::FirewallAction;
    match action {
        FirewallAction::Allow => 0,
        FirewallAction::Warn => 1,
        FirewallAction::Block => 2,
    }
}
