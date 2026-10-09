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
//! what it took (nonce, idempotency key). A pass mints the [`Permit`] the send
//! consumes; a send without one is a bug, refused (and a panic under test).

use serde_json::Value;

use crate::gateway::authz::{Emit, ToolTarget};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::{Error, Result};

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
        }
    }
}

/// The caller-controlled bytes one send carries: the tool arguments and, on a
/// retry or a bridged round, the client's answers. Operator-injected secrets
/// are added after the chokepoint and are not caller input (note r2, item 2).
pub(super) struct Outbound<'a> {
    pub(super) arguments: &'a Value,
    pub(super) answers: Option<&'a Value>,
}

impl MetaMcp {
    /// Pass or refuse one send. See the module documentation.
    pub(super) fn chokepoint(
        &self,
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
        (server, tool): (&str, &str),
        outbound: &Outbound<'_>,
        source: Source,
    ) -> Result<Permit> {
        self.recheck_target(caller, (server, tool), outbound.arguments)?;
        #[cfg(feature = "firewall")]
        self.rescan_outbound(caller, session_id, (server, tool), outbound, source)?;
        #[cfg(not(feature = "firewall"))]
        let _ = (session_id, source);
        Ok(Permit(()))
    }

    /// Target authorization, identity grants and the admin-capability rule,
    /// against the policy in force now. Silent on allow; a refusal writes the
    /// rows a route-layer refusal writes. Never skipped for a call signing
    /// prepared: a grant revoked since then is refused here (F5).
    fn recheck_target(
        &self,
        caller: &MetaMcpCallerContext<'_>,
        (server, tool): (&str, &str),
        arguments: &Value,
    ) -> Result<()> {
        let authorizer = caller.authorizer;
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
            self.admin_capability_rule(server, tool, caller.is_admin)
        };
        if let Err(e) = refusal {
            let (transport, name) = (authorizer.transport(), authorizer.caller_name());
            crate::gateway::authz::audit_refusal(transport, name, server, tool, &e.to_string());
            return Err(e);
        }
        if self
            .identity_grant_rule(server, tool, caller.scope(), Emit::Silent)
            .is_err()
        {
            // Re-run to write the refusal's own record, as the route would.
            return self.identity_grant_rule(server, tool, caller.scope(), Emit::Audit);
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
        caller: &MetaMcpCallerContext<'_>,
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
                code: -32602,
                status: 400,
                message: "inputResponses must be an object".to_owned(),
            });
        }
        let mut verdict = firewall.rescan(tool, outbound.arguments);
        if let Some(answers) = outbound.answers {
            let answered = firewall.rescan(tool, answers);
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
            caller: caller.authorizer.caller_name().unwrap_or("anonymous"),
            external_server: server,
            external_tool: tool,
            subject: None,
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
        let desc = verdict
            .findings
            .first()
            .map_or("Security firewall blocked this request", |f| {
                f.description.as_str()
            });
        Err(Error::Forbidden {
            code: -32600,
            status: 400,
            message: format!("Firewall blocked: {desc}"),
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

/// The send's half of the contract: a dispatch without a permit is a bug.
/// Refused in production (nothing is sent); a panic under test, so a path
/// that skips the chokepoint fails its own row (MX).
pub(super) fn require(permit: Option<Permit>) -> Result<Permit> {
    match permit {
        Some(permit) => Ok(permit),
        None if cfg!(test) => panic!("a backend send without a chokepoint permit"),
        None => Err(Error::Internal(
            "a backend send reached dispatch without passing the chokepoint".to_owned(),
        )),
    }
}
