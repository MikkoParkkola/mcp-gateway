// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! List = invoke (A3, GitHub #555).
//!
//! A backend tool is disclosed to a caller iff [`MetaMcp::may_invoke`] admits
//! it; a backend name iff [`MetaMcp::admits_backend`] does. Both are the
//! discovery-side composition of the pieces the invocation chokepoint
//! (`authorize_invocation`, `check_invocation_policy`) runs, taken with
//! [`Emit::Silent`] so that listing a catalogue writes no invocation audit.
//! Invocation never calls `may_invoke`: it keeps its own order and its own
//! records, and the pieces are conjunctive and side-effect free when silent,
//! so the order cannot change the verdict.
//!
//! Attestation, nonce, budget and idempotency are about one call rather than
//! about who may see what, and stay on the call path only.

use serde_json::json;
use tracing::warn;

use super::MetaMcp;
use crate::gateway::authz::{Emit, ToolAuthorizer, ToolTarget};
use crate::gateway::meta_mcp_tool_total::ToolTotal;
use crate::identity_grants::{GrantScope, GrantSubject, IdentityGrantRequest};
use crate::{Error, Result};

/// What the chokepoint reads about a caller, as a `Copy` view.
///
/// Not optional anywhere it is taken: an absent authorizer would fail open.
/// Tests pass `authz::AllowAll` explicitly.
#[derive(Clone, Copy)]
pub struct InvokeScope<'a> {
    /// The per-transport invocation predicate.
    pub authorizer: &'a (dyn ToolAuthorizer + Sync),
    /// Whether the caller holds admin.
    pub is_admin: bool,
    /// Static or temporary API-key name, the fallback grant subject.
    pub api_key_name: Option<&'a str>,
    /// The caller's proven agent principal.
    pub agent_id: Option<crate::security::ProvenAgentId<'a>>,
    /// Verified caller subject for identity-grant evaluation.
    pub grant_subject: Option<&'a GrantSubject>,
}

impl MetaMcp {
    /// Whether this caller could invoke `(server, tool)`: the routing profile,
    /// the transport's predicate, the admin-capability rule and identity
    /// grants, each decided silently.
    ///
    /// # Errors
    /// Returns the refusal the first failing piece gives.
    pub(crate) fn may_invoke(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Result<()> {
        self.active_profile(session_id)
            .check(server, tool)
            .map_err(Error::Protocol)?;
        // `{}`, never `Null`: invocation builds its target with an empty
        // object, and two gates that see different targets can disagree.
        let empty = json!({});
        let target = ToolTarget {
            server,
            tool,
            arguments: &empty,
        };
        scope
            .authorizer
            .decide(target)
            .emit(Emit::Silent)
            .map_err(|e| Error::Forbidden {
                code: e.code,
                status: e.status.as_u16(),
                message: e.message,
            })?;
        self.admin_capability_rule(server, tool, scope.is_admin)?;
        self.identity_grant_rule(server, tool, scope, Emit::Silent)
    }

    /// Whether a piece of `may_invoke` other than the authorizer refuses
    /// `(server, tool)`: for a caller whose authorizer verdict is already
    /// known, and must not be consulted twice.
    pub(super) fn refused_beyond_authorizer(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
    ) -> bool {
        self.active_profile(None).check(server, tool).is_err()
            || self
                .admin_capability_rule(server, tool, scope.is_admin)
                .is_err()
            || self
                .identity_grant_rule(server, tool, scope, Emit::Silent)
                .is_err()
    }

    /// The answer to a direct-name call of a surfaced tool this caller could
    /// not invoke: `-32601 Unknown tool`, the answer an absent name gets, never
    /// a refusal naming its backend (A3). The refusal is audited here, once.
    pub(super) fn withheld_surfaced(
        &self,
        server: &str,
        tool_name: &str,
        caller: &super::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Option<Error> {
        let refusal = self
            .may_invoke(server, tool_name, caller.scope(), session_id)
            .err()?;
        crate::gateway::authz::audit_refusal(
            caller.authorizer.transport(),
            caller.authorizer.caller_name(),
            server,
            tool_name,
            &refusal.to_string(),
        );
        Some(Error::json_rpc(
            -32601,
            format!("Unknown tool: {tool_name}"),
        ))
    }

    /// Whether this caller may be shown the backend name `server`: its
    /// backend scope and the routing profile. A cold cache does not hide it.
    pub(crate) fn admits_backend(
        &self,
        server: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> bool {
        self.active_profile(session_id).backend_allowed(server)
            && scope.authorizer.admits_backend(server)
    }

    /// `(tool total, backend count)` over what this caller could invoke: the
    /// one source for the initialize preamble and the meta-tool descriptions.
    pub(crate) fn admitted_counts(
        &self,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> (ToolTotal, usize) {
        let backends: Vec<_> = self
            .backends
            .all()
            .into_iter()
            .filter(|b| self.admits_backend(&b.name, scope, session_id))
            .collect();
        let known = backends.iter().filter(|b| b.cached_tools_known()).count();
        // A truncated drain is still "known" (enumerated), but its count is a
        // lower bound, never exact (MIK 7570 PAGING.1 design D). List and flag
        // are read under one guard so a fill landing between cannot tear them.
        let mut truncated = false;
        let admitted: usize = backends
            .iter()
            .map(|b| {
                let (tools, cut) = b.cached_tools_snapshot_and_truncated();
                truncated |= cut;
                tools
                    .iter()
                    .filter(|t| self.may_invoke(&b.name, &t.name, scope, session_id).is_ok())
                    .count()
            })
            .sum();
        let mut total = if known == backends.len() && !truncated {
            ToolTotal::Exact(admitted)
        } else if known == 0 {
            ToolTotal::Unknown
        } else {
            ToolTotal::AtLeast(admitted)
        };
        let mut servers = backends.len();
        if let Some(cap) = self.get_capabilities()
            && self.admits_backend(&cap.name, scope, session_id)
        {
            let admitted = cap
                .get_tools()
                .iter()
                .filter(|t| {
                    self.may_invoke(&cap.name, &t.name, scope, session_id)
                        .is_ok()
                })
                .count();
            total = total.plus(admitted);
            servers += 1;
        }
        (total, servers)
    }

    /// Whether a bare tool `name` (as a cost alternative carries it) resolves
    /// to at least one `(server, tool)` this caller could invoke.
    #[cfg(feature = "cost-governance")]
    pub(crate) fn admits_tool_named(
        &self,
        name: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> bool {
        let on_backend = self.backends.all().into_iter().any(|b| {
            b.get_cached_tool(name).is_some()
                && self.may_invoke(&b.name, name, scope, session_id).is_ok()
        });
        on_backend
            || self.get_capabilities().is_some_and(|cap| {
                cap.has_capability(name)
                    && self.may_invoke(&cap.name, name, scope, session_id).is_ok()
            })
    }

    /// A capability that registers a caller-chosen destination with a third
    /// party, which then calls it with this gateway's credential, is an
    /// out-of-band channel needing no readable response: an admin action.
    /// Derived from the definition, so one added later inherits the rule.
    pub(super) fn admin_capability_rule(
        &self,
        server: &str,
        tool: &str,
        is_admin: bool,
    ) -> Result<()> {
        if !is_admin
            && let Some(capabilities) = self.get_capabilities()
            && server == capabilities.name
            && let Some(def) = capabilities.get(tool)
            && crate::capability::definition::creates_caller_addressed_external_state(&def)
        {
            // A deliberate, permanent refusal: the admin-denial shape admin-only
            // tools answer with (403, -32600), never a retriable internal error.
            return Err(Error::Forbidden {
                code: -32600,
                status: 403,
                message: format!(
                    "'{tool}' registers a caller-supplied address with a third party, which \
                     then delivers to it using this gateway's credential. That requires an \
                     admin credential."
                ),
            });
        }
        Ok(())
    }

    /// Identity grants: whether this caller may reach a personal capability.
    /// Resolved from the definition, so a capability added later inherits it.
    pub(super) fn identity_grant_rule(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        emit: Emit,
    ) -> Result<()> {
        let Some(cap) = self.get_capabilities() else {
            return Ok(());
        };
        if server != cap.name || !cap.has_capability(tool) {
            return Ok(());
        }
        let cap_def = cap
            .get(tool)
            .ok_or_else(|| Error::Config(format!("Capability not found: {tool}")))?;
        let request = IdentityGrantRequest {
            identity: scope
                .grant_subject
                .cloned()
                .or_else(|| Self::grant_subject_from_api_key(scope.api_key_name)),
            agent_id: scope
                .agent_id
                .map(crate::security::OwnedProvenAgentId::from),
            capability: cap_def.name.clone(),
            tool: Some(tool.to_string()),
            scope: GrantScope::requested_by(&cap_def),
            exposure: cap_def.metadata.exposure,
            owner: cap_def.metadata.identity_owner.clone(),
            now: chrono::Utc::now(),
        };
        let evaluation = self.identity_grants.read().evaluate(&request);
        if evaluation.allowed {
            return Ok(());
        }
        if emit == Emit::Audit {
            warn!(
                capability = %cap_def.name,
                tool,
                agent_id = scope.agent_id.map_or("anonymous", |a| a.as_str()),
                reason = ?evaluation.reason,
                "Identity grant denied personal capability dispatch"
            );
        }
        Err(Error::json_rpc(
            -32004,
            format!(
                "Identity grant denied for capability '{}': {:?}",
                cap_def.name, evaluation.reason
            ),
        ))
    }
}

impl From<InvokeScope<'_>> for crate::gateway::router::CallerStanding {
    /// The admin bit has one source: the scope the caller is judged by.
    fn from(scope: InvokeScope<'_>) -> Self {
        Self::of_admin_flag(scope.is_admin)
    }
}

/// The authorizer of [`InvokeScope::unscoped`]: admits every tool. Never
/// built from a request; every request path constructs its transport's own.
struct Operator;

impl ToolAuthorizer for Operator {
    fn decide<'a>(&'a self, _target: ToolTarget<'a>) -> crate::gateway::authz::Decision<'a> {
        crate::gateway::authz::Decision::of(Ok(()))
    }
    fn admits_backend(&self, _server: &str) -> bool {
        true
    }
    fn transport(&self) -> crate::gateway::authz::Transport {
        crate::gateway::authz::Transport::Stdio
    }
    fn caller_name(&self) -> Option<&str> {
        None
    }
    fn quota_principal(&self) -> Option<&crate::gateway::auth::QuotaPrincipal> {
        None
    }
}

impl InvokeScope<'static> {
    /// The operator's own view at `standing`: every configured tool, judged
    /// by no per-caller predicate. For embedders and the surface-count gates
    /// that ask what the whole surface is; a request never builds one.
    #[must_use]
    pub fn unscoped(standing: crate::gateway::router::CallerStanding) -> Self {
        Self {
            authorizer: &Operator,
            is_admin: standing == crate::gateway::router::CallerStanding::Admin,
            api_key_name: None,
            agent_id: None,
            grant_subject: None,
        }
    }
}

#[cfg(test)]
impl InvokeScope<'static> {
    /// An `AllowAll` scope at `standing`, for cells about something else.
    pub(crate) fn allow_all(standing: crate::gateway::router::CallerStanding) -> Self {
        Self {
            authorizer: &crate::gateway::authz::AllowAll,
            is_admin: standing == crate::gateway::router::CallerStanding::Admin,
            api_key_name: None,
            agent_id: None,
            grant_subject: None,
        }
    }
}

impl<'a> InvokeScope<'a> {
    /// The scope stdio serves its metadata surfaces at. The client spawned
    /// this process, so it holds the operator's standing; its tools are
    /// judged by the stdio authorizer (the global tool policy), as its calls
    /// are, and identity grants see no subject, which also matches invoke.
    pub(crate) fn stdio(authorizer: &'a crate::gateway::authz::ToolPolicyAuthorizer<'a>) -> Self {
        Self {
            authorizer,
            is_admin: true,
            api_key_name: None,
            agent_id: None,
            grant_subject: None,
        }
    }
}
