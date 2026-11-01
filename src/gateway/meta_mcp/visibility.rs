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

use crate::error::rpc_codes::{INVALID_REQUEST, METHOD_NOT_FOUND};
use serde_json::json;
use tracing::warn;

use super::MetaMcp;
use crate::gateway::authz::{Emit, ToolAuthorizer, ToolTarget};
use crate::gateway::meta_mcp_tool_total::ToolTotal;
use crate::identity_grants::{
    GrantScope, GrantSubject, IdentityGrantEvaluation, IdentityGrantRequest,
};
use crate::{Error, Result};

/// One identity-grant evaluation: the request judged and its verdict.
type GrantVerdict = (IdentityGrantRequest, IdentityGrantEvaluation);

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
    /// The caller's display name, for guards and audit; never a grant subject (MIK-8518).
    pub api_key_name: Option<&'a str>,
    /// The API key's name, only for an authenticated API-key credential: the identity-grant
    /// fallback subject. `None` for every other credential kind (MIK-8518).
    pub(crate) grant_key: Option<&'a str>,
    /// The caller's proven agent principal.
    pub agent_id: Option<crate::security::ProvenAgentId<'a>>,
    /// Verified caller subject for identity-grant evaluation.
    pub grant_subject: Option<&'a GrantSubject>,
    /// What the caller proved, read only to find its own catalogue slot on a
    /// per-user backend (MIK-8356). Never an authorization input.
    pub(crate) caller: crate::identity_propagation::CallerProof<'a>,
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
        self.may_invoke_explained(server, tool, scope, session_id)
            .map_err(|(error, _)| error)
    }

    /// [`Self::may_invoke`], naming the check that refused: the one sequence,
    /// so a caller that records the refusal names the check that made it.
    pub(crate) fn may_invoke_explained(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> std::result::Result<(), (Error, crate::security::decision_record::DecisionKind)> {
        self.may_invoke_before_grants_explained(server, tool, scope, session_id)?;
        self.identity_grant_rule(server, tool, scope, Emit::Silent)
            .map_err(|error| (error, crate::security::decision_record::DecisionKind::Grant))
    }

    /// The pieces of [`Self::may_invoke`] before identity grants.
    fn may_invoke_before_grants(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Result<()> {
        self.may_invoke_before_grants_explained(server, tool, scope, session_id)
            .map_err(|(error, _)| error)
    }

    /// [`Self::may_invoke_before_grants`], naming the check that refused.
    fn may_invoke_before_grants_explained(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> std::result::Result<(), (Error, crate::security::decision_record::DecisionKind)> {
        self.active_profile(session_id)
            .check(server, tool)
            .map_err(|refusal| {
                (
                    Error::Protocol(refusal),
                    crate::security::decision_record::DecisionKind::RoutingProfile,
                )
            })?;
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
            .map_err(|e| {
                let kind = e.kind;
                (
                    Error::Forbidden {
                        code: e.code,
                        status: e.status.as_u16(),
                        message: e.message,
                    },
                    kind,
                )
            })?;
        self.admin_capability_rule(server, tool, scope.is_admin)
            .map_err(|error| {
                (
                    error,
                    crate::security::decision_record::DecisionKind::AdminCapability,
                )
            })
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
        self.withheld_surfaced_in(server, tool_name, caller.scope(), session_id)
    }

    /// [`Self::withheld_surfaced`] from the caller's [`InvokeScope`] alone, for
    /// the route stage, which asks before the caller context exists
    /// (MIK-8326, route-check-parity P3).
    pub(super) fn withheld_surfaced_in(
        &self,
        server: &str,
        tool_name: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Option<Error> {
        // A direct-name call is a dispatch, not a listing: its grant decision
        // is recorded (D3-a); a failed note answers -32005, not -32601.
        let refusal = match self.may_invoke_before_grants(server, tool_name, scope, session_id) {
            Err(refusal) => match self.identity_grant_rule(server, tool_name, scope, Emit::Audit) {
                Err(error @ Error::AuditUnavailable) => return Some(error),
                _ => refusal,
            },
            // MIK-7654: the one evaluation that refuses is the one recorded,
            // so a grant reload cannot make the record disagree with it.
            Ok(()) => match self.grant_evaluation(server, tool_name, scope) {
                Ok(None) => return None,
                Ok(Some(verdict)) if verdict.1.allowed => return None,
                Ok(Some(verdict)) => {
                    match self.settle_grant(server, tool_name, scope, &verdict, Emit::Audit) {
                        Err(error @ Error::AuditUnavailable) => return Some(error),
                        Err(refusal) => refusal,
                        Ok(()) => return None,
                    }
                }
                Err(refusal) => refusal,
            },
        };
        crate::gateway::authz::audit_refusal(
            scope.authorizer.transport(),
            scope.authorizer.caller_name(),
            server,
            tool_name,
            &refusal.to_string(),
        );
        Some(Error::json_rpc(
            METHOD_NOT_FOUND,
            format!("Unknown tool: {tool_name}"),
        ))
    }

    /// The one operator record for a direct-name call of a surfaced tool
    /// withheld from this caller (MIK-8340 A3), written by the meta direct
    /// route, which every entry reaches. Best-effort: a record that cannot be
    /// written is logged, never answered, so the answer stays the absent
    /// name's whatever the audit log does.
    pub(super) async fn record_withheld(
        &self,
        server: &str,
        tool_name: &str,
        reason: super::visible::Withholding,
        caller: &super::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) {
        match reason {
            // An absent backend is noted as a refused one is (MIK-8387), so
            // the three cells write the same operator record.
            super::visible::Withholding::Refused | super::visible::Withholding::Absent => {
                let refused = super::grant_audit::note_withheld_best_effort(server, || {
                    self.withheld_surfaced(server, tool_name, caller, session_id)
                })
                .await;
                // Outside a grant slot the note is refused and written on its
                // own task; the call still answers as an absent name.
                if matches!(refused, Some(Error::AuditUnavailable)) {
                    tracing::warn!(server, "{}", super::grant_audit::WITHHELD_RECORD_FAILED);
                }
            }
            super::visible::Withholding::Schema
            | super::visible::Withholding::Descriptor
            | super::visible::Withholding::Unselected
            | super::visible::Withholding::Lacked => {
                // Its record names the check that withheld it, never an allow.
                crate::gateway::meta_mcp::invoke::audit::note_refused_by(reason.kind(), None);
                tracing::warn!(
                    server,
                    tool = tool_name,
                    ?reason,
                    "Surfaced tool withheld from a call by its name; answered as a name that \
                     matches no tool"
                );
            }
        }
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

    /// One admitted backend's part of [`Self::admitted_counts`]: how many of its
    /// tools this caller is shown, whether that listing is known at all, and
    /// whether the list is cut short. The list and its cut flag are read
    /// together inside the backend's snapshot, so a fill landing between cannot
    /// tear them; `listing_known` is a separate read (MIK-8350 D12).
    pub(crate) fn admitted_count_for(
        &self,
        backend: &crate::backend::Backend,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> (usize, bool, bool) {
        let view = self.listing_snapshot(backend, scope);
        let known = view.is_some() && self.listing_known(backend, scope);
        match view {
            None => (0, known, false),
            Some((tools, cut)) => {
                let count = tools
                    .iter()
                    .filter(|t| self.shows_tool(&backend.name, t, scope, session_id))
                    .count();
                (count, known, cut)
            }
        }
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
            .all_for(crate::gateway::meta_mcp::scoped_backends::Unscoped::Visibility)
            .into_iter()
            .filter(|b| self.admits_backend(&b.name, scope, session_id))
            .collect();
        // MIK-8356: a per-user backend is counted from this caller's own slot,
        // and is not known while that slot is cold. A truncated drain is still
        // "known" (enumerated), but its count is a lower bound, never exact
        // (MIK 7570 PAGING.1 design D).
        let mut known = 0;
        let mut truncated = false;
        let mut admitted = 0;
        for backend in &backends {
            let (count, is_known, cut) = self.admitted_count_for(backend, scope, session_id);
            admitted += count;
            known += usize::from(is_known);
            truncated |= cut;
        }
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
            // Names only: this runs on every initialize and tools/list, and
            // `get_tools()` deep-clones every definition's schemas (#2110).
            let mut seen = std::collections::HashMap::new();
            let admitted = cap
                .list()
                .iter()
                .filter(|name| {
                    cap.is_listed_in(name, &mut seen)
                        && self.shows_name(&cap.name, name, scope, session_id)
                })
                .count();
            total = total.plus(admitted);
            servers += 1;
        }
        (total, servers)
    }

    /// The capabilities the initialize guide may name for this caller: listed
    /// ones it could invoke, each with its chain hints cut the same way.
    pub(super) fn guide_capabilities(
        &self,
        cap: &crate::capability::CapabilityBackend,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Vec<(String, String, Vec<String>)> {
        let mut seen = std::collections::HashMap::new();
        let mut allowed = |name: &str| {
            cap.is_listed_in(name, &mut seen) && self.shows_name(&cap.name, name, scope, session_id)
        };
        // Name, category and chain hints only (MIK-8014 PERF.8a): the guide
        // reads nothing else, so no definition is copied.
        let mut caps = cap.routing_fields();
        caps.retain(|(name, _, _)| allowed(name));
        for (_, _, chains_with) in &mut caps {
            chains_with.retain(|t| allowed(t));
        }
        caps
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
        let on_backend = self
            .backends
            .all_for(crate::gateway::meta_mcp::scoped_backends::Unscoped::Visibility)
            .into_iter()
            .any(|b| {
                self.listing_tool(&b, name, scope).is_some()
                    && self.shows_name(&b.name, name, scope, session_id)
            });
        on_backend
            || self.get_capabilities().is_some_and(|cap| {
                cap.has_capability(name)
                    && cap.is_listed(name)
                    && self.shows_name(&cap.name, name, scope, session_id)
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
            && capabilities
                .with_definition(
                    tool,
                    crate::capability::definition::creates_caller_addressed_external_state,
                )
                .unwrap_or(false)
        {
            // A deliberate, permanent refusal: the admin-denial shape admin-only
            // tools answer with (403, -32600), never a retriable internal error.
            return Err(Error::Forbidden {
                code: INVALID_REQUEST,
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
        let verdict = self
            .grant_evaluation(server, tool, scope)
            .and_then(|evaluation| {
                evaluation.map_or(Ok(()), |verdict| {
                    self.settle_grant(server, tool, scope, &verdict, emit)
                })
            });
        // Noted only when audited: a silent evaluation is a listing's, and a
        // listing inside a call must not name another target's check.
        if emit == Emit::Audit && verdict.is_err() {
            crate::gateway::meta_mcp::invoke::audit::note_refused_by(
                crate::security::decision_record::DecisionKind::Grant,
                None,
            );
        }
        verdict
    }

    /// One evaluation of the identity grants for `(server, tool)`: `None`
    /// when `server` is not the capability backend, so no grant applies.
    fn grant_evaluation(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
    ) -> Result<Option<GrantVerdict>> {
        let Some(cap) = self.get_capabilities() else {
            return Ok(None);
        };
        if server != cap.name {
            return Ok(None);
        }
        // A clock before 1970 can judge no grant expiry and date no decision,
        // so no grant authorizes on it: refused like a denied grant (MIK-8202).
        let Ok(now) = crate::clock::utc_now() else {
            return Err(Error::json_rpc(
                -32004,
                format!(
                    "Identity grant denied for tool '{tool}': the gateway clock reads before 1970"
                ),
            ));
        };
        // Borrowed, not cloned: this runs per tool on every listing (#2110).
        // One lookup, so a reload removing the tool reads as absent (#2236).
        // Absent is refused, not skipped: a skip here would admit a tool a
        // reload re-adds before dispatch, and a cached answer for a removed one.
        let Some(request) = cap.with_definition(tool, |cap_def| IdentityGrantRequest {
            identity: scope
                .grant_subject
                .cloned()
                .or_else(|| Self::grant_subject_from_api_key(scope.grant_key)),
            agent_id: scope
                .agent_id
                .map(crate::security::OwnedProvenAgentId::from),
            capability: cap_def.name.clone(),
            tool: Some(tool.to_string()),
            scope: GrantScope::requested_by(cap_def),
            exposure: cap_def.metadata.exposure,
            owner: cap_def.metadata.identity_owner.clone(),
            now,
        }) else {
            return Err(Error::ToolNotFound(tool.to_string()));
        };
        let evaluation = self.identity_grants.read().evaluate(&request);
        #[cfg(test)]
        after_grant_evaluation::fire();
        Ok(Some((request, evaluation)))
    }

    /// The answer one grant `verdict` gives, noted for its record under
    /// [`Emit::Audit`].
    fn settle_grant(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        (request, evaluation): &GrantVerdict,
        emit: Emit,
    ) -> Result<()> {
        // D3-a: a dispatch decision is noted for its record; an unslotted
        // check fails closed here, whatever the grant said.
        if emit == Emit::Audit {
            let logger = self.transparency_logger.as_ref();
            super::grant_audit::note_grant_decision(logger, server, tool, &evaluation.audit)?;
        }
        if evaluation.allowed {
            return Ok(());
        }
        if emit == Emit::Audit {
            warn!(
                capability = %request.capability,
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
                request.capability, evaluation.reason
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
    fn backend_grant(&self) -> crate::gateway::authz::BackendGrant<'_> {
        crate::gateway::authz::BackendGrant::Unscoped
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
            grant_key: None,
            agent_id: None,
            grant_subject: None,
            caller: crate::identity_propagation::CallerProof::Anonymous,
        }
    }
}

/// A reload landing just after a grant evaluation, set by a test cell.
#[cfg(test)]
pub(super) mod after_grant_evaluation {
    use std::cell::RefCell;

    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    /// Run `hook` once, after the next grant evaluation on this thread.
    pub(in crate::gateway::meta_mcp) fn set(hook: impl FnOnce() + 'static) {
        HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn fire() {
        if let Some(hook) = HOOK.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }
}

#[cfg(test)]
#[path = "withheld_grant_once_tests.rs"]
mod withheld_grant_once_tests;

#[cfg(test)]
impl InvokeScope<'static> {
    /// An `AllowAll` scope at `standing`, for cells about something else.
    pub(crate) fn allow_all(standing: crate::gateway::router::CallerStanding) -> Self {
        Self {
            authorizer: &crate::gateway::authz::AllowAll,
            is_admin: standing == crate::gateway::router::CallerStanding::Admin,
            api_key_name: None,
            grant_key: None,
            agent_id: None,
            grant_subject: None,
            caller: crate::identity_propagation::CallerProof::Anonymous,
        }
    }
}

impl<'a> InvokeScope<'a> {
    /// The scope stdio serves its metadata surfaces at. The client spawned
    /// this process, so it holds the operator's standing; its tools are
    /// judged by the stdio authorizer (the global tool policy), as its calls
    /// are, and identity grants see no subject, which also matches invoke.
    pub(crate) fn stdio(
        authorizer: &'a crate::gateway::authz::ToolPolicyAuthorizer<'a>,
        caller: crate::identity_propagation::CallerProof<'a>,
    ) -> Self {
        Self {
            authorizer,
            is_admin: true,
            api_key_name: None,
            grant_key: None,
            agent_id: None,
            grant_subject: None,
            // The process's one operator spawned it, so its own catalogue slot on
            // a per-user backend is the sole operator's (MIK-8356). Proven by
            // the caller, which holds the stdio nonce.
            caller,
        }
    }
}
