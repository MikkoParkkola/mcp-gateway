// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The router's hiding judgment: a backend the caller's mTLS policy or agent
//! scopes refuse outright is hidden from that caller
//! (`meta_mcp::hiding`).
//!
//! It applies the predicate listings apply (the session profile, then
//! [`admits_some_tool`]) to the catalogue listings read
//! (`MetaMcp::listed_catalogue`), from the registry directly, never through
//! the caller's scoped view the judgment feeds. A decision that would rest on
//! a catalogue not held now is no decision: the backend is hidden only if its
//! name alone refuses it.
//!
//! On a per-user backend the listing reads the shared slot alone, so the
//! caller's own slot decides too: an unlisted backend is hidden only when the
//! caller's own slot is held and refuses the call. A cold one proves nothing
//! and hides nothing, so no caller is refused a call it could make before.

use std::sync::Arc;

use super::AppState;
use super::authorization::OwnedRouterAuthorizer;
use crate::gateway::meta_mcp::hiding::{CallerHiding, CallerSlot, ListedCatalogue};
use crate::gateway::meta_mcp::scoped_backends::Unscoped;
use crate::gateway::oauth::scopes::Action;
use crate::gateway::oauth::{OAuthAgentIdentity, check_scopes};
use crate::identity_propagation::{CallerProof, CallerProvenance};
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::{CertIdentity, PolicyDecision};

/// One caller's identity, as a hiding judgment.
pub(crate) struct RouterHiding {
    state: Arc<AppState>,
    authorizer: OwnedRouterAuthorizer,
    /// What the caller proved, to find its own slot on a per-user backend.
    verified: Option<VerifiedIdentity>,
    session_id: Option<String>,
}

impl RouterHiding {
    /// The judgment for `authorizer`'s caller, who proved `verified` and
    /// whose session is `session_id`.
    pub(crate) fn caller(
        state: Arc<AppState>,
        authorizer: OwnedRouterAuthorizer,
        verified: Option<VerifiedIdentity>,
        session_id: Option<String>,
    ) -> Arc<dyn CallerHiding> {
        Arc::new(Self {
            state,
            authorizer,
            verified,
            session_id,
        })
    }

    /// Whether `server` names a registered backend or the capability provider.
    fn registered(&self, server: &str) -> bool {
        let meta = &self.state.meta_mcp;
        meta.registry()
            .get_for(Unscoped::Visibility, server)
            .is_some()
            || meta
                .get_capabilities()
                .is_some_and(|cap| cap.name == server)
    }
}

impl CallerHiding for RouterHiding {
    fn hides(&self, server: &str) -> bool {
        self.unlisted(server) && !self.own_slot_keeps(server)
    }
}

impl RouterHiding {
    /// Whether this caller's own slot on a per-user `server` keeps the
    /// backend from being hidden: it admits a call, or it is not held and so
    /// proves no refusal.
    fn own_slot_keeps(&self, server: &str) -> bool {
        let state = self.state.as_ref();
        let (client, agent, cert) = self.authorizer.parts();
        let caller = CallerProof::new(
            self.verified.as_ref(),
            CallerProvenance::classify(client.map(|c| c.principal.storage_form())),
        );
        let names = match state.meta_mcp.caller_slot(server, caller) {
            CallerSlot::Listing => return false,
            CallerSlot::Undecided => return true,
            CallerSlot::Held(names) => names,
        };
        !(agent.is_none() && state.agent_auth.enabled)
            && state
                .meta_mcp
                .active_profile(self.session_id.as_deref())
                .backend_allowed(server)
            && admits_some_tool(state, (agent, cert), server, &names)
    }

    /// Whether the listing leaves `server` out for this caller.
    fn unlisted(&self, server: &str) -> bool {
        let state = self.state.as_ref();
        if state.mtls_policy.is_empty() && !state.agent_auth.enabled {
            // Nothing is hidden beyond the grant, which the scoped view
            // already applies.
            return false;
        }
        let (client, agent, cert) = self.authorizer.parts();
        // A grant refusal is the grant's answer, not a hiding.
        if crate::gateway::authz::authorize_backend(client, server).is_err() {
            return false;
        }
        // A profile's backend deny refuses every tool by name, so it hides the
        // backend whatever is held of its catalogue: warm, cold or truncated.
        if !state
            .meta_mcp
            .active_profile(self.session_id.as_deref())
            .backend_allowed(server)
        {
            return self.registered(server);
        }
        let (names, complete) = match state.meta_mcp.listed_catalogue(server) {
            ListedCatalogue::NotHeld => {
                return self.registered(server) && refused_by_name(state, (agent, cert), server);
            }
            ListedCatalogue::Tools { names, complete } => (names, complete),
        };
        if agent.is_none() && state.agent_auth.enabled {
            // Agent auth with no validated agent admits no backend.
            return true;
        }
        if admits_some_tool(state, (agent, cert), server, &names) {
            return false;
        }
        // A truncated catalogue proves nothing about the tools it lacks.
        complete || refused_by_name(state, (agent, cert), server)
    }
}

/// Whether every tool on `server` is refused from its name alone: an mTLS
/// rule that denies the backend or leaves it out of its allow list, or agent
/// scopes that grant nothing on it.
fn refused_by_name(
    state: &AppState,
    (agent, cert): (
        Option<&crate::gateway::oauth::OAuthAgentIdentity>,
        Option<&crate::mtls::CertIdentity>,
    ),
    server: &str,
) -> bool {
    let by_mtls = !state.mtls_policy.is_empty() && state.mtls_policy.refuses_backend(cert, server);
    let by_agent = state.agent_auth.enabled
        && agent.is_none_or(|id| {
            !id.scopes
                .iter()
                .any(|scope| scope.may_grant_on(server, &Action::Execute))
        });
    by_mtls || by_agent
}

/// Whether some tool of `tools` passes the agent's scopes and the mTLS policy
/// on `server`: the backend admission check's test (`authorization.rs`),
/// shared with this judgment, which reads `tools` unfiltered so it cannot
/// re-enter the caller's view.
pub(super) fn admits_some_tool(
    state: &AppState,
    (agent, cert_identity): (Option<&OAuthAgentIdentity>, Option<&CertIdentity>),
    server: &str,
    tools: &[String],
) -> bool {
    let mtls = !state.mtls_policy.is_empty();
    tools.iter().any(|tool| {
        agent.is_none_or(|id| {
            check_scopes(&id.scopes, &id.client_id, server, tool, &Action::Execute).is_ok()
        }) && (!mtls
            || state.mtls_policy.evaluate(cert_identity, server, tool) != PolicyDecision::Deny)
    })
}
