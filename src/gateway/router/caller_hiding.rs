// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The router's hiding judgment: a backend the caller's mTLS policy or agent
//! scopes refuse outright is hidden from that caller
//! (`meta_mcp::hiding`).
//!
//! It applies the predicate listings apply (the session profile, then
//! [`super::authorization::admits_some_tool`]), but reads the backend's tools
//! from the registry directly, never through the caller's scoped view that
//! the judgment feeds. A decision that would rest on a catalogue not held
//! now is no decision: the backend is not hidden, as it was before.

use std::sync::Arc;

use super::AppState;
use super::authorization::{OwnedRouterAuthorizer, admits_some_tool};
use crate::gateway::meta_mcp::hiding::CallerHiding;
use crate::gateway::meta_mcp::scoped_backends::Unscoped;
use crate::gateway::oauth::scopes::Action;

/// One caller's identity, as a hiding judgment.
pub(crate) struct RouterHiding {
    state: Arc<AppState>,
    authorizer: OwnedRouterAuthorizer,
    session_id: Option<String>,
}

impl RouterHiding {
    /// The judgment for `authorizer`'s caller, whose session is `session_id`.
    pub(crate) fn new(
        state: Arc<AppState>,
        authorizer: OwnedRouterAuthorizer,
        session_id: Option<String>,
    ) -> Arc<dyn CallerHiding> {
        Arc::new(Self {
            state,
            authorizer,
            session_id,
        })
    }
}

impl CallerHiding for RouterHiding {
    fn hides(&self, server: &str) -> bool {
        let state = self.state.as_ref();
        let mtls = !state.mtls_policy.is_empty();
        if !mtls && !state.agent_auth.enabled {
            // Nothing is hidden beyond the grant, which the scoped view
            // already applies.
            return false;
        }
        let (client, agent, cert) = self.authorizer.parts();
        // A grant refusal is the grant's answer, not a hiding.
        if crate::gateway::authz::authorize_backend(client, server).is_err() {
            return false;
        }
        let Some(tools) = self.known_tools(server) else {
            // Not registered, or no catalogue held: hide only what the name
            // alone refuses.
            return self.registered(server) && refused_by_name(state, (agent, cert), server);
        };
        if agent.is_none() && state.agent_auth.enabled {
            // Agent auth with no validated agent admits no backend.
            return true;
        }
        let profile_allows = state
            .meta_mcp
            .active_profile(self.session_id.as_deref())
            .backend_allowed(server);
        !(profile_allows && admits_some_tool(state, (agent, cert), server, &tools))
            || refused_by_name(state, (agent, cert), server)
    }
}

impl RouterHiding {
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

    /// `server`'s tool names when its catalogue is held now: the capability
    /// provider's always, a shared backend's while its shared catalogue is
    /// held. `None` for an unregistered name, a catalogue not held, and a
    /// per-user backend, whose caller catalogue this judgment does not read.
    fn known_tools(&self, server: &str) -> Option<Vec<String>> {
        let meta = &self.state.meta_mcp;
        if let Some(backend) = meta.registry().get_for(Unscoped::Visibility, server) {
            if backend.keeps_per_user_catalogues() || !backend.holds_tools_for(None) {
                return None;
            }
            let (tools, _) = backend.cached_tools_snapshot_and_truncated(None);
            return Some(tools.iter().map(|t| t.name.clone()).collect());
        }
        meta.get_capabilities()
            .filter(|cap| cap.name == server)
            .map(|cap| cap.get_tools().into_iter().map(|t| t.name).collect())
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
