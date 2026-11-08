// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The owned authorizer queued and continued work dispatches under: captured
//! on the request thread, re-judged against the key table current at
//! dispatch (K15), then borrowed back into a [`RouterAuthorizer`].

use super::{
    AppState, AuthenticatedClient, CallerParts, CertIdentity, OAuthAgentIdentity, RouterAuthorizer,
    refusal_principal,
};

/// Owned twin of [`RouterAuthorizer`]: captured on the request thread so a
/// background worker can rebuild the identical borrowed authorizer after the
/// request future is gone.
#[derive(Clone)]
pub(crate) struct OwnedRouterAuthorizer {
    client: Option<AuthenticatedClient>,
    oauth_agent_identity: Option<OAuthAgentIdentity>,
    cert_identity: Option<CertIdentity>,
    principal: Option<String>,
}

impl OwnedRouterAuthorizer {
    pub(crate) fn capture(
        client: Option<&AuthenticatedClient>,
        oauth: Option<&OAuthAgentIdentity>,
        cert: Option<&CertIdentity>,
    ) -> Self {
        Self {
            client: client.cloned(),
            oauth_agent_identity: oauth.cloned(),
            cert_identity: cert.cloned(),
            principal: refusal_principal(client, oauth, cert),
        }
    }

    /// The caller's client, agent identity and certificate.
    pub(in crate::gateway::router) fn parts(&self) -> CallerParts<'_> {
        (
            self.client.as_ref(),
            self.oauth_agent_identity.as_ref(),
            self.cert_identity.as_ref(),
        )
    }

    /// The borrowed authorizer, judged by `generation`: the one current when
    /// the queued work dispatches, not the one at admission.
    pub(crate) fn borrow<'a>(
        &'a self,
        state: &'a AppState,
        generation: &'a crate::config_reload::Generation,
    ) -> RouterAuthorizer<'a> {
        RouterAuthorizer {
            state,
            generation,
            client: self.client.as_ref(),
            oauth_agent_identity: self.oauth_agent_identity.as_ref(),
            cert_identity: self.cert_identity.as_ref(),
            principal: self.principal.clone(),
        }
    }

    /// K15: this captured caller as `keys` now holds it, for queued or
    /// continued work about to dispatch. An API-key caller is rebuilt from its
    /// key's current entry, so a narrowed scope applies; `Err` when the key
    /// is gone, expired, re-issued (another digest) or below the admin
    /// standing it had at admission, or `at` is `None` (a wall clock that
    /// cannot be read cannot date the key: fail closed).
    ///
    /// A key-server or OIDC caller holds admin by `mapping`, not by a key
    /// entry: its standing is recomputed from its verified `identity` under
    /// the current mapping, and any step down ends the work.
    /// `Ok(None)`: nothing to redo, the captured caller stands.
    pub(crate) fn rejudged(
        &self,
        keys: &crate::gateway::auth::ResolvedAuthConfig,
        identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        mapping: &crate::control_plane::role_mapping::ControlPlaneRoleMappingConfig,
        at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Option<Self>, KeyGone> {
        let Some(client) = &self.client else {
            return Ok(None);
        };
        let Some(name) = client.api_key_identity() else {
            let Some(identity) = identity else {
                return Ok(None);
            };
            let fresh = crate::gateway::authz::admin_standing(
                mapping.grants_admin(identity),
                &client.backends,
            );
            return if fresh < client.admin_standing() {
                Err(KeyGone)
            } else {
                Ok(None)
            };
        };
        // The same credential, not only the same name and principal: a key
        // re-issued under an explicit principal keeps both, and its old
        // secret's work must not run. A client with no quota identity names
        // no credential to find again.
        let credential = client.quota_principal.as_ref().ok_or(KeyGone)?;
        let binding = crate::gateway::auth::KeyBinding::Credential(credential);
        let fresh = at
            .and_then(|at| {
                keys.client_for_key_at(name, client.principal.storage_form(), binding, at)
            })
            // Standing only ever falls on a running task: any step down
            // Gateway > InScope > None ends it.
            .filter(|fresh| fresh.admin_standing() >= client.admin_standing())
            .ok_or(KeyGone)?;
        Ok(Some(Self {
            client: Some(fresh),
            oauth_agent_identity: self.oauth_agent_identity.clone(),
            cert_identity: self.cert_identity.clone(),
            principal: self.principal.clone(),
        }))
    }
}

/// The API key queued or continued work was admitted under is no longer
/// valid as it was (K15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyGone;

#[cfg(test)]
#[path = "authorization_rejudge_tests.rs"]
mod rejudge_tests;
