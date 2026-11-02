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
    /// is gone, expired, re-issued (another digest) or no longer admin as it
    /// was at admission, or `at` is `None` (a wall clock that cannot be
    /// read cannot date the key: fail closed). `Ok(None)`: not an API-key
    /// caller, nothing to redo.
    pub(crate) fn rejudged(
        &self,
        keys: &crate::gateway::auth::ResolvedAuthConfig,
        at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Option<Self>, KeyGone> {
        let Some(client) = &self.client else {
            return Ok(None);
        };
        let Some(name) = client.api_key_identity() else {
            return Ok(None);
        };
        let fresh = at
            .and_then(|at| keys.client_for_key_at(name, client.principal.storage_form(), None, at))
            // The same credential, not only the same name and principal: a
            // key re-issued under an explicit principal keeps both, and its
            // old secret's work must not run.
            .filter(|fresh| fresh.quota_principal == client.quota_principal)
            .filter(|fresh| fresh.admin || !client.admin)
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
