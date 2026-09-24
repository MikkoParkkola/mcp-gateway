// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The caller behind a held credential, as authorization sees it now.
//!
//! A session outlives the request that opened it, so anything delivered to it
//! later must ask the authorizer again: a snapshot taken at session start keeps
//! granting access after the token behind it is revoked or expires.

use super::{
    AuthState, AuthenticatedClient, anonymous_client, dashboard_client, key_server_credential,
    session_cookie_value,
};

/// What a request authenticated with, kept for re-validation: a dashboard
/// session handle, a bearer credential, or both, as the middleware saw them.
/// `Debug` never prints either.
#[derive(Clone)]
pub(crate) struct HeldCredential {
    session: Option<String>,
    bearer: Option<String>,
}

impl std::fmt::Debug for HeldCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HeldCredential(<redacted>)")
    }
}

/// The session cookie and bearer credential `headers` present, held for later
/// re-validation; `None` when they present neither.
pub(crate) fn held_credential(headers: &axum::http::HeaderMap) -> Option<HeldCredential> {
    let session = session_cookie_value(headers);
    let bearer = super::presented_credential(headers);
    (session.is_some() || bearer.is_some()).then_some(HeldCredential { session, bearer })
}

/// The client `credential` authenticates as right now.
///
/// Mirrors the middleware's credential order (an issued dashboard session,
/// then static keys, then the key server) but not its public-path fallback: a
/// credential that no longer validates yields `None`, never the public
/// identity. With authentication on, a session that presented no credential
/// yields `None` as well.
pub(crate) async fn current_client(
    state: &AuthState,
    credential: Option<&HeldCredential>,
) -> Option<AuthenticatedClient> {
    if !state.auth_config.enabled {
        return Some(anonymous_client());
    }
    let credential = credential?;
    if let Some(handle) = &credential.session
        && state.dashboard_bootstrap.session_is_valid(handle)
    {
        return Some(dashboard_client());
    }
    let token = credential.bearer.as_deref()?;
    if let Some((client, _)) = state.auth_config.validate_token_with_origin(token) {
        return Some(client);
    }
    key_server_credential(state, token)
        .await
        .map(|(client, _, _)| client)
}
