// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who owns a streaming session: one derivation for POST, GET and DELETE.

use axum::http::HeaderMap;
use axum::response::IntoResponse;

use super::super::AppState;
use super::super::hardened_identity::hardened_identity_refusal;
use super::super::identity::{caller_grant_subject, identity_refusal_response, subject_key};
use crate::gateway::auth::live::held_credential;
use crate::gateway::auth::{AuthenticatedClient, NamedApiKey};
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::gateway::session_id::SessionOwner;
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;

/// A stable owner key for a caller that proved no grant subject.
///
/// Not the display name: `name` is operator-configured and two API keys may
/// share one, which would let them attach to each other's sessions. The key
/// records whether a credential was actually validated, so an API key named
/// "anonymous" cannot claim the unauthenticated identity's sessions.
pub(super) fn session_owner(client: Option<&AuthenticatedClient>) -> SessionOwner {
    match client {
        // The validated principal, a digest of the secret: two API keys
        // configured with the same display name are different owners.
        Some(c) if c.authenticated && !c.principal.is_empty() => {
            SessionOwner::Credential(c.principal.clone())
        }
        // Every other caller, named or not, is one class: an unvalidated name is
        // not a credential. Only the minted session id separates them (F9).
        _ => SessionOwner::Anonymous,
    }
}

/// The caller's grant subject and the session owner it implies, resolved from
/// what the request proved, before any session work. One rule for POST, GET
/// and DELETE: a route that skipped the subject would key its owner
/// differently and lock a subject out of its own session.
///
/// # Errors
///
/// The refusal response for an identity header that breaks the mode's rules.
#[allow(clippy::result_large_err)] // early-return pattern mirrors existing handlers
pub(super) async fn request_session_owner(
    state: &AppState,
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
    client: Option<&AuthenticatedClient>,
) -> Result<(Option<GrantSubject>, SessionOwner), axum::response::Response> {
    let cert = extensions.get::<CertIdentity>();
    // The peer is the direct TCP peer only.
    let peer = extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    let subject = caller_grant_subject(
        extensions.get::<VerifiedIdentity>(),
        headers,
        peer,
        state.meta_mcp.caller_identity(),
        state.meta_mcp.access_verifier(),
        cert,
        extensions.get::<OAuthAgentIdentity>(),
    )
    .await
    .map_err(|refusal| identity_refusal_response(refusal).into_response())?;
    let key = subject_key(subject.as_ref(), cert);
    if let Some(refusal) =
        hardened_identity_refusal(state, key.as_deref(), extensions.get::<NamedApiKey>())
    {
        return Err(refusal.into_response());
    }
    // A proven subject outranks the credential, so two people behind one shared
    // key never share a session. The credential half is what was presented,
    // not the principal (a delegated bearer's principal is its stable actor),
    // so one person's two credentials never share one either: a resumed
    // session's held credential is overwritten (GH1942.HARDEN.1 row 9).
    let owner = match key {
        Some(key) => SessionOwner::Subject {
            key,
            credential: held_credential(headers).map(|held| held.digest()),
        },
        None => session_owner(client),
    };
    Ok((subject, owner))
}
