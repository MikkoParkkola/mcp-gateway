// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who owns a streaming session: one derivation for POST, GET and DELETE.

use axum::http::HeaderMap;
use axum::response::IntoResponse;

use super::super::AppState;
use super::super::hardened_identity::hardened_identity_refusal;
use super::super::identity::{
    CallerAdmission, caller_grant_subject, identity_refusal_response, subject_key,
};
use crate::gateway::auth::live::held_credential;
use crate::gateway::auth::{AuthenticatedClient, NamedApiKey};
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::gateway::session_id::SessionOwner;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;

/// A stable owner key for a caller that proved no grant subject.
///
/// Not the display name: `name` is operator-configured and two API keys may
/// share one, which would let them attach to each other's sessions. The key
/// records whether a credential was actually validated, so an API key named
/// "anonymous" cannot claim the unauthenticated identity's sessions.
pub(super) fn session_owner(client: Option<&AuthenticatedClient>) -> SessionOwner {
    match client.and_then(|c| c.credential_principal()) {
        // The validated principal, a digest of the secret: two API keys
        // configured with the same display name are different owners.
        Some(principal) => SessionOwner::Credential(principal.to_owned()),
        // Every other caller, named or not, is one class: an unvalidated name is
        // not a credential. Only the minted session id separates them (F9).
        None => SessionOwner::Anonymous,
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
) -> Result<(CallerAdmission, SessionOwner), axum::response::Response> {
    let cert = extensions.get::<CertIdentity>();
    // The peer is the direct TCP peer only.
    let peer = extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    let admission = caller_grant_subject(
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
    let key = subject_key(admission.subject.as_ref(), cert);
    if let Some(refusal) =
        hardened_identity_refusal(state, key.as_deref(), extensions.get::<NamedApiKey>())
    {
        return Err(refusal.into_response());
    }
    let owner = owner_of(key, headers, client);
    Ok((admission, owner))
}

/// The owner a caller's session carries, one rule for `/mcp` and the direct
/// route. A proven subject outranks the credential, so two people behind one
/// shared key never share a session. The credential half is what was
/// presented, not the principal (a delegated bearer's principal is its stable
/// actor), so one person's two credentials never share one either: a resumed
/// session's held credential is overwritten (GH1942.HARDEN.1 row 9).
pub(in crate::gateway::router) fn owner_of(
    subject_key: Option<String>,
    headers: &HeaderMap,
    client: Option<&AuthenticatedClient>,
) -> SessionOwner {
    match subject_key {
        Some(key) => SessionOwner::Subject {
            key,
            credential: held_credential(headers).map(|held| held.digest()),
        },
        None => session_owner(client),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::gateway::streaming::NotificationMultiplexer;

    const SUBJECT_KEY: &str = "subject:8:corp-sso:5:alice";

    fn headers(authorization: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = authorization {
            headers.insert(
                axum::http::header::AUTHORIZATION,
                value.parse().expect("premise: an authorization header"),
            );
        }
        headers
    }

    fn subject_owner(headers: &HeaderMap) -> SessionOwner {
        owner_of(Some(SUBJECT_KEY.to_string()), headers, None)
    }

    fn multiplexer() -> NotificationMultiplexer {
        NotificationMultiplexer::new(
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::StreamingConfig::default(),
        )
    }

    /// Open `owner`'s session, then resume it as the same owner: one
    /// session, under the opened id. The receiver is retained throughout.
    fn same_owner_resumes(owner: &SessionOwner) {
        let multiplexer = multiplexer();
        let (id, _kept) = multiplexer.get_or_create_session_for(None, owner);
        assert_eq!(
            multiplexer.session_count(),
            1,
            "premise: opening mints one session"
        );
        let (resumed, _kept_again) = multiplexer.get_or_create_session_for(Some(&id), owner);
        assert_eq!(
            resumed, id,
            "own T5: the same owner resumes its own session"
        );
        assert_eq!(
            multiplexer.session_count(),
            1,
            "own T5: a same-owner resume mints no second session"
        );
    }

    /// Open `first`'s session, present its id as `second`, then resume as
    /// `first` again: the foreign owner gets a different session and the
    /// original owner keeps its own. Fresh multiplexer per direction;
    /// every receiver is retained.
    fn different_owner_direction(first: &SessionOwner, second: &SessionOwner) {
        let multiplexer = multiplexer();
        let (id, _kept) = multiplexer.get_or_create_session_for(None, first);
        assert_eq!(
            multiplexer.session_count(),
            1,
            "premise: opening mints one session"
        );
        let (foreign, _kept_foreign) = multiplexer.get_or_create_session_for(Some(&id), second);
        assert_ne!(
            foreign, id,
            "own T5: a different owner never resumes the presented session"
        );
        assert_eq!(
            multiplexer.session_count(),
            2,
            "own T5: a different owner opens its own session beside the first"
        );
        let (resumed, _kept_again) = multiplexer.get_or_create_session_for(Some(&id), first);
        assert_eq!(
            resumed, id,
            "dependent T5: the original owner still resumes its own session"
        );
        assert_eq!(
            multiplexer.session_count(),
            2,
            "dependent T5: the original resume mints no third session"
        );
    }

    /// C0 T5: a Basic-only caller owns its sessions under the no-part
    /// digest — the same digest whatever the non-Bearer scheme or value —
    /// where a caller presenting nothing carries no credential at all.
    #[test]
    fn t5_owner_basic_only_carries_the_no_part_digest() {
        // Control: no headers, no credential half.
        assert_eq!(
            subject_owner(&headers(None)),
            SessionOwner::Subject {
                key: SUBJECT_KEY.to_string(),
                credential: None,
            },
            "control: a caller presenting nothing carries no credential"
        );

        let basic_x = subject_owner(&headers(Some("Basic x")));
        let SessionOwner::Subject { key, credential } = &basic_x else {
            panic!("premise: a subject caller has a subject owner");
        };
        assert_eq!(
            key.as_str(),
            SUBJECT_KEY,
            "control: the subject key is unchanged by the credential half"
        );
        assert!(
            credential.is_some(),
            "own T5: a Basic-only owner carries Some(digest)"
        );
        assert_eq!(
            basic_x,
            subject_owner(&headers(Some("Basic y"))),
            "dependent T5: the Basic value never reaches the digest"
        );
        assert_eq!(
            basic_x,
            subject_owner(&headers(Some("Digest z"))),
            "dependent T5: every non-Bearer scheme carries the one no-part digest"
        );
    }

    /// C0 T5 positive control: the no-header owner resumes its own
    /// session (passes before and after; an always-new session fails it).
    #[test]
    fn t5_same_owner_without_headers_resumes() {
        same_owner_resumes(&subject_owner(&headers(None)));
    }

    /// C0 T5: the Basic-only owner likewise resumes its own session.
    #[test]
    fn t5_same_owner_basic_only_resumes() {
        same_owner_resumes(&subject_owner(&headers(Some("Basic x"))));
    }

    /// C0 T5: a Basic-only owner is a different owner from the same
    /// subject presenting nothing, so neither resumes the other's session.
    #[test]
    fn t5_basic_owner_does_not_resume_a_bare_session() {
        different_owner_direction(
            &subject_owner(&headers(None)),
            &subject_owner(&headers(Some("Basic x"))),
        );
    }

    /// C0 T5, the other direction: the bare owner does not resume the
    /// Basic-only owner's session either.
    #[test]
    fn t5_bare_owner_does_not_resume_a_basic_session() {
        different_owner_direction(
            &subject_owner(&headers(Some("Basic x"))),
            &subject_owner(&headers(None)),
        );
    }

    /// MIK-8659 T2 (GREEN): the session owner needs an authenticated
    /// non-empty principal; `{false, "p"}` and `{true, ""}` are anonymous.
    #[test]
    fn t2_session_owner_needs_a_principal() {
        fn client(
            authenticated: bool,
            principal: &str,
        ) -> crate::gateway::auth::AuthenticatedClient {
            crate::gateway::auth::AuthenticatedClient {
                name: "k".to_owned(),
                rate_limit: 0,
                backends: vec!["*".to_owned()],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
                // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
                principal: crate::gateway::record_principal::InternalPrincipal::new(
                    principal.to_owned(),
                ),
                quota_principal: None,
                authenticated,
                credential_kind: crate::security::audit::CredentialKind::ApiKey,
            }
        }
        let unauthenticated = client(false, "p");
        assert_eq!(
            session_owner(Some(&unauthenticated)),
            SessionOwner::Anonymous
        );
        let empty = client(true, "");
        assert_eq!(session_owner(Some(&empty)), SessionOwner::Anonymous);
        let ok = client(true, "p");
        assert_eq!(
            session_owner(Some(&ok)),
            SessionOwner::Credential("p".to_owned())
        );
    }
}
