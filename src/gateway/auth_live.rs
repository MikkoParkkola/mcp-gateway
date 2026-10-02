// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The caller behind a held credential, as authorization sees it now.
//!
//! A session outlives the request that opened it, so anything delivered to it
//! later must ask the authorizer again: a snapshot taken at session start keeps
//! granting access after the token behind it is revoked or expires.

use super::{
    AuthState, AuthenticatedClient, Now, SessionCheck, Touch, anonymous_client, dashboard_client,
    session_cookie_value, session_limits,
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

impl HeldCredential {
    /// A digest of exactly what was presented. Session ownership keys on this,
    /// not on the validated principal: a delegated OIDC bearer's principal is
    /// its stable actor, so two tokens for one subject share it. Each part is
    /// length-prefixed and an absent part is `-`, so no two presentations
    /// collide.
    pub(crate) fn digest(&self) -> String {
        let part = |value: Option<&String>| {
            value.map_or_else(|| "-".to_string(), |v| format!("{}:{v}", v.len()))
        };
        crate::hashing::sha256_hex(
            format!(
                "{}|{}",
                part(self.session.as_ref()),
                part(self.bearer.as_ref())
            )
            .as_bytes(),
        )
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
    // A delivery is not operator activity: checked, never extended, or server
    // push alone would keep an unattended session alive (E5).
    if let Some(handle) = &credential.session
        && state.dashboard_bootstrap.check_session(
            handle,
            Now::read(),
            &session_limits(state),
            Touch::No,
        ) == SessionCheck::Valid
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

/// Who a notification is for: callers who may access one backend, or every
/// caller whose credential is still live.
///
/// An enum rather than `Option<&str>`, which reads as "no backend means
/// everyone" at the one place that must never widen by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Audience<'a> {
    Backend(&'a str),
    Any,
}

/// What delivery to one held credential should do now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// The credential is live and in scope.
    Deliver,
    /// The credential is live but may not access the audience's backend.
    OutOfScope,
    /// The credential no longer authenticates (revoked, expired, or never
    /// presented under authentication): nothing will ever reach it.
    Dead,
}

/// The one entitlement rule for notifications delivered after the request
/// that opened the stream, shared by the legacy session stream and
/// `subscriptions/listen` so the two cannot drift.
pub(crate) async fn delivery(
    state: &AuthState,
    credential: Option<&HeldCredential>,
    audience: Audience<'_>,
) -> Delivery {
    let Some(client) = current_client(state, credential).await else {
        return Delivery::Dead;
    };
    match audience {
        Audience::Backend(backend) if !client.can_access_backend(backend) => Delivery::OutOfScope,
        Audience::Backend(_) | Audience::Any => Delivery::Deliver,
    }
}

/// Resolve a presented bearer against the key server, in the order the
/// protected path has always used: the opaque temporary token first (an O(1)
/// store lookup), then a raw OIDC ID token presented directly as a bearer
/// (delegated auth, MIK-6648).
///
/// One function so the protected and public branches recognise exactly the same
/// credentials. They did not, and the public path is where it mattered: a
/// verified caller was handed the anonymous identity, and so shared the
/// anonymous nonce quota with every unauthenticated request on the box.
///
/// The `via` label exists only so each caller keeps its own log line; it is a
/// fixed string, never anything the caller sent.
pub(super) async fn key_server_credential(
    state: &AuthState,
    token: &str,
) -> Option<(AuthenticatedClient, KeyServerSubject, &'static str)> {
    let ks = state.key_server.as_ref()?;
    let (mut client, identity, exp, via) =
        if let Some((client, temporary)) = ks.validate_token(token).await {
            let exp = Some(temporary.exp);
            (client, temporary.identity.clone(), exp, "temporary token")
        } else if ks.config.delegated_bearer && super::looks_like_jwt(token) {
            // Gated on config and a cheap JWT-shape check so JWKS verification
            // never runs on an opaque or static token.
            let (client, identity) = ks.verify_bearer_identity(token).await?;
            (client, identity, jwt_exp(token), "delegated OIDC bearer")
        } else {
            return None;
        };
    // E1-a: admin comes from the live role mapping on every request; no mint
    // site stores it, so a reload that removes the rule revokes it.
    let config = state.live_config.get();
    client.admin = config.control_plane.role_mapping.grants_admin(&identity);
    let expires_at = exp
        .and_then(|s| i64::try_from(s).ok())
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map(CredentialExpiry);
    Some((
        client,
        KeyServerSubject {
            identity,
            expires_at,
        },
        via,
    ))
}

/// When the credential a request presented stops being valid, where the
/// credential says: a key-server token's `exp` or a delegated bearer's. MCP
/// Events caps a subscription made with it at this instant (MIK-7630).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CredentialExpiry(pub chrono::DateTime<chrono::Utc>);

/// The verified subject behind a key-server credential, and its expiry.
pub(super) struct KeyServerSubject {
    identity: crate::key_server::oidc::VerifiedIdentity,
    expires_at: Option<CredentialExpiry>,
}

impl KeyServerSubject {
    /// Bind the subject, and its expiry when known, into `extensions`.
    pub(super) fn insert_into(self, extensions: &mut axum::http::Extensions) {
        extensions.insert(self.identity);
        if let Some(expires_at) = self.expires_at {
            extensions.insert(expires_at);
        }
    }
}

/// The `exp` claim of a JWT the key server has already verified.
fn jwt_exp(token: &str) -> Option<u64> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("exp")?
        .as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn jwt_exp_reads_the_verified_tokens_expiry() {
        use base64::Engine as _;
        let encode = |v: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        };
        let header = encode(&serde_json::json!({"alg": "RS256"}));
        let token = |claims| format!("{header}.{}.sig", encode(&claims));
        assert_eq!(
            jwt_exp(&token(serde_json::json!({"exp": 1_900_000_000_u64}))),
            Some(1_900_000_000)
        );
        assert_eq!(jwt_exp(&token(serde_json::json!({"sub": "a"}))), None);
        assert_eq!(jwt_exp("not-a-jwt"), None);
    }

    fn bearer(token: &str) -> Option<HeldCredential> {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        held_credential(&headers)
    }

    /// Authentication on, no static keys, and `key_server` issuing tokens.
    fn authorizer(key_server: Arc<crate::key_server::KeyServer>) -> AuthState {
        let config = crate::config::AuthConfig {
            enabled: true,
            ..crate::config::AuthConfig::default()
        };
        AuthState {
            auth_config: Arc::new(super::super::ResolvedAuthConfig::from_config(&config)),
            key_server: Some(key_server),
            dashboard_bootstrap: Arc::new(super::super::DashboardBootstrap::new()),
            tls_enabled: false,
            live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
                crate::config::Config::default(),
            )),
        }
    }

    /// A key-server temporary token for `backends`. Copied from
    /// `webhooks/tests.rs::temporary_token`, which is private to that suite.
    fn temporary_token(backends: &[&str]) -> crate::key_server::TemporaryToken {
        use crate::key_server::InMemoryTokenStore;
        use crate::key_server::oidc::VerifiedIdentity;
        use crate::key_server::store::TokenScopes;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        crate::key_server::TemporaryToken {
            jti: InMemoryTokenStore::generate_jti(),
            token: InMemoryTokenStore::generate_bearer(),
            identity: VerifiedIdentity {
                subject: "sub".to_string(),
                email: "user@issuer.test".to_string(),
                name: None,
                groups: vec![],
                issuer: "https://issuer.test".to_string(),
            },
            scopes: TokenScopes {
                backends: backends.iter().map(|b| (*b).to_string()).collect(),
                tools: vec![],
                rate_limit: 0,
            },
            iat: now,
            exp: now + 3600,
            client_ip: None,
        }
    }

    // U1
    #[tokio::test]
    async fn delivery_is_dead_for_a_revoked_token() {
        let key_server = Arc::new(crate::key_server::KeyServer::new(
            crate::config::KeyServerConfig::default(),
        ));
        let (kept, revoked) = (temporary_token(&["alpha"]), temporary_token(&["alpha"]));
        let (kept_cred, revoked_cred) = (bearer(&kept.token), bearer(&revoked.token));
        let revoked_jti = revoked.jti.clone();
        key_server.store.insert(kept).await;
        key_server.store.insert(revoked).await;
        assert!(key_server.store.revoke_by_jti(&revoked_jti).await);
        let state = authorizer(key_server);

        // Control: the same rule delivers to a token that is still live.
        assert_eq!(
            delivery(&state, kept_cred.as_ref(), Audience::Any).await,
            Delivery::Deliver
        );
        assert_eq!(
            delivery(&state, revoked_cred.as_ref(), Audience::Any).await,
            Delivery::Dead
        );
        assert_eq!(
            delivery(&state, None, Audience::Any).await,
            Delivery::Dead,
            "no credential under authentication can never be delivered to"
        );
    }

    #[tokio::test]
    async fn delivery_is_out_of_scope_for_a_live_token_without_the_backend() {
        let key_server = Arc::new(crate::key_server::KeyServer::new(
            crate::config::KeyServerConfig::default(),
        ));
        let token = temporary_token(&["alpha"]);
        let credential = bearer(&token.token);
        key_server.store.insert(token).await;
        let state = authorizer(key_server);

        assert_eq!(
            delivery(&state, credential.as_ref(), Audience::Backend("alpha")).await,
            Delivery::Deliver
        );
        assert_eq!(
            delivery(&state, credential.as_ref(), Audience::Backend("beta")).await,
            Delivery::OutOfScope
        );
    }
}
