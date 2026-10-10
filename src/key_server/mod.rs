// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! LLM Key Server — OIDC identity to temporary scoped API keys.
//!
//! This module implements the key server pattern described in RFC-0043:
//!
//! 1. **Token Exchange**: Accept an OIDC identity token (`POST /auth/token`),
//!    verify it against a configured OIDC issuer, map the identity to scopes
//!    via the policy engine, and return a short-lived opaque bearer token.
//!
//! 2. **Validation**: The auth middleware calls [`KeyServer::validate_token`] as
//!    a secondary validation path after the static key check.
//!
//! 3. **Revocation**: `DELETE /auth/token/{jti}` revokes a specific token instantly.
//!    Admin endpoints are guarded by a separate `admin.bearer_token`.
//!
//! 4. **Audit**: Every token lifecycle event is emitted via `tracing::info!` with
//!    structured fields queryable by any log aggregator.
//!
//! # Architecture
//!
//! ```text
//! Request arrives
//!   -> Extract bearer token
//!   -> Try static auth (existing ResolvedAuthConfig)  -- O(n) key comparison
//!   -> Try temporary token (KeyServer.validate_token) -- O(1) DashMap lookup
//!   -> Reject
//! ```
//!
//! The key server is **opt-in**: set `key_server.enabled: true` in the gateway
//! configuration. When disabled, no overhead is incurred.

pub mod audit;
pub mod handler;
#[cfg(test)]
mod identity_rules_tests;
pub mod oidc;
pub mod policy;
pub mod store;

use std::sync::Arc;

use tracing::debug;

use crate::config::{KeyServerConfig, KeyServerOidcConfig};
use crate::gateway::auth::{AuthenticatedClient, QuotaPrincipal};
use oidc::VerifiedIdentity;
use policy::RequestedScopes;

pub use audit::AuditEvent;
pub use oidc::{JwksCache, OidcVerifier};

/// The age bound a verifier applies on top of `exp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAgeCap {
    /// Refuse a token whose `iat` is more than this many seconds ago
    /// (replay bound for key-server and delegated-bearer tokens).
    MaxIat(u64),
    /// `exp` (with the verifier's leeway) is the only bound. A Cloudflare
    /// Access assertion's `iat` is the session start, so an `iat` cap would
    /// lock every Access user out minutes after login.
    ExpOnly,
}
pub use policy::PolicyEngine;
pub use store::{InMemoryTokenStore, TemporaryToken, TokenStore};

/// The key server — central coordinator for OIDC token exchange.
///
/// Holds all subsystems and exposes the two methods called from the
/// auth middleware: [`validate_token`](KeyServer::validate_token) and
/// the HTTP handlers in [`handler`].
pub struct KeyServer {
    /// Token store (in-memory `DashMap`)
    pub store: Arc<dyn TokenStore>,
    /// OIDC verifier (JWKS cache + signature verification)
    pub oidc: Arc<OidcVerifier>,
    /// Access policy engine
    pub policy: Arc<PolicyEngine>,
    /// Key server configuration
    pub config: KeyServerConfig,
}

impl KeyServer {
    /// Create a new key server from configuration.
    #[must_use]
    pub fn new(config: KeyServerConfig) -> Self {
        let store = Arc::new(InMemoryTokenStore::new());
        let oidc = Arc::new(OidcVerifier::new(config.oidc.clone()));
        let policy = Arc::new(PolicyEngine::new(config.policies.clone()));

        Self {
            store,
            oidc,
            policy,
            config,
        }
    }

    /// Validate a bearer token from an incoming request.
    ///
    /// Returns the [`AuthenticatedClient`] and the associated [`TemporaryToken`]
    /// if the token is valid and not expired/revoked. Returns `None` otherwise.
    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Option<(AuthenticatedClient, TemporaryToken)> {
        let temp = self.store.get(token).await?;

        let actor = oidc_client_identity_key(&temp.identity);
        let client = AuthenticatedClient {
            // The quota follows the verified identity, not this token: a second
            // exchange for the same issuer/subject must not mint a second cap.
            quota_principal: Some(QuotaPrincipal::oidc_identity(&actor)),
            name: actor,
            // A temporary token identifies one principal; its own key is the
            // stable identifier.
            // MIK-6704.IDENT.1a: a tagged digest of the token (MIK-8006).
            principal: runtime_principal(RuntimeIssuer::KeyServerToken, &temp.token),
            rate_limit: temp.scopes.rate_limit,
            backends: temp.scopes.backends.clone(),
            allowed_tools: if temp.scopes.tools.is_empty() {
                None
            } else {
                Some(temp.scopes.tools.clone())
            },
            denied_tools: None,
            admin: false,
            authenticated: true,
            credential_kind: crate::security::audit::CredentialKind::KeyServerToken,
        };

        let ev = AuditEvent::used(&temp, None);
        audit::emit(&ev);

        Some((client, temp))
    }

    /// Verify a raw OIDC ID token (JWT) presented directly as a bearer
    /// ("delegated auth", MIK-6648) and resolve it to a client + identity.
    ///
    /// Unlike [`validate_token`](Self::validate_token) (which looks up a
    /// previously-exchanged opaque token in the store), this verifies the JWT
    /// signature/claims against the configured OIDC providers and resolves the
    /// identity through the same policy engine used by the `/auth/token`
    /// exchange. Returns `None` when verification fails or no policy matches —
    /// i.e. it is fail-closed and never grants access without a policy rule.
    ///
    /// The caller is responsible for gating this on `config.delegated_bearer`.
    pub async fn verify_bearer_identity(
        &self,
        token: &str,
    ) -> Option<(AuthenticatedClient, VerifiedIdentity)> {
        let oidc_config = KeyServerOidcConfig {
            token_age: crate::key_server::TokenAgeCap::MaxIat(self.config.max_oidc_token_age_secs),
        };
        let identity = match self.oidc.verify(token, &oidc_config).await {
            Ok(id) => id,
            Err(e) => {
                debug!(error = %e, "Delegated OIDC bearer verification failed");
                return None;
            }
        };

        // Resolve scopes via the same first-match-wins policy engine. No
        // requested-scope narrowing: a delegated bearer takes the policy's
        // full grant for the identity.
        let scopes = self
            .policy
            .resolve_scopes(&identity, &RequestedScopes::default())
            .ok()?;

        let actor = oidc_client_identity_key(&identity);
        let client = AuthenticatedClient {
            // Same identity, same material, same kind as the exchanged token
            // above: one person's two credential mechanisms are one bucket.
            quota_principal: Some(QuotaPrincipal::oidc_identity(&actor)),
            // The verified subject identifies this principal.
            // MIK-6704.IDENT.1a: a tagged digest of the verified subject (MIK-8006).
            principal: runtime_principal(RuntimeIssuer::OidcBearer, &actor),
            name: actor,
            rate_limit: scopes.rate_limit,
            backends: scopes.backends.clone(),
            allowed_tools: if scopes.tools.is_empty() {
                None
            } else {
                Some(scopes.tools.clone())
            },
            denied_tools: None,
            admin: false,
            authenticated: true,
            credential_kind: crate::security::audit::CredentialKind::OidcBearer,
        };
        Some((client, identity))
    }
}

/// Who issued a runtime identity; each issuer has its own principal tag.
#[derive(Clone, Copy)]
enum RuntimeIssuer {
    KeyServerToken,
    OidcBearer,
}

/// MIK-8006: the principal of an identity issued at runtime. Configured
/// credentials own the 12-hex space (`principal_of`, `principal_of_digest`);
/// this is `<tag>:<full SHA-256 hex>`, and `:` never occurs in hex, so it can
/// equal neither a configured principal nor one under the other tag.
fn runtime_principal(issuer: RuntimeIssuer, material: &str) -> String {
    let tag = match issuer {
        RuntimeIssuer::KeyServerToken => "kst",
        RuntimeIssuer::OidcBearer => "oidc",
    };
    format!("{tag}:{}", crate::hashing::sha256_hex(material.as_bytes()))
}

fn oidc_client_identity_key(identity: &VerifiedIdentity) -> String {
    // Collision-safe (length-prefixed) — see VerifiedIdentity::stable_actor_id
    // (MIK-6702 CP.ID.1). Kept identical to the control-plane actor_id so a user
    // maps to one stable identity across both surfaces.
    identity.stable_actor_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(subject: &str, email: &str, issuer: &str) -> VerifiedIdentity {
        VerifiedIdentity {
            subject: subject.to_string(),
            email: email.to_string(),
            name: None,
            groups: vec![],
            issuer: issuer.to_string(),
        }
    }

    #[test]
    fn oidc_client_identity_key_uses_issuer_and_subject_not_email() {
        let first = identity(
            "same-subject",
            "shared@example.com",
            "https://issuer-a.example",
        );
        let second = identity(
            "same-subject",
            "shared@example.com",
            "https://issuer-b.example",
        );
        let missing_email = identity("subject-without-email", "", "https://issuer-a.example");

        assert_eq!(
            oidc_client_identity_key(&first),
            // Length-prefixed, collision-safe (MIK-6702 CP.ID.1):
            // issuer "https://issuer-a.example" len 24, subject "same-subject" len 12.
            "oidc:24:https://issuer-a.example:12:same-subject"
        );
        assert_ne!(
            oidc_client_identity_key(&first),
            oidc_client_identity_key(&second)
        );
        assert_eq!(
            oidc_client_identity_key(&missing_email),
            // issuer len 24, subject "subject-without-email" len 21.
            "oidc:24:https://issuer-a.example:21:subject-without-email"
        );
    }

    /// MIK-8286 R9: a stored identity is refused when it is read back, never
    /// trusted because it was valid when written. A live token whose identity
    /// names nobody (empty subject, or empty issuer) validates as no token.
    /// Mutant: the read-back check removed from the lookup.
    #[tokio::test]
    async fn a_stored_token_whose_identity_names_nobody_is_refused() {
        let ks = KeyServer::new(KeyServerConfig::default());
        for (bearer, subject, issuer) in [
            ("mcpgw_nameless_subject", "", "https://issuer.invalid"),
            ("mcpgw_nameless_issuer", "sub", ""),
        ] {
            ks.store
                .insert(TemporaryToken {
                    jti: format!("jti-{bearer}"),
                    token: bearer.to_string(),
                    identity: identity(subject, "u@corp.invalid", issuer),
                    scopes: store::TokenScopes::default(),
                    iat: 0,
                    exp: u64::MAX,
                    client_ip: None,
                })
                .await;
            assert!(ks.store.get(bearer).await.is_some(), "the store holds it");
            assert!(
                ks.validate_token(bearer).await.is_none(),
                "{bearer}: a stored identity that names nobody is no credential"
            );
        }
    }

    #[tokio::test]
    async fn oidc_token_with_empty_backends_reaches_none() {
        // BACKENDGRANT.1: the token's scopes are copied as-is, and an empty
        // backend list means none, never "all".
        let ks = KeyServer::new(KeyServerConfig::default());
        let token = TemporaryToken {
            jti: "jti-empty".to_string(),
            token: "mcpgw_empty_backends".to_string(),
            identity: identity("sub", "u@corp.invalid", "https://issuer.invalid"),
            scopes: store::TokenScopes::default(),
            iat: 0,
            exp: u64::MAX,
            client_ip: None,
        };
        ks.store.insert(token).await;
        let (client, _) = ks
            .validate_token("mcpgw_empty_backends")
            .await
            .expect("token is live");
        assert!(!client.can_access_backend("x"));
    }

    /// MIK-8006 RTPRIN.1: configured credentials own the 12-lowercase-hex
    /// principals; a key-server token's principal is outside that space, so
    /// a static bearer configured with the same text is another caller.
    #[tokio::test]
    async fn key_server_token_principal_is_outside_the_configured_space() {
        let ks = KeyServer::new(KeyServerConfig::default());
        let text = "mcpgw_runtime_principal";
        ks.store
            .insert(TemporaryToken {
                jti: "jti-runtime".to_string(),
                token: text.to_string(),
                identity: identity("sub", "u@corp.invalid", "https://issuer.invalid"),
                scopes: store::TokenScopes::default(),
                iat: 0,
                exp: u64::MAX,
                client_ip: None,
            })
            .await;
        let (client, _) = ks.validate_token(text).await.expect("token is live");
        let p = &client.principal;
        assert_ne!(*p, crate::gateway::auth::principal_of(text));
        assert_eq!(*p, runtime_principal(RuntimeIssuer::KeyServerToken, text));
        assert!(
            !(p.len() == 12 && p.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))),
            "{p} is in the configured principal space"
        );
    }

    /// MIK-8006 RTPRIN.3: each issuer has its own tag over a full digest.
    #[test]
    fn runtime_principals_carry_their_tag_and_a_full_digest() {
        let digest = crate::hashing::sha256_hex(b"x");
        assert_eq!(digest.len(), 64);
        assert_eq!(
            runtime_principal(RuntimeIssuer::KeyServerToken, "x"),
            format!("kst:{digest}")
        );
        assert_eq!(
            runtime_principal(RuntimeIssuer::OidcBearer, "x"),
            format!("oidc:{digest}")
        );
    }
}
