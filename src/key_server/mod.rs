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
pub mod oidc;
pub mod policy;
pub mod store;

use std::sync::Arc;

use tracing::debug;

use crate::config::{KeyServerConfig, KeyServerOidcConfig};
use crate::gateway::auth::AuthenticatedClient;
use oidc::VerifiedIdentity;
use policy::RequestedScopes;

pub use audit::AuditEvent;
pub use oidc::{JwksCache, OidcVerifier};
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

        let client = AuthenticatedClient {
            name: oidc_client_identity_key(&temp.identity),
            rate_limit: temp.scopes.rate_limit,
            backends: temp.scopes.backends.clone(),
            allowed_tools: if temp.scopes.tools.is_empty() {
                None
            } else {
                Some(temp.scopes.tools.clone())
            },
            denied_tools: None,
            admin: false,
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
            max_token_age_secs: self.config.max_oidc_token_age_secs,
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
            .resolve_scopes(&identity, &RequestedScopes::default())?;

        let client = AuthenticatedClient {
            name: oidc_client_identity_key(&identity),
            rate_limit: scopes.rate_limit,
            backends: scopes.backends.clone(),
            allowed_tools: if scopes.tools.is_empty() {
                None
            } else {
                Some(scopes.tools.clone())
            },
            denied_tools: None,
            admin: false,
        };
        Some((client, identity))
    }
}

fn oidc_client_identity_key(identity: &VerifiedIdentity) -> String {
    format!("oidc:{}:{}", identity.issuer, identity.subject)
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
            "oidc:https://issuer-a.example:same-subject"
        );
        assert_ne!(
            oidc_client_identity_key(&first),
            oidc_client_identity_key(&second)
        );
        assert_eq!(
            oidc_client_identity_key(&missing_email),
            "oidc:https://issuer-a.example:subject-without-email"
        );
    }
}
