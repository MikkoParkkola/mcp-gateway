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

use crate::config::KeyServerConfig;
use crate::gateway::auth::AuthenticatedClient;

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
    pub async fn validate_token(&self, token: &str) -> Option<(AuthenticatedClient, TemporaryToken)> {
        let temp = self.store.get(token).await?;

        let client = AuthenticatedClient {
            name: temp.identity.email.clone(),
            rate_limit: temp.scopes.rate_limit,
            backends: temp.scopes.backends.clone(),
            allowed_tools: if temp.scopes.tools.is_empty() {
                None
            } else {
                Some(temp.scopes.tools.clone())
            },
            denied_tools: None,
        };

        let ev = AuditEvent::used(&temp, None);
        audit::emit(&ev);

        Some((client, temp))
    }
}
