//! Agent-scoped OAuth 2.0 tool permissions.
//!
//! This module implements agent registration, JWT validation middleware,
//! scope-based tool access control, JWKS exposure, and audit logging
//! as described in GitHub issue #80.
//!
//! # Modules
//!
//! - [`agents`]  — Agent registration and in-memory registry.
//! - [`jwt`]     — JWT validation for HS256 / RS256 bearer tokens.
//! - [`scopes`]  — Scope format `tools:<backend>:<name>:<action>` and matching.
//! - [`jwks`]    — Gateway RSA key pair + JWKS endpoint handler.
//! - [`audit`]   — Structured audit log for every tool invocation.
//!
//! # Deny-by-Default
//!
//! When the `AgentAuthConfig.enabled` flag is `true`:
//! - Every tool invocation MUST carry a valid agent JWT.
//! - Missing / invalid JWT → 401 Unauthorized.
//! - Valid JWT but insufficient scope → 403 Forbidden.
//! - Unscoped tools are inaccessible.
//!
//! When disabled (default), the module is a no-op and existing auth applies.

pub mod agents;
pub mod audit;
pub mod jwks;
pub mod jwt;
pub mod scopes;

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use tracing::{debug, warn};

pub use agents::{AgentDefinition, AgentRegistry};
pub use audit::{Decision, ToolInvocationAudit, emit as emit_audit};
pub use jwks::{GatewayKeyPair, Jwk, JwkSet};
pub use jwt::{AgentClaims, JwtError, ValidatedToken, validate_agent_token};
pub use scopes::{Action, Scope, check_scopes};

/// Extension type inserted into the request by the agent auth middleware.
///
/// Downstream handlers use this to know which agent is calling and what
/// scopes it holds.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    /// Agent `client_id` (also the JWT `sub`).
    pub client_id: String,
    /// Agent display name.
    pub agent_name: String,
    /// Validated scopes from the registry definition.
    pub scopes: Vec<Scope>,
    /// Raw scope strings for audit/logging.
    pub raw_scopes: Vec<String>,
}

/// Shared state for the agent auth middleware.
#[derive(Clone)]
pub struct AgentAuthState {
    /// Whether agent auth is enabled.
    pub enabled: bool,
    /// Agent registry.
    pub registry: Arc<AgentRegistry>,
}

impl AgentAuthState {
    /// Create a new `AgentAuthState`.
    pub fn new(enabled: bool, registry: Arc<AgentRegistry>) -> Self {
        Self { enabled, registry }
    }
}

/// Axum middleware: validate agent JWT and populate [`AgentIdentity`] extension.
///
/// This middleware is additive — it runs after the existing [`auth_middleware`]
/// and enriches the request with agent scope information.  When agent auth is
/// disabled, it is a no-op.
///
/// [`auth_middleware`]: crate::gateway::auth::auth_middleware
pub async fn agent_auth_middleware(
    State(state): State<AgentAuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if !state.enabled {
        return next.run(request).await;
    }

    // Extract bearer token from Authorization header.
    let token_str = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });

    let Some(token_str) = token_str else {
        warn!(path = %request.uri().path(), "Agent auth: missing Authorization header");
        return agent_unauthorized(
            "Missing Authorization header. Use: Authorization: Bearer <token>",
        );
    };

    // Validate the agent JWT.
    match validate_agent_token(token_str, &state.registry) {
        Ok(validated) => {
            debug!(
                agent = %validated.agent.client_id,
                "Agent JWT validated"
            );
            let raw_scopes = validated.agent.scopes.clone();
            let identity = AgentIdentity {
                client_id: validated.claims.sub.clone(),
                agent_name: validated.agent.name.clone(),
                scopes: validated.scopes,
                raw_scopes,
            };
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(JwtError::UnknownAgent(id)) => {
            warn!(agent = %id, "Agent auth: unknown agent");
            agent_unauthorized("Unknown agent")
        }
        Err(ref e) => {
            warn!(error = %e, "Agent auth: JWT validation failed");
            agent_unauthorized("Invalid or expired token")
        }
    }
}

/// Check whether the [`AgentIdentity`] in `extensions` grants access to
/// `(backend, tool, action)` and emit an audit log entry.
///
/// Returns `Ok(())` on success or an `Err(Response)` (403) on denial.
///
/// Call this from tool dispatch handlers, **after** the middleware has run.
// `Response` is inherently large in axum; boxing it would complicate caller code.
#[allow(clippy::result_large_err)]
pub fn check_agent_scope_and_audit(
    identity: &AgentIdentity,
    backend: &str,
    tool: &str,
    action: &Action,
) -> Result<(), Response> {
    let raw_action = format!("{action:?}").to_lowercase();

    match check_scopes(&identity.scopes, &identity.client_id, backend, tool, action) {
        Ok(()) => {
            let entry = ToolInvocationAudit::allow(
                &identity.client_id,
                &identity.agent_name,
                backend,
                tool,
                identity.raw_scopes.clone(),
            );
            emit_audit(&entry);
            Ok(())
        }
        Err(reason) => {
            let entry = ToolInvocationAudit::deny(
                &identity.client_id,
                &identity.agent_name,
                backend,
                tool,
                identity.raw_scopes.clone(),
                &reason,
            );
            emit_audit(&entry);
            warn!(
                agent = %identity.client_id,
                backend = %backend,
                tool = %tool,
                action = %raw_action,
                "Agent scope denied: {reason}"
            );
            Err(agent_forbidden(&reason))
        }
    }
}

// ── HTTP response helpers ─────────────────────────────────────────────────────

fn agent_unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Bearer")],
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": message
            },
            "id": null
        })),
    )
        .into_response()
}

fn agent_forbidden(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32003,
                "message": message
            },
            "id": null
        })),
    )
        .into_response()
}

// ── JWKS endpoint handler ─────────────────────────────────────────────────────

/// Axum handler: `GET /.well-known/jwks.json`
///
/// Returns the gateway's own RSA public key in JWK Set format so that
/// backends can independently verify tokens signed by the gateway.
pub async fn jwks_handler(State(key_pair): State<Arc<GatewayKeyPair>>) -> impl IntoResponse {
    let jwks = key_pair.jwks();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::header::HeaderValue::from_static("application/json"),
        )],
        Json(jwks),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_agent_identity(scopes: Vec<&str>) -> AgentIdentity {
        let parsed: Vec<Scope> = scopes.iter().filter_map(|s| Scope::parse(s)).collect();
        let raw: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        AgentIdentity {
            client_id: "test-agent".to_string(),
            agent_name: "Test Agent".to_string(),
            scopes: parsed,
            raw_scopes: raw,
        }
    }

    // ── check_agent_scope_and_audit ───────────────────────────────────────

    #[test]
    fn allows_matching_scope() {
        let identity = make_agent_identity(vec!["tools:surreal:*"]);
        let result = check_agent_scope_and_audit(&identity, "surreal", "query", &Action::Read);
        assert!(result.is_ok());
    }

    #[test]
    fn denies_non_matching_scope() {
        let identity = make_agent_identity(vec!["tools:surreal:query:read"]);
        let result = check_agent_scope_and_audit(&identity, "brave", "search", &Action::Execute);
        assert!(result.is_err());
    }

    #[test]
    fn full_wildcard_allows_anything() {
        let identity = make_agent_identity(vec!["tools:*"]);
        assert!(
            check_agent_scope_and_audit(&identity, "any-backend", "any-tool", &Action::Execute)
                .is_ok()
        );
    }

    #[test]
    fn empty_scopes_denies_everything() {
        let identity = make_agent_identity(vec![]);
        let result = check_agent_scope_and_audit(&identity, "surreal", "query", &Action::Read);
        assert!(result.is_err());
    }

    // ── AgentAuthState ────────────────────────────────────────────────────

    #[test]
    fn agent_auth_state_stores_enabled_flag() {
        let reg = Arc::new(AgentRegistry::new());
        let state = AgentAuthState::new(true, Arc::clone(&reg));
        assert!(state.enabled);
    }

    #[test]
    fn agent_identity_preserves_raw_scopes() {
        let identity = make_agent_identity(vec!["tools:surreal:query:read"]);
        assert_eq!(identity.raw_scopes, vec!["tools:surreal:query:read"]);
    }
}
