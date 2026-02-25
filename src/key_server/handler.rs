//! HTTP handlers for the key server endpoints.
//!
//! # Endpoints
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | `POST` | `/auth/token` | Exchange OIDC token for temporary gateway token |
//! | `DELETE` | `/auth/token/{jti}` | Revoke a specific token (admin) |
//! | `DELETE` | `/auth/tokens` | Revoke all tokens for a subject (admin) |
//!
//! ## Token Exchange
//!
//! Request body follows [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) Token Exchange:
//!
//! ```json
//! {
//!   "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
//!   "subject_token": "<OIDC ID Token JWT>",
//!   "subject_token_type": "urn:ietf:params:oauth:token-type:id_token"
//! }
//! ```
//!
//! ## Admin Authentication
//!
//! Revocation endpoints require `Authorization: Bearer <admin_token>` where
//! `admin_token` is the value from `key_server.admin.bearer_token` in config.
//! If no admin token is configured, the endpoints return `503 Service Unavailable`.

use std::{net::IpAddr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

use super::{
    KeyServer,
    audit::{self, AuditEvent},
    policy::RequestedScopes,
    store::{InMemoryTokenStore, TemporaryToken},
};
use crate::config::KeyServerOidcConfig;

// ── Request / Response types ───────────────────────────────────────────────

/// RFC 8693 token exchange request body.
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    /// Must be `urn:ietf:params:oauth:grant-type:token-exchange`.
    pub grant_type: String,
    /// The OIDC ID token (JWT).
    pub subject_token: String,
    /// Must be `urn:ietf:params:oauth:token-type:id_token`.
    #[serde(default)]
    pub subject_token_type: String,
    /// Optional requested scopes (space-separated backend/tool names).
    #[serde(default)]
    pub scope: String,
}

/// RFC 8693 token exchange response.
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    /// The issued opaque bearer token.
    pub access_token: String,
    /// Always `"Bearer"`.
    pub token_type: String,
    /// Seconds until expiry.
    pub expires_in: u64,
    /// Granted scope string.
    pub scope: String,
    /// JTI for revocation.
    pub jti: String,
}

/// Query params for bulk revocation.
#[derive(Debug, Deserialize)]
pub struct RevokeBySubjectQuery {
    /// OIDC subject to revoke all tokens for.
    pub subject: String,
}

// ── Route builder ─────────────────────────────────────────────────────────

/// Build the key server routes, mounted at `/auth`.
///
/// These routes are added to the main router **without** the standard auth
/// middleware — the token exchange endpoint must be unauthenticated (it IS
/// the authentication step). The revocation endpoints have their own admin
/// auth check.
pub fn key_server_routes(key_server: Arc<KeyServer>) -> Router {
    Router::new()
        .route("/auth/token", post(exchange_token))
        .route("/auth/token/:jti", delete(revoke_token))
        .route("/auth/tokens", delete(revoke_tokens_by_subject))
        .with_state(key_server)
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// Extract client IP from `X-Forwarded-For` or `X-Real-IP` headers.
fn extract_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse().ok())
        })
}

/// `POST /auth/token` — Exchange an OIDC identity token for a temporary gateway token.
async fn exchange_token(
    State(ks): State<Arc<KeyServer>>,
    headers: HeaderMap,
    Json(body): Json<TokenExchangeRequest>,
) -> impl IntoResponse {
    // Items must be outside statement blocks to satisfy clippy::items_after_statements
    let client_ip: Option<IpAddr> = extract_client_ip(&headers);

    if body.grant_type != "urn:ietf:params:oauth:grant-type:token-exchange" {
        warn!(grant_type = %body.grant_type, "Invalid grant_type");
        let ev = AuditEvent::invalid(format!("invalid grant_type: {}", body.grant_type), client_ip);
        audit::emit(&ev);
        return error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type must be 'urn:ietf:params:oauth:grant-type:token-exchange'",
        );
    }

    if body.subject_token.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject_token is required",
        );
    }

    // Build OIDC config for verification
    let oidc_config = KeyServerOidcConfig {
        max_token_age_secs: ks.config.max_oidc_token_age_secs,
    };

    // Verify OIDC token
    let identity = match ks.oidc.verify(&body.subject_token, &oidc_config).await {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "OIDC verification failed");
            let ev = AuditEvent::denied(e.to_string(), client_ip);
            audit::emit(&ev);
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "OIDC token verification failed",
            );
        }
    };

    // Parse requested scopes from scope string
    let requested = parse_scope_string(&body.scope);

    // Resolve policy (let..else is cleaner than match + early return)
    let Some(scopes) = ks.policy.resolve_scopes(&identity, &requested) else {
        warn!(email = %identity.email, "No policy matched");
        let ev = AuditEvent::denied(
            format!("no policy matched for {}", identity.email),
            client_ip,
        );
        audit::emit(&ev);
        return error_response(
            StatusCode::FORBIDDEN,
            "access_denied",
            "No access policy matched for this identity",
        );
    };

    // Enforce max tokens per identity
    let active_count = ks.store.count_for_subject(&identity.subject).await;
    if active_count >= ks.config.max_tokens_per_identity as usize {
        warn!(
            subject = %identity.subject,
            active = active_count,
            max = ks.config.max_tokens_per_identity,
            "Max tokens per identity exceeded"
        );
        let ev = AuditEvent::denied(
            format!(
                "max tokens per identity ({}) exceeded",
                ks.config.max_tokens_per_identity
            ),
            client_ip,
        );
        audit::emit(&ev);
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_tokens",
            "Maximum number of active tokens for this identity exceeded",
        );
    }

    // Issue token
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    let ttl = ks.config.token_ttl_secs;
    let token = TemporaryToken {
        jti: InMemoryTokenStore::generate_jti(),
        token: InMemoryTokenStore::generate_bearer(),
        identity: identity.clone(),
        scopes: scopes.clone(),
        iat: now,
        exp: now + ttl,
        client_ip,
    };

    let response = TokenExchangeResponse {
        access_token: token.token.clone(),
        token_type: "Bearer".to_string(),
        expires_in: ttl,
        scope: format_scope_string(&token),
        jti: token.jti.clone(),
    };

    let ev = AuditEvent::issued(&token);
    audit::emit(&ev);
    ks.store.insert(token).await;

    (StatusCode::OK, Json(response)).into_response()
}

/// `DELETE /auth/token/{jti}` — Revoke a specific token by its JTI.
///
/// Requires admin authorization.
async fn revoke_token(
    State(ks): State<Arc<KeyServer>>,
    headers: HeaderMap,
    Path(jti): Path<String>,
) -> impl IntoResponse {
    if let Err(response) = check_admin_auth(&ks, &headers) {
        return response;
    }

    let removed = ks.store.revoke_by_jti(&jti).await;
    if removed {
        let ev = AuditEvent::revoked(&jti, None);
        audit::emit(&ev);
        (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "token_not_found", "message": "Token not found or already expired"})),
        )
            .into_response()
    }
}

/// `DELETE /auth/tokens?subject=<subject>` — Revoke all tokens for a subject.
///
/// Requires admin authorization.
async fn revoke_tokens_by_subject(
    State(ks): State<Arc<KeyServer>>,
    headers: HeaderMap,
    Query(params): Query<RevokeBySubjectQuery>,
) -> impl IntoResponse {
    if let Err(response) = check_admin_auth(&ks, &headers) {
        return response;
    }

    let count = ks.store.revoke_by_subject(&params.subject).await;
    let ev = AuditEvent::revoked(&format!("bulk:{}", params.subject), None);
    audit::emit(&ev);

    (
        StatusCode::OK,
        Json(json!({"revoked": count, "subject": params.subject})),
    )
        .into_response()
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Check the `Authorization: Bearer <token>` header against the configured
/// admin token. Returns `Err(response)` if auth fails.
///
/// The `Err` variant carries an `axum::response::Response` which is large
/// by design — it wraps the full HTTP response to be returned immediately.
#[allow(clippy::result_large_err)]
fn check_admin_auth(
    ks: &KeyServer,
    headers: &HeaderMap,
) -> Result<(), axum::response::Response> {
    use subtle::ConstantTimeEq;

    let Some(ref admin_token) = ks.config.admin_token else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "admin_not_configured",
                "message": "Admin token not configured — revocation endpoints disabled"
            })),
        )
            .into_response());
    };

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });

    // Constant-time comparison to prevent timing side-channels
    let matches = provided
        .map_or(false, |p| p.as_bytes().ct_eq(admin_token.as_bytes()).into());

    if matches {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Bearer")],
            Json(json!({
                "error": "unauthorized",
                "message": "Invalid admin token"
            })),
        )
            .into_response())
    }
}

/// Parse a space-separated scope string into [`RequestedScopes`].
///
/// Format: `backends:a,b tools:x,y` or simply empty for "grant all policy allows".
fn parse_scope_string(scope: &str) -> RequestedScopes {
    let mut backends = Vec::new();
    let mut tools = Vec::new();

    for part in scope.split_whitespace() {
        if let Some(rest) = part.strip_prefix("backends:") {
            backends.extend(rest.split(',').filter(|s| !s.is_empty()).map(str::to_string));
        } else if let Some(rest) = part.strip_prefix("tools:") {
            tools.extend(rest.split(',').filter(|s| !s.is_empty()).map(str::to_string));
        }
    }

    RequestedScopes { backends, tools }
}

/// Format the granted scopes into a space-separated string.
fn format_scope_string(token: &TemporaryToken) -> String {
    let mut parts = Vec::new();

    if !token.scopes.backends.is_empty() {
        parts.push(format!("backends:{}", token.scopes.backends.join(",")));
    }
    if !token.scopes.tools.is_empty() {
        parts.push(format!("tools:{}", token.scopes.tools.join(",")));
    }

    parts.join(" ")
}

/// Create a JSON error response.
fn error_response(status: StatusCode, error: &str, message: &str) -> axum::response::Response {
    (
        status,
        Json(json!({"error": error, "message": message})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_string_empty() {
        // GIVEN: empty scope string
        let scopes = parse_scope_string("");

        // THEN: both lists are empty
        assert!(scopes.backends.is_empty());
        assert!(scopes.tools.is_empty());
    }

    #[test]
    fn parse_scope_string_backends_only() {
        // GIVEN: scope with only backends
        let scopes = parse_scope_string("backends:tavily,brave");

        // THEN: backends parsed, tools empty
        assert_eq!(scopes.backends, vec!["tavily", "brave"]);
        assert!(scopes.tools.is_empty());
    }

    #[test]
    fn parse_scope_string_tools_only() {
        // GIVEN: scope with only tools
        let scopes = parse_scope_string("tools:tavily-search,brave_web_search");

        // THEN: tools parsed, backends empty
        assert!(scopes.backends.is_empty());
        assert_eq!(scopes.tools, vec!["tavily-search", "brave_web_search"]);
    }

    #[test]
    fn parse_scope_string_both() {
        // GIVEN: scope with both backends and tools
        let scopes = parse_scope_string("backends:tavily tools:tavily-search,brave_search");

        // THEN: both parsed correctly
        assert_eq!(scopes.backends, vec!["tavily"]);
        assert_eq!(scopes.tools, vec!["tavily-search", "brave_search"]);
    }

    #[test]
    fn parse_scope_string_ignores_unknown_prefixes() {
        // GIVEN: scope with unknown prefix
        let scopes = parse_scope_string("unknown:foo backends:tavily");

        // THEN: only known prefixes parsed
        assert_eq!(scopes.backends, vec!["tavily"]);
    }

    #[test]
    fn format_scope_string_empty() {
        // GIVEN: token with empty scopes
        use crate::key_server::{oidc::VerifiedIdentity, store::{TemporaryToken, TokenScopes}};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let token = TemporaryToken {
            jti: "jti".to_string(),
            token: "mcpgw_test".to_string(),
            identity: VerifiedIdentity {
                subject: "sub".to_string(),
                email: "alice@example.com".to_string(),
                name: None,
                groups: Vec::new(),
                issuer: "https://accounts.google.com".to_string(),
            },
            scopes: TokenScopes::default(),
            iat: now,
            exp: now + 3600,
            client_ip: None,
        };

        // WHEN: format scope string
        let scope = format_scope_string(&token);

        // THEN: empty string (no restrictions)
        assert_eq!(scope, "");
    }

    #[test]
    fn format_scope_string_with_data() {
        // GIVEN: token with specific scopes
        use crate::key_server::{oidc::VerifiedIdentity, store::{TemporaryToken, TokenScopes}};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let token = TemporaryToken {
            jti: "jti".to_string(),
            token: "mcpgw_test".to_string(),
            identity: VerifiedIdentity {
                subject: "sub".to_string(),
                email: "alice@example.com".to_string(),
                name: None,
                groups: Vec::new(),
                issuer: "https://accounts.google.com".to_string(),
            },
            scopes: TokenScopes {
                backends: vec!["tavily".to_string()],
                tools: vec!["tavily-search".to_string()],
                rate_limit: 100,
            },
            iat: now,
            exp: now + 3600,
            client_ip: None,
        };

        // WHEN: format scope string
        let scope = format_scope_string(&token);

        // THEN: both backends and tools encoded
        assert!(scope.contains("backends:tavily"));
        assert!(scope.contains("tools:tavily-search"));
    }
}
