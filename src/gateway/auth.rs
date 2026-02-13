//! Authentication middleware for MCP Gateway
//!
//! Supports:
//! - Bearer token authentication
//! - API key authentication with per-key restrictions
//! - Rate limiting per client
//! - Public paths that bypass authentication

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use serde_json::json;
use tracing::{debug, warn};

use crate::config::AuthConfig;

/// Type alias for our rate limiter
type ClientRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Resolved authentication configuration (tokens expanded)
#[derive(Debug)]
pub struct ResolvedAuthConfig {
    /// Whether auth is enabled
    pub enabled: bool,
    /// Resolved bearer token
    pub bearer_token: Option<String>,
    /// Resolved API keys
    pub api_keys: Vec<ResolvedApiKey>,
    /// Public paths
    pub public_paths: Vec<String>,
    /// Rate limiters per client (keyed by client name)
    rate_limiters: DashMap<String, Arc<ClientRateLimiter>>,
}

/// Resolved API key with expanded values
#[derive(Debug, Clone)]
pub struct ResolvedApiKey {
    /// The actual key value
    pub key: String,
    /// Client name
    pub name: String,
    /// Rate limit (requests per minute)
    pub rate_limit: u32,
    /// Allowed backends
    pub backends: Vec<String>,
}

impl ResolvedAuthConfig {
    /// Create resolved config from `AuthConfig`
    pub fn from_config(config: &AuthConfig) -> Self {
        let bearer_token = config.resolve_bearer_token();

        // Log if auto-generated token
        if config.bearer_token.as_deref() == Some("auto") {
            if let Some(ref token) = bearer_token {
                tracing::info!("Auto-generated bearer token: {}", token);
            }
        }

        let api_keys: Vec<ResolvedApiKey> = config
            .api_keys
            .iter()
            .map(|k| ResolvedApiKey {
                key: k.resolve_key(),
                name: k.name.clone(),
                rate_limit: k.rate_limit,
                backends: k.backends.clone(),
            })
            .collect();

        // Pre-create rate limiters for clients with rate limits
        let rate_limiters = DashMap::new();
        for key in &api_keys {
            if key.rate_limit > 0 {
                if let Some(quota) = NonZeroU32::new(key.rate_limit) {
                    let limiter = RateLimiter::direct(Quota::per_minute(quota));
                    rate_limiters.insert(key.name.clone(), Arc::new(limiter));
                }
            }
        }

        Self {
            enabled: config.enabled,
            bearer_token,
            api_keys,
            public_paths: config.public_paths.clone(),
            rate_limiters,
        }
    }

    /// Check if a path is public (bypasses auth)
    #[must_use]
    pub fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| path.starts_with(p))
    }

    /// Validate a token and return the client info if valid
    #[must_use]
    pub fn validate_token(&self, token: &str) -> Option<AuthenticatedClient> {
        // Check bearer token first
        if let Some(ref bearer) = self.bearer_token {
            if token == bearer {
                return Some(AuthenticatedClient {
                    name: "bearer".to_string(),
                    rate_limit: 0,
                    backends: vec!["*".to_string()],
                });
            }
        }

        // Check API keys
        for key in &self.api_keys {
            if token == key.key {
                return Some(AuthenticatedClient {
                    name: key.name.clone(),
                    rate_limit: key.rate_limit,
                    backends: key.backends.clone(),
                });
            }
        }

        None
    }

    /// Check rate limit for a client. Returns true if allowed, false if rate limited.
    #[must_use]
    pub fn check_rate_limit(&self, client_name: &str) -> bool {
        if let Some(limiter) = self.rate_limiters.get(client_name) {
            limiter.check().is_ok()
        } else {
            // No rate limiter = unlimited
            true
        }
    }
}

/// Information about an authenticated client
#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    /// Client name
    pub name: String,
    /// Rate limit (0 = unlimited)
    pub rate_limit: u32,
    /// Allowed backends (empty or `["*"]` = all)
    pub backends: Vec<String>,
}

impl AuthenticatedClient {
    /// Check if this client can access a backend
    #[must_use]
    pub fn can_access_backend(&self, backend: &str) -> bool {
        self.backends.is_empty() || self.backends.iter().any(|b| b == "*" || b == backend)
    }
}

/// Authentication middleware
pub async fn auth_middleware(
    State(auth_config): State<Arc<ResolvedAuthConfig>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // If auth is disabled, pass through with anonymous client
    if !auth_config.enabled {
        request.extensions_mut().insert(AuthenticatedClient {
            name: "anonymous".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
        });
        return next.run(request).await;
    }

    let path = request.uri().path();

    // Check if path is public
    if auth_config.is_public_path(path) {
        debug!(path = %path, "Public path, skipping auth");
        request.extensions_mut().insert(AuthenticatedClient {
            name: "public".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
        });
        return next.run(request).await;
    }

    // Extract token from Authorization header
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });

    let Some(token) = token else {
        warn!(path = %path, "Missing Authorization header");
        return unauthorized_response(
            "Missing Authorization header. Use: Authorization: Bearer <token>",
        );
    };

    if let Some(client) = auth_config.validate_token(token) {
        // Check rate limit
        if !auth_config.check_rate_limit(&client.name) {
            warn!(client = %client.name, path = %path, "Rate limit exceeded");
            return rate_limited_response(&client.name);
        }

        debug!(client = %client.name, path = %path, "Authenticated request");
        // Inject client info for downstream handlers
        request.extensions_mut().insert(client);
        next.run(request).await
    } else {
        warn!(path = %path, "Invalid token");
        unauthorized_response("Invalid token")
    }
}

/// Create a 401 Unauthorized response
fn unauthorized_response(message: &str) -> Response {
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

/// Create a 429 Rate Limited response
fn rate_limited_response(client_name: &str) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("Retry-After", "60")],
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": format!("Rate limit exceeded for client '{client_name}'. Try again later.")
            },
            "id": null
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_path_check() {
        let config = ResolvedAuthConfig {
            enabled: true,
            bearer_token: Some("test".to_string()),
            api_keys: vec![],
            public_paths: vec!["/health".to_string(), "/metrics".to_string()],
            rate_limiters: DashMap::new(),
        };

        assert!(config.is_public_path("/health"));
        assert!(config.is_public_path("/health/"));
        assert!(config.is_public_path("/metrics"));
        assert!(!config.is_public_path("/mcp"));
        assert!(!config.is_public_path("/"));
    }

    #[test]
    fn test_bearer_token_validation() {
        let config = ResolvedAuthConfig {
            enabled: true,
            bearer_token: Some("secret123".to_string()),
            api_keys: vec![],
            public_paths: vec![],
            rate_limiters: DashMap::new(),
        };

        assert!(config.validate_token("secret123").is_some());
        assert!(config.validate_token("wrong").is_none());
    }

    #[test]
    fn test_api_key_validation() {
        let config = ResolvedAuthConfig {
            enabled: true,
            bearer_token: None,
            api_keys: vec![
                ResolvedApiKey {
                    key: "key1".to_string(),
                    name: "Client A".to_string(),
                    rate_limit: 100,
                    backends: vec!["tavily".to_string()],
                },
                ResolvedApiKey {
                    key: "key2".to_string(),
                    name: "Client B".to_string(),
                    rate_limit: 0,
                    backends: vec![],
                },
            ],
            public_paths: vec![],
            rate_limiters: DashMap::new(),
        };

        let client_a = config.validate_token("key1").unwrap();
        assert_eq!(client_a.name, "Client A");
        assert!(client_a.can_access_backend("tavily"));
        assert!(!client_a.can_access_backend("brave"));

        let client_b = config.validate_token("key2").unwrap();
        assert_eq!(client_b.name, "Client B");
        assert!(client_b.can_access_backend("anything"));

        assert!(config.validate_token("wrong").is_none());
    }

    #[test]
    fn test_rate_limiting() {
        let rate_limiters = DashMap::new();
        // Create a rate limiter with 2 requests per minute for testing
        let limiter = RateLimiter::direct(Quota::per_minute(NonZeroU32::new(2).unwrap()));
        rate_limiters.insert("limited_client".to_string(), Arc::new(limiter));

        let config = ResolvedAuthConfig {
            enabled: true,
            bearer_token: None,
            api_keys: vec![],
            public_paths: vec![],
            rate_limiters,
        };

        // First two requests should succeed
        assert!(config.check_rate_limit("limited_client"));
        assert!(config.check_rate_limit("limited_client"));
        // Third request should be rate limited
        assert!(!config.check_rate_limit("limited_client"));
        // Unknown client (no limiter) should always succeed
        assert!(config.check_rate_limit("unknown_client"));
    }

    #[test]
    fn test_backend_access_control() {
        let client_restricted = AuthenticatedClient {
            name: "restricted".to_string(),
            rate_limit: 0,
            backends: vec!["tavily".to_string(), "brave".to_string()],
        };

        let client_unrestricted = AuthenticatedClient {
            name: "unrestricted".to_string(),
            rate_limit: 0,
            backends: vec![], // empty = all access
        };

        let client_wildcard = AuthenticatedClient {
            name: "wildcard".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
        };

        // Restricted client
        assert!(client_restricted.can_access_backend("tavily"));
        assert!(client_restricted.can_access_backend("brave"));
        assert!(!client_restricted.can_access_backend("context7"));

        // Unrestricted client (empty backends = all)
        assert!(client_unrestricted.can_access_backend("anything"));

        // Wildcard client
        assert!(client_wildcard.can_access_backend("anything"));
    }
}
