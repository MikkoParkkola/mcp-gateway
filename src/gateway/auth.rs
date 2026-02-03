//! Authentication middleware for MCP Gateway
//!
//! Supports:
//! - Bearer token authentication
//! - API key authentication with per-key restrictions
//! - Public paths that bypass authentication

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::{debug, warn};

use crate::config::AuthConfig;

/// Resolved authentication configuration (tokens expanded)
#[derive(Debug, Clone)]
pub struct ResolvedAuthConfig {
    /// Whether auth is enabled
    pub enabled: bool,
    /// Resolved bearer token
    pub bearer_token: Option<String>,
    /// Resolved API keys
    pub api_keys: Vec<ResolvedApiKey>,
    /// Public paths
    pub public_paths: Vec<String>,
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
    /// Create resolved config from AuthConfig
    pub fn from_config(config: &AuthConfig) -> Self {
        let bearer_token = config.resolve_bearer_token();

        // Log if auto-generated token
        if config.bearer_token.as_deref() == Some("auto") {
            if let Some(ref token) = bearer_token {
                tracing::info!(
                    "Auto-generated bearer token: {}",
                    token
                );
            }
        }

        let api_keys = config
            .api_keys
            .iter()
            .map(|k| ResolvedApiKey {
                key: k.resolve_key(),
                name: k.name.clone(),
                rate_limit: k.rate_limit,
                backends: k.backends.clone(),
            })
            .collect();

        Self {
            enabled: config.enabled,
            bearer_token,
            api_keys,
            public_paths: config.public_paths.clone(),
        }
    }

    /// Check if a path is public (bypasses auth)
    pub fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| path.starts_with(p))
    }

    /// Validate a token and return the client info if valid
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
}

/// Information about an authenticated client
#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    /// Client name
    pub name: String,
    /// Rate limit (0 = unlimited)
    pub rate_limit: u32,
    /// Allowed backends (empty or ["*"] = all)
    pub backends: Vec<String>,
}

impl AuthenticatedClient {
    /// Check if this client can access a backend
    pub fn can_access_backend(&self, backend: &str) -> bool {
        self.backends.is_empty() || self.backends.iter().any(|b| b == "*" || b == backend)
    }
}

/// Authentication middleware
pub async fn auth_middleware(
    State(auth_config): State<Arc<ResolvedAuthConfig>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // If auth is disabled, pass through
    if !auth_config.enabled {
        return next.run(request).await;
    }

    let path = request.uri().path();

    // Check if path is public
    if auth_config.is_public_path(path) {
        debug!(path = %path, "Public path, skipping auth");
        return next.run(request).await;
    }

    // Extract token from Authorization header
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")));

    match token {
        Some(token) => {
            if let Some(client) = auth_config.validate_token(token) {
                debug!(client = %client.name, path = %path, "Authenticated request");
                // TODO: Could inject client info into request extensions for downstream use
                next.run(request).await
            } else {
                warn!(path = %path, "Invalid token");
                unauthorized_response("Invalid token")
            }
        }
        None => {
            warn!(path = %path, "Missing Authorization header");
            unauthorized_response("Missing Authorization header. Use: Authorization: Bearer <token>")
        }
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
}
