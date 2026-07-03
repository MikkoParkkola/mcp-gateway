//! RFC 9728 OAuth Protected Resource Metadata endpoint.
//!
//! `GET /.well-known/oauth-protected-resource` lets an MCP client discover,
//! *before* it holds a token, that this gateway is a protected resource. Per
//! RFC 9728 §3.1 the endpoint is unauthenticated — a client fetches it in
//! response to a `401` carrying `WWW-Authenticate: Bearer resource_metadata="…"`.
//!
//! # Population
//!
//! The document is built from the gateway's own configuration, never from the
//! request `Host` header — reflecting an attacker-controlled `Host` into a
//! security-relevant discovery document would let a caller advertise a rogue
//! origin. `resource` is the gateway's configured public origin
//! (`server.public_url` when set, otherwise the bind `host:port`).
//!
//! `authorization_servers` is deliberately left empty: RFC 9728 defines it as
//! the OAuth authorization-server issuer identifiers a client resolves via
//! `/.well-known/oauth-authorization-server` (RFC 8414). This gateway does not
//! yet publish RFC 8414 metadata, so naming any issuer here would break client
//! discovery. It is omitted from the serialized document (RFC 9728 §3.2) until
//! the gateway serves authorization-server metadata. Per-user credentials the
//! gateway mints for identity-propagation backends are downstream assertions,
//! not the client-facing authorization server for reaching the gateway.

use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use crate::config::Config;
use crate::oauth::ProtectedResourceMetadata;

use super::AppState;

/// Build the gateway's externally reachable origin URL.
///
/// Uses `server.public_url` when configured — the only value that reliably
/// names the real external HTTPS origin behind a TLS-terminating proxy. When
/// unset, falls back to the raw bind `http://host:port`, which is correct for
/// local / development use only; a publicly exposed gateway should set
/// `server.public_url` so the advertised resource is its real HTTPS URL and
/// the internal bind address is not published.
// ponytail: config-only origin; bind fallback is dev-correct, prod sets public_url.
fn gateway_origin(config: &Config) -> String {
    if let Some(url) = &config.server.public_url {
        return url.trim_end_matches('/').to_string();
    }
    format!("http://{}:{}", config.server.host, config.server.port)
}

/// Build RFC 9728 protected-resource metadata from the live gateway config.
#[must_use]
pub fn build_protected_resource_metadata(config: &Config) -> ProtectedResourceMetadata {
    ProtectedResourceMetadata {
        resource: gateway_origin(config),
        // Empty until the gateway serves RFC 8414 authorization-server metadata;
        // see module docs. Omitted from the serialized document when empty.
        authorization_servers: Vec::new(),
        bearer_methods_supported: vec!["header".to_string()],
        scopes_supported: Vec::new(),
    }
}

/// `GET /.well-known/oauth-protected-resource` — unauthenticated (RFC 9728).
pub async fn oauth_protected_resource_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let config = state.live_config.get();
    let metadata = build_protected_resource_metadata(&config);
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::header::HeaderValue::from_static("application/json"),
        )],
        Json(metadata),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_host(host: &str, port: u16) -> Config {
        Config {
            server: crate::config::ServerConfig {
                host: host.to_string(),
                port,
                ..Config::default().server
            },
            ..Config::default()
        }
    }

    #[test]
    fn resource_is_configured_bind_origin_not_request_host() {
        let config = config_with_host("gateway.internal", 8080);
        let meta = build_protected_resource_metadata(&config);
        assert_eq!(meta.resource, "http://gateway.internal:8080");
    }

    #[test]
    fn public_url_overrides_bind_origin() {
        let mut config = config_with_host("127.0.0.1", 39400);
        config.server.public_url = Some("https://mcp.acme.internal/".to_string());
        let meta = build_protected_resource_metadata(&config);
        // Trailing slash trimmed; the internal bind address is never advertised.
        assert_eq!(meta.resource, "https://mcp.acme.internal");
        assert!(!meta.resource.contains("127.0.0.1"));
    }

    #[test]
    fn authorization_servers_empty_until_rfc8414_metadata_served() {
        let config = config_with_host("gw.internal", 9000);
        let meta = build_protected_resource_metadata(&config);
        assert!(
            meta.authorization_servers.is_empty(),
            "must not name an authorization server the gateway does not publish RFC 8414 metadata for"
        );
    }

    #[test]
    fn empty_arrays_are_omitted_not_serialized_as_empty() {
        // RFC 9728 §3.2: zero-value parameters are omitted, not sent as `[]`.
        let config = config_with_host("gw.internal", 9000);
        let json = serde_json::to_string(&build_protected_resource_metadata(&config)).unwrap();
        assert!(!json.contains("authorization_servers"));
        assert!(!json.contains("scopes_supported"));
    }

    #[test]
    fn serializes_rfc9728_shaped_json() {
        let config = config_with_host("gw.internal", 9000);
        let json = serde_json::to_string(&build_protected_resource_metadata(&config)).unwrap();
        assert!(json.contains("\"resource\":\"http://gw.internal:9000\""));
        assert!(json.contains("\"bearer_methods_supported\":[\"header\"]"));
    }
}
