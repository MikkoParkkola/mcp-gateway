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
/// Uses `server.public_url` when configured and well-formed — the only value
/// that reliably names the real external origin behind a TLS-terminating
/// proxy. A `public_url` that is not a scheme-qualified `http(s)` origin (or
/// that carries a fragment, query, or userinfo — none of which belong in an
/// RFC 9728 resource identifier) is rejected and logged, never published.
///
/// When `public_url` is unset the origin falls back to the bind address. `http`
/// is only RFC-legal for a loopback host (the OAuth loopback exception), so the
/// fallback advertises `http` for loopback binds (genuine local dev) and
/// `https` for any non-loopback bind — a gateway reachable off-box is behind
/// TLS in practice, and advertising `http://0.0.0.0:port` would be both
/// non-compliant and a bind-address leak.
// ponytail: config-only origin; validated public_url wins, else loopback-aware bind scheme.
fn gateway_origin(config: &Config) -> String {
    if let Some(url) = &config.server.public_url {
        if let Some(valid) = sanitize_public_url(url) {
            return valid;
        }
        tracing::warn!(
            public_url = %url,
            "server.public_url is not a valid http(s) origin (scheme://host[:port], no fragment/query/userinfo); falling back to bind origin"
        );
    }
    let host = &config.server.host;
    let scheme = if is_loopback_host(host) {
        "http"
    } else {
        "https"
    };
    format!("{scheme}://{host}:{}", config.server.port)
}

/// `true` when `host` names the loopback interface, for which advertising an
/// `http` origin is RFC-legal (OAuth loopback exception).
fn is_loopback_host(host: &str) -> bool {
    // Strip an IPv6 literal's brackets before parsing (`[::1]` -> `::1`).
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if matches!(bare, "localhost") {
        return true;
    }
    bare.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Validate an operator-supplied `public_url` as an RFC 9728 resource origin.
///
/// Accepts `http`/`https` with a non-empty authority and an optional path;
/// rejects any fragment, query, or userinfo (`user@host`). Returns the URL with
/// a trailing slash trimmed, or `None` if malformed.
fn sanitize_public_url(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    if url.contains('#') || url.contains('?') {
        return None;
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(url.trim_end_matches('/').to_string())
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
        // Non-loopback bind without public_url advertises https (off-box = TLS).
        assert_eq!(meta.resource, "https://gateway.internal:8080");
    }

    #[test]
    fn loopback_bind_advertises_http() {
        // http is RFC-legal only for loopback (OAuth loopback exception).
        for host in ["127.0.0.1", "localhost", "::1"] {
            let config = config_with_host(host, 39400);
            let meta = build_protected_resource_metadata(&config);
            assert_eq!(meta.resource, format!("http://{host}:39400"));
        }
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
        assert!(json.contains("\"resource\":\"https://gw.internal:9000\""));
        assert!(json.contains("\"bearer_methods_supported\":[\"header\"]"));
    }

    #[test]
    fn malformed_public_url_falls_back_to_bind_origin() {
        // A public_url that is not a valid http(s) origin must never be
        // published; the endpoint falls back to the bind origin instead.
        for bad in [
            "gateway.example",              // no scheme
            "ftp://gw.internal",            // wrong scheme
            "https://user@gw.internal",     // userinfo
            "https://gw.internal/path?x=1", // query
            "https://gw.internal#frag",     // fragment
            "https://",                     // empty authority
        ] {
            let mut config = config_with_host("gw.internal", 9000);
            config.server.public_url = Some(bad.to_string());
            let meta = build_protected_resource_metadata(&config);
            assert_eq!(
                meta.resource, "https://gw.internal:9000",
                "malformed public_url {bad:?} must fall back, not be published"
            );
        }
    }

    #[test]
    fn sanitize_public_url_accepts_wellformed_and_trims_slash() {
        assert_eq!(
            sanitize_public_url("https://mcp.acme.internal/"),
            Some("https://mcp.acme.internal".to_string())
        );
        assert_eq!(
            sanitize_public_url("http://gw.internal:8080/base"),
            Some("http://gw.internal:8080/base".to_string())
        );
        assert_eq!(sanitize_public_url("https://gw.internal#f"), None);
    }
}
