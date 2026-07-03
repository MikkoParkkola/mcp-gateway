//! RFC 9728 OAuth Protected Resource Metadata endpoint.
//!
//! `GET /.well-known/oauth-protected-resource` lets an MCP client discover,
//! *before* it holds a token, that this gateway is a protected resource and
//! which authorization server issues tokens for it. Per RFC 9728 §3.1 the
//! endpoint is unauthenticated — a client fetches it in response to a `401`
//! carrying `WWW-Authenticate: Bearer resource_metadata="…"`.
//!
//! # Population
//!
//! The document is built from the gateway's own configuration, never from the
//! request `Host` header — reflecting an attacker-controlled `Host` into a
//! security-relevant discovery document would let a caller advertise a rogue
//! authorization server. `resource` is the gateway's configured origin.
//! `authorization_servers` lists that same origin when any backend performs
//! identity propagation, because the gateway itself mints the per-user
//! credentials (signed with the key it publishes at `/.well-known/jwks.json`)
//! — so it is the authorization server for those tokens. Backend audiences are
//! deliberately *not* exposed; they are internal identifiers.

use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use crate::config::Config;
use crate::oauth::ProtectedResourceMetadata;

use super::AppState;

/// Build the gateway's origin URL (`scheme://host:port`) from its bind config.
///
/// The scheme is `http` — TLS termination is expected to sit in front of the
/// gateway. A deployment behind a reverse proxy with a different public origin
/// needs an explicit public-URL config field.
// ponytail: config-origin only; add `server.public_url` when a proxy fronts it.
fn gateway_origin(config: &Config) -> String {
    format!("http://{}:{}", config.server.host, config.server.port)
}

/// Build RFC 9728 protected-resource metadata from the live gateway config.
#[must_use]
pub fn build_protected_resource_metadata(config: &Config) -> ProtectedResourceMetadata {
    let resource = gateway_origin(config);

    // The gateway is the authorization server for propagated identity: it mints
    // and signs the per-user credentials. Advertise it only when at least one
    // backend actually propagates identity — otherwise no gateway-issued token
    // exists and the list stays empty.
    let propagates = config
        .backends
        .values()
        .any(|b| b.identity_propagation.is_some());
    let authorization_servers = if propagates {
        vec![resource.clone()]
    } else {
        Vec::new()
    };

    ProtectedResourceMetadata {
        resource,
        authorization_servers,
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
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };

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

    fn propagation_backend(audience: &str) -> crate::config::BackendConfig {
        crate::config::BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: audience.to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn resource_is_configured_origin_not_request_host() {
        let config = config_with_host("gateway.internal", 8080);
        let meta = build_protected_resource_metadata(&config);
        assert_eq!(meta.resource, "http://gateway.internal:8080");
    }

    #[test]
    fn no_propagation_backend_yields_empty_authorization_servers() {
        let config = config_with_host("localhost", 3000);
        let meta = build_protected_resource_metadata(&config);
        assert!(
            meta.authorization_servers.is_empty(),
            "gateway must not claim to be an AS when nothing propagates identity"
        );
    }

    #[test]
    fn propagation_backend_advertises_gateway_as_authorization_server() {
        let mut config = config_with_host("gw.example", 9000);
        config.backends.insert(
            "api".to_string(),
            propagation_backend("https://backend.example/api"),
        );

        let meta = build_protected_resource_metadata(&config);
        assert_eq!(meta.authorization_servers, vec!["http://gw.example:9000"]);
    }

    #[test]
    fn backend_audience_is_never_leaked_into_metadata() {
        let mut config = config_with_host("gw.example", 9000);
        let secret_audience = "https://internal-backend.example/private-api";
        config
            .backends
            .insert("api".to_string(), propagation_backend(secret_audience));

        let json = serde_json::to_string(&build_protected_resource_metadata(&config)).unwrap();
        assert!(
            !json.contains(secret_audience),
            "backend audience must not appear in the public metadata document"
        );
    }

    #[test]
    fn serializes_rfc9728_shaped_json() {
        let config = config_with_host("gw.example", 9000);
        let json = serde_json::to_string(&build_protected_resource_metadata(&config)).unwrap();
        assert!(json.contains("\"resource\":\"http://gw.example:9000\""));
        assert!(json.contains("\"bearer_methods_supported\":[\"header\"]"));
    }
}
