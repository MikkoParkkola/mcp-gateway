//! OAuth Metadata Discovery
//!
//! Implements RFC 8414 (OAuth Authorization Server Metadata) and
//! RFC 8707 (OAuth Protected Resource Metadata).

use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize};
use tracing::debug;
use url::Url;

use crate::{Error, Result};

/// OAuth Authorization Server Metadata (RFC 8414)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// Authorization server issuer URL
    pub issuer: String,

    /// Authorization endpoint URL
    pub authorization_endpoint: String,

    /// Token endpoint URL
    pub token_endpoint: String,

    /// Token revocation endpoint (optional)
    #[serde(default)]
    pub revocation_endpoint: Option<String>,

    /// Userinfo endpoint (optional)
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,

    /// Dynamic client registration endpoint (optional)
    #[serde(default)]
    pub registration_endpoint: Option<String>,

    /// Supported grant types
    #[serde(default)]
    pub grant_types_supported: Vec<String>,

    /// Supported response types
    #[serde(default)]
    pub response_types_supported: Vec<String>,

    /// Supported scopes (may be string or array due to implementation bugs)
    #[serde(default, deserialize_with = "deserialize_scopes")]
    pub scopes_supported: Vec<String>,

    /// Supported token endpoint auth methods
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,

    /// Supported PKCE code challenge methods
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

/// OAuth Protected Resource Metadata (RFC 8707)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// Protected resource identifier
    pub resource: String,

    /// Authorization servers that can issue tokens for this resource
    #[serde(default)]
    pub authorization_servers: Vec<String>,

    /// Supported bearer token methods
    #[serde(default)]
    pub bearer_methods_supported: Vec<String>,

    /// Supported scopes (may be string or array due to implementation bugs)
    #[serde(default, deserialize_with = "deserialize_scopes")]
    pub scopes_supported: Vec<String>,
}

/// Deserialize scopes that may be either a string or array
/// Some implementations (like Beeper) incorrectly return `"read write"` instead of `["read", "write"]`
fn deserialize_scopes<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Vec(Vec<String>),
    }

    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::String(s) => Ok(s.split_whitespace().map(String::from).collect()),
        StringOrVec::Vec(v) => Ok(v),
    }
}

impl AuthorizationServerMetadata {
    /// Discover authorization server metadata from a base URL
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata endpoint is unreachable or returns invalid data.
    pub async fn discover(client: &Client, base_url: &str) -> Result<Self> {
        let url = format!(
            "{}/.well-known/oauth-authorization-server",
            base_url.trim_end_matches('/')
        );
        debug!(url = %url, "Discovering OAuth authorization server metadata");

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Failed to fetch OAuth metadata: {e}")))?;

        if !response.status().is_success() {
            return Err(Error::Internal(format!(
                "OAuth metadata discovery failed: HTTP {}",
                response.status()
            )));
        }

        let metadata: Self = response
            .json()
            .await
            .map_err(|e| Error::Internal(format!("Failed to parse OAuth metadata: {e}")))?;

        debug!(issuer = %metadata.issuer, "Discovered authorization server");
        Ok(metadata)
    }

    /// Check if PKCE is supported (S256 method)
    #[must_use]
    pub fn supports_pkce(&self) -> bool {
        self.code_challenge_methods_supported
            .contains(&"S256".to_string())
    }
}

impl ProtectedResourceMetadata {
    /// Discover protected resource metadata from a base URL
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata endpoint is unreachable or returns invalid data.
    pub async fn discover(client: &Client, base_url: &str) -> Result<Self> {
        let url = format!(
            "{}/.well-known/oauth-protected-resource",
            base_url.trim_end_matches('/')
        );
        debug!(url = %url, "Discovering OAuth protected resource metadata");

        let response = client.get(&url).send().await.map_err(|e| {
            Error::Internal(format!("Failed to fetch protected resource metadata: {e}"))
        })?;

        if !response.status().is_success() {
            return Err(Error::Internal(format!(
                "Protected resource metadata discovery failed: HTTP {}",
                response.status()
            )));
        }

        let metadata: Self = response.json().await.map_err(|e| {
            Error::Internal(format!("Failed to parse protected resource metadata: {e}"))
        })?;

        debug!(resource = %metadata.resource, "Discovered protected resource");
        Ok(metadata)
    }

    /// Get the first authorization server URL
    pub fn authorization_server(&self) -> Option<&str> {
        self.authorization_servers
            .first()
            .map(std::string::String::as_str)
    }
}

/// Extract the base URL (scheme + host + port) from a full URL
pub fn base_url(url: &str) -> Result<String> {
    let parsed = Url::parse(url).map_err(|e| Error::Internal(format!("Invalid URL: {e}")))?;

    let mut base = format!(
        "{}://{}",
        parsed.scheme(),
        parsed.host_str().unwrap_or("localhost")
    );

    if let Some(port) = parsed.port() {
        use std::fmt::Write;
        let _ = write!(base, ":{port}");
    }

    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // deserialize_scopes
    // =========================================================================

    #[test]
    fn test_deserialize_scopes_array() {
        let json = r#"{"resource": "http://localhost", "scopes_supported": ["read", "write"]}"#;
        let meta: ProtectedResourceMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.scopes_supported, vec!["read", "write"]);
    }

    #[test]
    fn test_deserialize_scopes_string() {
        // Some implementations incorrectly return scopes as space-separated string
        let json = r#"{"resource": "http://localhost", "scopes_supported": "read write"}"#;
        let meta: ProtectedResourceMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.scopes_supported, vec!["read", "write"]);
    }

    #[test]
    fn deserialize_scopes_empty_array() {
        let json = r#"{"resource": "http://localhost", "scopes_supported": []}"#;
        let meta: ProtectedResourceMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.scopes_supported.is_empty());
    }

    #[test]
    fn deserialize_scopes_missing_field() {
        let json = r#"{"resource": "http://localhost"}"#;
        let meta: ProtectedResourceMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.scopes_supported.is_empty());
    }

    #[test]
    fn deserialize_scopes_single_string() {
        let json = r#"{"resource": "http://localhost", "scopes_supported": "read"}"#;
        let meta: ProtectedResourceMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.scopes_supported, vec!["read"]);
    }

    // =========================================================================
    // base_url extraction
    // =========================================================================

    #[test]
    fn test_base_url_extraction() {
        assert_eq!(
            base_url("http://localhost:8080/api/v1").unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            base_url("https://example.com/path").unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn base_url_strips_path_and_query() {
        assert_eq!(
            base_url("https://api.example.com/v1/auth?foo=bar").unwrap(),
            "https://api.example.com"
        );
    }

    #[test]
    fn base_url_preserves_port() {
        assert_eq!(
            base_url("http://127.0.0.1:3000/endpoint").unwrap(),
            "http://127.0.0.1:3000"
        );
    }

    #[test]
    fn base_url_no_port() {
        assert_eq!(
            base_url("https://example.com/some/path").unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn base_url_invalid_url_returns_error() {
        assert!(base_url("not a valid url").is_err());
    }

    #[test]
    fn base_url_with_trailing_slash() {
        assert_eq!(
            base_url("http://localhost:9090/").unwrap(),
            "http://localhost:9090"
        );
    }

    // =========================================================================
    // AuthorizationServerMetadata - supports_pkce
    // =========================================================================

    #[test]
    fn supports_pkce_with_s256() {
        let meta = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/authorize".to_string(),
            token_endpoint: "https://auth.example.com/token".to_string(),
            revocation_endpoint: None,
            userinfo_endpoint: None,
            registration_endpoint: None,
            grant_types_supported: vec![],
            response_types_supported: vec![],
            scopes_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
            code_challenge_methods_supported: vec!["S256".to_string()],
        };
        assert!(meta.supports_pkce());
    }

    #[test]
    fn supports_pkce_without_s256() {
        let meta = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/authorize".to_string(),
            token_endpoint: "https://auth.example.com/token".to_string(),
            revocation_endpoint: None,
            userinfo_endpoint: None,
            registration_endpoint: None,
            grant_types_supported: vec![],
            response_types_supported: vec![],
            scopes_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
            code_challenge_methods_supported: vec!["plain".to_string()],
        };
        assert!(!meta.supports_pkce());
    }

    #[test]
    fn supports_pkce_empty_methods() {
        let meta = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/authorize".to_string(),
            token_endpoint: "https://auth.example.com/token".to_string(),
            revocation_endpoint: None,
            userinfo_endpoint: None,
            registration_endpoint: None,
            grant_types_supported: vec![],
            response_types_supported: vec![],
            scopes_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
            code_challenge_methods_supported: vec![],
        };
        assert!(!meta.supports_pkce());
    }

    // =========================================================================
    // ProtectedResourceMetadata - authorization_server
    // =========================================================================

    #[test]
    fn authorization_server_returns_first() {
        let meta = ProtectedResourceMetadata {
            resource: "http://localhost".to_string(),
            authorization_servers: vec![
                "https://auth1.example.com".to_string(),
                "https://auth2.example.com".to_string(),
            ],
            bearer_methods_supported: vec![],
            scopes_supported: vec![],
        };
        assert_eq!(meta.authorization_server(), Some("https://auth1.example.com"));
    }

    #[test]
    fn authorization_server_returns_none_when_empty() {
        let meta = ProtectedResourceMetadata {
            resource: "http://localhost".to_string(),
            authorization_servers: vec![],
            bearer_methods_supported: vec![],
            scopes_supported: vec![],
        };
        assert_eq!(meta.authorization_server(), None);
    }

    // =========================================================================
    // AuthorizationServerMetadata deserialization
    // =========================================================================

    #[test]
    fn deserialize_auth_server_metadata_full() {
        let json = r#"{
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "registration_endpoint": "https://auth.example.com/register",
            "scopes_supported": ["read", "write"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code"],
            "response_types_supported": ["code"]
        }"#;
        let meta: AuthorizationServerMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.issuer, "https://auth.example.com");
        assert_eq!(meta.registration_endpoint, Some("https://auth.example.com/register".to_string()));
        assert!(meta.supports_pkce());
        assert_eq!(meta.scopes_supported, vec!["read", "write"]);
    }

    #[test]
    fn deserialize_auth_server_metadata_minimal() {
        let json = r#"{
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token"
        }"#;
        let meta: AuthorizationServerMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.registration_endpoint.is_none());
        assert!(meta.scopes_supported.is_empty());
        assert!(!meta.supports_pkce());
    }

    #[test]
    fn auth_metadata_scopes_from_string() {
        let json = r#"{
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "scopes_supported": "read write admin"
        }"#;
        let meta: AuthorizationServerMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.scopes_supported, vec!["read", "write", "admin"]);
    }
}
