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
}
