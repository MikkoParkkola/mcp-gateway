//! OAuth Client
//!
//! Main OAuth client implementation with PKCE support.

use std::collections::HashMap;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use parking_lot::RwLock;
use rand::Rng;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use url::Url;

use super::callback;
use super::metadata::{self, AuthorizationServerMetadata, ProtectedResourceMetadata};
use super::storage::{TokenInfo, TokenStorage};
use crate::{Error, Result};

/// OAuth client for a specific backend
pub struct OAuthClient {
    /// HTTP client for token requests
    http_client: Client,

    /// Backend name (for storage key)
    backend_name: String,

    /// Resource URL (MCP endpoint)
    resource_url: String,

    /// OAuth server base URL (discovered from metadata)
    oauth_base_url: Option<String>,

    /// Authorization server metadata
    auth_metadata: Option<AuthorizationServerMetadata>,

    /// Protected resource metadata
    resource_metadata: Option<ProtectedResourceMetadata>,

    /// Token storage
    storage: Arc<TokenStorage>,

    /// Current token (cached)
    current_token: RwLock<Option<TokenInfo>>,

    /// Requested scopes
    scopes: Vec<String>,

    /// Client ID (registered or generated)
    client_id: RwLock<Option<String>>,
}

/// OAuth token response
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

/// Client registration response
#[derive(Debug, Deserialize)]
struct ClientRegistrationResponse {
    client_id: String,
    #[allow(dead_code)]
    client_secret: Option<String>,
}

impl OAuthClient {
    /// Create a new OAuth client for a backend
    #[must_use]
    pub fn new(
        http_client: Client,
        backend_name: String,
        resource_url: String,
        scopes: Vec<String>,
        storage: Arc<TokenStorage>,
    ) -> Self {
        Self {
            http_client,
            backend_name,
            resource_url,
            oauth_base_url: None,
            auth_metadata: None,
            resource_metadata: None,
            storage,
            current_token: RwLock::new(None),
            scopes,
            client_id: RwLock::new(None),
        }
    }

    /// Initialize the OAuth client by discovering metadata
    ///
    /// # Errors
    ///
    /// Returns an error if authorization server metadata discovery fails.
    ///
    /// # Panics
    ///
    /// Panics if `oauth_base_url` is `None` after metadata discovery, which
    /// should not occur since both success and error paths set it.
    pub async fn initialize(&mut self) -> Result<()> {
        let base_url = metadata::base_url(&self.resource_url)?;

        // Try to discover protected resource metadata first
        match ProtectedResourceMetadata::discover(&self.http_client, &base_url).await {
            Ok(meta) => {
                debug!(resource = %meta.resource, "Found protected resource metadata");

                // Get authorization server from metadata
                if let Some(auth_server) = meta.authorization_server() {
                    self.oauth_base_url = Some(auth_server.to_string());
                } else {
                    // Fallback to same base URL
                    self.oauth_base_url = Some(base_url.clone());
                }

                // Use scopes from metadata if not specified
                if self.scopes.is_empty() && !meta.scopes_supported.is_empty() {
                    self.scopes.clone_from(&meta.scopes_supported);
                }

                self.resource_metadata = Some(meta);
            }
            Err(e) => {
                debug!(error = %e, "No protected resource metadata, using base URL");
                self.oauth_base_url = Some(base_url.clone());
            }
        }

        // Discover authorization server metadata
        let auth_base = self.oauth_base_url.as_ref().unwrap();
        self.auth_metadata =
            Some(AuthorizationServerMetadata::discover(&self.http_client, auth_base).await?);

        // Load any cached token
        if let Some(token) = self.storage.load(&self.backend_name, &self.resource_url) {
            *self.current_token.write() = Some(token);
        }

        info!(backend = %self.backend_name, "OAuth client initialized");
        Ok(())
    }

    /// Get a valid access token, refreshing or re-authorizing as needed
    ///
    /// # Errors
    ///
    /// Returns an error if token refresh and re-authorization both fail.
    pub async fn get_token(&self) -> Result<String> {
        // Check if we have a valid cached token
        {
            let token = self.current_token.read();
            if let Some(ref t) = *token {
                if !t.is_expired() {
                    return Ok(t.access_token.clone());
                }
            }
        }

        // Try to refresh if we have a refresh token
        let refresh_token_opt = {
            let token = self.current_token.read();
            token.as_ref().and_then(|t| t.refresh_token.clone())
        };

        if let Some(refresh_token) = refresh_token_opt {
            if let Ok(new_token) = self.refresh_token(&refresh_token).await {
                return Ok(new_token);
            }
        }

        // Need to authorize from scratch
        let token = self.authorize().await?;
        Ok(token)
    }

    /// Check if the client has a valid token
    pub fn has_valid_token(&self) -> bool {
        let token = self.current_token.read();
        token.as_ref().is_some_and(|t| !t.is_expired())
    }

    /// Perform the authorization flow
    ///
    /// # Errors
    ///
    /// Returns an error if any step of the OAuth authorization flow fails
    /// (callback server, client registration, browser auth, or code exchange).
    pub async fn authorize(&self) -> Result<String> {
        let auth_meta = self
            .auth_metadata
            .as_ref()
            .ok_or_else(|| Error::Internal("OAuth not initialized".to_string()))?;

        // Generate PKCE parameters
        let (code_verifier, code_challenge) = generate_pkce();

        // Generate state for CSRF protection
        let state = generate_state();

        // Start callback server FIRST to get the actual callback URL
        // This must happen BEFORE client registration so we know the port
        let callback_server = callback::start_callback_server(state.clone(), None).await?;
        let callback_url = callback_server.callback_url.clone();

        // Now ensure we have a client ID, passing the actual callback URL for registration
        let client_id = self.ensure_client_id_with_redirect(&callback_url).await?;

        // Build authorization URL with the ACTUAL callback URL
        let mut auth_url = Url::parse(&auth_meta.authorization_endpoint)
            .map_err(|e| Error::Internal(format!("Invalid auth endpoint: {e}")))?;

        {
            let mut params = auth_url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &client_id);
            params.append_pair("redirect_uri", &callback_url);
            params.append_pair("state", &state);
            params.append_pair("code_challenge", &code_challenge);
            params.append_pair("code_challenge_method", "S256");

            if !self.scopes.is_empty() {
                params.append_pair("scope", &self.scopes.join(" "));
            }
        }

        // Open browser
        let auth_url_str = auth_url.to_string();
        info!(url = %auth_url_str, "Opening browser for authorization");

        if let Err(e) = open::that(&auth_url_str) {
            warn!(error = %e, "Failed to open browser automatically");
            println!("\nPlease authorize this client by visiting:\n{auth_url_str}\n");
        }

        // Wait for callback
        let (actual_callback_url, callback_result) = callback_server.wait_for_callback().await?;

        debug!(code = %callback_result.code, "Received authorization code");

        // Exchange code for token
        let token = self
            .exchange_code(&callback_result.code, &actual_callback_url, &code_verifier)
            .await?;

        // Store and cache the token
        self.storage
            .save(&self.backend_name, &self.resource_url, &token)?;
        *self.current_token.write() = Some(token.clone());

        Ok(token.access_token)
    }

    /// Exchange authorization code for tokens
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenInfo> {
        let auth_meta = self
            .auth_metadata
            .as_ref()
            .ok_or_else(|| Error::Internal("OAuth not initialized".to_string()))?;

        let client_id = self
            .client_id
            .read()
            .clone()
            .ok_or_else(|| Error::Internal("No client ID".to_string()))?;

        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", redirect_uri);
        params.insert("client_id", &client_id);
        params.insert("code_verifier", code_verifier);

        let response = self
            .http_client
            .post(&auth_meta.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Token request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Internal(format!(
                "Token exchange failed: HTTP {status} - {body}"
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| Error::Internal(format!("Failed to parse token response: {e}")))?;

        Ok(TokenInfo::from_response(
            token_response.access_token,
            token_response.token_type,
            token_response.refresh_token,
            token_response.expires_in,
            token_response.scope,
        ))
    }

    /// Refresh an access token
    async fn refresh_token(&self, refresh_token: &str) -> Result<String> {
        let auth_meta = self
            .auth_metadata
            .as_ref()
            .ok_or_else(|| Error::Internal("OAuth not initialized".to_string()))?;

        let client_id = self
            .client_id
            .read()
            .clone()
            .ok_or_else(|| Error::Internal("No client ID".to_string()))?;

        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token);
        params.insert("client_id", &client_id);

        let response = self
            .http_client
            .post(&auth_meta.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Token refresh failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Internal(format!(
                "Token refresh failed: HTTP {status} - {body}"
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| Error::Internal(format!("Failed to parse refresh response: {e}")))?;

        let token = TokenInfo::from_response(
            token_response.access_token,
            token_response.token_type,
            token_response.refresh_token,
            token_response.expires_in,
            token_response.scope,
        );

        // Store and cache
        self.storage
            .save(&self.backend_name, &self.resource_url, &token)?;
        *self.current_token.write() = Some(token.clone());

        info!(backend = %self.backend_name, "Token refreshed successfully");
        Ok(token.access_token)
    }

    /// Ensure we have a client ID, registering with the specific redirect URI
    async fn ensure_client_id_with_redirect(&self, redirect_uri: &str) -> Result<String> {
        // Check if we already have one
        if let Some(id) = self.client_id.read().clone() {
            return Ok(id);
        }

        let auth_meta = self
            .auth_metadata
            .as_ref()
            .ok_or_else(|| Error::Internal("OAuth not initialized".to_string()))?;

        // Try dynamic registration if supported
        if let Some(ref reg_endpoint) = auth_meta.registration_endpoint {
            match self.register_client(reg_endpoint, redirect_uri).await {
                Ok(client_id) => {
                    *self.client_id.write() = Some(client_id.clone());
                    return Ok(client_id);
                }
                Err(e) => {
                    debug!(error = %e, "Dynamic registration failed, using generated ID");
                }
            }
        }

        // Generate a client ID
        let generated = generate_client_id();
        *self.client_id.write() = Some(generated.clone());
        Ok(generated)
    }

    /// Register a new client dynamically with the specified redirect URI
    async fn register_client(&self, endpoint: &str, redirect_uri: &str) -> Result<String> {
        let body = serde_json::json!({
            "client_name": format!("MCP Gateway - {}", self.backend_name),
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        });

        let response = self
            .http_client
            .post(endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Client registration failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Internal(format!(
                "Client registration failed: HTTP {status} - {body}"
            )));
        }

        let reg_response: ClientRegistrationResponse = response
            .json()
            .await
            .map_err(|e| Error::Internal(format!("Failed to parse registration response: {e}")))?;

        info!(client_id = %reg_response.client_id, "Registered OAuth client");
        Ok(reg_response.client_id)
    }
}

/// Generate PKCE code verifier and challenge
fn generate_pkce() -> (String, String) {
    // Generate 32 random bytes for verifier
    let verifier_bytes: [u8; 32] = rand::rng().random();
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    // SHA256 hash for challenge
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge_bytes = hasher.finalize();
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

    (verifier, challenge)
}

/// Generate a random state parameter
fn generate_state() -> String {
    let state_bytes: [u8; 16] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(state_bytes)
}

/// Generate a random client ID
fn generate_client_id() -> String {
    let id_bytes: [u8; 16] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(id_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // PKCE generation
    // =========================================================================

    #[test]
    fn test_pkce_generation() {
        let (verifier, challenge) = generate_pkce();

        // Verifier should be base64url encoded
        assert!(verifier.len() >= 43);
        assert!(!verifier.contains('+'));
        assert!(!verifier.contains('/'));

        // Challenge should be different from verifier (it's hashed)
        assert_ne!(verifier, challenge);
    }

    #[test]
    fn pkce_verifier_is_base64url_safe() {
        for _ in 0..10 {
            let (verifier, challenge) = generate_pkce();
            // base64url characters only
            assert!(!verifier.contains('+'));
            assert!(!verifier.contains('/'));
            assert!(!verifier.contains('='));
            assert!(!challenge.contains('+'));
            assert!(!challenge.contains('/'));
            assert!(!challenge.contains('='));
        }
    }

    #[test]
    fn pkce_challenge_is_sha256_of_verifier() {
        let (verifier, challenge) = generate_pkce();
        // Manually compute expected challenge
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let expected_bytes = hasher.finalize();
        let expected = URL_SAFE_NO_PAD.encode(expected_bytes);
        assert_eq!(challenge, expected);
    }

    #[test]
    fn pkce_generates_unique_values() {
        let (v1, c1) = generate_pkce();
        let (v2, c2) = generate_pkce();
        assert_ne!(v1, v2, "Two PKCE verifiers should be unique");
        assert_ne!(c1, c2, "Two PKCE challenges should be unique");
    }

    // =========================================================================
    // State generation
    // =========================================================================

    #[test]
    fn state_is_base64url_safe() {
        for _ in 0..10 {
            let state = generate_state();
            assert!(!state.contains('+'));
            assert!(!state.contains('/'));
            assert!(!state.contains('='));
            assert!(!state.is_empty());
        }
    }

    #[test]
    fn state_generates_unique_values() {
        let s1 = generate_state();
        let s2 = generate_state();
        assert_ne!(s1, s2);
    }

    #[test]
    fn state_has_sufficient_length() {
        let state = generate_state();
        // 16 random bytes -> 22 base64url chars
        assert!(state.len() >= 20, "State should be at least 20 chars, got {}", state.len());
    }

    // =========================================================================
    // Client ID generation
    // =========================================================================

    #[test]
    fn client_id_is_base64url_safe() {
        let id = generate_client_id();
        assert!(!id.contains('+'));
        assert!(!id.contains('/'));
        assert!(!id.contains('='));
    }

    #[test]
    fn client_id_generates_unique_values() {
        let id1 = generate_client_id();
        let id2 = generate_client_id();
        assert_ne!(id1, id2);
    }

    // =========================================================================
    // OAuthClient construction and has_valid_token
    // =========================================================================

    #[test]
    fn new_client_has_no_valid_token() {
        let storage = Arc::new(
            TokenStorage::new(std::env::temp_dir().join("oauth_test_no_token")).unwrap(),
        );
        let client = OAuthClient::new(
            Client::new(),
            "test-backend".to_string(),
            "http://localhost:8080".to_string(),
            vec!["read".to_string()],
            storage,
        );
        assert!(!client.has_valid_token());
    }

    #[test]
    fn client_with_valid_token_returns_true() {
        let storage = Arc::new(
            TokenStorage::new(std::env::temp_dir().join("oauth_test_valid_token")).unwrap(),
        );
        let client = OAuthClient::new(
            Client::new(),
            "test-backend".to_string(),
            "http://localhost:8080".to_string(),
            vec![],
            storage,
        );

        // Inject a non-expired token
        let token = TokenInfo::from_response(
            "access_token_123".to_string(),
            Some("Bearer".to_string()),
            None,
            Some(3600), // expires in 1 hour
            None,
        );
        *client.current_token.write() = Some(token);

        assert!(client.has_valid_token());
    }

    #[test]
    fn client_with_expired_token_returns_false() {
        let storage = Arc::new(
            TokenStorage::new(std::env::temp_dir().join("oauth_test_expired_token")).unwrap(),
        );
        let client = OAuthClient::new(
            Client::new(),
            "test-backend".to_string(),
            "http://localhost:8080".to_string(),
            vec![],
            storage,
        );

        // Inject an expired token
        let mut token = TokenInfo::from_response(
            "expired_token".to_string(),
            None,
            None,
            Some(3600),
            None,
        );
        token.expires_at = Some(0); // expired long ago
        *client.current_token.write() = Some(token);

        assert!(!client.has_valid_token());
    }
}
