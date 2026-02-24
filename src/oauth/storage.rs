//! OAuth Token Storage
//!
//! Persists OAuth tokens to disk for reuse across gateway restarts.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::{Error, Result};

/// OAuth token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Access token
    pub access_token: String,

    /// Token type (usually "Bearer")
    #[serde(default = "default_token_type")]
    pub token_type: String,

    /// Refresh token (optional)
    #[serde(default)]
    pub refresh_token: Option<String>,

    /// Token expiration time (Unix timestamp)
    #[serde(default)]
    pub expires_at: Option<u64>,

    /// Granted scopes
    #[serde(default)]
    pub scope: Option<String>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

impl TokenInfo {
    /// Create token info from OAuth token response
    pub fn from_response(
        access_token: String,
        token_type: Option<String>,
        refresh_token: Option<String>,
        expires_in: Option<u64>,
        scope: Option<String>,
    ) -> Self {
        let expires_at = expires_in.map(|secs| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + secs
        });

        Self {
            access_token,
            token_type: token_type.unwrap_or_else(default_token_type),
            refresh_token,
            expires_at,
            scope,
        }
    }

    /// Check if the token is expired (with 60 second buffer)
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Consider expired 60 seconds before actual expiry
            now + 60 >= expires_at
        } else {
            // No expiry = doesn't expire
            false
        }
    }

    /// Time until expiration
    #[must_use]
    pub fn time_until_expiry(&self) -> Option<Duration> {
        self.expires_at.and_then(|expires_at| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if expires_at > now {
                Some(Duration::from_secs(expires_at - now))
            } else {
                None
            }
        })
    }
}

/// Token storage for persisting OAuth tokens
pub struct TokenStorage {
    /// Base directory for token storage
    base_dir: PathBuf,
}

impl TokenStorage {
    /// Create a new token storage with the given base directory
    ///
    /// # Errors
    ///
    /// Returns an error if the storage directory cannot be created.
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        // Create directory if it doesn't exist
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir)
                .map_err(|e| Error::Internal(format!("Failed to create token storage dir: {e}")))?;
        }

        Ok(Self { base_dir })
    }

    /// Create token storage in the default location (~/.mcp-gateway/oauth)
    ///
    /// # Errors
    ///
    /// Returns an error if the home directory cannot be determined or the
    /// storage directory cannot be created.
    pub fn default_location() -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::Internal("Cannot determine home directory".to_string()))?;

        Self::new(home.join(".mcp-gateway").join("oauth"))
    }

    /// Generate a storage key for a backend
    fn storage_key(backend_name: &str, resource_url: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(backend_name.as_bytes());
        hasher.update(b":");
        hasher.update(resource_url.as_bytes());
        let hash = hasher.finalize();
        format!("{hash:x}")[..16].to_string()
    }

    /// Get the file path for a backend's tokens
    fn token_path(&self, backend_name: &str, resource_url: &str) -> PathBuf {
        let key = Self::storage_key(backend_name, resource_url);
        self.base_dir.join(format!("{key}_tokens.json"))
    }

    /// Load tokens for a backend
    pub fn load(&self, backend_name: &str, resource_url: &str) -> Option<TokenInfo> {
        let path = self.token_path(backend_name, resource_url);

        if !path.exists() {
            debug!(backend = %backend_name, "No stored tokens found");
            return None;
        }

        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<TokenInfo>(&content) {
                Ok(token) => {
                    if token.is_expired() {
                        debug!(backend = %backend_name, "Stored token is expired");
                        // Keep the token info in case we can refresh it
                        Some(token)
                    } else {
                        info!(backend = %backend_name, expires_in = ?token.time_until_expiry(), "Loaded valid token");
                        Some(token)
                    }
                }
                Err(e) => {
                    warn!(backend = %backend_name, error = %e, "Failed to parse stored token");
                    None
                }
            },
            Err(e) => {
                warn!(backend = %backend_name, error = %e, "Failed to read token file");
                None
            }
        }
    }

    /// Save tokens for a backend
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be serialized or written to disk.
    pub fn save(&self, backend_name: &str, resource_url: &str, token: &TokenInfo) -> Result<()> {
        let path = self.token_path(backend_name, resource_url);

        let content = serde_json::to_string_pretty(token)
            .map_err(|e| Error::Internal(format!("Failed to serialize token: {e}")))?;

        fs::write(&path, content)
            .map_err(|e| Error::Internal(format!("Failed to write token file: {e}")))?;

        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(&path, perms);
        }

        info!(backend = %backend_name, "Saved OAuth token");
        Ok(())
    }

    /// Delete tokens for a backend
    ///
    /// # Errors
    ///
    /// Returns an error if the token file exists but cannot be deleted.
    pub fn delete(&self, backend_name: &str, resource_url: &str) -> Result<()> {
        let path = self.token_path(backend_name, resource_url);

        if path.exists() {
            fs::remove_file(&path)
                .map_err(|e| Error::Internal(format!("Failed to delete token file: {e}")))?;
            info!(backend = %backend_name, "Deleted OAuth token");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TokenInfo::from_response
    // =========================================================================

    #[test]
    fn test_token_expiry() {
        // Token that expires in 1 hour
        let token =
            TokenInfo::from_response("test_token".to_string(), None, None, Some(3600), None);
        assert!(!token.is_expired());

        // Token that expired
        let mut expired = token.clone();
        expired.expires_at = Some(0);
        assert!(expired.is_expired());
    }

    #[test]
    fn test_token_no_expiry() {
        let token = TokenInfo::from_response("test_token".to_string(), None, None, None, None);
        assert!(!token.is_expired());
    }

    #[test]
    fn from_response_sets_default_token_type() {
        let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
        assert_eq!(token.token_type, "Bearer");
    }

    #[test]
    fn from_response_preserves_custom_token_type() {
        let token = TokenInfo::from_response(
            "tok".to_string(),
            Some("MAC".to_string()),
            None,
            None,
            None,
        );
        assert_eq!(token.token_type, "MAC");
    }

    #[test]
    fn from_response_stores_refresh_token() {
        let token = TokenInfo::from_response(
            "access".to_string(),
            None,
            Some("refresh_123".to_string()),
            None,
            None,
        );
        assert_eq!(token.refresh_token, Some("refresh_123".to_string()));
    }

    #[test]
    fn from_response_calculates_expiry() {
        let token = TokenInfo::from_response("tok".to_string(), None, None, Some(3600), None);
        assert!(token.expires_at.is_some());
        // Should be roughly now + 3600
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let diff = token.expires_at.unwrap() - now;
        assert!((3598..=3602).contains(&diff)); // allow 2 sec slack
    }

    #[test]
    fn from_response_no_expiry_when_none() {
        let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
        assert!(token.expires_at.is_none());
    }

    #[test]
    fn from_response_stores_scope() {
        let token = TokenInfo::from_response(
            "tok".to_string(),
            None,
            None,
            None,
            Some("read write".to_string()),
        );
        assert_eq!(token.scope, Some("read write".to_string()));
    }

    // =========================================================================
    // TokenInfo::is_expired
    // =========================================================================

    #[test]
    fn is_expired_with_60_second_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Token that "expires" in 30 seconds - within 60s buffer, so treated as expired
        let token = TokenInfo {
            access_token: "tok".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_at: Some(now + 30),
            scope: None,
        };
        assert!(token.is_expired());
    }

    #[test]
    fn is_not_expired_beyond_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Token expires in 120 seconds - well beyond 60s buffer
        let token = TokenInfo {
            access_token: "tok".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_at: Some(now + 120),
            scope: None,
        };
        assert!(!token.is_expired());
    }

    // =========================================================================
    // TokenInfo::time_until_expiry
    // =========================================================================

    #[test]
    fn time_until_expiry_future_token() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = TokenInfo {
            access_token: "tok".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_at: Some(now + 3600),
            scope: None,
        };
        let ttl = token.time_until_expiry().unwrap();
        assert!(ttl.as_secs() >= 3598 && ttl.as_secs() <= 3601);
    }

    #[test]
    fn time_until_expiry_expired_token() {
        let token = TokenInfo {
            access_token: "tok".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_at: Some(0), // long expired
            scope: None,
        };
        assert!(token.time_until_expiry().is_none());
    }

    #[test]
    fn time_until_expiry_no_expiry() {
        let token = TokenInfo {
            access_token: "tok".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_at: None,
            scope: None,
        };
        assert!(token.time_until_expiry().is_none());
    }

    // =========================================================================
    // TokenInfo serialization roundtrip
    // =========================================================================

    #[test]
    fn token_info_serialization_roundtrip() {
        let original = TokenInfo::from_response(
            "access_token_xyz".to_string(),
            Some("Bearer".to_string()),
            Some("refresh_abc".to_string()),
            Some(7200),
            Some("read write".to_string()),
        );
        let json = serde_json::to_string(&original).unwrap();
        let restored: TokenInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.access_token, original.access_token);
        assert_eq!(restored.token_type, original.token_type);
        assert_eq!(restored.refresh_token, original.refresh_token);
        assert_eq!(restored.expires_at, original.expires_at);
        assert_eq!(restored.scope, original.scope);
    }

    // =========================================================================
    // TokenStorage - storage_key
    // =========================================================================

    #[test]
    fn storage_key_is_deterministic() {
        let k1 = TokenStorage::storage_key("backend1", "http://localhost");
        let k2 = TokenStorage::storage_key("backend1", "http://localhost");
        assert_eq!(k1, k2);
    }

    #[test]
    fn storage_key_differs_for_different_inputs() {
        let k1 = TokenStorage::storage_key("backend1", "http://localhost");
        let k2 = TokenStorage::storage_key("backend2", "http://localhost");
        let k3 = TokenStorage::storage_key("backend1", "http://other");
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn storage_key_has_expected_length() {
        let key = TokenStorage::storage_key("test", "http://example.com");
        assert_eq!(key.len(), 16); // first 16 hex chars of SHA256
    }

    // =========================================================================
    // TokenStorage - save/load/delete roundtrip
    // =========================================================================

    #[test]
    fn storage_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();

        let token = TokenInfo::from_response(
            "my_access_token".to_string(),
            Some("Bearer".to_string()),
            Some("my_refresh".to_string()),
            Some(3600),
            Some("read".to_string()),
        );

        storage.save("mybackend", "http://localhost:8080", &token).unwrap();

        let loaded = storage.load("mybackend", "http://localhost:8080").unwrap();
        assert_eq!(loaded.access_token, "my_access_token");
        assert_eq!(loaded.refresh_token, Some("my_refresh".to_string()));
    }

    #[test]
    fn storage_load_nonexistent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
        assert!(storage.load("nonexistent", "http://localhost").is_none());
    }

    #[test]
    fn storage_delete_removes_token() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();

        let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
        storage.save("backend", "http://localhost", &token).unwrap();
        assert!(storage.load("backend", "http://localhost").is_some());

        storage.delete("backend", "http://localhost").unwrap();
        assert!(storage.load("backend", "http://localhost").is_none());
    }

    #[test]
    fn storage_delete_nonexistent_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
        // Should not error when deleting non-existent token
        storage.delete("no_such_backend", "http://localhost").unwrap();
    }

    #[test]
    fn storage_overwrite_updates_token() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();

        let token1 = TokenInfo::from_response("token_v1".to_string(), None, None, None, None);
        storage.save("backend", "http://localhost", &token1).unwrap();

        let token2 = TokenInfo::from_response("token_v2".to_string(), None, None, None, None);
        storage.save("backend", "http://localhost", &token2).unwrap();

        let loaded = storage.load("backend", "http://localhost").unwrap();
        assert_eq!(loaded.access_token, "token_v2");
    }

    #[test]
    fn storage_creates_directory_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("deeply").join("nested").join("oauth");
        let storage = TokenStorage::new(nested).unwrap();

        let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
        storage.save("b", "http://localhost", &token).unwrap();
        assert!(storage.load("b", "http://localhost").is_some());
    }
}
