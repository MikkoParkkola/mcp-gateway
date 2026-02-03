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
    pub fn from_response(access_token: String, token_type: Option<String>, refresh_token: Option<String>, expires_in: Option<u64>, scope: Option<String>) -> Self {
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
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        // Create directory if it doesn't exist
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir)
                .map_err(|e| Error::Internal(format!("Failed to create token storage dir: {e}")))?;
        }

        Ok(Self { base_dir })
    }

    /// Create token storage in the default location (~/.mcp-gateway/oauth)
    pub fn default_location() -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::Internal("Cannot determine home directory".to_string()))?;

        Self::new(home.join(".mcp-gateway").join("oauth"))
    }

    /// Generate a storage key for a backend
    fn storage_key(&self, backend_name: &str, resource_url: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(backend_name.as_bytes());
        hasher.update(b":");
        hasher.update(resource_url.as_bytes());
        let hash = hasher.finalize();
        format!("{hash:x}")[..16].to_string()
    }

    /// Get the file path for a backend's tokens
    fn token_path(&self, backend_name: &str, resource_url: &str) -> PathBuf {
        let key = self.storage_key(backend_name, resource_url);
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

    #[test]
    fn test_token_expiry() {
        // Token that expires in 1 hour
        let token = TokenInfo::from_response(
            "test_token".to_string(),
            None,
            None,
            Some(3600),
            None,
        );
        assert!(!token.is_expired());

        // Token that expired
        let mut expired = token.clone();
        expired.expires_at = Some(0);
        assert!(expired.is_expired());
    }

    #[test]
    fn test_token_no_expiry() {
        let token = TokenInfo::from_response(
            "test_token".to_string(),
            None,
            None,
            None,
            None,
        );
        assert!(!token.is_expired());
    }
}
