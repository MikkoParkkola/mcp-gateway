//! Credential resolution for capability execution
//!
//! # Security
//!
//! All methods in this module fetch secrets at request time and NEVER log,
//! store, or return credentials in error messages.
//!
//! # Supported Sources
//!
//! - `env:VAR_NAME` - Environment variable
//! - `keychain:name` - macOS Keychain
//! - `oauth:provider` - OAuth token from vault (with auto-refresh)
//! - `file:/path/to/file.json:field` - JSON file with dot-path field extraction
//! - `{env.VAR}` - Template format for environment variables
//! - `VAR_NAME` - Bare uppercase name treated as env var

use serde_json::Value;

use crate::{Error, Result};

use super::CapabilityExecutor;

impl CapabilityExecutor {
    /// Fetch credential from secure storage.
    ///
    /// Supported formats: `env:`, `keychain:`, `oauth:`, `file:`,
    /// `{env.VAR}`, or bare `UPPERCASE_NAME` (implicit env var).
    pub(super) async fn fetch_credential(&self, auth: &super::super::AuthConfig) -> Result<String> {
        let key = &auth.key;

        if let Some(var_name) = key.strip_prefix("env:") {
            // Explicit environment variable
            std::env::var(var_name).map_err(|_| {
                Error::Config(format!(
                    "Environment variable '{}' not set (required for {})",
                    var_name, auth.description
                ))
            })
        } else if let Some(keychain_key) = key.strip_prefix("keychain:") {
            // macOS Keychain
            self.fetch_from_keychain(keychain_key).await
        } else if let Some(provider) = key.strip_prefix("oauth:") {
            // OAuth token from vault
            self.fetch_oauth_token(provider).await
        } else if let Some(file_spec) = key.strip_prefix("file:") {
            // JSON file with field extraction
            self.fetch_from_file(file_spec)
        } else if key.starts_with("{env.") && key.ends_with('}') {
            // Template format: {env.VAR_NAME}
            let var_name = &key[5..key.len() - 1];
            std::env::var(var_name)
                .map_err(|_| Error::Config(format!("Environment variable '{var_name}' not set")))
        } else if key.is_empty() {
            Err(Error::Config("No credential key configured".to_string()))
        } else if Self::looks_like_env_var_name(key) {
            // Bare name like BRAVE_API_KEY is treated as env var
            std::env::var(key).map_err(|_| {
                Error::Config(format!(
                    "Environment variable '{key}' not set. Set it with: export {key}=your_key"
                ))
            })
        } else {
            Err(Error::Config(format!(
                "Unknown credential format: {}. Use env:, keychain:, oauth:, file:, or set environment variable",
                key.chars().take(20).collect::<String>()
            )))
        }
    }

    /// Check if a string looks like an environment variable name.
    ///
    /// Returns `true` when the string contains only uppercase ASCII letters,
    /// digits, and underscores, and starts with an uppercase letter.
    pub(super) fn looks_like_env_var_name(s: &str) -> bool {
        !s.is_empty()
            && s.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && s.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    /// Fetch a credential value from a JSON file.
    ///
    /// Format: `file:/path/to/file.json:field_name`
    ///
    /// Supports:
    /// - `~` expansion to home directory
    /// - Nested fields with dot notation: `file:~/.config/tokens.json:data.access_token`
    /// - String and numeric values
    ///
    /// # Security
    ///
    /// The file should have restrictive permissions (0600).
    /// Credential values are never logged.
    #[allow(clippy::unused_self)]
    pub(super) fn fetch_from_file(&self, spec: &str) -> Result<String> {
        // Split on last colon to separate path from field
        let (path, field) = spec.rsplit_once(':').ok_or_else(|| {
            Error::Config(format!(
                "Invalid file credential format. Expected: file:/path/to/file.json:field_name (got 'file:{}')",
                spec.chars().take(50).collect::<String>()
            ))
        })?;

        if field.is_empty() {
            return Err(Error::Config(
                "Empty field name in file credential. Expected: file:/path/to/file.json:field_name"
                    .to_string(),
            ));
        }

        let expanded_path = expand_home_dir(path)?;

        let content = std::fs::read_to_string(&expanded_path).map_err(|e| {
            Error::Config(format!(
                "Failed to read credential file '{}': {}",
                expanded_path.display(),
                e
            ))
        })?;

        let json: Value = serde_json::from_str(&content).map_err(|e| {
            Error::Config(format!(
                "Failed to parse credential file '{}' as JSON: {}",
                expanded_path.display(),
                e
            ))
        })?;

        extract_json_field(&json, field, &expanded_path)
    }

    /// Fetch an OAuth token from vault.
    ///
    /// # Token Resolution Order
    ///
    /// 1. Check in-memory cache for a valid (non-expired) token
    /// 2. Load from disk storage if available
    /// 3. Return an error with re-auth instructions if not found
    #[allow(clippy::unused_async)]
    pub(super) async fn fetch_oauth_token(&self, provider: &str) -> Result<String> {
        // Check in-memory cache first
        {
            let tokens = self.oauth_tokens.read();
            if let Some(token) = tokens.get(provider) {
                if !token.is_expired() {
                    return Ok(token.access_token.clone());
                }
            }
        }

        // Try to load from disk storage
        if let Some(ref storage) = self.token_storage {
            if let Some(token) = storage.load(provider, provider) {
                if !token.is_expired() {
                    let tokens = self.oauth_tokens.read();
                    tokens.insert(provider.to_string(), token.clone());
                    return Ok(token.access_token);
                }
                return Err(Error::Config(format!(
                    "OAuth token for '{provider}' is expired. Re-authenticate using the gateway OAuth flow or refresh the token."
                )));
            }
        }

        Err(Error::Config(format!(
            "OAuth token for '{provider}' not found. \
            To authorize, use the gateway's OAuth flow: \
            1. Configure an OAuth-enabled backend named '{provider}' in gateway config \
            2. Make a request to trigger authorization \
            3. Complete browser-based authorization \
            Or manually set the token via set_oauth_token()"
        )))
    }

    /// Fetch a credential from macOS Keychain.
    #[cfg(target_os = "macos")]
    #[allow(clippy::unused_async)]
    pub(super) async fn fetch_from_keychain(&self, key: &str) -> Result<String> {
        use std::process::Command;

        let output = Command::new("security")
            .args(["find-generic-password", "-s", key, "-w"])
            .output()
            .map_err(|e| Error::Config(format!("Failed to access keychain: {e}")))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(Error::Config(format!(
                "Keychain entry '{key}' not found. Add it with: security add-generic-password -s '{key}' -a 'mcp-gateway' -w 'YOUR_SECRET'"
            )))
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub(super) async fn fetch_from_keychain(&self, _key: &str) -> Result<String> {
        Err(Error::Config(
            "Keychain access only supported on macOS. Use env: instead.".to_string(),
        ))
    }
}

// ── Private helpers ──────────────────────────────────────────────────────────

/// Expand a leading `~` to the user's home directory.
fn expand_home_dir(path: &str) -> Result<std::path::PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        match dirs::home_dir() {
            Some(home) => Ok(home.join(rest)),
            None => Err(Error::Config(
                "Cannot expand ~ in file credential path: HOME not set".to_string(),
            )),
        }
    } else {
        Ok(std::path::PathBuf::from(path))
    }
}

/// Navigate a JSON value using dot-notation and return the scalar as a `String`.
fn extract_json_field(
    json: &Value,
    field: &str,
    path: &std::path::Path,
) -> Result<String> {
    let mut current = json;
    for segment in field.split('.') {
        current = current.get(segment).ok_or_else(|| {
            Error::Config(format!(
                "Field '{}' not found in credential file '{}'",
                field,
                path.display()
            ))
        })?;
    }

    match current {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(Error::Config(format!(
            "Field '{}' in '{}' must be a string or number, got {}",
            field,
            path.display(),
            match current {
                Value::Bool(_) => "boolean",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
                Value::Null => "null",
                _ => "unknown",
            }
        ))),
    }
}
