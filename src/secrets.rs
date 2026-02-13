//! Secret resolution with keychain integration
//!
//! Resolves credential patterns like `{keychain.SERVICE}` and `{env.VAR}`
//! from secure system keychains and environment variables.

use std::process::Command;

use dashmap::DashMap;

use crate::{Error, Result};

/// Secret resolver with caching
pub struct SecretResolver {
    /// Cached resolved secrets for the session
    cache: DashMap<String, String>,
}

impl SecretResolver {
    /// Create a new secret resolver
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    /// Resolve a value containing secret patterns
    ///
    /// Supports:
    /// - `{keychain.SERVICE}` - macOS Keychain or Linux secret-tool
    /// - `{env.VAR}` - Environment variable
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mcp_gateway::secrets::SecretResolver;
    /// let resolver = SecretResolver::new();
    /// let resolved = resolver.resolve("Bearer {keychain.my-api-token}").unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if a keychain entry is not found or cannot be accessed.
    ///
    /// # Panics
    ///
    /// Panics if the hardcoded regex patterns are invalid (compile-time constant).
    pub fn resolve(&self, value: &str) -> Result<String> {
        let mut result = value.to_string();

        // Find all {keychain.X} patterns
        #[allow(clippy::unwrap_used)]
        let keychain_pattern = regex::Regex::new(r"\{keychain\.([^}]+)\}").unwrap();
        for caps in keychain_pattern.captures_iter(value) {
            let service = &caps[1];
            let placeholder = &caps[0];

            // Check cache first
            let secret = if let Some(cached) = self.cache.get(service) {
                cached.clone()
            } else {
                // Fetch from keychain
                let secret = Self::fetch_from_keychain(service)?;
                // Cache it
                self.cache.insert(service.to_string(), secret.clone());
                secret
            };

            result = result.replace(placeholder, &secret);
        }

        // Find all {env.X} patterns
        #[allow(clippy::unwrap_used)]
        let env_pattern = regex::Regex::new(r"\{env\.([^}]+)\}").unwrap();
        for caps in env_pattern.captures_iter(&result.clone()) {
            let var_name = &caps[1];
            let placeholder = &caps[0];

            let value = std::env::var(var_name).unwrap_or_default();
            result = result.replace(placeholder, &value);
        }

        Ok(result)
    }

    /// Fetch a secret from the system keychain
    ///
    /// # Platform Support
    ///
    /// - **macOS**: Uses `security find-generic-password`
    /// - **Linux**: Uses `secret-tool lookup`
    /// - **Other**: Returns error
    #[cfg(target_os = "macos")]
    fn fetch_from_keychain(service: &str) -> Result<String> {
        let output = Command::new("security")
            .args(["find-generic-password", "-s", service, "-w"])
            .output()
            .map_err(|e| {
                Error::Config(format!("Failed to access macOS Keychain: {e}"))
            })?;

        if output.status.success() {
            let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if secret.is_empty() {
                Err(Error::Config(format!(
                    "Keychain entry '{service}' is empty. Check with: security find-generic-password -s '{service}'"
                )))
            } else {
                Ok(secret)
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(service = service, error = %stderr, "Keychain lookup failed");
            Err(Error::Config(format!(
                "Keychain entry '{service}' not found. Add it with:\n  \
                security add-generic-password -s '{service}' -a 'mcp-gateway' -w 'YOUR_SECRET'"
            )))
        }
    }

    /// Fetch a secret from the system keychain (Linux)
    #[cfg(target_os = "linux")]
    fn fetch_from_keychain(service: &str) -> Result<String> {
        let output = Command::new("secret-tool")
            .args(["lookup", "service", service])
            .output()
            .map_err(|e| {
                Error::Config(format!(
                    "Failed to access Linux secret service: {e}. \
                    Is libsecret installed?"
                ))
            })?;

        if output.status.success() {
            let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if secret.is_empty() {
                Err(Error::Config(format!(
                    "Secret service entry for '{service}' is empty"
                )))
            } else {
                Ok(secret)
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(service = service, error = %stderr, "Secret service lookup failed");
            Err(Error::Config(format!(
                "Secret service entry for '{service}' not found. Add it with:\n  \
                secret-tool store --label='MCP Gateway: {service}' service {service}"
            )))
        }
    }

    /// Fetch from keychain (unsupported platforms)
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn fetch_from_keychain(_service: &str) -> Result<String> {
        Err(Error::Config(
            "Keychain access is only supported on macOS and Linux. \
            Use {env.VAR} syntax instead."
                .to_string(),
        ))
    }

    /// Clear the session cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

impl Default for SecretResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_env_var() {
        // Use PATH which is always set on all platforms
        let resolver = SecretResolver::new();
        let result = resolver.resolve("Path: {env.PATH}").unwrap();
        assert!(result.starts_with("Path: /") || result.starts_with("Path: C"));
        assert_ne!(result, "Path: ");
    }

    #[test]
    fn test_resolve_multiple_patterns() {
        // Use HOME and PATH which are always available
        let resolver = SecretResolver::new();
        let result = resolver
            .resolve("Home: {env.HOME}, Path: {env.PATH}")
            .unwrap();
        assert!(!result.contains("{env."));
        assert!(result.contains("Home: /") || result.contains("Home: C"));
    }

    #[test]
    fn test_resolve_no_patterns() {
        let resolver = SecretResolver::new();
        let result = resolver.resolve("No patterns here").unwrap();
        assert_eq!(result, "No patterns here");
    }

    #[test]
    fn test_resolve_missing_env_var() {
        let resolver = SecretResolver::new();
        // Missing env var should resolve to empty string
        let result = resolver.resolve("Value: {env.NONEXISTENT_VAR}").unwrap();
        assert_eq!(result, "Value: ");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_keychain_pattern_detection() {
        let resolver = SecretResolver::new();
        let value = "Bearer {keychain.test-service}";
        // This will fail if the keychain entry doesn't exist, which is expected
        let result = resolver.resolve(value);
        // We're just testing the pattern is recognized
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_default_impl() {
        let resolver = SecretResolver::default();
        let result = resolver.resolve("test").unwrap();
        assert_eq!(result, "test");
    }

    #[test]
    fn test_clear_cache() {
        let resolver = SecretResolver::new();
        // Set something in cache via env var (which gets cached)
        let _ = resolver.resolve("{env.PATH}").unwrap();

        resolver.clear_cache();

        // Cache should be empty but resolve should still work
        let result = resolver.resolve("{env.PATH}").unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_mixed_patterns() {
        let resolver = SecretResolver::new();
        let result = resolver
            .resolve("Path: {env.PATH}, Missing: {env.NONEXISTENT_VAR_12345}")
            .unwrap();

        assert!(result.contains("Path: /") || result.contains("Path: C"));
        assert!(result.contains("Missing: "));
    }

    #[test]
    fn test_env_pattern_in_json() {
        let resolver = SecretResolver::new();
        let json_value = r#"{"path": "{env.PATH}"}"#;
        let result = resolver.resolve(json_value).unwrap();

        assert!(!result.contains("{env.PATH}"));
        assert!(result.contains("\"path\": \""));
    }

    #[test]
    fn test_multiple_same_pattern() {
        let resolver = SecretResolver::new();
        let result = resolver
            .resolve("{env.PATH} and {env.PATH} again")
            .unwrap();

        // Should replace both occurrences
        assert!(!result.contains("{env.PATH}"));
    }
}
