// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Secret resolution with keychain integration
//!
//! Resolves credential patterns like `{keychain.SERVICE}` and `{env.VAR}`
//! from secure system keychains and environment variables.

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

use dashmap::DashMap;

use crate::{Error, Result};

/// A `{name}` placeholder: `{keychain.X}`, `{env.X}`, or a caller parameter.
#[allow(clippy::unwrap_used)] // a constant pattern
static PLACEHOLDER: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"\{([^{}]*)\}").unwrap());

/// Replace every `{name}` in `value` for which `fill` returns `Some(text)`;
/// `None` leaves the placeholder as written.
///
/// One scan of `value`: substituted text is never looked at again, so a value
/// holding `{other}` arrives byte for byte (MIK-7888).
///
/// # Errors
///
/// The first error `fill` returns.
pub(crate) fn fill_placeholders(
    value: &str,
    mut fill: impl FnMut(&str) -> Result<Option<String>>,
) -> Result<String> {
    let mut out = String::with_capacity(value.len());
    let mut copied_to = 0;
    for caps in PLACEHOLDER.captures_iter(value) {
        let (Some(whole), Some(name)) = (caps.get(0), caps.get(1)) else {
            continue;
        };
        if let Some(text) = fill(name.as_str())? {
            out.push_str(&value[copied_to..whole.start()]);
            out.push_str(&text);
            copied_to = whole.end();
        }
    }
    out.push_str(&value[copied_to..]);
    Ok(out)
}

/// Secret resolver with caching
pub struct SecretResolver {
    /// Cached resolved secrets for the session
    cache: DashMap<String, String>,
    /// Where `{env.VAR}` is looked up. The default overlay assigns nothing, so
    /// lookups fall through to the process environment.
    env: std::sync::Arc<crate::config::LiveEnv>,
}

impl SecretResolver {
    /// Create a new secret resolver
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
            env: std::sync::Arc::new(crate::config::LiveEnv::default()),
        }
    }

    /// Resolve `{env.VAR}` against `env` instead of the process environment.
    ///
    /// Env files are loaded into an in-memory overlay rather than into the
    /// process environment, so a resolver that only reads `std::env` cannot see
    /// a variable an env file assigns.
    #[must_use]
    pub fn with_env(mut self, env: std::sync::Arc<crate::config::LiveEnv>) -> Self {
        self.env = env;
        self
    }

    /// Resolve a value containing secret patterns
    ///
    /// Supports:
    /// - `{keychain.SERVICE}` - macOS Keychain or Linux secret-tool
    /// - `{env.VAR}` - Environment variable
    ///
    /// One pass over `value`: a resolved secret is data and is never scanned
    /// for another reference.
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
    pub fn resolve(&self, value: &str) -> Result<String> {
        self.resolve_with(value, &|_| None)
    }

    /// [`Self::resolve`], also handing every other `{name}` to `other`: its
    /// `Some(text)` replaces the placeholder, `None` leaves it in place.
    ///
    /// One scan of `value` does all of it, so no substituted text (a secret or
    /// an `other` value) is looked at again; a secret that contains `{q}`
    /// reaches the caller of this function byte for byte.
    ///
    /// # Errors
    ///
    /// As [`Self::resolve`].
    pub fn resolve_with(
        &self,
        value: &str,
        other: &dyn Fn(&str) -> Option<String>,
    ) -> Result<String> {
        // One snapshot for the whole value: a reload between two placeholders
        // would otherwise splice a pre-reload half onto a post-reload half and
        // produce a credential that never existed in either generation.
        let env = self.env.get();
        fill_placeholders(value, |name| {
            if let Some(service) = name.strip_prefix("keychain.")
                && !service.is_empty()
            {
                self.keychain_secret(service).map(Some)
            } else if let Some(var_name) = name.strip_prefix("env.")
                && !var_name.is_empty()
            {
                Self::env_secret(&env, var_name).map(Some)
            } else {
                Ok(other(name))
            }
        })
    }

    /// A keychain entry, from the session cache when it was read before.
    fn keychain_secret(&self, service: &str) -> Result<String> {
        if let Some(cached) = self.cache.get(service) {
            return Ok(cached.clone());
        }
        let secret = Self::fetch_from_keychain(service)?;
        self.cache.insert(service.to_string(), secret.clone());
        Ok(secret)
    }

    /// An environment variable, read from the snapshot `env`.
    fn env_secret(env: &crate::config::EnvOverlay, var_name: &str) -> Result<String> {
        // `{env.X:-}` allows empty on purpose, as `${VAR:-}` does in config.
        if let Some(name) = var_name.strip_suffix(":-") {
            return Ok(env.resolve(name).unwrap_or_default());
        }
        // Empty is refused like unset, as `SecretRef::resolve` does (C4).
        env.resolve(var_name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Error::Config(format!(
                    "{{env.{var_name}}} is not set or is empty{}",
                    env.absent_files_hint()
                ))
            })
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
            .map_err(|e| Error::Config(format!("Failed to access macOS Keychain: {e}")))?;

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
        let path = std::env::var("PATH").expect("PATH is set");
        assert!(!path.is_empty());
        assert_eq!(result, format!("Path: {path}"));
    }

    #[test]
    fn test_resolve_multiple_patterns() {
        // The home variable and PATH, which every platform sets; Windows names
        // the home `USERPROFILE` and leaves `HOME` unset.
        let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let resolver = SecretResolver::new();
        let result = resolver
            .resolve(&format!("Home: {{env.{home_var}}}, Path: {{env.PATH}}"))
            .unwrap();
        let home = std::env::var(home_var).expect("home is set");
        let path = std::env::var("PATH").expect("PATH is set");
        assert_eq!(result, format!("Home: {home}, Path: {path}"));
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
        // C4: an unset variable is an error, never an empty credential.
        assert!(resolver.resolve("Value: {env.NONEXISTENT_VAR}").is_err());
    }

    #[test]
    fn resolve_reads_a_variable_the_env_overlay_assigns() {
        // Env files load into an overlay rather than into the process
        // environment, so a resolver reading only `std::env` cannot see them.
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env");
        crate::gateway::test_helpers::write_owner_only(
            &env_file,
            "SECRETS_OVERLAY_ONLY=from-the-overlay\n",
        )
        .unwrap();
        let overlay = crate::config::EnvOverlay::from_paths(&[env_file]);
        let env = std::sync::Arc::new(crate::config::LiveEnv::new(
            std::sync::Arc::new(overlay),
            crate::config::ResolvedEnvFiles::default(),
        ));

        let resolver = SecretResolver::new().with_env(env);
        let result = resolver
            .resolve("Value: {env.SECRETS_OVERLAY_ONLY}")
            .unwrap();

        assert_eq!(result, "Value: from-the-overlay");
        assert!(std::env::var("SECRETS_OVERLAY_ONLY").is_err());
    }

    // macOS-only (W-L9): exercises the macOS keychain pattern.
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
        // One unset variable fails the whole value (C4).
        assert!(
            resolver
                .resolve("Path: {env.PATH}, Missing: {env.NONEXISTENT_VAR_12345}")
                .is_err()
        );
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
        let result = resolver.resolve("{env.PATH} and {env.PATH} again").unwrap();

        // Should replace both occurrences
        assert!(!result.contains("{env.PATH}"));
    }
}

#[cfg(test)]
mod c4_tests {
    use super::*;

    #[test]
    fn env_template_unset_errors() {
        let err = SecretResolver::new()
            .resolve("Bearer {env.MCP_GW_C4_NOPE}")
            .expect_err("an unset {env.X} must not become an empty credential");
        assert!(err.to_string().contains("MCP_GW_C4_NOPE"), "got: {err}");
    }

    #[test]
    fn env_template_empty_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c4.env");
        crate::gateway::test_helpers::write_owner_only(&path, "MCP_GW_C4_BLANK_TPL=\n")
            .expect("write");
        let overlay = crate::config::EnvOverlay::from_paths(&[path]);
        let env = std::sync::Arc::new(crate::config::LiveEnv::new(
            std::sync::Arc::new(overlay),
            crate::config::ResolvedEnvFiles::default(),
        ));
        let err = SecretResolver::new()
            .with_env(env)
            .resolve("Bearer {env.MCP_GW_C4_BLANK_TPL}")
            .expect_err("an empty {env.X} must not become an empty credential");
        assert!(
            err.to_string().contains("MCP_GW_C4_BLANK_TPL"),
            "got: {err}"
        );
        // `{env.X:-}` is the explicit escape, as `${VAR:-}` is for config.
        assert_eq!(
            SecretResolver::new()
                .resolve("a{env.MCP_GW_C4_UNSET_TPL:-}b")
                .expect("explicit empty"),
            "ab"
        );
    }
}
