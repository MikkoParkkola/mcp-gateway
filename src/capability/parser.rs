//! YAML capability parser

use super::CapabilityDefinition;
use super::hash::compute_capability_hash;
use crate::{Error, Result};
use tracing::info;

/// Parse a capability definition from YAML content
///
/// # Errors
///
/// Returns an error if the YAML content cannot be parsed into a capability definition.
pub fn parse_capability(content: &str) -> Result<CapabilityDefinition> {
    serde_yaml::from_str(content)
        .map_err(|e| Error::Config(format!("Failed to parse capability YAML: {e}")))
}

/// Parse a capability definition from a file.
///
/// Verifies the optional `sha256:` pin as a rug-pull guard: if the file
/// embeds a pin, a mismatch returns [`Error::CapabilityHashMismatch`] and the
/// capability is refused. Files without a pin are loaded, and the computed
/// hash is logged at INFO so operators can add `sha256:` to pin them.
///
/// # Errors
///
/// Returns an error if the file cannot be read, is not valid YAML, or its
/// embedded `sha256:` pin does not match the current file contents.
pub async fn parse_capability_file(path: &std::path::Path) -> Result<CapabilityDefinition> {
    let content = tokio::fs::read_to_string(path).await.map_err(|e| {
        Error::Config(format!(
            "Failed to read capability file {}: {e}",
            path.display()
        ))
    })?;

    let mut capability = parse_capability(&content)?;

    // ── Rug-pull guard: SHA-256 pin verification ────────────────────────────
    //
    // Computed over the raw file content with the top-level `sha256:` line
    // stripped, so pinning is stable across `cap pin` rewrites.
    let actual_hash = compute_capability_hash(&content);
    match capability.sha256.as_deref() {
        Some(expected) if !expected.eq_ignore_ascii_case(&actual_hash) => {
            return Err(Error::CapabilityHashMismatch {
                expected: expected.to_string(),
                actual: actual_hash,
                file: path.display().to_string(),
            });
        }
        Some(_) => {
            // Pin verified — nothing to log at load time. Loader reports.
        }
        None => {
            info!(
                path = %path.display(),
                sha256 = %actual_hash,
                "unpinned capability loaded, compute hash: {actual_hash} — add `sha256: {actual_hash}` to pin",
            );
        }
    }

    // Use filename as name if not specified
    if capability.name.is_empty()
        && let Some(stem) = path.file_stem()
    {
        capability.name = stem.to_string_lossy().to_string();
    }

    Ok(capability)
}

/// Validate a capability definition
///
/// # Errors
///
/// Returns an error if the capability definition is invalid (missing name, no providers, etc.).
pub fn validate_capability(capability: &CapabilityDefinition) -> Result<()> {
    // Name is required
    if capability.name.is_empty() {
        return Err(Error::Config("Capability name is required".to_string()));
    }

    // Name must be valid identifier
    if !capability
        .name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_')
    {
        return Err(Error::Config(format!(
            "Capability name '{}' must contain only alphanumeric characters and underscores",
            capability.name
        )));
    }

    // Webhook-only capabilities don't need providers
    let is_webhook_only = !capability.webhooks.is_empty() && capability.providers.is_empty();

    if !is_webhook_only {
        // Must have at least one provider
        if capability.providers.is_empty() {
            return Err(Error::Config(format!(
                "Capability '{}' must have at least one provider",
                capability.name
            )));
        }

        // Primary provider should exist
        if !capability.providers.contains_key("primary") {
            return Err(Error::Config(format!(
                "Capability '{}' should have a 'primary' provider",
                capability.name
            )));
        }
    }

    // Validate auth config doesn't contain actual secrets
    validate_no_secrets(&capability.auth)?;

    Ok(())
}

/// Ensure auth config doesn't contain actual secrets
fn validate_no_secrets(auth: &super::AuthConfig) -> Result<()> {
    // Check that key references are properly formatted
    if !auth.key.is_empty() {
        let valid_prefixes = ["keychain:", "env:", "oauth:", "file:", "{env."];
        let is_reference = valid_prefixes.iter().any(|p| auth.key.starts_with(p));

        // Check if it looks like a bare environment variable name (UPPERCASE_WITH_UNDERSCORES)
        let looks_like_env_var = !auth.key.is_empty()
            && auth
                .key
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase())
            && auth
                .key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');

        if !is_reference && !looks_like_env_var && !auth.key.contains('{') {
            // Looks like a raw secret - reject it
            if auth.key.len() > 20 || auth.key.contains("sk-") || auth.key.contains("token") {
                return Err(Error::Config(
                    "Auth key appears to contain a raw secret. Use 'keychain:name', 'env:VAR', or 'oauth:provider' instead.".to_string()
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_capability() {
        let yaml = r"
name: test_capability
description: A test capability
providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /test
";

        let cap = parse_capability(yaml).unwrap();
        assert_eq!(cap.name, "test_capability");
        assert_eq!(cap.description, "A test capability");
    }

    #[test]
    fn test_validate_missing_name() {
        let yaml = r"
description: No name
providers:
  primary:
    service: rest
";

        let cap = parse_capability(yaml).unwrap();
        let result = validate_capability(&cap);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_no_raw_secrets() {
        use super::super::AuthConfig;

        // Valid references
        let auth = AuthConfig {
            key: "keychain:my-api-key".to_string(),
            ..Default::default()
        };
        assert!(validate_no_secrets(&auth).is_ok());

        let auth = AuthConfig {
            key: "env:API_KEY".to_string(),
            ..Default::default()
        };
        assert!(validate_no_secrets(&auth).is_ok());

        let auth = AuthConfig {
            key: "{env.API_KEY}".to_string(),
            ..Default::default()
        };
        assert!(validate_no_secrets(&auth).is_ok());

        // File-based credential
        let auth = AuthConfig {
            key: "file:~/.config/tokens.json:access_token".to_string(),
            ..Default::default()
        };
        assert!(validate_no_secrets(&auth).is_ok());

        // Raw secret (should fail)
        let auth = AuthConfig {
            key: "sk-1234567890abcdefghijklmnop".to_string(),
            ..Default::default()
        };
        assert!(validate_no_secrets(&auth).is_err());
    }

    // ── SHA-256 pin verification (rug-pull guard) ────────────────────────────

    use super::super::hash::{compute_capability_hash, rewrite_with_pin};
    use crate::Error;
    use std::io::Write;
    use tempfile::TempDir;

    const UNPINNED_YAML: &str = "\
name: pinned_cap
description: Pin me
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /test
";

    fn write_capability_file(dir: &TempDir, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        path
    }

    #[tokio::test]
    async fn parse_capability_file_accepts_correct_pin() {
        // GIVEN: a capability file rewritten with its true sha256 pin
        let dir = TempDir::new().unwrap();
        let hash = compute_capability_hash(UNPINNED_YAML);
        let pinned = rewrite_with_pin(UNPINNED_YAML, &hash);
        let path = write_capability_file(&dir, "pinned.yaml", &pinned);
        // WHEN: loading it
        let cap = parse_capability_file(&path).await.unwrap();
        // THEN: the capability parses and the pin survives into the struct
        assert_eq!(cap.name, "pinned_cap");
        assert_eq!(cap.sha256.as_deref(), Some(hash.as_str()));
    }

    #[tokio::test]
    async fn parse_capability_file_rejects_wrong_pin() {
        // GIVEN: a capability file with a bogus sha256 pin
        let dir = TempDir::new().unwrap();
        let fake_hash = "0".repeat(64);
        let tampered = format!("sha256: {fake_hash}\n{UNPINNED_YAML}");
        let path = write_capability_file(&dir, "bad.yaml", &tampered);
        // WHEN: loading it
        let err = parse_capability_file(&path).await.unwrap_err();
        // THEN: CapabilityHashMismatch with the right details
        match err {
            Error::CapabilityHashMismatch {
                expected, actual, ..
            } => {
                assert_eq!(expected, fake_hash);
                assert_eq!(actual, compute_capability_hash(UNPINNED_YAML));
            }
            other => panic!("expected CapabilityHashMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn parse_capability_file_unpinned_loads_successfully() {
        // GIVEN: a capability file with no sha256 pin
        let dir = TempDir::new().unwrap();
        let path = write_capability_file(&dir, "unpinned.yaml", UNPINNED_YAML);
        // WHEN: loading it
        let cap = parse_capability_file(&path).await.unwrap();
        // THEN: it loads with sha256 == None (INFO log about pinning is emitted)
        assert_eq!(cap.name, "pinned_cap");
        assert!(cap.sha256.is_none());
    }

    #[tokio::test]
    async fn parse_capability_file_detects_post_pin_tamper() {
        // GIVEN: a pinned capability whose body is then tampered with
        let dir = TempDir::new().unwrap();
        let hash = compute_capability_hash(UNPINNED_YAML);
        let pinned = rewrite_with_pin(UNPINNED_YAML, &hash);
        // Poison description AFTER pinning
        let poisoned = pinned.replace("Pin me", "Exfiltrate me");
        let path = write_capability_file(&dir, "poisoned.yaml", &poisoned);
        // WHEN: reloading it
        let err = parse_capability_file(&path).await.unwrap_err();
        // THEN: mismatch is detected
        assert!(matches!(err, Error::CapabilityHashMismatch { .. }));
    }
}
