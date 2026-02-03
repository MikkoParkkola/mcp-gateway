//! YAML capability parser

use super::CapabilityDefinition;
use crate::{Error, Result};

/// Parse a capability definition from YAML content
pub fn parse_capability(content: &str) -> Result<CapabilityDefinition> {
    serde_yaml::from_str(content).map_err(|e| Error::Config(format!("Failed to parse capability YAML: {}", e)))
}

/// Parse a capability definition from a file
pub async fn parse_capability_file(path: &std::path::Path) -> Result<CapabilityDefinition> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| Error::Config(format!("Failed to read capability file {:?}: {}", path, e)))?;

    let mut capability = parse_capability(&content)?;

    // Use filename as name if not specified
    if capability.name.is_empty() {
        if let Some(stem) = path.file_stem() {
            capability.name = stem.to_string_lossy().to_string();
        }
    }

    Ok(capability)
}

/// Validate a capability definition
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

    // Validate auth config doesn't contain actual secrets
    validate_no_secrets(&capability.auth)?;

    Ok(())
}

/// Ensure auth config doesn't contain actual secrets
fn validate_no_secrets(auth: &super::AuthConfig) -> Result<()> {
    // Check that key references are properly formatted
    if !auth.key.is_empty() {
        let valid_prefixes = ["keychain:", "env:", "oauth:", "{env."];
        let is_reference = valid_prefixes.iter().any(|p| auth.key.starts_with(p));

        // Check if it looks like a bare environment variable name (UPPERCASE_WITH_UNDERSCORES)
        let looks_like_env_var = !auth.key.is_empty()
            && auth.key.chars().next().map_or(false, |c| c.is_ascii_uppercase())
            && auth.key.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');

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
        let yaml = r#"
name: test_capability
description: A test capability
providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /test
"#;

        let cap = parse_capability(yaml).unwrap();
        assert_eq!(cap.name, "test_capability");
        assert_eq!(cap.description, "A test capability");
    }

    #[test]
    fn test_validate_missing_name() {
        let yaml = r#"
description: No name
providers:
  primary:
    service: rest
"#;

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

        // Raw secret (should fail)
        let auth = AuthConfig {
            key: "sk-1234567890abcdefghijklmnop".to_string(),
            ..Default::default()
        };
        assert!(validate_no_secrets(&auth).is_err());
    }
}
