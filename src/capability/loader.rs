//! Capability directory loader

use super::{
    CapabilityDefinition, IssueSeverity, parse_capability_file, validate_capability,
    validate_capability_definition,
};
use crate::{Error, Result};
use std::path::Path;
use tracing::{debug, info, warn};

/// Loader for capability definitions from directories
pub struct CapabilityLoader;

impl CapabilityLoader {
    /// Load all capabilities from a directory (recursive)
    ///
    /// # Errors
    ///
    /// Returns an error if the directory does not exist or is not a valid directory.
    pub async fn load_directory(path: &str) -> Result<Vec<CapabilityDefinition>> {
        let path = Path::new(path);

        if !path.exists() {
            return Err(Error::Config(format!(
                "Capabilities directory does not exist: {}", path.display()
            )));
        }

        if !path.is_dir() {
            return Err(Error::Config(format!(
                "Capabilities path is not a directory: {}", path.display()
            )));
        }

        let mut capabilities = Vec::new();
        Self::load_directory_recursive(path, &mut capabilities).await?;

        info!(
            count = capabilities.len(),
            path = %path.display(),
            "Loaded capabilities"
        );

        Ok(capabilities)
    }

    /// Recursively load capabilities from a directory
    async fn load_directory_recursive(
        dir: &Path,
        capabilities: &mut Vec<CapabilityDefinition>,
    ) -> Result<()> {
        let mut entries = tokio::fs::read_dir(dir)
            .await
            .map_err(|e| Error::Config(format!("Failed to read directory {}: {e}", dir.display())))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| Error::Config(format!("Failed to read directory entry: {e}")))?
        {
            let path = entry.path();

            // Skip hidden files/directories
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
                continue;
            }

            if path.is_dir() {
                // Recurse into subdirectories
                Box::pin(Self::load_directory_recursive(&path, capabilities)).await?;
            } else if path
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                // Load YAML files
                match Self::load_capability_file(&path).await {
                    Ok(cap) => {
                        debug!(name = %cap.name, path = %path.display(), "Loaded capability");
                        capabilities.push(cap);
                    }
                    Err(e) => {
                        warn!(error = %e, path = %path.display(), "Failed to load capability");
                    }
                }
            }
        }

        Ok(())
    }

    /// Load and validate a single capability file.
    ///
    /// Runs both the legacy `validate_capability` check and the structural
    /// validator.  Structural errors cause the capability to be skipped (this
    /// function returns `Err`); structural warnings are logged but the capability
    /// is still loaded.
    async fn load_capability_file(path: &Path) -> Result<CapabilityDefinition> {
        let capability = parse_capability_file(path).await?;
        validate_capability(&capability)?;

        let path_str = path.to_string_lossy();
        let issues = validate_capability_definition(&capability, Some(&path_str));

        let has_errors = issues.iter().any(|i| i.severity == IssueSeverity::Error);

        for issue in &issues {
            if issue.severity == IssueSeverity::Error {
                warn!(
                    code = issue.code,
                    field = ?issue.field,
                    path = %path_str,
                    "Structural validation error: {}",
                    issue.message,
                );
            } else {
                warn!(
                    code = issue.code,
                    field = ?issue.field,
                    path = %path_str,
                    "Structural validation warning: {}",
                    issue.message,
                );
            }
        }

        if has_errors {
            return Err(Error::Config(format!(
                "Capability '{}' has {} structural error(s); skipping",
                path_str,
                issues.iter().filter(|i| i.severity == IssueSeverity::Error).count(),
            )));
        }

        Ok(capability)
    }

    /// Load capabilities from multiple directories
    ///
    /// # Errors
    ///
    /// Returns an error only if all directories fail to load. Individual failures are logged as warnings.
    pub async fn load_directories(paths: &[&str]) -> Result<Vec<CapabilityDefinition>> {
        let mut all_capabilities = Vec::new();

        for path in paths {
            match Self::load_directory(path).await {
                Ok(caps) => all_capabilities.extend(caps),
                Err(e) => {
                    warn!(error = %e, path = %path, "Failed to load capabilities directory");
                }
            }
        }

        Ok(all_capabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_load_directory() {
        let temp_dir = TempDir::new().unwrap();

        // Create a test capability file
        let cap_path = temp_dir.path().join("test_cap.yaml");
        let mut file = std::fs::File::create(&cap_path).unwrap();
        writeln!(
            file,
            r"
name: test_capability
description: A test capability
providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /test
"
        )
        .unwrap();

        let capabilities = CapabilityLoader::load_directory(temp_dir.path().to_str().unwrap())
            .await
            .unwrap();

        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].name, "test_capability");
    }

    #[tokio::test]
    async fn test_load_nested_directories() {
        let temp_dir = TempDir::new().unwrap();

        // Create nested structure
        let subdir = temp_dir.path().join("google");
        std::fs::create_dir(&subdir).unwrap();

        let cap_path = subdir.join("gmail.yaml");
        let mut file = std::fs::File::create(&cap_path).unwrap();
        writeln!(
            file,
            r"
name: gmail_test
description: Gmail test
providers:
  primary:
    service: rest
    config:
      base_url: https://gmail.googleapis.com
"
        )
        .unwrap();

        let capabilities = CapabilityLoader::load_directory(temp_dir.path().to_str().unwrap())
            .await
            .unwrap();

        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].name, "gmail_test");
    }
}
