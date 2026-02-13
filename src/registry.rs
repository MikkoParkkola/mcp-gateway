//! Capability registry for community-shared capability definitions
//!
//! Provides discovery and installation of pre-built capability definitions
//! from both local capabilities directory and remote GitHub sources.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::capability::parse_capability_file;
use crate::{Error, Result};

/// Registry entry describing a capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Capability name
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Relative path to capability YAML
    pub path: String,
    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether this capability requires authentication
    #[serde(default)]
    pub requires_key: bool,
}

/// Capability registry index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryIndex {
    /// Registry format version
    pub version: String,
    /// All available capabilities
    pub capabilities: Vec<RegistryEntry>,
}

impl RegistryIndex {
    /// Create a new registry index
    #[must_use]
    pub fn new(capabilities: Vec<RegistryEntry>) -> Self {
        Self {
            version: "2.0".to_string(),
            capabilities,
        }
    }

    /// Search capabilities by name, description, or tags
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&RegistryEntry> {
        let query_lower = query.to_lowercase();
        self.capabilities
            .iter()
            .filter(|entry| {
                entry.name.to_lowercase().contains(&query_lower)
                    || entry.description.to_lowercase().contains(&query_lower)
                    || entry.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    /// Find capability by exact name
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&RegistryEntry> {
        self.capabilities.iter().find(|e| e.name == name)
    }
}

/// Capability registry manager
pub struct Registry {
    /// Path to capabilities directory
    capabilities_path: PathBuf,
}

impl Registry {
    /// Create a new registry manager
    ///
    /// # Arguments
    ///
    /// * `capabilities_path` - Path to the capabilities directory
    #[must_use]
    pub fn new<P: AsRef<Path>>(capabilities_path: P) -> Self {
        Self {
            capabilities_path: capabilities_path.as_ref().to_path_buf(),
        }
    }

    /// Build registry index by scanning capabilities directory
    ///
    /// Recursively scans the capabilities directory for YAML files and builds
    /// a searchable index from their metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read or YAML files cannot be parsed.
    pub async fn build_index(&self) -> Result<RegistryIndex> {
        let mut capabilities = Vec::new();

        // Recursively scan capabilities directory for YAML files
        for entry in WalkDir::new(&self.capabilities_path)
            .follow_links(true)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            let path = entry.path();

            // Only process YAML files
            if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("yaml") {
                continue;
            }

            // Parse capability file
            match parse_capability_file(path).await {
                Ok(capability) => {
                    // Calculate relative path from capabilities directory
                    let relative_path = path
                        .strip_prefix(&self.capabilities_path)
                        .map_err(|e| Error::Config(format!("Failed to calculate relative path: {e}")))?
                        .to_string_lossy()
                        .to_string();

                    // Extract tags from metadata
                    let tags = capability.metadata.tags.clone();

                    // Determine if authentication is required
                    let requires_key = capability.auth.required;

                    capabilities.push(RegistryEntry {
                        name: capability.name,
                        description: capability.description,
                        path: relative_path,
                        tags,
                        requires_key,
                    });
                }
                Err(e) => {
                    eprintln!("Warning: Failed to parse {}: {e}", path.display());
                }
            }
        }

        Ok(RegistryIndex::new(capabilities))
    }

    /// Install a capability from GitHub
    ///
    /// Downloads a capability file from a remote GitHub repository's capabilities/ directory.
    ///
    /// # Arguments
    ///
    /// * `name` - Capability name (must exist in remote repository)
    /// * `repo` - GitHub repository (format: `owner/repo`)
    /// * `branch` - Branch name (default: "main")
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails or the file cannot be written.
    pub async fn install_from_github(
        &self,
        name: &str,
        repo: &str,
        branch: &str,
    ) -> Result<PathBuf> {
        // Build remote index by fetching a listing (we'll try common paths)
        // For now, we'll construct the URL directly based on the capability name
        // A more robust implementation would fetch a directory listing first

        let client = reqwest::Client::new();

        // Try common capability paths
        let search_patterns = vec![
            format!("capabilities/finance/{name}.yaml"),
            format!("capabilities/communication/{name}.yaml"),
            format!("capabilities/knowledge/{name}.yaml"),
            format!("capabilities/search/{name}.yaml"),
            format!("capabilities/utility/{name}.yaml"),
            format!("capabilities/entertainment/{name}.yaml"),
            format!("capabilities/food/{name}.yaml"),
            format!("capabilities/geo/{name}.yaml"),
        ];

        let mut last_error = None;

        for pattern in search_patterns {
            let capability_url = format!(
                "https://raw.githubusercontent.com/{repo}/{branch}/{pattern}"
            );

            match client.get(&capability_url).send().await {
                Ok(response) if response.status().is_success() => {
                    let capability_content = response
                        .text()
                        .await
                        .map_err(|e| Error::Transport(format!("Failed to read capability content: {e}")))?;

                    // Determine subdirectory from pattern
                    let pattern_path = PathBuf::from(&pattern);
                    let subdir = pattern_path
                        .parent()
                        .and_then(|p| p.file_name())
                        .ok_or_else(|| Error::Config("Invalid capability path".to_string()))?;

                    let target_dir = self.capabilities_path.join(subdir);
                    fs::create_dir_all(&target_dir).map_err(|e| {
                        Error::Config(format!("Failed to create target directory: {e}"))
                    })?;

                    let target = target_dir.join(format!("{name}.yaml"));
                    fs::write(&target, capability_content).map_err(|e| {
                        Error::Config(format!("Failed to write capability file: {e}"))
                    })?;

                    return Ok(target);
                }
                Ok(_) => {}
                Err(e) => last_error = Some(e),
            }
        }

        Err(Error::Transport(format!(
            "Capability '{name}' not found in repository {repo}:{branch}. Last error: {}",
            last_error.map_or_else(|| "Not found".to_string(), |e| e.to_string())
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_entry_serialization() {
        let entry = RegistryEntry {
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            path: "utility/test_tool.yaml".to_string(),
            tags: vec!["test".to_string()],
            requires_key: true,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: RegistryEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, "test_tool");
        assert_eq!(deserialized.tags.len(), 1);
    }

    #[test]
    fn test_registry_search() {
        let index = RegistryIndex {
            version: "1.0".to_string(),
            capabilities: vec![
                RegistryEntry {
                    name: "stripe_charges".to_string(),
                    description: "List Stripe charges".to_string(),
                    path: "finance/stripe_charges.yaml".to_string(),
                    tags: vec!["finance".to_string(), "stripe".to_string()],
                    requires_key: true,
                },
                RegistryEntry {
                    name: "gmail_send".to_string(),
                    description: "Send email via Gmail".to_string(),
                    path: "communication/gmail_send.yaml".to_string(),
                    tags: vec!["email".to_string(), "google".to_string()],
                    requires_key: true,
                },
            ],
        };

        let results = index.search("stripe");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "stripe_charges");

        let results = index.search("email");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "gmail_send");

        let results = index.search("finance");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_registry_find_exact() {
        let index = RegistryIndex {
            version: "1.0".to_string(),
            capabilities: vec![
                RegistryEntry {
                    name: "test_tool".to_string(),
                    description: "Test".to_string(),
                    path: "test.yaml".to_string(),
                    tags: vec![],
                    requires_key: false,
                },
            ],
        };

        let result = index.find("test_tool");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "test_tool");

        let missing = index.find("nonexistent");
        assert!(missing.is_none());
    }

    #[test]
    fn test_registry_search_case_insensitive() {
        let index = RegistryIndex {
            version: "1.0".to_string(),
            capabilities: vec![
                RegistryEntry {
                    name: "MyTool".to_string(),
                    description: "Description".to_string(),
                    path: "tool.yaml".to_string(),
                    tags: vec!["TAG".to_string()],
                    requires_key: false,
                },
            ],
        };

        let results = index.search("mytool");
        assert_eq!(results.len(), 1);

        let tag_results = index.search("tag");
        assert_eq!(tag_results.len(), 1);
    }

    #[test]
    fn test_registry_search_empty_query() {
        let index = RegistryIndex {
            version: "1.0".to_string(),
            capabilities: vec![
                RegistryEntry {
                    name: "tool1".to_string(),
                    description: "Desc".to_string(),
                    path: "tool1.yaml".to_string(),
                    tags: vec![],
                    requires_key: false,
                },
            ],
        };

        let results = index.search("");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_registry_requires_key_flag() {
        let entry = RegistryEntry {
            name: "secure_tool".to_string(),
            description: "Requires auth".to_string(),
            path: "secure.yaml".to_string(),
            tags: vec![],
            requires_key: true,
        };

        assert!(entry.requires_key);

        let entry_no_key = RegistryEntry {
            name: "open_tool".to_string(),
            description: "No auth".to_string(),
            path: "open.yaml".to_string(),
            tags: vec![],
            requires_key: false,
        };

        assert!(!entry_no_key.requires_key);
    }

    #[tokio::test]
    async fn test_build_index_from_capabilities() {
        use crate::capability::validate_capability;
        use std::path::PathBuf;

        // Build index from capabilities directory
        let capabilities_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("capabilities");
        let registry = Registry::new(&capabilities_path);

        let index = registry.build_index().await.expect("Failed to build registry index");

        // Verify we have a reasonable number of capabilities (should be 43+)
        assert!(
            index.capabilities.len() >= 43,
            "Registry should contain at least 43 capabilities, found {}",
            index.capabilities.len()
        );

        // Verify each capability file exists and is valid
        for entry in &index.capabilities {
            let capability_path = capabilities_path.join(&entry.path);

            // File must exist
            assert!(
                capability_path.exists(),
                "Capability file not found: {}",
                capability_path.display()
            );

            // File must parse correctly
            let capability = parse_capability_file(&capability_path)
                .await
                .unwrap_or_else(|e| panic!(
                    "Failed to parse {}: {e}",
                    capability_path.display()
                ));

            // Capability must validate
            validate_capability(&capability).unwrap_or_else(|e| panic!(
                "Validation failed for {}: {e}",
                capability.name
            ));

            // Name must match registry entry
            assert_eq!(
                capability.name, entry.name,
                "Capability name mismatch in {}",
                capability_path.display()
            );
        }
    }

    #[tokio::test]
    async fn test_registry_capabilities_metadata() {
        use std::path::PathBuf;

        let capabilities_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("capabilities");
        let registry = Registry::new(&capabilities_path);
        let index = registry.build_index().await.expect("Failed to build registry index");

        // Expected capabilities with their metadata
        let expected = vec![
            ("yahoo_stock_quote", "finance", false),
            ("ecb_exchange_rates", "finance", false),
            ("stripe_list_charges", "finance", true),
            ("weather_current", "knowledge", false),
            ("wikipedia_search", "knowledge", false),
            ("github_create_issue", "utility", true),
            ("slack_post_message", "communication", true),
            ("gmail_send_email", "communication", true),
        ];

        for (name, category, requires_key) in expected {
            let entry = index
                .find(name)
                .unwrap_or_else(|| panic!("Capability '{name}' not found in index"));

            assert_eq!(
                entry.requires_key, requires_key,
                "{name} should have requires_key={requires_key}"
            );

            assert!(
                entry.path.contains(category),
                "{name} should be in {category} directory, found: {}",
                entry.path
            );
        }
    }
}
