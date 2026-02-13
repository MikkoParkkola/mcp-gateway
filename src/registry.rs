//! Capability registry for community-shared capability definitions
//!
//! Provides discovery and installation of pre-built capability definitions
//! from both local registry and remote GitHub sources.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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
    /// Load registry index from file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the JSON is invalid.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            Error::Config(format!("Failed to read registry index: {e}"))
        })?;

        serde_json::from_str(&content).map_err(|e| {
            Error::Config(format!("Failed to parse registry index: {e}"))
        })
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
    /// Path to local registry directory
    registry_path: PathBuf,
}

impl Registry {
    /// Create a new registry manager
    ///
    /// # Arguments
    ///
    /// * `registry_path` - Path to the registry directory (typically `registry/`)
    pub fn new<P: AsRef<Path>>(registry_path: P) -> Self {
        Self {
            registry_path: registry_path.as_ref().to_path_buf(),
        }
    }

    /// Get the registry index file path
    fn index_path(&self) -> PathBuf {
        self.registry_path.join("index.json")
    }

    /// Load the registry index
    ///
    /// # Errors
    ///
    /// Returns an error if the index file doesn't exist or cannot be parsed.
    pub fn load_index(&self) -> Result<RegistryIndex> {
        let index_path = self.index_path();
        if !index_path.exists() {
            return Err(Error::Config(format!(
                "Registry index not found: {}",
                index_path.display()
            )));
        }
        RegistryIndex::load(&index_path)
    }

    /// Install a capability from the local registry to the capabilities directory
    ///
    /// # Arguments
    ///
    /// * `name` - Capability name from registry
    /// * `target_dir` - Target directory to install to (typically `capabilities/`)
    ///
    /// # Errors
    ///
    /// Returns an error if the capability is not found or the file copy fails.
    pub fn install_local(&self, name: &str, target_dir: &Path) -> Result<PathBuf> {
        let index = self.load_index()?;
        let entry = index
            .find(name)
            .ok_or_else(|| Error::Config(format!("Capability '{name}' not found in registry")))?;

        let source = self.registry_path.join(&entry.path);
        if !source.exists() {
            return Err(Error::Config(format!(
                "Capability file not found: {}",
                source.display()
            )));
        }

        // Create target directory if needed
        fs::create_dir_all(target_dir).map_err(|e| {
            Error::Config(format!("Failed to create target directory: {e}"))
        })?;

        let filename = source
            .file_name()
            .ok_or_else(|| Error::Config("Invalid source path".to_string()))?;
        let target = target_dir.join(filename);

        fs::copy(&source, &target).map_err(|e| {
            Error::Config(format!(
                "Failed to copy capability from {} to {}: {e}",
                source.display(),
                target.display()
            ))
        })?;

        Ok(target)
    }

    /// Install a capability from GitHub
    ///
    /// # Arguments
    ///
    /// * `name` - Capability name from registry
    /// * `target_dir` - Target directory to install to
    /// * `repo` - GitHub repository (format: `owner/repo`)
    /// * `branch` - Branch name (default: "main")
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails or the file cannot be written.
    pub async fn install_from_github(
        &self,
        name: &str,
        target_dir: &Path,
        repo: &str,
        branch: &str,
    ) -> Result<PathBuf> {
        // Load index from GitHub
        let index_url = format!(
            "https://raw.githubusercontent.com/{repo}/{branch}/registry/index.json"
        );

        let client = reqwest::Client::new();
        let index_content = client
            .get(&index_url)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("Failed to fetch registry index: {e}")))?
            .text()
            .await
            .map_err(|e| Error::Transport(format!("Failed to read registry index: {e}")))?;

        let index: RegistryIndex = serde_json::from_str(&index_content)
            .map_err(|e| Error::Config(format!("Failed to parse registry index: {e}")))?;

        let entry = index
            .find(name)
            .ok_or_else(|| Error::Config(format!("Capability '{name}' not found in registry")))?;

        // Download capability file
        let capability_url = format!(
            "https://raw.githubusercontent.com/{repo}/{branch}/{}",
            entry.path
        );

        let capability_content = client
            .get(&capability_url)
            .send()
            .await
            .map_err(|e| {
                Error::Transport(format!("Failed to download capability: {e}"))
            })?
            .text()
            .await
            .map_err(|e| Error::Transport(format!("Failed to read capability content: {e}")))?;

        // Create target directory
        fs::create_dir_all(target_dir).map_err(|e| {
            Error::Config(format!("Failed to create target directory: {e}"))
        })?;

        // Write capability file
        let filename = PathBuf::from(&entry.path)
            .file_name()
            .ok_or_else(|| Error::Config("Invalid capability path".to_string()))?
            .to_owned();
        let target = target_dir.join(filename);

        fs::write(&target, capability_content).map_err(|e| {
            Error::Config(format!("Failed to write capability file: {e}"))
        })?;

        Ok(target)
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
            path: "registry/test/test_tool.yaml".to_string(),
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
                    path: "registry/finance/stripe_charges.yaml".to_string(),
                    tags: vec!["finance".to_string(), "stripe".to_string()],
                    requires_key: true,
                },
                RegistryEntry {
                    name: "gmail_send".to_string(),
                    description: "Send email via Gmail".to_string(),
                    path: "registry/communication/gmail_send.yaml".to_string(),
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
    async fn test_registry_yaml_files_exist_and_valid() {
        use crate::capability::{parse_capability_file, validate_capability};
        use std::path::PathBuf;

        // Load registry index
        let registry_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("registry");
        let registry = Registry::new(&registry_path);

        let index = registry.load_index().expect("Failed to load registry index");

        // Verify all 8 expected capabilities are present
        assert_eq!(
            index.capabilities.len(),
            8,
            "Registry should contain exactly 8 capabilities"
        );

        // Verify each capability file exists and is valid
        for entry in &index.capabilities {
            let capability_path = registry_path.join(&entry.path);

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
    async fn test_all_registry_capabilities_match_index() {
        use crate::capability::parse_capability_file;
        use std::path::PathBuf;

        let registry_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("registry");
        let registry = Registry::new(&registry_path);
        let index = registry.load_index().expect("Failed to load registry index");

        // Expected capabilities with their metadata
        let expected = vec![
            ("yahoo_stock_quote", "finance", false),
            ("ecb_exchange_rates", "finance", false),
            ("stripe_list_charges", "finance", true),
            ("weather_current", "productivity", false),
            ("wikipedia_search", "productivity", false),
            ("github_create_issue", "productivity", true),
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
                "{name} should be in {category} directory"
            );

            // Verify the capability file is valid
            let capability_path = registry_path.join(&entry.path);
            let capability = parse_capability_file(&capability_path)
                .await
                .unwrap_or_else(|e| panic!("Failed to parse {name}: {e}"));

            assert_eq!(capability.name, name);
        }
    }
}
