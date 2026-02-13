//! Capability backend - integrates capabilities with the gateway
//!
//! This module provides a bridge between the capability system and the
//! gateway's backend infrastructure, allowing capabilities to appear
//! as tools via the Meta-MCP interface.
//!
//! # Hot Reload
//!
//! The backend supports hot-reloading of capabilities. When capability
//! files change, call `reload()` to refresh the registry without
//! restarting the gateway.

use std::sync::Arc;

use parking_lot::RwLock;
use serde_json::Value;
use tracing::{debug, info, warn};

use super::{CapabilityDefinition, CapabilityExecutor, CapabilityLoader};
use crate::Result;
use crate::protocol::{Content, Tool, ToolsCallResult};

/// Backend that exposes capabilities as MCP tools
///
/// This backend is thread-safe and supports hot-reloading via the
/// `reload()` method.
pub struct CapabilityBackend {
    /// Backend name (for gateway integration)
    pub name: String,
    /// Executor for running capabilities
    executor: Arc<CapabilityExecutor>,
    /// Loaded capabilities (protected for hot-reload)
    capabilities: RwLock<Vec<CapabilityDefinition>>,
    /// Directories to load capabilities from
    directories: RwLock<Vec<String>>,
}

impl CapabilityBackend {
    /// Create a new capability backend
    pub fn new(name: &str, executor: Arc<CapabilityExecutor>) -> Self {
        Self {
            name: name.to_string(),
            executor,
            capabilities: RwLock::new(Vec::new()),
            directories: RwLock::new(Vec::new()),
        }
    }

    /// Load capabilities from a directory
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be loaded.
    pub async fn load_from_directory(&self, path: &str) -> Result<usize> {
        let loaded = CapabilityLoader::load_directory(path).await?;
        let count = loaded.len();

        // Add directory to watch list
        {
            let mut dirs = self.directories.write();
            if !dirs.contains(&path.to_string()) {
                dirs.push(path.to_string());
            }
        }

        // Add capabilities
        {
            let mut caps = self.capabilities.write();
            for cap in loaded {
                // Remove existing with same name (allows updates)
                caps.retain(|c| c.name != cap.name);
                caps.push(cap);
            }
        }

        info!(backend = %self.name, count = count, path = path, "Loaded capabilities");
        Ok(count)
    }

    /// Reload all capabilities from registered directories
    ///
    /// This is the hot-reload entry point. It re-reads all capability
    /// files from the registered directories and updates the registry.
    ///
    /// # Errors
    ///
    /// Returns an error if reloading fails for all directories.
    pub async fn reload(&self) -> Result<usize> {
        let dirs: Vec<String> = self.directories.read().clone();

        if dirs.is_empty() {
            debug!(backend = %self.name, "No directories to reload");
            return Ok(0);
        }

        // Clear and reload all capabilities
        let mut all_caps = Vec::new();
        let mut total = 0;

        for dir in &dirs {
            match CapabilityLoader::load_directory(dir).await {
                Ok(loaded) => {
                    total += loaded.len();
                    all_caps.extend(loaded);
                }
                Err(e) => {
                    warn!(backend = %self.name, directory = %dir, error = %e, "Failed to reload directory");
                }
            }
        }

        // Atomic swap
        {
            let mut caps = self.capabilities.write();
            *caps = all_caps;
        }

        info!(backend = %self.name, count = total, directories = dirs.len(), "Hot-reloaded capabilities");
        Ok(total)
    }

    /// Get all tools (capability definitions as MCP tools)
    pub fn get_tools(&self) -> Vec<Tool> {
        self.capabilities
            .read()
            .iter()
            .map(CapabilityDefinition::to_mcp_tool)
            .collect()
    }

    /// Get a specific capability by name
    pub fn get(&self, name: &str) -> Option<CapabilityDefinition> {
        self.capabilities
            .read()
            .iter()
            .find(|c| c.name == name)
            .cloned()
    }

    /// List all capability names
    pub fn list(&self) -> Vec<String> {
        self.capabilities
            .read()
            .iter()
            .map(|c| c.name.clone())
            .collect()
    }

    /// Execute a capability (call a tool)
    ///
    /// # Errors
    ///
    /// Returns an error if the capability is not found or execution fails.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<ToolsCallResult> {
        debug!(capability = %name, "Executing capability");

        // Get capability (clone to release lock)
        let capability = self
            .get(name)
            .ok_or_else(|| crate::Error::Config(format!("Capability not found: {name}")))?;

        let result = self.executor.execute(&capability, arguments).await?;

        // Format result as MCP tool response
        let text = serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());

        Ok(ToolsCallResult {
            content: vec![Content::Text {
                text,
                annotations: None,
            }],
            is_error: false,
        })
    }

    /// Check if a capability exists
    pub fn has_capability(&self, name: &str) -> bool {
        self.capabilities.read().iter().any(|c| c.name == name)
    }

    /// Get capability count
    pub fn len(&self) -> usize {
        self.capabilities.read().len()
    }

    /// Check if backend has no capabilities
    pub fn is_empty(&self) -> bool {
        self.capabilities.read().is_empty()
    }

    /// Get backend status
    pub fn status(&self) -> CapabilityBackendStatus {
        let caps = self.capabilities.read();
        CapabilityBackendStatus {
            name: self.name.clone(),
            capabilities_count: caps.len(),
            capabilities: caps.iter().map(|c| c.name.clone()).collect(),
        }
    }

    /// Get watched directories
    pub fn watched_directories(&self) -> Vec<String> {
        self.directories.read().clone()
    }
}

/// Status information for a capability backend
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapabilityBackendStatus {
    /// Backend name
    pub name: String,
    /// Number of loaded capabilities
    pub capabilities_count: usize,
    /// List of capability names
    pub capabilities: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_backend_new() {
        let executor = Arc::new(CapabilityExecutor::new());
        let backend = CapabilityBackend::new("test", executor);
        assert_eq!(backend.name, "test");
        assert!(backend.is_empty());
    }
}
