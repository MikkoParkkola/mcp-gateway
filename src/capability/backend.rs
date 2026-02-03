//! Capability backend - integrates capabilities with the gateway
//!
//! This module provides a bridge between the capability system and the
//! gateway's backend infrastructure, allowing capabilities to appear
//! as tools via the Meta-MCP interface.

use std::sync::Arc;

use serde_json::Value;
use tracing::{debug, info};

use super::{CapabilityDefinition, CapabilityExecutor, CapabilityRegistry};
use crate::protocol::{Content, Tool, ToolsCallResult};
use crate::Result;

/// Backend that exposes capabilities as MCP tools
pub struct CapabilityBackend {
    /// Capability registry
    registry: CapabilityRegistry,
    /// Backend name (for gateway integration)
    pub name: String,
}

impl CapabilityBackend {
    /// Create a new capability backend
    pub fn new(name: &str, executor: Arc<CapabilityExecutor>) -> Self {
        Self {
            registry: CapabilityRegistry::new(executor),
            name: name.to_string(),
        }
    }

    /// Load capabilities from a directory
    pub async fn load_from_directory(&mut self, path: &str) -> Result<usize> {
        let count = self.registry.load_from_directory(path).await?;
        info!(backend = %self.name, count = count, path = path, "Loaded capabilities");
        Ok(count)
    }

    /// Get all tools (capability definitions as MCP tools)
    pub fn get_tools(&self) -> Vec<Tool> {
        self.registry
            .list()
            .iter()
            .filter_map(|name| self.registry.get(name))
            .map(CapabilityDefinition::to_mcp_tool)
            .collect()
    }

    /// Get a specific capability
    pub fn get(&self, name: &str) -> Option<&CapabilityDefinition> {
        self.registry.get(name)
    }

    /// List all capability names
    pub fn list(&self) -> Vec<&str> {
        self.registry.list()
    }

    /// Execute a capability (call a tool)
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<ToolsCallResult> {
        debug!(capability = %name, "Executing capability");

        let result = self.registry.execute(name, arguments).await?;

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
        self.registry.get(name).is_some()
    }

    /// Get capability count
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// Check if backend has no capabilities
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
    }

    /// Get backend status
    pub fn status(&self) -> CapabilityBackendStatus {
        CapabilityBackendStatus {
            name: self.name.clone(),
            capabilities_count: self.registry.len(),
            capabilities: self.registry.list().iter().map(|s| s.to_string()).collect(),
        }
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
