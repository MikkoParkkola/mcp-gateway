//! Capability system for direct REST API integration
//!
//! This module provides the ability to define API capabilities via YAML
//! and execute them as MCP tools without requiring an external MCP server.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │  YAML Definition │────▶│   Capability    │────▶│    Executor     │
//! │  (gmail.yaml)    │     │   Definition    │     │  (REST Client)  │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//!                                                          │
//!                                                          ▼
//!                                                  ┌─────────────────┐
//!                                                  │ Credential Vault│
//!                                                  │  (Keychain/Env) │
//!                                                  └─────────────────┘
//! ```
//!
//! # Security
//!
//! Credentials are NEVER stored in capability definitions. Instead, they
//! reference credential sources:
//!
//! - `keychain:name` - macOS Keychain entry
//! - `env:VAR_NAME` - Environment variable
//! - `oauth:provider` - OAuth token from vault
//!
//! The executor injects credentials at runtime, so they never appear in
//! logs, error messages, or MCP responses.

mod backend;
mod definition;
mod executor;
mod loader;
mod openapi;
mod parser;

pub use backend::{CapabilityBackend, CapabilityBackendStatus};
pub use definition::*;
pub use executor::CapabilityExecutor;
pub use loader::CapabilityLoader;
pub use openapi::{AuthTemplate, CacheTemplate, GeneratedCapability, OpenApiConverter};
pub use parser::{parse_capability, parse_capability_file, validate_capability};

use crate::Result;
use std::collections::HashMap;
use std::sync::Arc;

/// Registry of loaded capabilities
pub struct CapabilityRegistry {
    capabilities: HashMap<String, CapabilityDefinition>,
    executor: Arc<CapabilityExecutor>,
}

impl CapabilityRegistry {
    /// Create a new capability registry
    pub fn new(executor: Arc<CapabilityExecutor>) -> Self {
        Self {
            capabilities: HashMap::new(),
            executor,
        }
    }

    /// Load capabilities from a directory
    pub async fn load_from_directory(&mut self, path: &str) -> Result<usize> {
        let loaded = CapabilityLoader::load_directory(path).await?;
        let count = loaded.len();
        for cap in loaded {
            self.capabilities.insert(cap.name.clone(), cap);
        }
        Ok(count)
    }

    /// Get a capability by name
    pub fn get(&self, name: &str) -> Option<&CapabilityDefinition> {
        self.capabilities.get(name)
    }

    /// List all capability names
    pub fn list(&self) -> Vec<&str> {
        self.capabilities.keys().map(|s| s.as_str()).collect()
    }

    /// Execute a capability
    pub async fn execute(
        &self,
        name: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let capability = self
            .get(name)
            .ok_or_else(|| crate::Error::Config(format!("Capability not found: {}", name)))?;
        self.executor.execute(capability, params).await
    }

    /// Get capability count
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}
