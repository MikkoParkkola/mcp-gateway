//! Provider abstraction — pluggable tool sources for `FastMCP` 3.0.
//!
//! This module unifies all tool sources (MCP backends, REST capabilities,
//! `OpenAPI` specs) behind a single `Provider` trait, enabling composable
//! transform pipelines and a unified `ProviderRegistry`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │  ProviderRegistry│
//! │  (name → Arc<dyn Provider>)│
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐   ┌──────────────────┐
//! │ TransformChain  │──▶│  Built-in Provider│
//! │ (middleware)    │   │  McpProvider      │
//! │  NamespaceTransform │  CapabilityProvider│
//! │  FilterTransform│   │  CompositeProvider│
//! │  AuthTransform  │   └──────────────────┘
//! └─────────────────┘
//! ```
//!
//! # Backward Compatibility
//!
//! Existing `BackendRegistry` and `CapabilityBackend` continue to work unchanged.
//! The provider layer wraps them as adapters. Migration is additive: no existing
//! code paths are removed.
//!
//! # Example
//!
//! ```rust
//! use std::sync::Arc;
//! use mcp_gateway::provider::{ProviderRegistry, McpProvider, TransformChain};
//! use mcp_gateway::provider::transforms::{NamespaceTransform, FilterTransform};
//! ```

mod capability_provider;
mod composite_provider;
mod mcp_provider;
pub mod transforms;

pub use capability_provider::CapabilityProvider;
pub use composite_provider::CompositeProvider;
pub use mcp_provider::McpProvider;
pub use transforms::chain::TransformChain;

use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;

use crate::protocol::{Resource, Tool};
use crate::{Error, Result};

// ============================================================================
// Provider trait
// ============================================================================

/// Health status for a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderHealth {
    /// Provider is operating normally.
    Healthy,
    /// Provider is degraded but partially operational.
    Degraded(String),
    /// Provider is unavailable.
    Unavailable(String),
}

impl ProviderHealth {
    /// Returns `true` if the provider is healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

/// A source of MCP tools.
///
/// Implementations may wrap existing infrastructure (MCP backends,
/// REST capabilities) or provide new tool sources. The trait is
/// intentionally minimal; richer behaviour is composed via [`TransformChain`].
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync + 'static` so they can be
/// stored in `Arc<dyn Provider>` and shared across async tasks.
#[async_trait]
pub trait Provider: Send + Sync + 'static {
    /// Unique, stable name for this provider instance.
    fn name(&self) -> &str;

    /// List available tools (may be cached internally).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying source is unavailable.
    async fn list_tools(&self) -> Result<Vec<Tool>>;

    /// Invoke a tool by name with JSON arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if the tool is not found or the invocation fails.
    async fn invoke(&self, tool: &str, args: Value) -> Result<Value>;

    /// Health status of this provider.
    async fn health(&self) -> ProviderHealth;

    /// List MCP resources (optional — default returns empty).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying source is unavailable.
    async fn list_resources(&self) -> Result<Vec<Resource>> {
        Ok(vec![])
    }
}

// ============================================================================
// ProviderRegistry
// ============================================================================

/// Registry of named providers.
///
/// Thin wrapper over `DashMap` that routes tool invocations to the
/// correct provider by name.  Designed to coexist with the existing
/// `BackendRegistry` during the incremental migration described in
/// RFC-0032 Phase 1.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use mcp_gateway::provider::ProviderRegistry;
///
/// let registry = ProviderRegistry::new();
/// // registry.register(Arc::new(my_provider));
/// ```
pub struct ProviderRegistry {
    providers: DashMap<String, Arc<dyn Provider>>,
}

impl ProviderRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: DashMap::new(),
        }
    }

    /// Register a provider under its own name.
    pub fn register(&self, provider: Arc<dyn Provider>) {
        self.providers.insert(provider.name().to_string(), provider);
    }

    /// Look up a provider by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<dyn Provider>> {
        self.providers.get(name).map(|p| Arc::clone(&*p))
    }

    /// Remove a provider by name. Returns `true` if it existed.
    pub fn remove(&self, name: &str) -> bool {
        self.providers.remove(name).is_some()
    }

    /// List all tools across all providers.
    ///
    /// Returns `(provider_name, tool)` pairs for routing.
    ///
    /// # Errors
    ///
    /// Providers that fail are skipped; only individual errors are logged.
    /// Returns `Err` only if every provider fails.
    pub async fn all_tools(&self) -> Vec<(String, Tool)> {
        let mut out = Vec::new();
        for entry in &self.providers {
            match entry.value().list_tools().await {
                Ok(tools) => {
                    for t in tools {
                        out.push((entry.key().clone(), t));
                    }
                }
                Err(e) => {
                    tracing::warn!(provider = %entry.key(), error = %e, "Failed to list tools");
                }
            }
        }
        out
    }

    /// Invoke a tool on a named provider.
    ///
    /// # Errors
    ///
    /// Returns `Error::BackendNotFound` if the provider is not registered,
    /// or the provider's own error if the invocation fails.
    pub async fn invoke(&self, provider: &str, tool: &str, args: Value) -> Result<Value> {
        let p = self
            .get(provider)
            .ok_or_else(|| Error::BackendNotFound(provider.to_string()))?;
        p.invoke(tool, args).await
    }

    /// Number of registered providers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Returns `true` if no providers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Health check for all providers.
    pub async fn health_all(&self) -> Vec<(String, ProviderHealth)> {
        let mut out = Vec::new();
        for entry in &self.providers {
            let health = entry.value().health().await;
            out.push((entry.key().clone(), health));
        }
        out
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Transform trait
// ============================================================================

/// A transform modifies tool lists and/or invocations for a provider.
///
/// Transforms are composed into a [`TransformChain`], implementing
/// the middleware/decorator pattern without runtime heap allocation
/// on the hot path (the chain itself is `Arc<dyn Provider>`).
///
/// # Transform Ordering
///
/// The fixed pipeline order is:
/// `namespace → filter → auth → response`
///
/// This order has well-defined semantics:
/// 1. **namespace** — rename tools first so all subsequent transforms see final names.
/// 2. **filter** — allow/deny based on (possibly renamed) tool names.
/// 3. **auth** — inject credentials only for tools that pass the filter.
/// 4. **response** — shape output after the underlying call succeeds.
#[async_trait]
pub trait Transform: Send + Sync + 'static {
    /// Transform the tool list (filter, rename, add metadata).
    ///
    /// # Errors
    ///
    /// Returns an error if transformation fails unrecoverably.
    async fn transform_tools(&self, tools: Vec<Tool>) -> Result<Vec<Tool>>;

    /// Transform an invocation request.
    ///
    /// Return `None` to **block** the invocation (e.g. deny by policy).
    /// Return `Some((tool, args))` to forward (possibly mutated).
    ///
    /// # Errors
    ///
    /// Returns an error on unexpected failures (not normal "deny" — use `None` for that).
    async fn transform_invoke(
        &self,
        tool: &str,
        args: Value,
    ) -> Result<Option<(String, Value)>>;

    /// Transform the invocation result.
    ///
    /// Called in **reverse** order relative to `transform_invoke`, mirroring
    /// the tower middleware convention.
    ///
    /// # Errors
    ///
    /// Returns an error if result transformation fails.
    async fn transform_result(&self, tool: &str, result: Value) -> Result<Value>;
}
