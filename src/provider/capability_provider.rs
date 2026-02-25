//! `CapabilityProvider` — adapts [`CapabilityBackend`] to the [`Provider`] trait.
//!
//! Phase 2 adapter from RFC-0032.  The existing `CapabilityBackend` (YAML-defined
//! REST API tools) is wrapped without modification.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::{Provider, ProviderHealth};
use crate::capability::CapabilityBackend;
use crate::protocol::Tool;
use crate::Result;

/// Provider adapter that wraps an existing [`CapabilityBackend`].
///
/// Capabilities are YAML-defined REST API tools executed directly by the
/// gateway.  This adapter surfaces them through the unified `Provider` API.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use mcp_gateway::provider::CapabilityProvider;
/// use mcp_gateway::capability::{CapabilityBackend, CapabilityExecutor};
///
/// let executor = Arc::new(CapabilityExecutor::new());
/// let backend = Arc::new(CapabilityBackend::new("rest_tools", executor));
/// let provider = Arc::new(CapabilityProvider::new(backend));
/// ```
pub struct CapabilityProvider {
    backend: Arc<CapabilityBackend>,
}

impl CapabilityProvider {
    /// Wrap an existing capability backend as a provider.
    #[must_use]
    pub fn new(backend: Arc<CapabilityBackend>) -> Self {
        Self { backend }
    }

    /// Access the underlying backend (e.g. for hot-reload).
    #[must_use]
    pub fn backend(&self) -> &Arc<CapabilityBackend> {
        &self.backend
    }
}

#[async_trait]
impl Provider for CapabilityProvider {
    fn name(&self) -> &str {
        &self.backend.name
    }

    async fn list_tools(&self) -> Result<Vec<Tool>> {
        Ok(self.backend.get_tools())
    }

    async fn invoke(&self, tool: &str, args: Value) -> Result<Value> {
        let result = self.backend.call_tool(tool, args).await?;

        // Convert ToolsCallResult to a single JSON value.
        let texts: Vec<Value> = result
            .content
            .into_iter()
            .filter_map(|c| match c {
                crate::protocol::Content::Text { text, .. } => {
                    serde_json::from_str(&text).ok().or(Some(Value::String(text)))
                }
                _ => None,
            })
            .collect();

        Ok(match texts.len() {
            0 => Value::Null,
            1 => texts.into_iter().next().unwrap_or(Value::Null),
            _ => Value::Array(texts),
        })
    }

    async fn health(&self) -> ProviderHealth {
        if self.backend.is_empty() {
            ProviderHealth::Degraded("No capabilities loaded".to_string())
        } else {
            ProviderHealth::Healthy
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilityBackend, CapabilityExecutor};

    fn make_backend() -> Arc<CapabilityBackend> {
        let executor = Arc::new(CapabilityExecutor::new());
        Arc::new(CapabilityBackend::new("test_caps", executor))
    }

    #[test]
    fn capability_provider_name_matches_backend() {
        let backend = make_backend();
        let provider = CapabilityProvider::new(backend);
        assert_eq!(provider.name(), "test_caps");
    }

    #[tokio::test]
    async fn capability_provider_lists_empty_tools_when_no_capabilities() {
        // GIVEN: a provider with no loaded capabilities
        let backend = make_backend();
        let provider = CapabilityProvider::new(backend);

        // WHEN: listing tools
        let tools = provider.list_tools().await.unwrap();

        // THEN: empty list
        assert!(tools.is_empty());
    }

    #[tokio::test]
    async fn capability_provider_health_degraded_when_empty() {
        // GIVEN: empty backend
        let backend = make_backend();
        let provider = CapabilityProvider::new(backend);

        // WHEN: checking health
        let health = provider.health().await;

        // THEN: degraded (no capabilities loaded)
        assert!(matches!(health, ProviderHealth::Degraded(_)));
    }

    #[tokio::test]
    async fn capability_provider_invoke_unknown_tool_returns_error() {
        // GIVEN: backend with no capabilities
        let backend = make_backend();
        let provider = CapabilityProvider::new(backend);

        // WHEN: invoking a nonexistent tool
        let result = provider.invoke("ghost_tool", serde_json::json!({})).await;

        // THEN: error returned
        assert!(result.is_err());
    }

    #[test]
    fn capability_provider_is_send_sync() {
        fn _assert_send_sync<T: Send + Sync>() {}
        _assert_send_sync::<CapabilityProvider>();
    }

    #[test]
    fn capability_provider_backend_accessor() {
        let backend = make_backend();
        let provider = CapabilityProvider::new(Arc::clone(&backend));
        assert_eq!(provider.backend().name, "test_caps");
    }
}
