//! `CompositeProvider` — aggregates multiple providers into one.
//!
//! Tool names are assumed globally unique across all sources.
//! If two providers expose a tool with the same name, the first one
//! registered wins for invocation routing (list returns both).

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::{Provider, ProviderHealth};
use crate::protocol::Tool;
use crate::{Error, Result};

/// Provider that aggregates multiple child providers into a single unified interface.
///
/// Use a `CompositeProvider` when you want to expose tools from several
/// sources (e.g. `tavily` + `brave`) under one logical provider name.
///
/// # Routing
///
/// `invoke` searches child providers **in registration order** for a provider
/// that exposes the requested tool.  The first match wins.  This means
/// registration order determines priority when names collide.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use mcp_gateway::provider::{CompositeProvider, CapabilityProvider};
/// use mcp_gateway::capability::{CapabilityBackend, CapabilityExecutor};
///
/// let executor = Arc::new(CapabilityExecutor::new());
/// let backend_a = Arc::new(CapabilityBackend::new("a", Arc::clone(&executor)));
/// let backend_b = Arc::new(CapabilityBackend::new("b", executor));
/// let provider_a = Arc::new(CapabilityProvider::new(backend_a)) as Arc<dyn mcp_gateway::provider::Provider>;
/// let provider_b = Arc::new(CapabilityProvider::new(backend_b)) as Arc<dyn mcp_gateway::provider::Provider>;
///
/// let composite = CompositeProvider::new("research", vec![provider_a, provider_b]);
/// ```
pub struct CompositeProvider {
    name: String,
    sources: Vec<Arc<dyn Provider>>,
}

impl CompositeProvider {
    /// Create a composite provider from named children.
    ///
    /// `name` is the logical name of this composite (used by `ProviderRegistry`).
    #[must_use]
    pub fn new(name: impl Into<String>, sources: Vec<Arc<dyn Provider>>) -> Self {
        Self {
            name: name.into(),
            sources,
        }
    }

    /// Add a source provider.
    pub fn add_source(&mut self, source: Arc<dyn Provider>) {
        self.sources.push(source);
    }
}

#[async_trait]
impl Provider for CompositeProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn list_tools(&self) -> Result<Vec<Tool>> {
        let mut tools = Vec::new();
        for source in &self.sources {
            match source.list_tools().await {
                Ok(ts) => tools.extend(ts),
                Err(e) => {
                    tracing::warn!(
                        composite = %self.name,
                        source = %source.name(),
                        error = %e,
                        "Source failed to list tools"
                    );
                }
            }
        }
        Ok(tools)
    }

    async fn invoke(&self, tool: &str, args: Value) -> Result<Value> {
        // Find the first source that knows about this tool.
        for source in &self.sources {
            let Ok(tools) = source.list_tools().await else {
                continue;
            };
            if tools.iter().any(|t| t.name == tool) {
                return source.invoke(tool, args).await;
            }
        }
        Err(Error::BackendNotFound(format!(
            "Tool '{tool}' not found in composite provider '{}'",
            self.name
        )))
    }

    async fn health(&self) -> ProviderHealth {
        let mut degraded = Vec::new();
        let mut all_unavailable = true;

        for source in &self.sources {
            match source.health().await {
                ProviderHealth::Healthy => {
                    all_unavailable = false;
                }
                ProviderHealth::Degraded(msg) => {
                    degraded.push(format!("{}: {msg}", source.name()));
                    all_unavailable = false;
                }
                ProviderHealth::Unavailable(msg) => {
                    degraded.push(format!("{}: {msg}", source.name()));
                }
            }
        }

        if all_unavailable && !self.sources.is_empty() {
            ProviderHealth::Unavailable(format!(
                "All sources unavailable: {}",
                degraded.join("; ")
            ))
        } else if degraded.is_empty() {
            ProviderHealth::Healthy
        } else {
            ProviderHealth::Degraded(degraded.join("; "))
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Tool;
    use serde_json::json;

    /// Minimal in-memory provider for testing.
    struct StaticProvider {
        name: String,
        tools: Vec<Tool>,
    }

    impl StaticProvider {
        fn new(name: &str, tool_names: &[&str]) -> Arc<dyn Provider> {
            Arc::new(Self {
                name: name.to_string(),
                tools: tool_names
                    .iter()
                    .map(|n| Tool {
                        name: n.to_string(),
                        title: None,
                        description: None,
                        input_schema: json!({}),
                        output_schema: None,
                        annotations: None,
                    })
                    .collect(),
            })
        }
    }

    #[async_trait::async_trait]
    impl Provider for StaticProvider {
        fn name(&self) -> &str {
            &self.name
        }

        async fn list_tools(&self) -> Result<Vec<Tool>> {
            Ok(self.tools.clone())
        }

        async fn invoke(&self, tool: &str, _args: Value) -> Result<Value> {
            if self.tools.iter().any(|t| t.name == tool) {
                Ok(json!({ "from": self.name, "tool": tool }))
            } else {
                Err(crate::Error::BackendNotFound(tool.to_string()))
            }
        }

        async fn health(&self) -> ProviderHealth {
            ProviderHealth::Healthy
        }
    }

    #[test]
    fn composite_provider_name() {
        let composite = CompositeProvider::new("combined", vec![]);
        assert_eq!(composite.name(), "combined");
    }

    #[tokio::test]
    async fn composite_lists_all_tools_from_all_sources() {
        // GIVEN: two sources with distinct tool sets
        let a = StaticProvider::new("a", &["tool_a1", "tool_a2"]);
        let b = StaticProvider::new("b", &["tool_b1"]);
        let composite = CompositeProvider::new("combined", vec![a, b]);

        // WHEN: listing tools
        let tools = composite.list_tools().await.unwrap();

        // THEN: all three tools present
        let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"tool_a1"));
        assert!(names.contains(&"tool_a2"));
        assert!(names.contains(&"tool_b1"));
        assert_eq!(tools.len(), 3);
    }

    #[tokio::test]
    async fn composite_routes_invoke_to_correct_source() {
        // GIVEN: two sources with distinct tools
        let a = StaticProvider::new("source_a", &["tool_a"]);
        let b = StaticProvider::new("source_b", &["tool_b"]);
        let composite = CompositeProvider::new("c", vec![a, b]);

        // WHEN: invoking tool from second source
        let result = composite.invoke("tool_b", json!({})).await.unwrap();

        // THEN: routed to source_b
        assert_eq!(result["from"], "source_b");
    }

    #[tokio::test]
    async fn composite_returns_error_for_unknown_tool() {
        // GIVEN: composite with tools that don't include "ghost"
        let a = StaticProvider::new("a", &["tool_a"]);
        let composite = CompositeProvider::new("c", vec![a]);

        // WHEN: invoking unknown tool
        let result = composite.invoke("ghost", json!({})).await;

        // THEN: error
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ghost"));
    }

    #[tokio::test]
    async fn composite_health_healthy_when_all_sources_healthy() {
        let a = StaticProvider::new("a", &["x"]);
        let b = StaticProvider::new("b", &["y"]);
        let composite = CompositeProvider::new("c", vec![a, b]);

        let health = composite.health().await;
        assert_eq!(health, ProviderHealth::Healthy);
    }

    #[tokio::test]
    async fn composite_empty_lists_empty_tools() {
        let composite = CompositeProvider::new("empty", vec![]);
        let tools = composite.list_tools().await.unwrap();
        assert!(tools.is_empty());
    }

    #[tokio::test]
    async fn composite_first_source_wins_on_name_collision() {
        // GIVEN: both sources expose "shared_tool"
        let a = StaticProvider::new("first", &["shared_tool"]);
        let b = StaticProvider::new("second", &["shared_tool"]);
        let composite = CompositeProvider::new("c", vec![a, b]);

        // WHEN: invoking the shared tool
        let result = composite.invoke("shared_tool", json!({})).await.unwrap();

        // THEN: first source wins
        assert_eq!(result["from"], "first");
    }
}
