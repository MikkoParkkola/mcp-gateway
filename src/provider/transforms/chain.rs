//! `TransformChain` — wraps a provider with an ordered list of transforms.
//!
//! The chain itself implements [`Provider`], so chains can be nested and
//! stored in `Arc<dyn Provider>` for the `ProviderRegistry`.
//!
//! # Execution Model
//!
//! - `list_tools`: transforms applied **in order** (left-to-right).
//! - `transform_invoke`: applied **in order**; any `None` return blocks.
//! - `transform_result`: applied **in reverse** (right-to-left), mirroring
//!   the tower/onion middleware model.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::provider::{Provider, ProviderHealth, Transform};
use crate::protocol::{Resource, Tool};
use crate::{Error, Result};

/// A provider wrapped with an ordered list of transforms.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use mcp_gateway::provider::{TransformChain, CapabilityProvider};
/// use mcp_gateway::provider::transforms::{NamespaceTransform, FilterTransform};
/// use mcp_gateway::capability::{CapabilityBackend, CapabilityExecutor};
///
/// let executor = Arc::new(CapabilityExecutor::new());
/// let backend = Arc::new(CapabilityBackend::new("gmail", executor));
/// let inner: Arc<dyn mcp_gateway::provider::Provider> =
///     Arc::new(CapabilityProvider::new(backend));
///
/// let chain = TransformChain::builder("gmail", inner)
///     .transform(Arc::new(NamespaceTransform::new("gmail")))
///     .build();
/// ```
pub struct TransformChain {
    name: String,
    inner: Arc<dyn Provider>,
    transforms: Vec<Arc<dyn Transform>>,
}

impl TransformChain {
    /// Start building a transform chain.
    #[must_use]
    pub fn builder(name: impl Into<String>, inner: Arc<dyn Provider>) -> TransformChainBuilder {
        TransformChainBuilder {
            name: name.into(),
            inner,
            transforms: Vec::new(),
        }
    }
}

/// Builder for [`TransformChain`].
pub struct TransformChainBuilder {
    name: String,
    inner: Arc<dyn Provider>,
    transforms: Vec<Arc<dyn Transform>>,
}

impl TransformChainBuilder {
    /// Append a transform to the chain.
    #[must_use]
    pub fn transform(mut self, t: Arc<dyn Transform>) -> Self {
        self.transforms.push(t);
        self
    }

    /// Finalise and produce a [`TransformChain`].
    #[must_use]
    pub fn build(self) -> TransformChain {
        TransformChain {
            name: self.name,
            inner: self.inner,
            transforms: self.transforms,
        }
    }
}

#[async_trait]
impl Provider for TransformChain {
    fn name(&self) -> &str {
        &self.name
    }

    async fn list_tools(&self) -> Result<Vec<Tool>> {
        let mut tools = self.inner.list_tools().await?;
        for t in &self.transforms {
            tools = t.transform_tools(tools).await?;
        }
        Ok(tools)
    }

    async fn invoke(&self, tool: &str, args: Value) -> Result<Value> {
        // Forward pass: each transform may rename the tool or mutate args,
        // or block by returning None.
        let mut current_tool = tool.to_string();
        let mut current_args = args;

        for t in &self.transforms {
            match t.transform_invoke(&current_tool, current_args).await? {
                Some((next_tool, next_args)) => {
                    current_tool = next_tool;
                    current_args = next_args;
                }
                None => {
                    return Err(Error::Config(format!(
                        "Tool '{}' blocked by transform in provider '{}'",
                        tool, self.name
                    )));
                }
            }
        }

        let result = self.inner.invoke(&current_tool, current_args).await?;

        // Reverse pass: result transforms in reverse order (onion model).
        let mut result = result;
        for t in self.transforms.iter().rev() {
            result = t.transform_result(tool, result).await?;
        }
        Ok(result)
    }

    async fn health(&self) -> ProviderHealth {
        self.inner.health().await
    }

    async fn list_resources(&self) -> Result<Vec<Resource>> {
        self.inner.list_resources().await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Transform;
    use crate::protocol::Tool;
    use serde_json::json;

    /// Static in-memory provider for tests.
    struct EchoProvider {
        name: String,
        tool_names: Vec<String>,
    }

    impl EchoProvider {
        fn new(name: &str, tools: &[&str]) -> Arc<dyn Provider> {
            Arc::new(Self {
                name: name.to_string(),
                tool_names: tools.iter().map(|s| s.to_string()).collect(),
            })
        }
    }

    #[async_trait::async_trait]
    impl Provider for EchoProvider {
        fn name(&self) -> &str {
            &self.name
        }

        async fn list_tools(&self) -> Result<Vec<Tool>> {
            Ok(self
                .tool_names
                .iter()
                .map(|n| Tool {
                    name: n.clone(),
                    title: None,
                    description: None,
                    input_schema: json!({}),
                    output_schema: None,
                    annotations: None,
                })
                .collect())
        }

        async fn invoke(&self, tool: &str, args: Value) -> Result<Value> {
            if self.tool_names.iter().any(|t| t == tool) {
                Ok(json!({ "echo": tool, "args": args }))
            } else {
                Err(crate::Error::BackendNotFound(tool.to_string()))
            }
        }

        async fn health(&self) -> ProviderHealth {
            ProviderHealth::Healthy
        }
    }

    /// Transform that uppercases all tool names.
    struct UppercaseTransform;

    #[async_trait::async_trait]
    impl Transform for UppercaseTransform {
        async fn transform_tools(&self, tools: Vec<Tool>) -> Result<Vec<Tool>> {
            Ok(tools
                .into_iter()
                .map(|mut t| {
                    t.name = t.name.to_uppercase();
                    t
                })
                .collect())
        }

        async fn transform_invoke(
            &self,
            tool: &str,
            args: Value,
        ) -> Result<Option<(String, Value)>> {
            Ok(Some((tool.to_lowercase(), args)))
        }

        async fn transform_result(&self, _tool: &str, result: Value) -> Result<Value> {
            Ok(result)
        }
    }

    /// Transform that blocks a specific tool.
    struct BlockTransform {
        blocked: String,
    }

    #[async_trait::async_trait]
    impl Transform for BlockTransform {
        async fn transform_tools(&self, tools: Vec<Tool>) -> Result<Vec<Tool>> {
            Ok(tools
                .into_iter()
                .filter(|t| t.name != self.blocked)
                .collect())
        }

        async fn transform_invoke(
            &self,
            tool: &str,
            args: Value,
        ) -> Result<Option<(String, Value)>> {
            if tool == self.blocked {
                Ok(None)
            } else {
                Ok(Some((tool.to_string(), args)))
            }
        }

        async fn transform_result(&self, _tool: &str, result: Value) -> Result<Value> {
            Ok(result)
        }
    }

    #[tokio::test]
    async fn chain_no_transforms_passes_through() {
        // GIVEN: chain with no transforms
        let inner = EchoProvider::new("echo", &["tool_a"]);
        let chain = TransformChain::builder("c", inner).build();

        // WHEN: listing and invoking
        let tools = chain.list_tools().await.unwrap();
        let result = chain.invoke("tool_a", json!({"x": 1})).await.unwrap();

        // THEN: unmodified passthrough
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "tool_a");
        assert_eq!(result["echo"], "tool_a");
    }

    #[tokio::test]
    async fn chain_applies_transform_to_tool_list() {
        // GIVEN: uppercase transform
        let inner = EchoProvider::new("echo", &["my_tool"]);
        let chain = TransformChain::builder("c", inner)
            .transform(Arc::new(UppercaseTransform))
            .build();

        // WHEN: listing tools
        let tools = chain.list_tools().await.unwrap();

        // THEN: tool name is uppercased
        assert_eq!(tools[0].name, "MY_TOOL");
    }

    #[tokio::test]
    async fn chain_blocked_tool_returns_error() {
        // GIVEN: block transform on "danger"
        let inner = EchoProvider::new("echo", &["safe", "danger"]);
        let chain = TransformChain::builder("c", inner)
            .transform(Arc::new(BlockTransform {
                blocked: "danger".to_string(),
            }))
            .build();

        // WHEN: invoking the blocked tool
        let result = chain.invoke("danger", json!({})).await;

        // THEN: error returned
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("blocked") || msg.contains("danger"));
    }

    #[tokio::test]
    async fn chain_allowed_tool_passes_through_block_transform() {
        // GIVEN: block transform that only blocks "danger"
        let inner = EchoProvider::new("echo", &["safe", "danger"]);
        let chain = TransformChain::builder("c", inner)
            .transform(Arc::new(BlockTransform {
                blocked: "danger".to_string(),
            }))
            .build();

        // WHEN: invoking a safe tool
        let result = chain.invoke("safe", json!({})).await.unwrap();

        // THEN: passes through
        assert_eq!(result["echo"], "safe");
    }

    #[tokio::test]
    async fn chain_health_delegates_to_inner() {
        let inner = EchoProvider::new("echo", &[]);
        let chain = TransformChain::builder("c", inner).build();
        let health = chain.health().await;
        assert_eq!(health, ProviderHealth::Healthy);
    }

    #[tokio::test]
    async fn chain_name_uses_given_name() {
        let inner = EchoProvider::new("inner_name", &[]);
        let chain = TransformChain::builder("my_chain", inner).build();
        assert_eq!(chain.name(), "my_chain");
    }

    #[tokio::test]
    async fn chain_multiple_transforms_applied_in_order() {
        // GIVEN: uppercase + block transform (uppercase fires first)
        let inner = EchoProvider::new("echo", &["tool_a", "tool_b"]);
        let chain = TransformChain::builder("c", inner)
            .transform(Arc::new(UppercaseTransform))
            .transform(Arc::new(BlockTransform {
                blocked: "TOOL_B".to_string(),
            }))
            .build();

        // WHEN: listing
        let tools = chain.list_tools().await.unwrap();

        // THEN: TOOL_B removed after uppercase, TOOL_A survives
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "TOOL_A");
    }
}
