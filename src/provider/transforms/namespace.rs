//! `NamespaceTransform` — prefixes all tool names with a namespace.
//!
//! # Behaviour
//!
//! `list_tools`: renames `search` → `gmail_search` for namespace `"gmail"`.
//! `transform_invoke`: strips the prefix before forwarding to the inner provider.
//! `transform_result`: passes through unchanged.

use async_trait::async_trait;
use serde_json::Value;

use crate::protocol::Tool;
use crate::{provider::Transform, Result};

/// Adds a namespace prefix to all tool names.
///
/// # Example
///
/// ```rust
/// use mcp_gateway::provider::transforms::NamespaceTransform;
///
/// let t = NamespaceTransform::new("gmail");
/// // tool "search" becomes "gmail_search"
/// ```
pub struct NamespaceTransform {
    prefix: String,
    separator: String,
}

impl NamespaceTransform {
    /// Create a namespace transform with `_` as the separator.
    ///
    /// Tool `"search"` becomes `"{namespace}_search"`.
    #[must_use]
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            prefix: namespace.into(),
            separator: "_".to_string(),
        }
    }

    /// Create a namespace transform with a custom separator.
    #[must_use]
    pub fn with_separator(namespace: impl Into<String>, sep: impl Into<String>) -> Self {
        Self {
            prefix: namespace.into(),
            separator: sep.into(),
        }
    }

    /// Build the full prefixed name.
    fn prefixed(&self, name: &str) -> String {
        format!("{}{}{name}", self.prefix, self.separator)
    }

    /// Strip the prefix if present; return original if not.
    fn strip(&self, name: &str) -> String {
        let full_prefix = format!("{}{}", self.prefix, self.separator);
        name.strip_prefix(&full_prefix)
            .unwrap_or(name)
            .to_string()
    }
}

#[async_trait]
impl Transform for NamespaceTransform {
    async fn transform_tools(&self, tools: Vec<Tool>) -> Result<Vec<Tool>> {
        Ok(tools
            .into_iter()
            .map(|mut t| {
                t.name = self.prefixed(&t.name);
                t
            })
            .collect())
    }

    async fn transform_invoke(
        &self,
        tool: &str,
        args: Value,
    ) -> Result<Option<(String, Value)>> {
        // Strip namespace prefix before forwarding to inner provider.
        Ok(Some((self.strip(tool), args)))
    }

    async fn transform_result(&self, _tool: &str, result: Value) -> Result<Value> {
        Ok(result)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: None,
            input_schema: json!({}),
            output_schema: None,
            annotations: None,
        }
    }

    #[tokio::test]
    async fn namespace_transform_prefixes_tool_names() {
        // GIVEN: transform with "gmail" namespace
        let t = NamespaceTransform::new("gmail");
        let tools = vec![make_tool("search"), make_tool("send")];

        // WHEN: transforming tools
        let result = t.transform_tools(tools).await.unwrap();

        // THEN: all names prefixed
        assert_eq!(result[0].name, "gmail_search");
        assert_eq!(result[1].name, "gmail_send");
    }

    #[tokio::test]
    async fn namespace_transform_strips_prefix_on_invoke() {
        // GIVEN: "gmail" namespace
        let t = NamespaceTransform::new("gmail");

        // WHEN: invoking "gmail_search"
        let result = t
            .transform_invoke("gmail_search", json!({"q": "test"}))
            .await
            .unwrap();

        // THEN: prefix stripped, args unchanged
        let (tool, args) = result.unwrap();
        assert_eq!(tool, "search");
        assert_eq!(args["q"], "test");
    }

    #[tokio::test]
    async fn namespace_transform_invoke_without_prefix_passes_unchanged() {
        // GIVEN: "gmail" namespace
        let t = NamespaceTransform::new("gmail");

        // WHEN: invoking a tool without the prefix
        let result = t
            .transform_invoke("search", json!({}))
            .await
            .unwrap();

        // THEN: name unchanged (already stripped / never had prefix)
        let (tool, _) = result.unwrap();
        assert_eq!(tool, "search");
    }

    #[tokio::test]
    async fn namespace_transform_result_passes_through() {
        let t = NamespaceTransform::new("ns");
        let val = json!({"key": "value"});
        let result = t.transform_result("any_tool", val.clone()).await.unwrap();
        assert_eq!(result, val);
    }

    #[tokio::test]
    async fn namespace_transform_empty_tool_list() {
        let t = NamespaceTransform::new("ns");
        let result = t.transform_tools(vec![]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn namespace_transform_custom_separator() {
        // GIVEN: hyphen separator
        let t = NamespaceTransform::with_separator("aws", "-");
        let tools = vec![make_tool("s3_list")];
        let result = t.transform_tools(tools).await.unwrap();
        assert_eq!(result[0].name, "aws-s3_list");
    }

    #[tokio::test]
    async fn namespace_transform_custom_separator_strips_on_invoke() {
        let t = NamespaceTransform::with_separator("aws", "-");
        let (tool, _) = t
            .transform_invoke("aws-s3_list", json!({}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tool, "s3_list");
    }
}
