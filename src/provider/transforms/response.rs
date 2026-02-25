//! `ResponseTransform` — project and redact fields in tool responses.
//!
//! Wraps the existing [`TransformPipeline`] from `crate::transform` to
//! expose it through the provider middleware chain.

use async_trait::async_trait;
use serde_json::Value;

use crate::protocol::Tool;
use crate::transform::{TransformConfig, TransformPipeline};
use crate::{provider::Transform, Result};

/// Shapes tool responses using the existing transform pipeline.
///
/// Supports:
/// - **project**: keep only listed JSON paths.
/// - **rename**: rename fields in the response.
/// - **redact**: replace sensitive patterns with placeholders.
/// - **format**: flatten / template the response.
///
/// # Example
///
/// ```rust
/// use mcp_gateway::provider::transforms::ResponseTransform;
/// use mcp_gateway::transform::TransformConfig;
///
/// let config = TransformConfig {
///     project: vec!["id".to_string(), "subject".to_string()],
///     ..Default::default()
/// };
/// let t = ResponseTransform::new(&config);
/// ```
pub struct ResponseTransform {
    pipeline: TransformPipeline,
}

impl ResponseTransform {
    /// Compile a `TransformConfig` into an executable response transform.
    #[must_use]
    pub fn new(config: &TransformConfig) -> Self {
        Self {
            pipeline: TransformPipeline::compile(config),
        }
    }
}

#[async_trait]
impl Transform for ResponseTransform {
    async fn transform_tools(&self, tools: Vec<Tool>) -> Result<Vec<Tool>> {
        // Response transforms do not modify tool definitions.
        Ok(tools)
    }

    async fn transform_invoke(
        &self,
        tool: &str,
        args: Value,
    ) -> Result<Option<(String, Value)>> {
        // Response transforms do not intercept the invocation request.
        Ok(Some((tool.to_string(), args)))
    }

    async fn transform_result(&self, _tool: &str, result: Value) -> Result<Value> {
        if self.pipeline.is_noop() {
            return Ok(result);
        }
        Ok(self.pipeline.apply(result))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transform::RedactRule;
    use serde_json::json;

    #[tokio::test]
    async fn response_transform_noop_passes_result_through() {
        // GIVEN: default (empty) transform config
        let t = ResponseTransform::new(&TransformConfig::default());
        let val = json!({"a": 1, "b": 2});

        // WHEN: transforming result
        let result = t.transform_result("tool", val.clone()).await.unwrap();

        // THEN: unchanged
        assert_eq!(result, val);
    }

    #[tokio::test]
    async fn response_transform_project_keeps_listed_fields() {
        // GIVEN: project config keeping only "id"
        let config = TransformConfig {
            project: vec!["id".to_string()],
            ..Default::default()
        };
        let t = ResponseTransform::new(&config);
        let val = json!({"id": "abc", "secret": "xyz"});

        // WHEN
        let result = t.transform_result("t", val).await.unwrap();

        // THEN: only "id" remains
        assert_eq!(result.get("id"), Some(&json!("abc")));
        assert!(result.get("secret").is_none() || result["secret"].is_null());
    }

    #[tokio::test]
    async fn response_transform_tool_list_unchanged() {
        // GIVEN: any transform
        let t = ResponseTransform::new(&TransformConfig::default());
        let tools = vec![crate::protocol::Tool {
            name: "x".to_string(),
            title: None,
            description: None,
            input_schema: json!({}),
            output_schema: None,
            annotations: None,
        }];

        // WHEN: transforming tools
        let result = t.transform_tools(tools.clone()).await.unwrap();

        // THEN: unchanged
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "x");
    }

    #[tokio::test]
    async fn response_transform_invoke_passes_through() {
        // GIVEN: any transform
        let t = ResponseTransform::new(&TransformConfig::default());

        // WHEN: transform_invoke called
        let result = t
            .transform_invoke("my_tool", json!({"arg": 1}))
            .await
            .unwrap();

        // THEN: unchanged passthrough
        let (tool, args) = result.unwrap();
        assert_eq!(tool, "my_tool");
        assert_eq!(args["arg"], 1);
    }

    #[tokio::test]
    async fn response_transform_redacts_sensitive_patterns() {
        // GIVEN: redact email addresses
        let config = TransformConfig {
            redact: vec![RedactRule {
                pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string(),
                replacement: "[REDACTED]".to_string(),
            }],
            ..Default::default()
        };
        let t = ResponseTransform::new(&config);
        let val = json!({"message": "Contact user@example.com for details"});

        // WHEN
        let result = t.transform_result("t", val).await.unwrap();

        // THEN: email replaced
        let msg = result["message"].as_str().unwrap();
        assert!(!msg.contains("user@example.com"));
        assert!(msg.contains("[REDACTED]"));
    }
}
