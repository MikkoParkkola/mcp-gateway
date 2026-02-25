//! `RenameTransform` — rename individual tools.
//!
//! Useful for normalising tool names across providers or for creating
//! stable API aliases when upstream names change.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value;

use crate::protocol::Tool;
use crate::{provider::Transform, Result};

/// Renames individual tools based on a mapping table.
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
/// use mcp_gateway::provider::transforms::RenameTransform;
///
/// let mut map = HashMap::new();
/// map.insert("brave_web_search".to_string(), "web_search".to_string());
/// let t = RenameTransform::new(map);
/// ```
pub struct RenameTransform {
    /// `old_name` → `new_name`
    renames: HashMap<String, String>,
    /// Reverse map for stripping on invoke: `new_name` → `old_name`
    reverse: HashMap<String, String>,
}

impl RenameTransform {
    /// Create from an explicit `old → new` mapping.
    #[must_use]
    pub fn new(renames: HashMap<String, String>) -> Self {
        let reverse = renames
            .iter()
            .map(|(k, v)| (v.clone(), k.clone()))
            .collect();
        Self { renames, reverse }
    }

    /// Convenience builder from a list of `(old, new)` pairs.
    #[must_use]
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let renames: HashMap<_, _> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self::new(renames)
    }
}

#[async_trait]
impl Transform for RenameTransform {
    async fn transform_tools(&self, tools: Vec<Tool>) -> Result<Vec<Tool>> {
        Ok(tools
            .into_iter()
            .map(|mut t| {
                if let Some(new_name) = self.renames.get(&t.name) {
                    t.name = new_name.clone();
                }
                t
            })
            .collect())
    }

    async fn transform_invoke(
        &self,
        tool: &str,
        args: Value,
    ) -> Result<Option<(String, Value)>> {
        // If the caller used the new (aliased) name, translate back to original.
        let resolved = self
            .reverse
            .get(tool)
            .cloned()
            .unwrap_or_else(|| tool.to_string());
        Ok(Some((resolved, args)))
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
    async fn rename_renames_tool_in_list() {
        // GIVEN: rename "old" → "new"
        let t = RenameTransform::from_pairs(&[("old_name", "new_name")]);
        let tools = vec![make_tool("old_name"), make_tool("untouched")];

        // WHEN: transforming tools
        let result = t.transform_tools(tools).await.unwrap();

        // THEN: renamed and untouched
        assert_eq!(result[0].name, "new_name");
        assert_eq!(result[1].name, "untouched");
    }

    #[tokio::test]
    async fn rename_strips_alias_on_invoke() {
        // GIVEN: "brave_search" aliased to "web_search"
        let t = RenameTransform::from_pairs(&[("brave_search", "web_search")]);

        // WHEN: invoking with the alias
        let (resolved, _) = t
            .transform_invoke("web_search", json!({}))
            .await
            .unwrap()
            .unwrap();

        // THEN: original name restored for inner provider
        assert_eq!(resolved, "brave_search");
    }

    #[tokio::test]
    async fn rename_passes_unknown_tool_unchanged_on_invoke() {
        let t = RenameTransform::from_pairs(&[("a", "b")]);
        let (tool, _) = t
            .transform_invoke("other_tool", json!({}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tool, "other_tool");
    }

    #[tokio::test]
    async fn rename_result_passes_through() {
        let t = RenameTransform::from_pairs(&[]);
        let val = json!({"k": "v"});
        let result = t.transform_result("t", val.clone()).await.unwrap();
        assert_eq!(result, val);
    }

    #[tokio::test]
    async fn rename_empty_mapping_noop() {
        let t = RenameTransform::new(HashMap::new());
        let tools = vec![make_tool("a")];
        let result = t.transform_tools(tools).await.unwrap();
        assert_eq!(result[0].name, "a");
    }
}
