//! `FilterTransform` — allow/deny tools by name pattern.
//!
//! Pattern matching supports:
//! - Exact names: `"gmail_search"` matches only that tool.
//! - Glob suffix: `"gmail_*"` matches any tool starting with `"gmail_"`.
//!
//! # Precedence
//!
//! 1. If the `allow` list is non-empty, a tool must match at least one
//!    allow pattern — otherwise it is denied, regardless of the deny list.
//! 2. If the tool matches any deny pattern, it is denied.
//! 3. Otherwise it is allowed.

use async_trait::async_trait;
use serde_json::Value;

use crate::protocol::Tool;
use crate::{provider::Transform, Result};

/// Filters the tool set and blocks invocations based on allow/deny patterns.
///
/// # Example
///
/// ```rust
/// use mcp_gateway::provider::transforms::FilterTransform;
///
/// let t = FilterTransform::allow(&["search*", "weather"]);
/// // Only tools matching "search*" or exactly "weather" are exposed.
/// ```
pub struct FilterTransform {
    allow: Vec<String>,
    deny: Vec<String>,
}

impl FilterTransform {
    /// Create a filter with only an allow list (deny everything else).
    #[must_use]
    pub fn allow(patterns: &[impl AsRef<str>]) -> Self {
        Self {
            allow: patterns.iter().map(|p| p.as_ref().to_string()).collect(),
            deny: Vec::new(),
        }
    }

    /// Create a filter with only a deny list (allow everything else).
    #[must_use]
    pub fn deny(patterns: &[impl AsRef<str>]) -> Self {
        Self {
            allow: Vec::new(),
            deny: patterns.iter().map(|p| p.as_ref().to_string()).collect(),
        }
    }

    /// Create a filter with explicit allow and deny lists.
    ///
    /// Allow list takes precedence: if non-empty, only listed tools survive.
    #[must_use]
    pub fn new(allow: Vec<String>, deny: Vec<String>) -> Self {
        Self { allow, deny }
    }

    /// Test whether a tool name is allowed by this filter.
    #[must_use]
    pub fn is_allowed(&self, tool: &str) -> bool {
        // Allow list — if populated, tool must match at least one entry.
        if !self.allow.is_empty() && !self.allow.iter().any(|p| matches_pattern(p, tool)) {
            return false;
        }
        // Deny list — tool must not match any deny pattern.
        !self.deny.iter().any(|p| matches_pattern(p, tool))
    }
}

/// Match a pattern against a tool name.
///
/// Supports `*` as a wildcard suffix only (e.g. `"gmail_*"` matches
/// any tool starting with `"gmail_"`).  For simplicity, `*` anywhere
/// else in the pattern is treated as a literal character.
fn matches_pattern(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        pattern == name
    }
}

#[async_trait]
impl Transform for FilterTransform {
    async fn transform_tools(&self, tools: Vec<Tool>) -> Result<Vec<Tool>> {
        Ok(tools
            .into_iter()
            .filter(|t| self.is_allowed(&t.name))
            .collect())
    }

    async fn transform_invoke(
        &self,
        tool: &str,
        args: Value,
    ) -> Result<Option<(String, Value)>> {
        if self.is_allowed(tool) {
            Ok(Some((tool.to_string(), args)))
        } else {
            Ok(None)
        }
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

    // ── matches_pattern ──────────────────────────────────────────────────

    #[test]
    fn pattern_exact_match() {
        assert!(matches_pattern("gmail_search", "gmail_search"));
        assert!(!matches_pattern("gmail_search", "gmail_send"));
    }

    #[test]
    fn pattern_glob_suffix_matches_prefix() {
        assert!(matches_pattern("gmail_*", "gmail_search"));
        assert!(matches_pattern("gmail_*", "gmail_send"));
        assert!(!matches_pattern("gmail_*", "brave_search"));
    }

    #[test]
    fn pattern_star_only_matches_everything() {
        assert!(matches_pattern("*", "any_tool"));
        assert!(matches_pattern("*", "gmail_search"));
    }

    // ── FilterTransform::is_allowed ──────────────────────────────────────

    #[test]
    fn filter_allow_list_permits_matching_tool() {
        let f = FilterTransform::allow(&["search", "weather"]);
        assert!(f.is_allowed("search"));
        assert!(f.is_allowed("weather"));
        assert!(!f.is_allowed("forecast"));
    }

    #[test]
    fn filter_allow_glob_permits_prefix_tools() {
        let f = FilterTransform::allow(&["gmail_*"]);
        assert!(f.is_allowed("gmail_search"));
        assert!(f.is_allowed("gmail_send"));
        assert!(!f.is_allowed("brave_search"));
    }

    #[test]
    fn filter_deny_list_blocks_matching_tool() {
        let f = FilterTransform::deny(&["danger*"]);
        assert!(!f.is_allowed("danger_delete"));
        assert!(f.is_allowed("safe_read"));
    }

    #[test]
    fn filter_empty_lists_allows_everything() {
        let f = FilterTransform::new(vec![], vec![]);
        assert!(f.is_allowed("anything"));
    }

    // ── transform_tools ──────────────────────────────────────────────────

    #[tokio::test]
    async fn filter_transform_tools_removes_denied() {
        // GIVEN: filter that allows only "safe_*"
        let f = FilterTransform::allow(&["safe_*"]);
        let tools = vec![make_tool("safe_read"), make_tool("danger_delete")];

        // WHEN: transforming
        let result = f.transform_tools(tools).await.unwrap();

        // THEN: only "safe_read" survives
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "safe_read");
    }

    #[tokio::test]
    async fn filter_transform_tools_empty_input() {
        let f = FilterTransform::allow(&["x"]);
        let result = f.transform_tools(vec![]).await.unwrap();
        assert!(result.is_empty());
    }

    // ── transform_invoke ─────────────────────────────────────────────────

    #[tokio::test]
    async fn filter_invoke_allowed_tool_passes() {
        let f = FilterTransform::allow(&["search"]);
        let res = f.transform_invoke("search", json!({})).await.unwrap();
        assert!(res.is_some());
        let (tool, _) = res.unwrap();
        assert_eq!(tool, "search");
    }

    #[tokio::test]
    async fn filter_invoke_denied_tool_returns_none() {
        let f = FilterTransform::allow(&["search"]);
        let res = f.transform_invoke("delete", json!({})).await.unwrap();
        assert!(res.is_none());
    }

    // ── transform_result ─────────────────────────────────────────────────

    #[tokio::test]
    async fn filter_result_passes_through_unchanged() {
        let f = FilterTransform::new(vec![], vec![]);
        let val = json!({"data": 42});
        let result = f.transform_result("any", val.clone()).await.unwrap();
        assert_eq!(result, val);
    }
}
