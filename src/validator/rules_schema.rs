//! Schema validation rules (AX-007, AX-008, AX-009)
//!
//! These rules validate JSON Schema completeness, detect conflicts across tools,
//! and enforce naming consistency.

use crate::protocol::Tool;
use crate::Result;
use super::{ValidationResult, Severity, Rule};

/// AX-007: Schema Completeness
///
/// Every input property must have: type, description; required array must exist
pub struct SchemaCompletenessRule;

#[allow(clippy::unnecessary_literal_bound)]
impl Rule for SchemaCompletenessRule {
    fn code(&self) -> &str {
        "AX-007"
    }

    fn name(&self) -> &str {
        "Schema Completeness"
    }

    fn description(&self) -> &str {
        "Every input property must have type and description; required array must exist"
    }

    fn check(&self, tool: &Tool) -> Result<ValidationResult> {
        let mut result = ValidationResult::new(self.code(), self.name(), &tool.name);

        let properties = tool.input_schema
            .get("properties")
            .and_then(|p| p.as_object());

        let Some(props) = properties else {
            result.add_issue("No input properties defined");
            result.add_suggestion("Define input properties with type and description for each");
            return Ok(result.with_score(0.2).with_severity(Severity::Fail));
        };

        if props.is_empty() {
            result.passed = true;
            return Ok(result.with_score(1.0).with_severity(Severity::Pass));
        }

        let total = props.len();
        let mut missing_type = 0u32;
        let mut missing_desc = 0u32;

        for (name, prop) in props {
            let has_type = prop.get("type").is_some_and(|t| !t.is_null());
            let has_desc = prop.get("description").is_some_and(|d| {
                d.as_str().is_some_and(|s| !s.is_empty())
            });

            if !has_type {
                result.add_issue(format!("Property '{name}' missing 'type'"));
                missing_type += 1;
            }
            if !has_desc {
                result.add_issue(format!("Property '{name}' missing 'description'"));
                missing_desc += 1;
            }
        }

        // Check for required array
        let has_required = tool.input_schema.get("required").is_some_and(|r| {
            r.as_array().is_some_and(|a| !a.is_empty())
        });

        if !has_required {
            result.add_issue("Missing 'required' array in input schema");
            result.add_suggestion("Define which properties are required");
        }

        let missing_total = missing_type + missing_desc;
        #[allow(clippy::cast_precision_loss)]
        let completeness = if total > 0 {
            1.0 - (f64::from(missing_total) / (total as f64 * 2.0))
        } else {
            1.0
        };

        let score = if has_required { completeness } else { (completeness - 0.1).max(0.0) };

        let severity = if score < 0.5 {
            Severity::Fail
        } else if score < 0.8 {
            Severity::Warn
        } else {
            Severity::Pass
        };

        if !result.issues.is_empty() {
            result.add_suggestion("Add 'type' and 'description' to every input property");
        }

        result.passed = result.issues.is_empty();

        Ok(result.with_score(score).with_severity(severity))
    }
}

/// AX-008: Cross-Capability Conflict Detection
///
/// Detects duplicate tool names and overlapping functionality across tools.
/// This rule requires multi-tool context; for single-tool validation it passes.
pub struct ConflictDetectionRule;

#[allow(clippy::unnecessary_literal_bound)]
impl Rule for ConflictDetectionRule {
    fn code(&self) -> &str {
        "AX-008"
    }

    fn name(&self) -> &str {
        "Cross-Capability Conflict Detection"
    }

    fn description(&self) -> &str {
        "Detects duplicate tool names and overlapping functionality"
    }

    fn check(&self, tool: &Tool) -> Result<ValidationResult> {
        // Single-tool check: verify the tool name is reasonable for coexistence.
        // The multi-tool conflict detection is done in `check_conflicts`.
        let mut result = ValidationResult::new(self.code(), self.name(), &tool.name);

        // Check for overly generic names that are likely to conflict
        let generic_names = [
            "search", "query", "find", "get", "fetch",
            "send", "create", "update", "delete",
        ];

        if generic_names.contains(&tool.name.to_lowercase().as_str()) {
            result.add_issue(format!(
                "Name '{}' is too generic and likely to conflict with other tools",
                tool.name
            ));
            result.add_suggestion("Use a service-prefixed name (e.g., 'brave_search' instead of 'search')");
            return Ok(result.with_score(0.4).with_severity(Severity::Warn));
        }

        result.passed = true;
        Ok(result.with_score(1.0).with_severity(Severity::Pass))
    }
}

impl ConflictDetectionRule {
    /// Check for conflicts across multiple tools.
    ///
    /// Returns additional `ValidationResult` entries for any conflicts found.
    #[must_use]
    pub fn check_conflicts(tools: &[Tool]) -> Vec<ValidationResult> {
        let mut results = Vec::new();
        let mut seen_names: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

        // Detect duplicate names
        for (idx, tool) in tools.iter().enumerate() {
            if let Some(&prev_idx) = seen_names.get(tool.name.as_str()) {
                let mut result = ValidationResult::new("AX-008", "Cross-Capability Conflict Detection", &tool.name);
                result.add_issue(format!(
                    "Duplicate tool name '{}' (also at index {prev_idx})",
                    tool.name
                ));
                result.add_suggestion("Rename one of the duplicates with a distinguishing prefix");
                results.push(result.with_score(0.0).with_severity(Severity::Fail));
            }
            seen_names.insert(&tool.name, idx);
        }

        // Detect overlapping functionality (tools with very similar names)
        for i in 0..tools.len() {
            for j in (i + 1)..tools.len() {
                let name_a = &tools[i].name;
                let name_b = &tools[j].name;

                // Check if one name is a substring of another (excluding prefix)
                let parts_a: Vec<&str> = name_a.split('_').collect();
                let parts_b: Vec<&str> = name_b.split('_').collect();

                // Same action verb with same service prefix suggests overlap
                if parts_a.len() >= 2
                    && parts_b.len() >= 2
                    && parts_a[0] == parts_b[0]
                    && parts_a.last() == parts_b.last()
                    && parts_a.len() != parts_b.len()
                {
                    let mut result = ValidationResult::new("AX-008", "Cross-Capability Conflict Detection", name_a);
                    result.add_issue(format!(
                        "Potential overlap: '{name_a}' and '{name_b}' share prefix and suffix"
                    ));
                    result.add_suggestion("Consider merging or clearly differentiating these tools");
                    results.push(result.with_score(0.6).with_severity(Severity::Warn));
                }
            }
        }

        results
    }
}

/// AX-009: Naming Consistency
///
/// Enforces consistent naming patterns within a set of tools:
/// all should use the same separator style and follow a common convention.
pub struct NamingConsistencyRule;

#[allow(clippy::unnecessary_literal_bound)]
impl Rule for NamingConsistencyRule {
    fn code(&self) -> &str {
        "AX-009"
    }

    fn name(&self) -> &str {
        "Naming Consistency"
    }

    fn description(&self) -> &str {
        "Enforces consistent naming patterns across tools"
    }

    fn check(&self, tool: &Tool) -> Result<ValidationResult> {
        // Single-tool check: verify consistent internal naming convention
        let mut result = ValidationResult::new(self.code(), self.name(), &tool.name);

        let name = &tool.name;

        // Check for mixed separators within one name
        let has_underscore = name.contains('_');
        let has_dash = name.contains('-');
        let has_upper = name.chars().any(char::is_uppercase);

        let convention_count = usize::from(has_underscore)
            + usize::from(has_dash)
            + usize::from(has_upper);

        if convention_count > 1 {
            result.add_issue(format!(
                "Name '{name}' mixes naming conventions (found {})",
                [
                    has_underscore.then_some("snake_case"),
                    has_dash.then_some("kebab-case"),
                    has_upper.then_some("camelCase"),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(", ")
            ));
            result.add_suggestion("Use consistent snake_case for tool names");
            return Ok(result.with_score(0.5).with_severity(Severity::Warn));
        }

        // Prefer snake_case
        if has_dash {
            result.add_issue(format!("Name '{name}' uses kebab-case instead of snake_case"));
            result.add_suggestion("Use snake_case for MCP tool names (e.g., 'my_tool' not 'my-tool')");
            return Ok(result.with_score(0.7).with_severity(Severity::Info));
        }

        if has_upper {
            result.add_issue(format!("Name '{name}' uses camelCase instead of snake_case"));
            result.add_suggestion("Use snake_case for MCP tool names (e.g., 'my_tool' not 'myTool')");
            return Ok(result.with_score(0.7).with_severity(Severity::Info));
        }

        result.passed = true;
        Ok(result.with_score(1.0).with_severity(Severity::Pass))
    }
}

impl NamingConsistencyRule {
    /// Check naming consistency across a set of tools.
    ///
    /// Returns additional `ValidationResult` entries for cross-tool inconsistencies.
    #[must_use]
    pub fn check_consistency(tools: &[Tool]) -> Vec<ValidationResult> {
        let mut results = Vec::new();

        if tools.len() < 2 {
            return results;
        }

        // Count naming conventions used across all tools
        let mut snake_count = 0usize;
        let mut kebab_count = 0usize;
        let mut camel_count = 0usize;

        for tool in tools {
            if tool.name.contains('_') {
                snake_count += 1;
            }
            if tool.name.contains('-') {
                kebab_count += 1;
            }
            if tool.name.chars().any(char::is_uppercase) {
                camel_count += 1;
            }
        }

        let conventions_used = usize::from(snake_count > 0)
            + usize::from(kebab_count > 0)
            + usize::from(camel_count > 0);

        if conventions_used > 1 {
            let mut result = ValidationResult::new(
                "AX-009",
                "Naming Consistency",
                "(cross-tool)",
            );
            result.add_issue(format!(
                "Mixed naming conventions across tools: {snake_count} snake_case, {kebab_count} kebab-case, {camel_count} camelCase"
            ));
            result.add_suggestion("Standardize all tool names to snake_case");
            results.push(result.with_score(0.4).with_severity(Severity::Warn));
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use crate::protocol::Tool;

    fn create_tool(name: &str, description: &str, input_schema: serde_json::Value) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: Some(description.to_string()),
            input_schema,
            output_schema: None,
            annotations: None,
        }
    }

    // ── AX-007: Schema Completeness ──────────────────────────────

    #[test]
    fn schema_completeness_pass_all_properties_typed_and_described() {
        let rule = SchemaCompletenessRule;
        let tool = create_tool(
            "brave_search",
            "Search the web",
            json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of results"
                    }
                },
                "required": ["query"]
            }),
        );

        let result = rule.check(&tool).unwrap();
        assert!(result.passed, "Expected pass, got issues: {:?}", result.issues);
        assert!(result.score > 0.8);
    }

    #[test]
    fn schema_completeness_fail_missing_type() {
        let rule = SchemaCompletenessRule;
        let tool = create_tool(
            "test_tool",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "query": {
                        "description": "Search query"
                    }
                },
                "required": ["query"]
            }),
        );

        let result = rule.check(&tool).unwrap();
        assert!(!result.passed);
        assert!(result.issues.iter().any(|i| i.contains("missing 'type'")));
    }

    #[test]
    fn schema_completeness_fail_missing_description() {
        let rule = SchemaCompletenessRule;
        let tool = create_tool(
            "test_tool",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string"
                    }
                },
                "required": ["query"]
            }),
        );

        let result = rule.check(&tool).unwrap();
        assert!(!result.passed);
        assert!(result.issues.iter().any(|i| i.contains("missing 'description'")));
    }

    #[test]
    fn schema_completeness_fail_no_required_array() {
        let rule = SchemaCompletenessRule;
        let tool = create_tool(
            "test_tool",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Query"
                    }
                }
            }),
        );

        let result = rule.check(&tool).unwrap();
        assert!(!result.passed);
        assert!(result.issues.iter().any(|i| i.contains("required")));
    }

    #[test]
    fn schema_completeness_fail_no_properties() {
        let rule = SchemaCompletenessRule;
        let tool = create_tool(
            "test_tool",
            "A tool",
            json!({"type": "object"}),
        );

        let result = rule.check(&tool).unwrap();
        assert!(!result.passed);
        assert!(result.severity == Severity::Fail);
    }

    // ── AX-008: Conflict Detection ──────────────────────────────

    #[test]
    fn conflict_detection_pass_specific_name() {
        let rule = ConflictDetectionRule;
        let tool = create_tool(
            "brave_search",
            "Search the web via Brave",
            json!({"type": "object", "properties": {}}),
        );

        let result = rule.check(&tool).unwrap();
        assert!(result.passed);
        assert!(result.score > 0.9);
    }

    #[test]
    fn conflict_detection_warn_generic_name() {
        let rule = ConflictDetectionRule;
        let tool = create_tool(
            "search",
            "Search things",
            json!({"type": "object", "properties": {}}),
        );

        let result = rule.check(&tool).unwrap();
        assert!(!result.passed);
        assert!(result.severity == Severity::Warn);
    }

    #[test]
    fn conflict_detection_cross_tool_duplicate_names() {
        let tools = vec![
            create_tool("brave_search", "Search A", json!({"type": "object", "properties": {}})),
            create_tool("brave_search", "Search B", json!({"type": "object", "properties": {}})),
        ];

        let results = ConflictDetectionRule::check_conflicts(&tools);
        assert!(!results.is_empty());
        assert!(results[0].issues.iter().any(|i| i.contains("Duplicate")));
    }

    #[test]
    fn conflict_detection_cross_tool_no_duplicates() {
        let tools = vec![
            create_tool("brave_search", "Search A", json!({"type": "object", "properties": {}})),
            create_tool("google_search", "Search B", json!({"type": "object", "properties": {}})),
        ];

        let results = ConflictDetectionRule::check_conflicts(&tools);
        // No duplicates, possibly no overlap either
        assert!(results.iter().all(|r| !r.issues.iter().any(|i| i.contains("Duplicate"))));
    }

    // ── AX-009: Naming Consistency ──────────────────────────────

    #[test]
    fn naming_consistency_pass_snake_case() {
        let rule = NamingConsistencyRule;
        let tool = create_tool(
            "brave_search_web",
            "Search",
            json!({"type": "object", "properties": {}}),
        );

        let result = rule.check(&tool).unwrap();
        assert!(result.passed);
        assert!(result.score > 0.9);
    }

    #[test]
    fn naming_consistency_warn_kebab_case() {
        let rule = NamingConsistencyRule;
        let tool = create_tool(
            "brave-search",
            "Search",
            json!({"type": "object", "properties": {}}),
        );

        let result = rule.check(&tool).unwrap();
        assert!(!result.passed);
        assert!(result.severity == Severity::Info);
    }

    #[test]
    fn naming_consistency_warn_mixed_conventions() {
        let rule = NamingConsistencyRule;
        let tool = create_tool(
            "brave_search-Web",
            "Search",
            json!({"type": "object", "properties": {}}),
        );

        let result = rule.check(&tool).unwrap();
        assert!(!result.passed);
        assert!(result.severity == Severity::Warn);
    }

    #[test]
    fn naming_consistency_cross_tool_mixed_conventions() {
        let tools = vec![
            create_tool("brave_search", "A", json!({"type": "object", "properties": {}})),
            create_tool("google-search", "B", json!({"type": "object", "properties": {}})),
        ];

        let results = NamingConsistencyRule::check_consistency(&tools);
        assert!(!results.is_empty());
        assert!(results[0].issues.iter().any(|i| i.contains("Mixed naming")));
    }

    #[test]
    fn naming_consistency_cross_tool_all_snake_case() {
        let tools = vec![
            create_tool("brave_search", "A", json!({"type": "object", "properties": {}})),
            create_tool("google_search", "B", json!({"type": "object", "properties": {}})),
        ];

        let results = NamingConsistencyRule::check_consistency(&tools);
        assert!(results.is_empty());
    }
}
