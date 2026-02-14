//! Agent-UX validation rules
//!
//! Based on Phil Schmid's "MCP is a User Interface for Agents" principles:
//!
//! 1. **Outcomes, Not Operations** - Tools should achieve goals, not wrap API operations
//! 2. **Flatten Your Arguments** - Use primitives, not nested objects
//! 3. **Instructions are Context** - Documentation is agent context
//! 4. **Curate Ruthlessly** - Return only what's needed
//! 5. **Name for Discovery** - Service-prefixed, searchable names
//! 6. **Paginate Large Results** - Include pagination and metadata

use crate::protocol::Tool;
use crate::Result;
use super::{ValidationResult, Severity};
use regex::Regex;
use std::sync::OnceLock;

/// Validation rule trait
#[allow(clippy::unnecessary_literal_bound)]
pub trait Rule: Send + Sync {
    /// Get rule code (e.g., "AX-001")
    fn code(&self) -> &str;

    /// Get rule name/principle
    fn name(&self) -> &str;

    /// Get rule description
    fn description(&self) -> &str;

    /// Check a tool against this rule
    ///
    /// # Errors
    ///
    /// Returns an error if the validation check encounters an internal failure.
    fn check(&self, tool: &Tool) -> Result<ValidationResult>;
}

// Re-export schema rules
pub use super::rules_schema::{SchemaCompletenessRule, ConflictDetectionRule, NamingConsistencyRule};

/// Collection of all validation rules
pub struct ValidationRules {
    rules: Vec<Box<dyn Rule>>,
}

impl Default for ValidationRules {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidationRules {
    /// Create default rule set
    #[must_use]
    pub fn new() -> Self {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(OutcomeOrientedRule),
            Box::new(FlatArgumentsRule),
            Box::new(DocumentationQualityRule),
            Box::new(ResponseCurationRule),
            Box::new(NamingDiscoveryRule),
            Box::new(PaginationRule),
            Box::new(SchemaCompletenessRule),
            Box::new(ConflictDetectionRule),
            Box::new(NamingConsistencyRule),
        ];

        Self { rules }
    }

    /// Get all rules
    #[must_use]
    pub fn all_rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }
}

/// AX-001: Outcomes, Not Operations
///
/// Tools should achieve agent goals, not wrap API operations.
/// Red flags: CRUD operations, API-wrapper naming
struct OutcomeOrientedRule;

#[allow(clippy::unnecessary_literal_bound)]
impl Rule for OutcomeOrientedRule {
    fn code(&self) -> &str {
        "AX-001"
    }

    fn name(&self) -> &str {
        "Outcomes, Not Operations"
    }

    fn description(&self) -> &str {
        "Tools should achieve goals, not wrap API operations"
    }

    fn check(&self, tool: &Tool) -> Result<ValidationResult> {
        let mut result = ValidationResult::new(self.code(), self.name(), &tool.name);

        let name_lower = tool.name.to_lowercase();
        let desc = tool.description.as_deref().unwrap_or("");
        let desc_lower = desc.to_lowercase();

        // CRUD patterns that suggest operation-oriented design
        let crud_patterns = [
            "create_", "read_", "update_", "delete_",
            "get_", "set_", "list_", "fetch_",
            "retrieve_", "insert_", "remove_", "add_",
        ];

        // Check name for CRUD patterns
        for pattern in &crud_patterns {
            if name_lower.starts_with(pattern) {
                result.add_issue(format!("Name '{}' starts with '{}' suggesting operation, not outcome", tool.name, pattern));
                result.add_suggestion("Rename to describe what agent achieves (e.g., 'find_', 'search_', 'analyze_')");
                break;
            }
        }

        // Check for API-wrapper language in description
        let api_wrapper_terms = [
            "calls the api", "api endpoint", "rest api",
            "wrapper", "proxy to", "forwards to",
        ];

        for term in &api_wrapper_terms {
            if desc_lower.contains(term) {
                result.add_issue(format!("Description mentions '{term}' - focus on agent outcomes, not implementation"));
                result.add_suggestion("Describe what the agent accomplishes, not how the API is called");
                break;
            }
        }

        // Positive patterns: outcome verbs
        let outcome_verbs = [
            "check", "find", "search", "analyze", "summarize",
            "extract", "generate", "transform", "validate",
            "calculate", "compare", "discover", "identify",
        ];

        let has_outcome_verb = outcome_verbs.iter().any(|v|
            name_lower.contains(v) || desc_lower.contains(v)
        );

        if !has_outcome_verb && result.issues.is_empty() {
            result.add_issue("Tool lacks outcome-oriented verbs in name or description");
            result.add_suggestion("Use action verbs that describe agent goals: find, search, analyze, etc.");
        }

        // Calculate score
        let score = if result.issues.is_empty() {
            1.0
        } else if has_outcome_verb {
            0.7 // Has some outcome language but also issues
        } else {
            0.3 // Pure CRUD/API wrapper
        };

        let severity = if score < 0.5 {
            Severity::Fail
        } else if score < 0.8 {
            Severity::Warn
        } else {
            Severity::Pass
        };

        // Update passed status based on final severity and score
        result.passed = result.issues.is_empty() && severity == Severity::Pass;

        Ok(result.with_score(score).with_severity(severity))
    }
}

/// AX-002: Flatten Your Arguments
///
/// Arguments should be primitives or enums, not nested objects
struct FlatArgumentsRule;

#[allow(clippy::unnecessary_literal_bound)]
impl Rule for FlatArgumentsRule {
    fn code(&self) -> &str {
        "AX-002"
    }

    fn name(&self) -> &str {
        "Flatten Your Arguments"
    }

    fn description(&self) -> &str {
        "Arguments should be primitives/enums, not nested objects"
    }

    fn check(&self, tool: &Tool) -> Result<ValidationResult> {
        let mut result = ValidationResult::new(self.code(), self.name(), &tool.name);

        let properties = tool.input_schema
            .get("properties")
            .and_then(|p| p.as_object());

        if let Some(props) = properties {
            let mut nesting_count = 0;

            for (name, prop) in props {
                let prop_type = prop.get("type").and_then(|t| t.as_str()).unwrap_or("");

                // Check for nested objects
                if prop_type == "object" {
                    result.add_issue(format!("Parameter '{name}' is a nested object - flatten to primitives"));
                    nesting_count += 1;
                }

                // Check for arrays of objects
                if prop_type == "array" {
                    if let Some(items) = prop.get("items") {
                        let items_type = items.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        if items_type == "object" {
                            result.add_issue(format!("Parameter '{name}' is an array of objects - simplify structure"));
                            nesting_count += 1;
                        }
                    }
                }
            }

            if nesting_count > 0 {
                result.add_suggestion("Use primitives: string, number, boolean, enum");
                result.add_suggestion("For complex data, use multiple flat parameters or string encoding (JSON, CSV)");
            }

            // Score based on nesting depth
            let score = if nesting_count == 0 {
                1.0
            } else {
                (1.0 - (f64::from(nesting_count) * 0.3)).max(0.0)
            };

            let severity = if score < 0.5 {
                Severity::Fail
            } else if score < 0.8 {
                Severity::Warn
            } else {
                Severity::Pass
            };

            result.passed = result.issues.is_empty() && severity == Severity::Pass;

            Ok(result.with_score(score).with_severity(severity))
        } else {
            // No properties defined - give neutral score
            result.passed = true;
            Ok(result.with_score(0.5).with_severity(Severity::Info))
        }
    }
}

/// AX-003: Instructions are Context
///
/// Docstrings and error messages are agent context, not just human documentation
struct DocumentationQualityRule;

#[allow(clippy::unnecessary_literal_bound)]
impl Rule for DocumentationQualityRule {
    fn code(&self) -> &str {
        "AX-003"
    }

    fn name(&self) -> &str {
        "Instructions are Context"
    }

    fn description(&self) -> &str {
        "Documentation should provide rich context for agents"
    }

    fn check(&self, tool: &Tool) -> Result<ValidationResult> {
        let mut result = ValidationResult::new(self.code(), self.name(), &tool.name);

        let desc = tool.description.as_deref().unwrap_or("");
        let mut quality_score = 1.0;

        // Check description length (too short lacks context)
        if desc.len() < 50 {
            result.add_issue("Description too short - agents need rich context");
            result.add_suggestion("Add 2-3 sentences explaining when to use this tool and what it returns");
            quality_score -= 0.3;
        }

        // Check for contextual keywords
        let context_keywords = ["use", "when", "returns", "helps", "provides", "enables"];
        let has_context = context_keywords.iter().any(|k| desc.to_lowercase().contains(k));

        if !has_context {
            result.add_issue("Description lacks usage guidance");
            result.add_suggestion("Explain WHEN to use this tool and WHAT it provides");
            quality_score -= 0.2;
        }

        // Check parameter descriptions
        let properties = tool.input_schema
            .get("properties")
            .and_then(|p| p.as_object());

        if let Some(props) = properties {
            let mut missing_desc = 0;

            for (name, prop) in props {
                if prop.get("description").is_none_or(|d| d.as_str().unwrap_or("").is_empty()) {
                    result.add_issue(format!("Parameter '{name}' missing description"));
                    missing_desc += 1;
                }
            }

            if missing_desc > 0 {
                result.add_suggestion("Add descriptions to all parameters with examples");
                quality_score -= f64::from(missing_desc) * 0.15;
            }
        }

        // Check for examples
        let has_example = desc.contains("example") || desc.contains("e.g.") || desc.contains("for instance");
        if !has_example && desc.len() > 50 {
            result.add_issue("No examples provided");
            result.add_suggestion("Include concrete examples of usage");
            quality_score -= 0.1;
        }

        quality_score = quality_score.max(0.0);

        let severity = if quality_score < 0.5 {
            Severity::Fail
        } else if quality_score < 0.7 {
            Severity::Warn
        } else if quality_score < 0.9 {
            Severity::Info
        } else {
            Severity::Pass
        };

        result.passed = result.issues.is_empty() || severity == Severity::Pass || severity == Severity::Info;

        Ok(result.with_score(quality_score).with_severity(severity))
    }
}

/// AX-004: Curate Ruthlessly
///
/// Return only what the agent needs, not full API responses
struct ResponseCurationRule;

#[allow(clippy::unnecessary_literal_bound)]
impl Rule for ResponseCurationRule {
    fn code(&self) -> &str {
        "AX-004"
    }

    fn name(&self) -> &str {
        "Curate Ruthlessly"
    }

    fn description(&self) -> &str {
        "Return only what agent needs, not full API responses"
    }

    fn check(&self, tool: &Tool) -> Result<ValidationResult> {
        let mut result = ValidationResult::new(self.code(), self.name(), &tool.name);

        let desc = tool.description.as_deref().unwrap_or("").to_lowercase();
        let mut curation_score: f64 = 1.0;

        // Red flags: returning everything
        let over_return_patterns = [
            ("all data", "Returning 'all data' - consider filtering/summarizing"),
            ("full response", "Returning 'full response' - curate to essential fields"),
            ("entire", "Returning 'entire' response - extract key information"),
            ("complete", "Returning 'complete' data - select relevant subset"),
        ];

        for (pattern, issue) in &over_return_patterns {
            if desc.contains(pattern) {
                result.add_issue(issue.to_string());
                curation_score -= 0.3;
                break;
            }
        }

        // Check output schema if present
        if let Some(output_schema) = &tool.output_schema {
            let properties = output_schema
                .get("properties")
                .and_then(|p| p.as_object());

            if let Some(props) = properties {
                let field_count = props.len();

                // Too many fields suggests lack of curation
                if field_count > 15 {
                    result.add_issue(format!("Output has {field_count} fields - consider curating to essential data"));
                    result.add_suggestion("Reduce to 5-10 most relevant fields for agent decision-making");
                    curation_score -= 0.2;
                } else if field_count > 10 {
                    result.add_issue(format!("Output has {field_count} fields - verify all are necessary"));
                    result.add_suggestion("Review if all fields are needed for agent tasks");
                    curation_score -= 0.1;
                }
            }
        }

        // Positive signals
        let curation_keywords = ["summarize", "extract", "key", "relevant", "essential", "filtered"];
        let has_curation = curation_keywords.iter().any(|k| desc.contains(k));

        if has_curation {
            result.add_suggestion("Good: Tool indicates data curation");
        } else if curation_score < 1.0 {
            result.add_suggestion("Focus on extracting key information, not dumping full API responses");
        }

        curation_score = curation_score.max(0.0);

        let severity = if curation_score < 0.5 {
            Severity::Warn
        } else if curation_score < 0.8 {
            Severity::Info
        } else {
            Severity::Pass
        };

        result.passed = result.issues.is_empty() || severity == Severity::Pass || severity == Severity::Info;

        Ok(result.with_score(curation_score).with_severity(severity))
    }
}

/// AX-005: Name for Discovery
///
/// Service-prefixed names for easy discovery in large tool lists
struct NamingDiscoveryRule;

#[allow(clippy::unnecessary_literal_bound)]
impl Rule for NamingDiscoveryRule {
    fn code(&self) -> &str {
        "AX-005"
    }

    fn name(&self) -> &str {
        "Name for Discovery"
    }

    fn description(&self) -> &str {
        "Service-prefixed names for easy discovery"
    }

    fn check(&self, tool: &Tool) -> Result<ValidationResult> {
        // Check for service prefix pattern (service_action)
        static SEPARATOR_RE: OnceLock<Regex> = OnceLock::new();

        let mut result = ValidationResult::new(self.code(), self.name(), &tool.name);
        let mut discovery_score: f64 = 1.0;

        let separator_re = SEPARATOR_RE.get_or_init(|| Regex::new(r"[_-]").unwrap());

        let parts: Vec<&str> = separator_re.split(&tool.name).collect();

        if parts.len() < 2 {
            result.add_issue("No service prefix - hard to discover in large tool lists");
            result.add_suggestion("Use pattern: service_action (e.g., github_search_issues, slack_send_message)");
            discovery_score -= 0.4;
        }

        // Check name length
        if tool.name.len() < 5 {
            result.add_issue("Name too short for good discoverability");
            result.add_suggestion("Use descriptive names that clearly indicate purpose");
            discovery_score -= 0.2;
        }

        // Check for ambiguous names
        let ambiguous_terms = ["tool", "handler", "helper", "util", "misc"];
        for term in &ambiguous_terms {
            if tool.name.to_lowercase().contains(term) {
                result.add_issue(format!("Name contains ambiguous term '{term}'"));
                result.add_suggestion("Use specific, descriptive names that indicate the service and action");
                discovery_score -= 0.2;
                break;
            }
        }

        // Check for consistent naming convention
        let has_snake_case = tool.name.contains('_');
        let has_kebab_case = tool.name.contains('-');
        let has_camel_case = tool.name.chars().any(char::is_uppercase);

        let conventions_used = [has_snake_case, has_kebab_case, has_camel_case]
            .iter()
            .filter(|&&x| x)
            .count();

        if conventions_used > 1 {
            result.add_issue("Mixed naming conventions (snake_case, kebab-case, camelCase)");
            result.add_suggestion("Use consistent snake_case for tool names");
            discovery_score -= 0.1;
        }

        discovery_score = discovery_score.max(0.0);

        let severity = if discovery_score < 0.5 {
            Severity::Warn
        } else if discovery_score < 0.8 {
            Severity::Info
        } else {
            Severity::Pass
        };

        result.passed = result.issues.is_empty() || severity == Severity::Pass || severity == Severity::Info;

        Ok(result.with_score(discovery_score).with_severity(severity))
    }
}

/// AX-006: Paginate Large Results
///
/// Include pagination params and metadata for list operations
struct PaginationRule;

#[allow(clippy::unnecessary_literal_bound)]
impl Rule for PaginationRule {
    fn code(&self) -> &str {
        "AX-006"
    }

    fn name(&self) -> &str {
        "Paginate Large Results"
    }

    fn description(&self) -> &str {
        "Include pagination for list operations with metadata"
    }

    fn check(&self, tool: &Tool) -> Result<ValidationResult> {
        let mut result = ValidationResult::new(self.code(), self.name(), &tool.name);

        let desc = tool.description.as_deref().unwrap_or("").to_lowercase();
        let name_lower = tool.name.to_lowercase();

        // Determine if this is a list/search operation
        let list_indicators = ["list", "search", "find", "query", "all", "multiple"];
        let is_list_operation = list_indicators.iter().any(|i|
            name_lower.contains(i) || desc.contains(i)
        );

        if !is_list_operation {
            // Not a list operation, pagination not required
            result.passed = true;
            return Ok(result.with_score(1.0).with_severity(Severity::Pass));
        }

        // Check for pagination parameters
        let properties = tool.input_schema
            .get("properties")
            .and_then(|p| p.as_object());

        let pagination_params = ["limit", "offset", "page", "cursor", "page_size", "max_results"];
        let has_pagination = properties.is_some_and(|props| {
            pagination_params.iter().any(|param| props.contains_key(*param))
        });

        let mut pagination_score: f64 = 1.0;

        if !has_pagination {
            result.add_issue("List operation lacks pagination parameters");
            result.add_suggestion("Add 'limit' and 'offset' (or 'page' and 'page_size') parameters");
            pagination_score -= 0.5;
        }

        // Check output schema for pagination metadata
        if let Some(output_schema) = &tool.output_schema {
            let properties = output_schema
                .get("properties")
                .and_then(|p| p.as_object());

            let metadata_fields = ["total", "total_count", "has_more", "next_cursor", "page_info"];
            let has_metadata = properties.is_some_and(|props| {
                metadata_fields.iter().any(|field| props.contains_key(*field))
            });

            if !has_metadata {
                result.add_issue("Output lacks pagination metadata (total_count, has_more, etc.)");
                result.add_suggestion("Include metadata fields: total_count, has_more, next_cursor");
                pagination_score -= 0.3;
            }
        } else {
            // No output schema defined for list operation
            result.add_issue("List operation should define output schema with pagination metadata");
            result.add_suggestion("Define output schema including items array and pagination metadata");
            pagination_score -= 0.2;
        }

        pagination_score = pagination_score.max(0.0);

        let severity = if pagination_score < 0.5 {
            Severity::Fail
        } else if pagination_score < 0.8 {
            Severity::Warn
        } else {
            Severity::Pass
        };

        result.passed = result.issues.is_empty() || severity == Severity::Pass;

        Ok(result.with_score(pagination_score).with_severity(severity))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    #[test]
    fn test_outcome_oriented_rule_pass() {
        let rule = OutcomeOrientedRule;
        let tool = create_tool(
            "github_search_issues",
            "Find and analyze GitHub issues matching search criteria",
            json!({"type": "object", "properties": {}})
        );

        let result = rule.check(&tool).unwrap();
        assert!(result.score > 0.8);
    }

    #[test]
    fn test_outcome_oriented_rule_fail() {
        let rule = OutcomeOrientedRule;
        let tool = create_tool(
            "get_user",
            "Calls the API endpoint to retrieve user data",
            json!({"type": "object", "properties": {}})
        );

        let result = rule.check(&tool).unwrap();
        assert!(result.score < 0.5);
        assert!(!result.issues.is_empty());
    }

    #[test]
    fn test_flat_arguments_rule_pass() {
        let rule = FlatArgumentsRule;
        let tool = create_tool(
            "search",
            "Search",
            json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "number"}
                }
            })
        );

        let result = rule.check(&tool).unwrap();
        assert!(result.score > 0.9);
    }

    #[test]
    fn test_flat_arguments_rule_fail() {
        let rule = FlatArgumentsRule;
        let tool = create_tool(
            "search",
            "Search",
            json!({
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "object",
                        "properties": {"field": {"type": "string"}}
                    }
                }
            })
        );

        let result = rule.check(&tool).unwrap();
        assert!(result.score < 0.8);
        assert!(!result.issues.is_empty());
    }

    #[test]
    fn test_documentation_quality_good() {
        let rule = DocumentationQualityRule;
        let tool = create_tool(
            "search",
            "Search the knowledge base for relevant documents. Use this when you need to find information about a specific topic. Returns a list of matching documents with relevance scores.",
            json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query string"
                    }
                }
            })
        );

        let result = rule.check(&tool).unwrap();
        assert!(result.score > 0.8);
    }

    #[test]
    fn test_naming_discovery_good() {
        let rule = NamingDiscoveryRule;
        let tool = create_tool(
            "github_search_issues",
            "Search GitHub issues",
            json!({"type": "object"})
        );

        let result = rule.check(&tool).unwrap();
        assert!(result.score > 0.8);
    }

    #[test]
    fn test_naming_discovery_bad() {
        let rule = NamingDiscoveryRule;
        let tool = create_tool(
            "search",
            "Search",
            json!({"type": "object"})
        );

        let result = rule.check(&tool).unwrap();
        assert!(result.score < 0.7);
    }

    #[test]
    fn test_pagination_rule_list_operation() {
        let rule = PaginationRule;
        let tool = create_tool(
            "list_users",
            "List all users",
            json!({
                "type": "object",
                "properties": {
                    "limit": {"type": "number"},
                    "offset": {"type": "number"}
                }
            })
        );

        let result = rule.check(&tool).unwrap();
        // Has pagination params but no output schema
        assert!(result.score > 0.4);
    }

}
