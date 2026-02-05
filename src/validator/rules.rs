//! Validation rules for agent-UX best practices

use crate::capability::CapabilityDefinition;
use serde::{Deserialize, Serialize};

/// A validation violation with severity and context
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Violation {
    /// Severity level
    pub severity: ViolationSeverity,
    /// Rule identifier
    pub rule_id: String,
    /// Human-readable message
    pub message: String,
    /// Tool name context
    pub tool_name: String,
    /// Optional suggestion for fixing
    pub suggestion: Option<String>,
}

/// Severity levels for violations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Critical issue that prevents good agent UX
    Error,
    /// Issue that degrades agent UX
    Warning,
    /// Minor improvement suggestion
    Info,
}

impl Violation {
    /// Create a new error violation
    pub fn error(rule_id: &str, message: String, tool_name: String) -> Self {
        Self {
            severity: ViolationSeverity::Error,
            rule_id: rule_id.to_string(),
            message,
            tool_name,
            suggestion: None,
        }
    }

    /// Create a new warning violation
    pub fn warning(rule_id: &str, message: String, tool_name: String) -> Self {
        Self {
            severity: ViolationSeverity::Warning,
            rule_id: rule_id.to_string(),
            message,
            tool_name,
            suggestion: None,
        }
    }

    /// Create a new info violation
    pub fn info(rule_id: &str, message: String, tool_name: String) -> Self {
        Self {
            severity: ViolationSeverity::Info,
            rule_id: rule_id.to_string(),
            message,
            tool_name,
            suggestion: None,
        }
    }

    /// Add a suggestion for fixing the violation
    pub fn with_suggestion(mut self, suggestion: String) -> Self {
        self.suggestion = Some(suggestion);
        self
    }
}

/// Check tool naming conventions
pub fn check_tool_naming(cap: &CapabilityDefinition) -> Vec<Violation> {
    let mut violations = Vec::new();
    let name = &cap.name;

    // Check name length
    if name.len() < 3 {
        violations.push(
            Violation::error(
                "tool_name_too_short",
                format!("Tool name '{name}' is too short (minimum 3 characters)"),
                name.clone(),
            )
            .with_suggestion("Use a descriptive verb phrase like 'searchDocuments' or 'sendEmail'".to_string()),
        );
    } else if name.len() > 50 {
        violations.push(Violation::warning(
            "tool_name_too_long",
            format!("Tool name '{name}' is very long ({} characters)", name.len()),
            name.clone(),
        ));
    }

    // Check for underscores (prefer camelCase)
    if name.contains('_') {
        violations.push(Violation::info(
            "tool_name_underscores",
            format!("Tool name '{name}' uses underscores; consider camelCase for better readability"),
            name.clone(),
        ));
    }

    // Check for generic names
    let generic_names = ["run", "execute", "do", "perform", "action", "tool", "function"];
    if generic_names.contains(&name.to_lowercase().as_str()) {
        violations.push(
            Violation::error(
                "tool_name_generic",
                format!("Tool name '{name}' is too generic and doesn't describe the action"),
                name.clone(),
            )
            .with_suggestion("Use a specific verb that describes what the tool does (e.g., 'calculateTax', 'generateReport')".to_string()),
        );
    }

    // Check if name starts with a verb (heuristic)
    let common_verbs = [
        "get", "set", "list", "create", "delete", "update", "search", "find", "fetch",
        "send", "receive", "calculate", "generate", "validate", "check", "analyze",
        "process", "convert", "transform", "parse", "format", "render", "query",
        "read", "write", "open", "close", "start", "stop", "pause", "resume",
    ];

    let name_lower = name.to_lowercase();
    let starts_with_verb = common_verbs
        .iter()
        .any(|verb| name_lower.starts_with(verb));

    if !starts_with_verb && name.len() >= 3 {
        violations.push(Violation::warning(
            "tool_name_no_verb",
            format!("Tool name '{name}' should start with an action verb for clarity"),
            name.clone(),
        ).with_suggestion("Prefix with a verb like 'get', 'list', 'create', 'search', etc.".to_string()));
    }

    violations
}

/// Check description quality
pub fn check_description_quality(cap: &CapabilityDefinition) -> Vec<Violation> {
    let mut violations = Vec::new();
    let name = &cap.name;
    let description = &cap.description;

    // Check if description exists
    if description.is_empty() {
        violations.push(
            Violation::error(
                "description_missing",
                format!("Tool '{name}' has no description"),
                name.clone(),
            )
            .with_suggestion(
                "Add a description explaining what the tool does and when to use it".to_string(),
            ),
        );
        return violations;
    }

    // Check description length
    if description.len() < 20 {
        violations.push(
            Violation::warning(
                "description_too_short",
                format!(
                    "Tool '{name}' description is very short ({} characters)",
                    description.len()
                ),
                name.clone(),
            )
            .with_suggestion(
                "Expand the description to explain WHEN and WHY to use this tool".to_string(),
            ),
        );
    }

    // Check if description explains WHEN to use (contains contextual words)
    let contextual_words = ["when", "use", "for", "if", "need", "want", "should"];
    let has_context = contextual_words
        .iter()
        .any(|word| description.to_lowercase().contains(word));

    if !has_context {
        violations.push(Violation::info(
            "description_no_context",
            format!("Tool '{name}' description doesn't explain when to use it"),
            name.clone(),
        ).with_suggestion("Add context like 'Use this tool when...' or 'Call this tool if the user needs...'".to_string()));
    }

    // Check if description is just repeating the name
    let name_words: Vec<&str> = name.split('_').collect();
    let desc_lower = description.to_lowercase();
    let name_repetition_count = name_words
        .iter()
        .filter(|word| word.len() > 3 && desc_lower.contains(&word.to_lowercase()))
        .count();

    if name_repetition_count >= name_words.len() && description.len() < 50 {
        violations.push(Violation::warning(
            "description_repeats_name",
            format!("Tool '{name}' description just repeats the name without adding context"),
            name.clone(),
        ).with_suggestion("Explain the purpose and usage context, not just what the name says".to_string()));
    }

    violations
}

/// Check parameter validation rules
pub fn check_parameter_validation(cap: &CapabilityDefinition) -> Vec<Violation> {
    let mut violations = Vec::new();
    let name = &cap.name;
    let schema = &cap.schema.input;

    // Skip if no schema
    if schema.is_null() || !schema.is_object() {
        return violations;
    }

    // Get properties
    let properties = schema.get("properties");
    let required = schema.get("required").and_then(|r| r.as_array());

    if let Some(props) = properties.and_then(|p| p.as_object()) {
        for (param_name, param_def) in props {
            // Check for generic parameter names
            let generic_params = ["input", "data", "params", "args", "options"];
            if generic_params.contains(&param_name.as_str()) {
                violations.push(Violation::warning(
                    "param_name_generic",
                    format!(
                        "Tool '{name}' has generic parameter name '{param_name}'"
                    ),
                    name.clone(),
                ).with_suggestion(format!("Use a specific name like 'query', 'userId', 'documentId' instead of '{param_name}'")));
            }

            // Check if required params have descriptions
            let is_required = required
                .as_ref()
                .map(|r| {
                    r.iter()
                        .any(|v| v.as_str() == Some(param_name.as_str()))
                })
                .unwrap_or(false);

            if is_required {
                let has_description = param_def
                    .get("description")
                    .and_then(|d| d.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);

                if !has_description {
                    violations.push(Violation::warning(
                        "required_param_no_description",
                        format!(
                            "Tool '{name}' has required parameter '{param_name}' without description"
                        ),
                        name.clone(),
                    ).with_suggestion("Add a description explaining what value to provide".to_string()));
                }
            }

            // Check enum cardinality
            if let Some(enum_values) = param_def.get("enum").and_then(|e| e.as_array()) {
                if enum_values.len() > 20 {
                    violations.push(Violation::warning(
                        "enum_too_many_values",
                        format!(
                            "Tool '{name}' parameter '{param_name}' has {} enum values (more than 20)",
                            enum_values.len()
                        ),
                        name.clone(),
                    ).with_suggestion("Consider using a string parameter with validation instead of a large enum".to_string()));
                }
            }
        }
    }

    violations
}

/// Check response design
pub fn check_response_design(cap: &CapabilityDefinition) -> Vec<Violation> {
    let mut violations = Vec::new();
    let name = &cap.name;
    let output_schema = &cap.schema.output;

    // Check if output schema is defined
    if output_schema.is_null() {
        violations.push(Violation::info(
            "no_output_schema",
            format!("Tool '{name}' has no output schema defined"),
            name.clone(),
        ).with_suggestion("Define an output schema to help agents understand the response structure".to_string()));
    } else if let Some(output_obj) = output_schema.as_object() {
        // Check if output has description
        if !output_obj.contains_key("description")
            && !output_obj.contains_key("title")
        {
            violations.push(Violation::info(
                "output_schema_no_description",
                format!("Tool '{name}' output schema has no description"),
                name.clone(),
            ));
        }
    }

    violations
}

/// Check naming consistency across tools (requires multiple tools)
/// For single tool validation, this checks internal consistency
pub fn check_naming_consistency(cap: &CapabilityDefinition) -> Vec<Violation> {
    let mut violations = Vec::new();
    let name = &cap.name;

    // Check if name uses consistent casing
    let has_uppercase = name.chars().any(|c| c.is_uppercase());
    let has_underscore = name.contains('_');
    let has_dash = name.contains('-');

    // Mixed conventions are a red flag
    if has_uppercase && (has_underscore || has_dash) {
        violations.push(Violation::info(
            "naming_mixed_convention",
            format!("Tool '{name}' mixes naming conventions (camelCase with underscores/dashes)"),
            name.clone(),
        ).with_suggestion("Use either camelCase or snake_case consistently, not both".to_string()));
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        AuthConfig, CacheConfig, CapabilityMetadata, ProvidersConfig, SchemaDefinition,
    };
    use serde_json::json;

    fn create_test_capability(
        name: &str,
        description: &str,
        input_schema: Option<serde_json::Value>,
    ) -> CapabilityDefinition {
        CapabilityDefinition {
            fulcrum: "1.0".to_string(),
            name: name.to_string(),
            description: description.to_string(),
            schema: SchemaDefinition {
                input: input_schema.unwrap_or(json!({})),
                output: serde_json::Value::Null,
            },
            providers: ProvidersConfig::default(),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata::default(),
        }
    }

    #[test]
    fn test_check_tool_naming_good() {
        let cap = create_test_capability("searchDocuments", "Search docs", None);
        let violations = check_tool_naming(&cap);
        assert!(violations.is_empty() || violations.iter().all(|v| v.severity == ViolationSeverity::Info));
    }

    #[test]
    fn test_check_tool_naming_generic() {
        let cap = create_test_capability("run", "Run things", None);
        let violations = check_tool_naming(&cap);
        assert!(violations
            .iter()
            .any(|v| v.rule_id == "tool_name_generic"));
    }

    #[test]
    fn test_check_tool_naming_too_short() {
        let cap = create_test_capability("ab", "Do stuff", None);
        let violations = check_tool_naming(&cap);
        assert!(violations
            .iter()
            .any(|v| v.rule_id == "tool_name_too_short"));
    }

    #[test]
    fn test_check_description_missing() {
        let cap = create_test_capability("searchDocs", "", None);
        let violations = check_description_quality(&cap);
        assert!(violations
            .iter()
            .any(|v| v.rule_id == "description_missing"));
    }

    #[test]
    fn test_check_description_too_short() {
        let cap = create_test_capability("searchDocs", "Search", None);
        let violations = check_description_quality(&cap);
        assert!(violations
            .iter()
            .any(|v| v.rule_id == "description_too_short"));
    }

    #[test]
    fn test_check_param_generic_name() {
        let schema = json!({
            "type": "object",
            "properties": {
                "input": {"type": "string"}
            },
            "required": ["input"]
        });
        let cap = create_test_capability("searchDocs", "Search documents", Some(schema));
        let violations = check_parameter_validation(&cap);
        assert!(violations
            .iter()
            .any(|v| v.rule_id == "param_name_generic"));
    }

    #[test]
    fn test_check_required_param_no_description() {
        let schema = json!({
            "type": "object",
            "properties": {
                "query": {"type": "string"}
            },
            "required": ["query"]
        });
        let cap = create_test_capability("searchDocs", "Search documents", Some(schema));
        let violations = check_parameter_validation(&cap);
        assert!(violations
            .iter()
            .any(|v| v.rule_id == "required_param_no_description"));
    }

    #[test]
    fn test_check_enum_too_many_values() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": (0..25).map(|i| format!("value{}", i)).collect::<Vec<_>>()
                }
            }
        });
        let cap = create_test_capability("updateStatus", "Update status", Some(schema));
        let violations = check_parameter_validation(&cap);
        assert!(violations
            .iter()
            .any(|v| v.rule_id == "enum_too_many_values"));
    }
}
