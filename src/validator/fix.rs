//! Auto-fix for validation issues
//!
//! Provides suggested fixes and the ability to apply them to capability YAML files.

use serde::{Deserialize, Serialize};

/// Suggested fix for a validation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedFix {
    /// Rule that produced this fix
    pub rule_code: String,
    /// Description of what the fix does
    pub description: String,
    /// The field path to modify (e.g., "schema.input.properties.query")
    pub field_path: String,
    /// The suggested new value (serialized YAML fragment)
    pub suggested_value: serde_json::Value,
}

/// Apply fixes to a capability definition
pub struct CapabilityFixer;

impl CapabilityFixer {
    /// Generate suggested fixes from validation results.
    ///
    /// Analyzes the validation issues and produces concrete fix suggestions
    /// that can be applied to the source YAML.
    #[must_use]
    pub fn suggest_fixes(results: &[super::ValidationResult]) -> Vec<SuggestedFix> {
        let mut fixes = Vec::new();

        for result in results {
            if result.passed {
                continue;
            }

            match result.rule_code.as_str() {
                "AX-007" => {
                    Self::suggest_schema_fixes(result, &mut fixes);
                }
                "AX-009" => {
                    Self::suggest_naming_fixes(result, &mut fixes);
                }
                _ => {}
            }
        }

        fixes
    }

    /// Generate schema completeness fixes (add missing type/description).
    fn suggest_schema_fixes(
        result: &super::ValidationResult,
        fixes: &mut Vec<SuggestedFix>,
    ) {
        for issue in &result.issues {
            if issue.contains("missing 'type'") {
                // Extract property name from issue text
                if let Some(name) = extract_property_name(issue) {
                    fixes.push(SuggestedFix {
                        rule_code: "AX-007".to_string(),
                        description: format!("Add type to property '{name}'"),
                        field_path: format!("schema.input.properties.{name}.type"),
                        suggested_value: serde_json::Value::String("string".to_string()),
                    });
                }
            }
            if issue.contains("missing 'description'") {
                if let Some(name) = extract_property_name(issue) {
                    fixes.push(SuggestedFix {
                        rule_code: "AX-007".to_string(),
                        description: format!("Add description to property '{name}'"),
                        field_path: format!("schema.input.properties.{name}.description"),
                        suggested_value: serde_json::Value::String(
                            format!("The {name} parameter"),
                        ),
                    });
                }
            }
        }
    }

    /// Generate naming consistency fixes (convert to `snake_case`).
    fn suggest_naming_fixes(
        result: &super::ValidationResult,
        fixes: &mut Vec<SuggestedFix>,
    ) {
        for issue in &result.issues {
            if issue.contains("kebab-case") || issue.contains("camelCase") {
                let suggested = to_snake_case(&result.tool_name);
                if suggested != result.tool_name {
                    fixes.push(SuggestedFix {
                        rule_code: "AX-009".to_string(),
                        description: format!(
                            "Rename '{}' to '{suggested}'",
                            result.tool_name
                        ),
                        field_path: "name".to_string(),
                        suggested_value: serde_json::Value::String(suggested),
                    });
                }
            }
        }
    }

    /// Apply a list of fixes to raw YAML content.
    ///
    /// Returns the modified YAML string, or `None` if no fixes were applicable.
    #[must_use]
    pub fn apply_fixes(yaml_content: &str, fixes: &[SuggestedFix]) -> Option<String> {
        if fixes.is_empty() {
            return None;
        }

        let mut content = yaml_content.to_string();
        let mut modified = false;

        for fix in fixes {
            if fix.field_path == "name" {
                // Simple name replacement
                if let Some(new_name) = fix.suggested_value.as_str() {
                    let old_pattern = format!("name: {}", extract_tool_name_from_fix(fix));
                    let new_pattern = format!("name: {new_name}");
                    if content.contains(&old_pattern) {
                        content = content.replace(&old_pattern, &new_pattern);
                        modified = true;
                    }
                }
            }
        }

        modified.then_some(content)
    }
}

/// Extract a property name from an issue string like "Property 'query' missing 'type'"
fn extract_property_name(issue: &str) -> Option<String> {
    let start = issue.find('\'')?;
    let rest = &issue[start + 1..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

/// Extract the tool name that a fix applies to (from description or field path)
fn extract_tool_name_from_fix(fix: &SuggestedFix) -> String {
    // The description contains "Rename 'old_name' to 'new_name'"
    if let Some(start) = fix.description.find('\'') {
        let rest = &fix.description[start + 1..];
        if let Some(end) = rest.find('\'') {
            return rest[..end].to_string();
        }
    }
    String::new()
}

/// Convert a string to `snake_case`
fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    let mut prev_lower = false;

    for ch in s.chars() {
        if ch == '-' {
            result.push('_');
            prev_lower = false;
        } else if ch.is_uppercase() {
            if prev_lower {
                result.push('_');
            }
            result.push(ch.to_lowercase().next().unwrap_or(ch));
            prev_lower = false;
        } else {
            result.push(ch);
            prev_lower = ch.is_lowercase();
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::{Severity, ValidationResult};

    #[test]
    fn extract_property_name_from_issue() {
        let issue = "Property 'query' missing 'type'";
        assert_eq!(extract_property_name(issue), Some("query".to_string()));
    }

    #[test]
    fn extract_property_name_none_on_no_quotes() {
        assert_eq!(extract_property_name("no quotes here"), None);
    }

    #[test]
    fn to_snake_case_from_kebab() {
        assert_eq!(to_snake_case("my-tool-name"), "my_tool_name");
    }

    #[test]
    fn to_snake_case_from_camel() {
        assert_eq!(to_snake_case("myToolName"), "my_tool_name");
    }

    #[test]
    fn to_snake_case_already_snake() {
        assert_eq!(to_snake_case("my_tool_name"), "my_tool_name");
    }

    #[test]
    fn suggest_fixes_for_missing_type() {
        let mut result = ValidationResult::new("AX-007", "Schema Completeness", "test_tool");
        result.add_issue("Property 'query' missing 'type'");
        result.severity = Severity::Warn;

        let fixes = CapabilityFixer::suggest_fixes(&[result]);
        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0].rule_code, "AX-007");
        assert!(fixes[0].field_path.contains("query"));
    }

    #[test]
    fn suggest_fixes_for_naming() {
        let mut result = ValidationResult::new("AX-009", "Naming Consistency", "my-tool");
        result.add_issue("Name 'my-tool' uses kebab-case instead of snake_case");
        result.severity = Severity::Info;

        let fixes = CapabilityFixer::suggest_fixes(&[result]);
        assert_eq!(fixes.len(), 1);
        assert_eq!(
            fixes[0].suggested_value.as_str(),
            Some("my_tool")
        );
    }

    #[test]
    fn suggest_fixes_skips_passed_results() {
        let result = ValidationResult::new("AX-007", "Schema Completeness", "test_tool");
        // passed = true by default

        let fixes = CapabilityFixer::suggest_fixes(&[result]);
        assert!(fixes.is_empty());
    }

    #[test]
    fn apply_fixes_renames_tool() {
        let yaml = "name: my-tool\ndescription: A tool\n";
        let fixes = vec![SuggestedFix {
            rule_code: "AX-009".to_string(),
            description: "Rename 'my-tool' to 'my_tool'".to_string(),
            field_path: "name".to_string(),
            suggested_value: serde_json::Value::String("my_tool".to_string()),
        }];

        let result = CapabilityFixer::apply_fixes(yaml, &fixes);
        assert!(result.is_some());
        assert!(result.unwrap().contains("name: my_tool"));
    }

    #[test]
    fn apply_fixes_returns_none_for_empty() {
        let yaml = "name: my_tool\n";
        let result = CapabilityFixer::apply_fixes(yaml, &[]);
        assert!(result.is_none());
    }
}
