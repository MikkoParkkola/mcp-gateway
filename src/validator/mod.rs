//! MCP Server Design Validator - Agent-UX Compliance
//!
//! Validates MCP servers against agent-UX design best practices based on
//! Phil Schmid's "MCP is a User Interface for Agents" principles.
//!
//! # References
//!
//! - <https://www.philschmid.de/mcp-best-practices>

pub mod fix;
pub mod report;
pub mod rules;
pub mod sarif;

use crate::protocol::Tool;
use crate::Result;

pub use report::{ValidationReport, ValidationResult, Severity};
pub use rules::{Rule, ValidationRules, ConflictDetectionRule, NamingConsistencyRule};

/// Output format for validation reports
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable colored text
    Text,
    /// Structured JSON
    Json,
    /// SARIF 2.1.0 for CI integration
    Sarif,
}

/// Minimum severity filter
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum SeverityFilter {
    /// Show only failures
    Fail,
    /// Show warnings and failures
    Warn,
    /// Show everything including informational
    Info,
}

/// Configuration for a validation run
pub struct ValidateConfig {
    /// Output format
    pub format: OutputFormat,
    /// Minimum severity to report
    pub min_severity: SeverityFilter,
    /// Whether to attempt auto-fixing
    pub auto_fix: bool,
    /// Whether to use colored output
    pub color: bool,
}

impl SeverityFilter {
    /// Check whether a `Severity` passes this filter
    #[must_use]
    pub fn includes(self, severity: Severity) -> bool {
        match self {
            Self::Info => true,
            Self::Warn => matches!(severity, Severity::Fail | Severity::Warn | Severity::Pass),
            Self::Fail => matches!(severity, Severity::Fail | Severity::Pass),
        }
    }
}

/// Validator for MCP tool definitions against agent-UX best practices
pub struct AgentUxValidator {
    rules: ValidationRules,
}

impl AgentUxValidator {
    /// Create a new validator with default rules
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: ValidationRules::default(),
        }
    }

    /// Create a validator with custom rules
    #[must_use]
    pub fn with_rules(rules: ValidationRules) -> Self {
        Self { rules }
    }

    /// Validate a single tool against all rules
    ///
    /// # Errors
    ///
    /// Returns error if validation logic fails (not if tool fails validation)
    pub fn validate_tool(&self, tool: &Tool) -> Result<Vec<ValidationResult>> {
        let mut results = Vec::new();

        for rule in self.rules.all_rules() {
            let result = rule.check(tool)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Validate multiple tools and generate a comprehensive report
    ///
    /// # Errors
    ///
    /// Returns error if validation logic fails (not if tools fail validation)
    pub fn validate_tools(&self, tools: &[Tool]) -> Result<ValidationReport> {
        let mut all_results = Vec::new();

        for tool in tools {
            let tool_results = self.validate_tool(tool)?;
            for result in tool_results {
                all_results.push(result);
            }
        }

        Ok(ValidationReport::from_results(tools.len(), all_results))
    }
}

impl Default for AgentUxValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_tool(name: &str, description: &str) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: Some(description.to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    }
                }
            }),
            output_schema: None,
            annotations: None,
        }
    }

    #[test]
    fn test_validator_creation() {
        let validator = AgentUxValidator::new();
        assert!(!validator.rules.all_rules().is_empty());
    }

    #[test]
    fn test_validate_single_tool() {
        let validator = AgentUxValidator::new();
        let tool = create_test_tool(
            "search_knowledge",
            "Search the knowledge base for relevant information using semantic search"
        );

        let results = validator.validate_tool(&tool);
        assert!(results.is_ok());
        let results = results.unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_validate_multiple_tools() {
        let validator = AgentUxValidator::new();
        let tools = vec![
            create_test_tool("search_docs", "Search documentation"),
            create_test_tool("get_user", "Get a user by ID"),
        ];

        let report = validator.validate_tools(&tools);
        assert!(report.is_ok());
        let report = report.unwrap();
        assert_eq!(report.total_tools, 2);
    }

    #[test]
    fn test_good_tool_naming() {
        let validator = AgentUxValidator::new();
        let good_tool = create_test_tool(
            "github_search_issues",
            "Find GitHub issues using semantic search with filters"
        );

        let results = validator.validate_tool(&good_tool).unwrap();
        let naming_result = results.iter().find(|r| r.rule_code == "AX-005");
        assert!(naming_result.is_some());
    }

    #[test]
    fn test_bad_tool_naming_crud() {
        let validator = AgentUxValidator::new();
        let bad_tool = create_test_tool(
            "get_user",
            "Get user from database"
        );

        let results = validator.validate_tool(&bad_tool).unwrap();
        let outcome_result = results.iter().find(|r| r.rule_code == "AX-001");
        assert!(outcome_result.is_some());
        // Should flag CRUD operation naming
        assert!(!outcome_result.unwrap().issues.is_empty() || !outcome_result.unwrap().passed);
    }
}
