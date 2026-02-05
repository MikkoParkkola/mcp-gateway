//! Validation report generation and formatting

use super::rules::Violation;
use serde::{Deserialize, Serialize};

// Re-export for convenience
pub use super::rules::ViolationSeverity;

/// A validation report containing all violations and scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Tool name being validated
    pub tool_name: String,
    /// All violations found
    violations: Vec<Violation>,
    /// Overall quality score (0-100)
    score: i32,
}

impl ValidationReport {
    /// Create a new validation report
    pub fn new(tool_name: String, violations: Vec<Violation>) -> Self {
        let score = Self::calculate_score(&violations);
        Self {
            tool_name,
            violations,
            score,
        }
    }

    /// Calculate quality score based on violations
    /// Starts at 100, deducts points for each violation:
    /// - Error: -10 points
    /// - Warning: -3 points
    /// - Info: -1 point
    fn calculate_score(violations: &[Violation]) -> i32 {
        let deductions: i32 = violations
            .iter()
            .map(|v| match v.severity {
                ViolationSeverity::Error => 10,
                ViolationSeverity::Warning => 3,
                ViolationSeverity::Info => 1,
            })
            .sum();

        (100 - deductions).max(0)
    }

    /// Get the quality score
    pub fn score(&self) -> i32 {
        self.score
    }

    /// Get all violations
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }

    /// Check if validation passed (no errors)
    pub fn passed(&self) -> bool {
        !self
            .violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error)
    }

    /// Count violations by severity
    pub fn count_by_severity(&self, severity: ViolationSeverity) -> usize {
        self.violations
            .iter()
            .filter(|v| v.severity == severity)
            .count()
    }

    /// Format as human-readable text
    pub fn format_text(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!("\n{}\n", "=".repeat(60)));
        output.push_str(&format!("  Tool: {}\n", self.tool_name));
        output.push_str(&format!("  Score: {}/100\n", self.score));
        output.push_str(&format!("  Status: {}\n", if self.passed() { "✅ PASSED" } else { "❌ FAILED" }));
        output.push_str(&format!("{}\n", "=".repeat(60)));

        if self.violations.is_empty() {
            output.push_str("\n✨ No issues found! This tool follows agent-UX best practices.\n");
            return output;
        }

        // Summary
        let error_count = self.count_by_severity(ViolationSeverity::Error);
        let warning_count = self.count_by_severity(ViolationSeverity::Warning);
        let info_count = self.count_by_severity(ViolationSeverity::Info);

        output.push_str("\nSummary:\n");
        if error_count > 0 {
            output.push_str(&format!("  ❌ {} error(s)\n", error_count));
        }
        if warning_count > 0 {
            output.push_str(&format!("  ⚠️  {} warning(s)\n", warning_count));
        }
        if info_count > 0 {
            output.push_str(&format!("  ℹ️  {} suggestion(s)\n", info_count));
        }

        // Detailed violations
        output.push_str("\nDetails:\n");
        for violation in &self.violations {
            let icon = match violation.severity {
                ViolationSeverity::Error => "❌",
                ViolationSeverity::Warning => "⚠️",
                ViolationSeverity::Info => "ℹ️",
            };
            output.push_str(&format!("\n{} [{}] {}\n", icon, violation.rule_id, violation.message));
            if let Some(suggestion) = &violation.suggestion {
                output.push_str(&format!("   💡 {}\n", suggestion));
            }
        }

        output.push('\n');
        output
    }

    /// Format as JSON
    pub fn format_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Format as compact JSON (single line)
    pub fn format_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_score_no_violations() {
        let report = ValidationReport::new("testTool".to_string(), vec![]);
        assert_eq!(report.score(), 100);
        assert!(report.passed());
    }

    #[test]
    fn test_calculate_score_with_errors() {
        let violations = vec![
            Violation::error(
                "test_error",
                "Test error".to_string(),
                "testTool".to_string(),
            ),
            Violation::warning(
                "test_warning",
                "Test warning".to_string(),
                "testTool".to_string(),
            ),
        ];
        let report = ValidationReport::new("testTool".to_string(), violations);
        assert_eq!(report.score(), 87); // 100 - 10 (error) - 3 (warning)
        assert!(!report.passed()); // Has errors
    }

    #[test]
    fn test_calculate_score_only_warnings() {
        let violations = vec![
            Violation::warning(
                "test_warning1",
                "Warning 1".to_string(),
                "testTool".to_string(),
            ),
            Violation::warning(
                "test_warning2",
                "Warning 2".to_string(),
                "testTool".to_string(),
            ),
        ];
        let report = ValidationReport::new("testTool".to_string(), violations);
        assert_eq!(report.score(), 94); // 100 - 3 - 3
        assert!(report.passed()); // No errors
    }

    #[test]
    fn test_score_minimum_zero() {
        let violations = vec![
            Violation::error("e1", "E1".to_string(), "test".to_string()),
            Violation::error("e2", "E2".to_string(), "test".to_string()),
            Violation::error("e3", "E3".to_string(), "test".to_string()),
            Violation::error("e4", "E4".to_string(), "test".to_string()),
            Violation::error("e5", "E5".to_string(), "test".to_string()),
            Violation::error("e6", "E6".to_string(), "test".to_string()),
            Violation::error("e7", "E7".to_string(), "test".to_string()),
            Violation::error("e8", "E8".to_string(), "test".to_string()),
            Violation::error("e9", "E9".to_string(), "test".to_string()),
            Violation::error("e10", "E10".to_string(), "test".to_string()),
            Violation::error("e11", "E11".to_string(), "test".to_string()),
        ];
        let report = ValidationReport::new("testTool".to_string(), violations);
        assert_eq!(report.score(), 0); // Should not go below 0
    }

    #[test]
    fn test_format_text() {
        let violations = vec![
            Violation::error(
                "test_error",
                "This is a test error".to_string(),
                "testTool".to_string(),
            )
            .with_suggestion("Fix it like this".to_string()),
        ];
        let report = ValidationReport::new("testTool".to_string(), violations);
        let text = report.format_text();
        assert!(text.contains("testTool"));
        assert!(text.contains("❌"));
        assert!(text.contains("test_error"));
        assert!(text.contains("Fix it like this"));
    }

    #[test]
    fn test_format_json() {
        let violations = vec![Violation::warning(
            "test_warning",
            "Test".to_string(),
            "testTool".to_string(),
        )];
        let report = ValidationReport::new("testTool".to_string(), violations);
        let json = report.format_json().unwrap();
        assert!(json.contains("testTool"));
        assert!(json.contains("test_warning"));
    }

    #[test]
    fn test_count_by_severity() {
        let violations = vec![
            Violation::error("e1", "Error".to_string(), "test".to_string()),
            Violation::warning("w1", "Warning".to_string(), "test".to_string()),
            Violation::warning("w2", "Warning".to_string(), "test".to_string()),
            Violation::info("i1", "Info".to_string(), "test".to_string()),
        ];
        let report = ValidationReport::new("test".to_string(), violations);
        assert_eq!(report.count_by_severity(ViolationSeverity::Error), 1);
        assert_eq!(report.count_by_severity(ViolationSeverity::Warning), 2);
        assert_eq!(report.count_by_severity(ViolationSeverity::Info), 1);
    }
}
