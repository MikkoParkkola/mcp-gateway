//! Validation reporting structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity level for validation issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Critical issue - breaks agent UX
    Fail,
    /// Warning - degrades agent experience
    Warn,
    /// Informational - best practice suggestion
    Info,
    /// Passed validation
    Pass,
}

impl Severity {
    /// Get numeric score (0-1) for this severity
    #[must_use]
    pub const fn score(self) -> f64 {
        match self {
            Self::Pass => 1.0,
            Self::Info => 0.9,
            Self::Warn => 0.6,
            Self::Fail => 0.0,
        }
    }
}

/// Result of validating a tool against a single rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Rule code (e.g., "AX-001")
    pub rule_code: String,
    /// Rule name/principle
    pub rule_name: String,
    /// Overall pass/fail status
    pub passed: bool,
    /// Severity level
    pub severity: Severity,
    /// Score between 0.0 and 1.0
    pub score: f64,
    /// List of specific issues found
    pub issues: Vec<String>,
    /// Suggestions for fixing violations
    pub suggestions: Vec<String>,
    /// Tool name that was validated
    pub tool_name: String,
}

impl ValidationResult {
    /// Create a new validation result
    #[must_use]
    pub fn new(
        rule_code: impl Into<String>,
        rule_name: impl Into<String>,
        tool_name: impl Into<String>,
    ) -> Self {
        Self {
            rule_code: rule_code.into(),
            rule_name: rule_name.into(),
            passed: true,
            severity: Severity::Pass,
            score: 1.0,
            issues: Vec::new(),
            suggestions: Vec::new(),
            tool_name: tool_name.into(),
        }
    }

    /// Add an issue (marks as failed)
    pub fn add_issue(&mut self, issue: impl Into<String>) {
        self.issues.push(issue.into());
        self.passed = false;
    }

    /// Add a suggestion
    pub fn add_suggestion(&mut self, suggestion: impl Into<String>) {
        self.suggestions.push(suggestion.into());
    }

    /// Set severity level
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        // Update passed status based on severity (Fail = not passed)
        if severity == Severity::Fail {
            self.passed = false;
        }
        self
    }

    /// Set score
    pub fn with_score(mut self, score: f64) -> Self {
        self.score = score.clamp(0.0, 1.0);
        self
    }
}

/// Comprehensive validation report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Overall score (0.0 - 1.0)
    pub overall_score: f64,
    /// Letter grade (A-F)
    pub grade: String,
    /// Total number of tools validated
    pub total_tools: usize,
    /// Results by principle/rule
    pub by_principle: HashMap<String, PrincipleScore>,
    /// All individual results
    pub results: Vec<ValidationResult>,
    /// Summary statistics
    pub summary: ValidationSummary,
}

/// Score summary for a specific principle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipleScore {
    /// Number of tools that passed this principle
    pub passed: usize,
    /// Number of tools that failed this principle
    pub failed: usize,
    /// Number of tools with warnings
    pub warnings: usize,
    /// Average score for this principle
    pub avg_score: f64,
}

/// Summary statistics for the validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationSummary {
    /// Total checks performed
    pub total_checks: usize,
    /// Number of passed checks
    pub passed: usize,
    /// Number of failed checks
    pub failed: usize,
    /// Number of warnings
    pub warnings: usize,
    /// Pass rate (0.0 - 1.0)
    pub pass_rate: f64,
}

impl ValidationReport {
    /// Create a report from validation results
    #[must_use]
    pub fn from_results(total_tools: usize, results: Vec<ValidationResult>) -> Self {
        let mut by_principle: HashMap<String, PrincipleScore> = HashMap::new();

        // Aggregate by principle
        for result in &results {
            let entry = by_principle
                .entry(result.rule_name.clone())
                .or_insert_with(|| PrincipleScore {
                    passed: 0,
                    failed: 0,
                    warnings: 0,
                    avg_score: 0.0,
                });

            if result.passed {
                entry.passed += 1;
            } else {
                match result.severity {
                    Severity::Fail => entry.failed += 1,
                    Severity::Warn => entry.warnings += 1,
                    Severity::Info => entry.warnings += 1,
                    Severity::Pass => entry.passed += 1,
                }
            }
        }

        // Calculate average scores per principle
        for (principle, score) in &mut by_principle {
            let principle_results: Vec<_> = results
                .iter()
                .filter(|r| r.rule_name == *principle)
                .collect();

            if !principle_results.is_empty() {
                score.avg_score = principle_results.iter().map(|r| r.score).sum::<f64>()
                    / principle_results.len() as f64;
            }
        }

        // Calculate summary
        let total_checks = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = results
            .iter()
            .filter(|r| !r.passed && r.severity == Severity::Fail)
            .count();
        let warnings = results
            .iter()
            .filter(|r| {
                !r.passed && (r.severity == Severity::Warn || r.severity == Severity::Info)
            })
            .count();

        let pass_rate = if total_checks > 0 {
            passed as f64 / total_checks as f64
        } else {
            0.0
        };

        // Calculate overall score (weighted by severity)
        let overall_score = if !results.is_empty() {
            results.iter().map(|r| r.score).sum::<f64>() / results.len() as f64
        } else {
            0.0
        };

        let grade = Self::calculate_grade(overall_score);

        Self {
            overall_score,
            grade,
            total_tools,
            by_principle,
            results,
            summary: ValidationSummary {
                total_checks,
                passed,
                failed,
                warnings,
                pass_rate,
            },
        }
    }

    /// Calculate letter grade from score
    fn calculate_grade(score: f64) -> String {
        match score {
            s if s >= 0.95 => "A+".to_string(),
            s if s >= 0.90 => "A".to_string(),
            s if s >= 0.85 => "A-".to_string(),
            s if s >= 0.80 => "B+".to_string(),
            s if s >= 0.75 => "B".to_string(),
            s if s >= 0.70 => "B-".to_string(),
            s if s >= 0.65 => "C+".to_string(),
            s if s >= 0.60 => "C".to_string(),
            s if s >= 0.55 => "C-".to_string(),
            s if s >= 0.50 => "D".to_string(),
            _ => "F".to_string(),
        }
    }

    /// Get failures only
    #[must_use]
    pub fn failures(&self) -> Vec<&ValidationResult> {
        self.results
            .iter()
            .filter(|r| !r.passed && r.severity == Severity::Fail)
            .collect()
    }

    /// Get warnings only
    #[must_use]
    pub fn warnings(&self) -> Vec<&ValidationResult> {
        self.results
            .iter()
            .filter(|r| {
                !r.passed && (r.severity == Severity::Warn || r.severity == Severity::Info)
            })
            .collect()
    }

    /// Format as human-readable text
    #[must_use]
    pub fn format_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "\n╔══════════════════════════════════════════════════════════════╗\n"
        ));
        output.push_str(&format!(
            "║         MCP Agent-UX Validation Report                      ║\n"
        ));
        output.push_str(&format!(
            "╚══════════════════════════════════════════════════════════════╝\n\n"
        ));

        output.push_str(&format!("Overall Score: {:.1}% ({})\n", self.overall_score * 100.0, self.grade));
        output.push_str(&format!("Tools Validated: {}\n\n", self.total_tools));

        output.push_str("Summary:\n");
        output.push_str(&format!("  ✓ Passed:   {}\n", self.summary.passed));
        output.push_str(&format!("  ✗ Failed:   {}\n", self.summary.failed));
        output.push_str(&format!("  ⚠ Warnings: {}\n", self.summary.warnings));
        output.push_str(&format!("  Pass Rate:  {:.1}%\n\n", self.summary.pass_rate * 100.0));

        // Failures
        let failures = self.failures();
        if !failures.is_empty() {
            output.push_str(&format!("╔══════════════════════════════════════════════════════════════╗\n"));
            output.push_str(&format!("║ FAILURES ({})                                                  \n", failures.len()));
            output.push_str(&format!("╚══════════════════════════════════════════════════════════════╝\n\n"));

            for result in failures {
                output.push_str(&format!("[{}] {} - {}\n", result.rule_code, result.tool_name, result.rule_name));
                for issue in &result.issues {
                    output.push_str(&format!("  ✗ {}\n", issue));
                }
                if !result.suggestions.is_empty() {
                    output.push_str("  Suggestions:\n");
                    for suggestion in &result.suggestions {
                        output.push_str(&format!("    → {}\n", suggestion));
                    }
                }
                output.push('\n');
            }
        }

        // Warnings
        let warnings = self.warnings();
        if !warnings.is_empty() {
            output.push_str(&format!("╔══════════════════════════════════════════════════════════════╗\n"));
            output.push_str(&format!("║ WARNINGS ({})                                                  \n", warnings.len()));
            output.push_str(&format!("╚══════════════════════════════════════════════════════════════╝\n\n"));

            for result in warnings {
                output.push_str(&format!("[{}] {} - {}\n", result.rule_code, result.tool_name, result.rule_name));
                for issue in &result.issues {
                    output.push_str(&format!("  ⚠ {}\n", issue));
                }
                if !result.suggestions.is_empty() {
                    output.push_str("  Suggestions:\n");
                    for suggestion in &result.suggestions {
                        output.push_str(&format!("    → {}\n", suggestion));
                    }
                }
                output.push('\n');
            }
        }

        // By Principle
        output.push_str("╔══════════════════════════════════════════════════════════════╗\n");
        output.push_str("║ BY PRINCIPLE                                                ║\n");
        output.push_str("╚══════════════════════════════════════════════════════════════╝\n\n");

        let mut principles: Vec<_> = self.by_principle.iter().collect();
        principles.sort_by(|a, b| b.1.avg_score.partial_cmp(&a.1.avg_score).unwrap());

        for (principle, score) in principles {
            output.push_str(&format!(
                "{:40} {:.1}% ({}/{})\n",
                principle,
                score.avg_score * 100.0,
                score.passed,
                score.passed + score.failed + score.warnings
            ));
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_score() {
        assert_eq!(Severity::Pass.score(), 1.0);
        assert_eq!(Severity::Info.score(), 0.9);
        assert_eq!(Severity::Warn.score(), 0.6);
        assert_eq!(Severity::Fail.score(), 0.0);
    }

    #[test]
    fn test_validation_result_builder() {
        let mut result = ValidationResult::new("AX-001", "Test Rule", "test_tool");
        assert!(result.passed);
        assert_eq!(result.score, 1.0);

        result.add_issue("Test issue");
        assert!(!result.passed);
        assert_eq!(result.issues.len(), 1);
    }

    #[test]
    fn test_grade_calculation() {
        assert_eq!(ValidationReport::calculate_grade(0.96), "A+");
        assert_eq!(ValidationReport::calculate_grade(0.91), "A");
        assert_eq!(ValidationReport::calculate_grade(0.76), "B");
        assert_eq!(ValidationReport::calculate_grade(0.61), "C");
        assert_eq!(ValidationReport::calculate_grade(0.51), "D");
        assert_eq!(ValidationReport::calculate_grade(0.40), "F");
    }

    #[test]
    fn test_report_from_results() {
        let results = vec![
            ValidationResult::new("AX-001", "Rule 1", "tool1")
                .with_severity(Severity::Pass)
                .with_score(1.0),
            ValidationResult::new("AX-002", "Rule 2", "tool1")
                .with_severity(Severity::Fail)
                .with_score(0.0),
        ];

        let report = ValidationReport::from_results(1, results);
        assert_eq!(report.total_tools, 1);
        assert_eq!(report.summary.total_checks, 2);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.failed, 1);
    }
}
