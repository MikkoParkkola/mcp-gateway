//! SARIF 2.1.0 output format for CI integration
//!
//! Produces Static Analysis Results Interchange Format (SARIF) reports
//! compatible with GitHub Code Scanning, Azure DevOps, and other CI tools.

use serde::Serialize;

use super::{Severity, ValidationReport, ValidationResult};

/// SARIF 2.1.0 report
#[derive(Debug, Serialize)]
pub struct SarifReport {
    /// SARIF version (always "2.1.0")
    pub version: String,
    /// Schema URI
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Analysis runs
    pub runs: Vec<SarifRun>,
}

/// A single analysis run
#[derive(Debug, Serialize)]
pub struct SarifRun {
    /// Tool that produced the results
    pub tool: SarifTool,
    /// Validation results
    pub results: Vec<SarifResult>,
}

/// Tool descriptor
#[derive(Debug, Serialize)]
pub struct SarifTool {
    /// Tool driver info
    pub driver: SarifDriver,
}

/// Tool driver metadata
#[derive(Debug, Serialize)]
pub struct SarifDriver {
    /// Tool name
    pub name: String,
    /// Tool version
    pub version: String,
    /// Rule descriptors
    pub rules: Vec<SarifRuleDescriptor>,
}

/// Rule metadata in SARIF
#[derive(Debug, Serialize)]
pub struct SarifRuleDescriptor {
    /// Rule identifier (e.g., "AX-001")
    pub id: String,
    /// Rule short name
    pub name: String,
    /// Short description
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
}

/// A single SARIF result
#[derive(Debug, Serialize)]
pub struct SarifResult {
    /// Rule identifier
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    /// Severity level ("error", "warning", "note")
    pub level: String,
    /// Result message
    pub message: SarifMessage,
    /// Locations where the issue was found
    pub locations: Vec<SarifLocation>,
}

/// SARIF message
#[derive(Debug, Serialize)]
pub struct SarifMessage {
    /// Message text
    pub text: String,
}

/// Location of a result
#[derive(Debug, Serialize)]
pub struct SarifLocation {
    /// Physical file location
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

/// Physical location in a file
#[derive(Debug, Serialize)]
pub struct SarifPhysicalLocation {
    /// File path
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

/// Artifact (file) location
#[derive(Debug, Serialize)]
pub struct SarifArtifactLocation {
    /// URI or file path
    pub uri: String,
}

/// Convert a `Severity` to SARIF level string
fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Fail => "error",
        Severity::Warn => "warning",
        Severity::Info | Severity::Pass => "note",
    }
}

/// Convert a `ValidationReport` into a SARIF report.
///
/// Each failed or warned validation result becomes a SARIF result entry.
/// The `file_uri` is attached to every result location.
#[must_use]
pub fn to_sarif(report: &ValidationReport, file_uri: &str) -> SarifReport {
    let mut rule_descriptors = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();

    // Collect unique rule descriptors
    for result in &report.results {
        if seen_rules.insert(result.rule_code.clone()) {
            rule_descriptors.push(SarifRuleDescriptor {
                id: result.rule_code.clone(),
                name: result.rule_name.clone(),
                short_description: SarifMessage {
                    text: result.rule_name.clone(),
                },
            });
        }
    }

    // Convert results (only non-passing)
    let sarif_results: Vec<SarifResult> = report
        .results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| validation_result_to_sarif(r, file_uri))
        .collect();

    SarifReport {
        version: "2.1.0".to_string(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "mcp-gateway-validate".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    rules: rule_descriptors,
                },
            },
            results: sarif_results,
        }],
    }
}

/// Convert a single `ValidationResult` to a SARIF result
fn validation_result_to_sarif(result: &ValidationResult, file_uri: &str) -> SarifResult {
    let message_text = if result.issues.is_empty() {
        result.rule_name.clone()
    } else {
        result.issues.join("; ")
    };

    SarifResult {
        rule_id: result.rule_code.clone(),
        level: severity_to_sarif_level(result.severity).to_string(),
        message: SarifMessage { text: message_text },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: file_uri.to_string(),
                },
            },
        }],
    }
}

/// Convert a collection of validation results from multiple files to a single SARIF report.
///
/// Each entry in `file_results` is `(file_uri, results_for_that_file)`.
#[must_use]
pub fn to_sarif_multi(file_results: &[(&str, &[ValidationResult])]) -> SarifReport {
    let mut rule_descriptors = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();
    let mut sarif_results = Vec::new();

    for &(file_uri, results) in file_results {
        for result in results {
            if seen_rules.insert(result.rule_code.clone()) {
                rule_descriptors.push(SarifRuleDescriptor {
                    id: result.rule_code.clone(),
                    name: result.rule_name.clone(),
                    short_description: SarifMessage {
                        text: result.rule_name.clone(),
                    },
                });
            }

            if !result.passed {
                sarif_results.push(validation_result_to_sarif(result, file_uri));
            }
        }
    }

    SarifReport {
        version: "2.1.0".to_string(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "mcp-gateway-validate".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    rules: rule_descriptors,
                },
            },
            results: sarif_results,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::report::ValidationReport;

    fn make_result(code: &str, name: &str, tool: &str, passed: bool, severity: Severity) -> ValidationResult {
        let mut r = ValidationResult::new(code, name, tool);
        if !passed {
            r.add_issue("Test issue");
        }
        r.severity = severity;
        r
    }

    #[test]
    fn sarif_report_has_correct_version() {
        let report = ValidationReport::from_results(1, vec![
            make_result("AX-001", "Rule 1", "tool1", true, Severity::Pass),
        ]);

        let sarif = to_sarif(&report, "test.yaml");
        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
    }

    #[test]
    fn sarif_report_includes_only_failures() {
        let report = ValidationReport::from_results(1, vec![
            make_result("AX-001", "Rule 1", "tool1", true, Severity::Pass),
            make_result("AX-002", "Rule 2", "tool1", false, Severity::Fail),
            make_result("AX-003", "Rule 3", "tool1", false, Severity::Warn),
        ]);

        let sarif = to_sarif(&report, "test.yaml");
        assert_eq!(sarif.runs[0].results.len(), 2);
    }

    #[test]
    fn sarif_severity_mapping() {
        assert_eq!(severity_to_sarif_level(Severity::Fail), "error");
        assert_eq!(severity_to_sarif_level(Severity::Warn), "warning");
        assert_eq!(severity_to_sarif_level(Severity::Info), "note");
        assert_eq!(severity_to_sarif_level(Severity::Pass), "note");
    }

    #[test]
    fn sarif_result_has_file_location() {
        let report = ValidationReport::from_results(1, vec![
            make_result("AX-001", "Rule 1", "tool1", false, Severity::Fail),
        ]);

        let sarif = to_sarif(&report, "capabilities/search/brave.yaml");
        let result = &sarif.runs[0].results[0];
        assert_eq!(
            result.locations[0].physical_location.artifact_location.uri,
            "capabilities/search/brave.yaml"
        );
    }

    #[test]
    fn sarif_rule_descriptors_are_unique() {
        let report = ValidationReport::from_results(2, vec![
            make_result("AX-001", "Rule 1", "tool1", false, Severity::Fail),
            make_result("AX-001", "Rule 1", "tool2", false, Severity::Fail),
        ]);

        let sarif = to_sarif(&report, "test.yaml");
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 1);
    }

    #[test]
    fn sarif_multi_aggregates_files() {
        let results_a = vec![
            make_result("AX-001", "Rule 1", "tool1", false, Severity::Fail),
        ];
        let results_b = vec![
            make_result("AX-002", "Rule 2", "tool2", false, Severity::Warn),
        ];

        let sarif = to_sarif_multi(&[
            ("file_a.yaml", &results_a),
            ("file_b.yaml", &results_b),
        ]);

        assert_eq!(sarif.runs[0].results.len(), 2);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 2);
    }

    #[test]
    fn sarif_serializes_to_valid_json() {
        let report = ValidationReport::from_results(1, vec![
            make_result("AX-001", "Rule 1", "tool1", false, Severity::Fail),
        ]);

        let sarif = to_sarif(&report, "test.yaml");
        let json = serde_json::to_string_pretty(&sarif);
        assert!(json.is_ok());

        let json_str = json.unwrap();
        assert!(json_str.contains("\"version\": \"2.1.0\""));
        assert!(json_str.contains("\"$schema\""));
    }
}
