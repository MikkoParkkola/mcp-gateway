//! CLI handler for the validate command.

use std::path::PathBuf;
use std::process::ExitCode;

use super::{
    AgentUxValidator, ConflictDetectionRule, NamingConsistencyRule,
    OutputFormat, ValidateConfig, Severity,
};
use crate::capability::parse_capability_file;

/// Collect YAML capability files from paths.
fn collect_capability_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for path in paths {
        if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "yaml" || ext == "yml" {
                files.push(path.clone());
            }
        } else if path.is_dir() {
            collect_yaml_recursive(path, &mut files);
        } else {
            eprintln!("Warning: skipping non-existent path: {}", path.display());
        }
    }

    files
}

/// Recursively collect YAML files from a directory.
fn collect_yaml_recursive(dir: &std::path::Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_yaml_recursive(&path, files);
        } else if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "yaml" || ext == "yml" {
                files.push(path);
            }
        }
    }
}

/// Format validation results as human-readable text.
fn format_validate_text(
    file_results: &[(&str, &super::ValidationReport)],
    config: &ValidateConfig,
) -> String {
    use std::fmt::Write;

    let mut output = String::new();

    let pass_marker = if config.color { "\x1b[32mPASS\x1b[0m" } else { "PASS" };
    let warn_marker = if config.color { "\x1b[33mWARN\x1b[0m" } else { "WARN" };
    let fail_marker = if config.color { "\x1b[31mFAIL\x1b[0m" } else { "FAIL" };

    let mut total_pass = 0usize;
    let mut total_warn = 0usize;
    let mut total_fail = 0usize;

    for &(file_path, report) in file_results {
        let _ = writeln!(output, "\n--- {file_path} ---");

        for result in &report.results {
            // Apply severity filter
            if !config.min_severity.includes(result.severity) {
                continue;
            }

            let marker = if result.passed {
                total_pass += 1;
                pass_marker
            } else if result.severity == Severity::Fail {
                total_fail += 1;
                fail_marker
            } else {
                total_warn += 1;
                warn_marker
            };

            let _ = writeln!(
                output,
                "  [{marker}] [{}] {} - {}",
                result.rule_code, result.tool_name, result.rule_name
            );

            if !result.passed {
                for issue in &result.issues {
                    let _ = writeln!(output, "         {issue}");
                }
            }
        }
    }

    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "Summary: {total_pass} passed, {total_warn} warnings, {total_fail} failures"
    );

    output
}

/// Run the validate command against one or more capability paths.
#[allow(clippy::too_many_lines)]
pub async fn run_validate_command(
    paths: &[PathBuf],
    config: &ValidateConfig,
) -> ExitCode {
    let files = collect_capability_files(paths);

    if files.is_empty() {
        eprintln!("No YAML capability files found in the given paths.");
        return ExitCode::from(2);
    }

    let validator = AgentUxValidator::new();
    let mut all_tools = Vec::new();
    let mut file_reports: Vec<(String, super::ValidationReport)> = Vec::new();
    let mut has_failures = false;
    let mut parse_errors = false;

    // Phase 1: Parse and validate each file
    for file in &files {
        let cap = match parse_capability_file(file).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Parse error in {}: {e}", file.display());
                parse_errors = true;
                continue;
            }
        };

        let tool = cap.to_mcp_tool();
        let report = match validator.validate_tools(std::slice::from_ref(&tool)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Validation error for {}: {e}", file.display());
                continue;
            }
        };

        if !report.failures().is_empty() {
            has_failures = true;
        }

        // Auto-fix if requested
        if config.auto_fix {
            let suggested = super::fix::CapabilityFixer::suggest_fixes(&report.results);
            if !suggested.is_empty() {
                if let Ok(content) = std::fs::read_to_string(file) {
                    if let Some(patched) = super::fix::CapabilityFixer::apply_fixes(&content, &suggested) {
                        if std::fs::write(file, patched).is_ok() {
                            eprintln!("Auto-fixed {} issue(s) in {}", suggested.len(), file.display());
                        }
                    }
                }
            }
        }

        all_tools.push(tool);
        file_reports.push((file.display().to_string(), report));
    }

    // Phase 2: Cross-capability checks
    let conflict_results = ConflictDetectionRule::check_conflicts(&all_tools);
    let consistency_results = NamingConsistencyRule::check_consistency(&all_tools);

    let has_cross_failures = conflict_results.iter().any(|r| !r.passed && r.severity == Severity::Fail)
        || consistency_results.iter().any(|r| !r.passed && r.severity == Severity::Fail);

    if has_cross_failures {
        has_failures = true;
    }

    // Phase 3: Output
    match config.format {
        OutputFormat::Text => {
            let refs: Vec<(&str, &super::ValidationReport)> = file_reports
                .iter()
                .map(|(p, r)| (p.as_str(), r))
                .collect();

            print!("{}", format_validate_text(&refs, config));

            // Print cross-capability results
            if !conflict_results.is_empty() || !consistency_results.is_empty() {
                println!("\n--- Cross-Capability Checks ---");
                for result in conflict_results.iter().chain(consistency_results.iter()) {
                    if !config.min_severity.includes(result.severity) {
                        continue;
                    }
                    let marker = if result.passed {
                        if config.color { "\x1b[32mPASS\x1b[0m" } else { "PASS" }
                    } else {
                        match result.severity {
                            Severity::Fail => {
                                if config.color { "\x1b[31mFAIL\x1b[0m" } else { "FAIL" }
                            }
                            _ => {
                                if config.color { "\x1b[33mWARN\x1b[0m" } else { "WARN" }
                            }
                        }
                    };
                    println!("  [{marker}] [{}] {} - {}", result.rule_code, result.tool_name, result.rule_name);
                    for issue in &result.issues {
                        println!("         {issue}");
                    }
                }
            }
        }

        OutputFormat::Json => {
            let json_output: Vec<serde_json::Value> = file_reports
                .iter()
                .map(|(path, report)| {
                    serde_json::json!({
                        "file": path,
                        "score": report.overall_score,
                        "grade": report.grade,
                        "results": report.results,
                        "summary": report.summary,
                    })
                })
                .collect();

            let full = serde_json::json!({
                "files": json_output,
                "cross_capability": {
                    "conflicts": conflict_results,
                    "consistency": consistency_results,
                },
            });

            println!("{}", serde_json::to_string_pretty(&full).unwrap_or_default());
        }

        OutputFormat::Sarif => {
            let file_result_refs: Vec<(&str, &[super::ValidationResult])> = file_reports
                .iter()
                .map(|(p, r)| (p.as_str(), r.results.as_slice()))
                .collect();

            let sarif = super::sarif::to_sarif_multi(&file_result_refs);
            println!("{}", serde_json::to_string_pretty(&sarif).unwrap_or_default());
        }
    }

    if parse_errors {
        ExitCode::from(2)
    } else if has_failures {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
