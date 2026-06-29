//! Adaptive ranking evaluation command handlers.

use std::{path::Path, process::ExitCode};

use mcp_gateway::{
    cli::{RankingCommand, output::OutputFormat},
    ranking::{RankingEvalCase, RankingEvalReport, SearchRanker},
};
use serde::{Deserialize, Serialize};

/// Run an adaptive ranking subcommand.
pub fn run_ranking_command(cmd: RankingCommand) -> ExitCode {
    match cmd {
        RankingCommand::Eval { file, format } => match evaluate_ranking_file(&file) {
            Ok(report) => {
                print_ranking_eval_report(&report, format);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

#[derive(Debug, Serialize)]
struct RankingEvalCliReport {
    schema_version: &'static str,
    report: RankingEvalReport,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RankingEvalInput {
    Cases(Vec<RankingEvalCase>),
    Wrapped { cases: Vec<RankingEvalCase> },
}

fn evaluate_ranking_file(path: &Path) -> Result<RankingEvalCliReport, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    evaluate_ranking_fixture_str(&content)
}

fn evaluate_ranking_fixture_str(content: &str) -> Result<RankingEvalCliReport, String> {
    let input: RankingEvalInput = serde_json::from_str(content)
        .map_err(|e| format!("failed to parse ranking fixture JSON: {e}"))?;
    let cases = match input {
        RankingEvalInput::Cases(cases) | RankingEvalInput::Wrapped { cases } => cases,
    };
    if cases.is_empty() {
        return Err("ranking fixture must contain at least one case".to_string());
    }

    Ok(RankingEvalCliReport {
        schema_version: "ranking-eval.v1",
        report: SearchRanker::new().evaluate_offline(&cases),
    })
}

fn print_ranking_eval_report(report: &RankingEvalCliReport, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).unwrap_or_default()
            );
        }
        OutputFormat::Plain => {
            println!("schema_version={}", report.schema_version);
            println!("case_count={}", report.report.case_count);
            println!("top1_hits={}", report.report.top1_hits);
            println!("top1_hit_rate={:.3}", report.report.top1_hit_rate);
            println!(
                "baseline_top1_hit_rate={:.3}",
                report.report.baseline_top1_hit_rate
            );
            println!(
                "improvements_over_baseline={}",
                report.report.improvements_over_baseline
            );
            println!(
                "regressions_vs_baseline={}",
                report.report.regressions_vs_baseline
            );
            println!("filtered_candidates={}", report.report.filtered_candidates);
            println!("invalid_candidates={}", report.report.invalid_candidates);
        }
        OutputFormat::Table => {
            println!("Adaptive ranking evaluation ({})", report.schema_version);
            println!("Cases: {}", report.report.case_count);
            println!(
                "Top-1 hit rate: {:.1}% (baseline {:.1}%)",
                report.report.top1_hit_rate * 100.0,
                report.report.baseline_top1_hit_rate * 100.0
            );
            println!(
                "Lift: +{} / regressions: {} / filtered candidates: {} / invalid candidates: {}",
                report.report.improvements_over_baseline,
                report.report.regressions_vs_baseline,
                report.report.filtered_candidates,
                report.report.invalid_candidates
            );
            println!();
            println!(
                "{:<24} {:<16} {:<16} {:<16} HIT",
                "CASE", "EXPECTED", "ADAPTIVE", "BASELINE"
            );
            println!("{}", "-".repeat(82));
            for case in &report.report.cases {
                println!(
                    "{:<24} {:<16} {:<16} {:<16} {}",
                    truncate(&case.id, 24),
                    truncate(&case.expected_top_tool, 16),
                    truncate(case.actual_top_tool.as_deref().unwrap_or("-"), 16),
                    truncate(case.baseline_top_tool.as_deref().unwrap_or("-"), 16),
                    if case.top1_hit { "yes" } else { "no" }
                );
            }
        }
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut s: String = value.chars().take(max_chars.saturating_sub(3)).collect();
    s.push_str("...");
    s
}

#[cfg(test)]
mod tests {
    use super::evaluate_ranking_fixture_str;

    #[test]
    fn eval_accepts_wrapped_fixture_and_omits_query_from_report() {
        let fixture = r#"{
            "cases": [
                {
                    "id": "unsafe_exact_match",
                    "query": "delete customer",
                    "expected_top_tool": "customer_lookup",
                    "candidates": [
                        {
                            "server": "ops",
                            "tool": "delete_customer",
                            "description": "Delete customer record",
                            "safety": 0.0
                        },
                        {
                            "server": "crm",
                            "tool": "customer_lookup",
                            "description": "Read customer profile safely"
                        }
                    ]
                }
            ]
        }"#;

        let report = evaluate_ranking_fixture_str(fixture).unwrap();
        assert_eq!(report.schema_version, "ranking-eval.v1");
        assert_eq!(report.report.case_count, 1);
        assert_eq!(report.report.top1_hits, 1);
        assert_eq!(report.report.baseline_top1_hits, 0);
        assert_eq!(report.report.improvements_over_baseline, 1);
        assert_eq!(report.report.filtered_candidates, 1);

        let rendered = serde_json::to_string(&report).unwrap();
        assert!(!rendered.contains("delete customer"));
    }

    #[test]
    fn eval_rejects_empty_fixture() {
        let err = evaluate_ranking_fixture_str(r#"{"cases":[]}"#).unwrap_err();
        assert!(err.contains("at least one case"));
    }
}
