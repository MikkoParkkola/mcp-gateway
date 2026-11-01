// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The doctor report: the human table and the JSON document, and the
//! stable ids and badges they print.

use super::{CheckResult, CheckStatus, OutputFormat, Value, json};

// ── Output formatting ─────────────────────────────────────────────────────────

pub(super) fn print_results(results: &[CheckResult], format: OutputFormat) {
    match format {
        OutputFormat::Json => print_results_json(results),
        OutputFormat::Plain | OutputFormat::Table => print_results_human(results),
    }
}

fn print_results_human(results: &[CheckResult]) {
    use std::fmt::Write as _;

    let use_color = std::env::var("NO_COLOR").is_err();

    for result in results {
        print!(
            "{}",
            super::human_lines(format_badge(&result.status, use_color), result)
        );
    }

    println!();

    // Summary line.
    let (pass, fail, warn) = summary_counts(results);

    let mut summary = String::new();
    let _ = write!(
        summary,
        "{pass} check{} passed",
        if pass == 1 { "" } else { "s" }
    );
    if fail > 0 {
        let _ = write!(summary, ", {fail} failed");
    }
    if warn > 0 {
        let _ = write!(
            summary,
            ", {warn} warning{}",
            if warn == 1 { "" } else { "s" }
        );
    }
    println!("{summary}");
}

fn print_results_json(results: &[CheckResult]) {
    println!(
        "{}",
        serde_json::to_string_pretty(&doctor_report_json_value(results)).unwrap_or_default()
    );
}

pub(super) fn doctor_report_json_value(results: &[CheckResult]) -> Value {
    let (pass, fail, warn) = summary_counts(results);
    let checks: Vec<Value> = results.iter().map(check_result_json_value).collect();
    json!({
        "schema_version": "doctor.v1",
        "ok": fail == 0,
        "summary": {
            "pass": pass,
            "fail": fail,
            "warn": warn,
            "total": results.len(),
        },
        "checks": checks,
    })
}

pub(super) fn check_result_json_value(result: &CheckResult) -> Value {
    json!({
        "id": stable_check_id(&result.label),
        "label": result.label,
        "category": result.category,
        "status": status_str(&result.status),
        "detail": result.full_detail(),
        "hint": result.hint,
        "fixability": {
            "auto_fixable": result.auto_fixable,
            "safe_to_apply": result.auto_fixable,
            "command": result.fix_command,
            "requires_user": result.status != CheckStatus::Pass && !result.auto_fixable,
            "risk": result.risk,
            "confirmation_required": result.confirmation_required,
            "verification": result.verification_command,
            "rollback": result.rollback_command,
        },
    })
}

fn summary_counts(results: &[CheckResult]) -> (usize, usize, usize) {
    let pass = results
        .iter()
        .filter(|r| r.status == CheckStatus::Pass)
        .count();
    let fail = results
        .iter()
        .filter(|r| r.status == CheckStatus::Fail)
        .count();
    let warn = results
        .iter()
        .filter(|r| r.status == CheckStatus::Warn)
        .count();
    (pass, fail, warn)
}

fn status_str(status: &CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "pass",
        CheckStatus::Fail => "fail",
        CheckStatus::Warn => "warn",
    }
}

fn stable_check_id(label: &str) -> String {
    label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

pub(super) fn format_badge(status: &CheckStatus, color: bool) -> &'static str {
    match (status, color) {
        (CheckStatus::Pass, true) => "\x1b[32m[PASS]\x1b[0m",
        (CheckStatus::Fail, true) => "\x1b[31m[FAIL]\x1b[0m",
        (CheckStatus::Warn, true) => "\x1b[33m[WARN]\x1b[0m",
        (CheckStatus::Pass, false) => "[PASS]",
        (CheckStatus::Fail, false) => "[FAIL]",
        (CheckStatus::Warn, false) => "[WARN]",
    }
}
