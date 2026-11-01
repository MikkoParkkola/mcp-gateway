// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

#[test]
fn dlp_rules_has_ten_entries() {
    assert_eq!(DLP_RULES.len(), 10, "ten DLP patterns ship");
}

#[test]
fn dlp_rules_all_have_non_empty_fields() {
    for rule in DLP_RULES {
        assert!(!rule.name.is_empty(), "name must not be empty");
        assert!(!rule.category.is_empty(), "category must not be empty");
        assert!(!rule.regex.is_empty(), "regex must not be empty");
        assert!(
            !rule.description.is_empty(),
            "description must not be empty"
        );
    }
}

#[test]
fn dlp_rules_categories_are_valid() {
    let valid = ["host", "uri", "body"];
    for rule in DLP_RULES {
        assert!(
            valid.contains(&rule.category),
            "unexpected category '{}' for rule '{}'",
            rule.category,
            rule.name
        );
    }
}

#[test]
fn render_grep_contains_header_disclaimer() {
    let out = render_grep(DLP_RULES);
    assert!(
        out.contains("OPERATOR NOTE"),
        "must include operator disclaimer"
    );
    assert!(
        out.contains("docs/SHADOW_SCAN.md"),
        "must cite the operator docs"
    );
}

#[test]
fn render_grep_contains_each_rule_regex() {
    let out = render_grep(DLP_RULES);
    for rule in DLP_RULES {
        assert!(
            out.contains(rule.regex),
            "grep output missing regex for rule '{}'",
            rule.name
        );
    }
}

#[test]
fn render_grep_one_grep_command_per_rule() {
    let out = render_grep(DLP_RULES);
    let grep_lines: Vec<&str> = out.lines().filter(|l| l.starts_with("grep -E")).collect();
    assert_eq!(
        grep_lines.len(),
        DLP_RULES.len(),
        "expected one grep line per rule"
    );
}

#[test]
fn render_nginx_contains_map_block() {
    let out = render_nginx(DLP_RULES);
    assert!(
        out.contains("map $request_body $mcp_shadow"),
        "must include map block"
    );
    assert!(
        out.contains("OPERATOR NOTE"),
        "must include operator disclaimer"
    );
}

#[test]
fn render_nginx_contains_each_escaped_rule_in_map() {
    let out = render_nginx(DLP_RULES);
    for rule in DLP_RULES {
        let escaped = rule.regex.replace('\\', "\\\\").replace('"', "\\\"");
        assert!(
            out.contains(&escaped),
            "nginx output missing regex for rule '{}'",
            rule.name
        );
    }
}

#[test]
fn render_yaml_starts_with_dlp_rules_key() {
    let out = render_yaml(DLP_RULES);
    assert!(
        out.contains("dlp_rules:"),
        "must have top-level dlp_rules: key"
    );
}

#[test]
fn render_yaml_contains_all_rule_names() {
    let out = render_yaml(DLP_RULES);
    for rule in DLP_RULES {
        assert!(
            out.contains(rule.name),
            "yaml output missing name for rule '{}'",
            rule.name
        );
    }
}

#[test]
fn render_yaml_escapes_backslashes_in_regex() {
    let out = render_yaml(DLP_RULES);
    let has_backslash_rule = DLP_RULES.iter().any(|r| r.regex.contains('\\'));
    if has_backslash_rule {
        assert!(
            out.contains("\\\\s"),
            "backslashes in regex must be escaped to \\\\ in YAML"
        );
    }
}

#[test]
fn render_yaml_contains_disclaimer() {
    let out = render_yaml(DLP_RULES);
    assert!(
        out.contains("OPERATOR NOTE"),
        "yaml must include operator disclaimer"
    );
}

#[test]
fn shadow_command_invalid_format_returns_failure() {
    let code = run_doctor_shadow_command("iptables");
    assert_eq!(code, ExitCode::FAILURE);
}

#[test]
fn shadow_command_haproxy_alias_is_accepted() {
    let code = run_doctor_shadow_command("haproxy");
    assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn shadow_command_empty_format_defaults_to_grep() {
    let code = run_doctor_shadow_command("");
    assert_eq!(code, ExitCode::SUCCESS);
}

/// A finding's label, detail and hint reach the terminal escaped, with the
/// result's own two lines and no more; a Windows path keeps its backslashes.
#[test]
fn a_result_prints_client_text_escaped() {
    let result = CheckResult::warn(
        "ShadowRadar srv\u{1b}[31m",
        "tool\u{202e}x is unmanaged via stdio\u{2028}forged",
    )
    .with_hint("see C:\\Users\\me\\gw.yaml\u{1b}[0m");
    let lines = human_lines("[WARN]", &result);
    for raw in ['\u{1b}', '\u{202e}', '\u{2028}'] {
        assert!(!lines.contains(raw), "{raw:?} in {lines:?}");
    }
    assert_eq!(lines.lines().count(), 2, "{lines:?}");
    assert!(
        lines.contains("C:\\Users\\me\\gw.yaml\\u{1b}[0m"),
        "{lines}"
    );
}

/// The stderr tail prints under a gateway banner, each captured line behind
/// the gateway's marker and escaped; `--format json` gets the old text raw.
#[test]
fn a_stderr_tail_prints_marked_and_escaped_and_joins_raw_for_json() {
    let mut result = CheckResult::fail("Backend tool", "exited 1");
    assert_eq!(result.full_detail(), "exited 1", "no tail asked for");
    result.stderr_tail = Some(vec![
        "\u{1b}[31mpanic\u{202e}".to_string(),
        "a\nb\rc\u{2028}d".to_string(),
    ]);
    let lines = human_lines("[FAIL]", &result);
    assert_eq!(lines.lines().count(), 4, "{lines:?}");
    assert!(
        lines.contains("  stderr | a\\u{a}b\\u{d}c\\u{2028}d"),
        "{lines}"
    );
    assert!(
        !lines.contains('\u{1b}') && !lines.contains('\u{202e}'),
        "{lines:?}"
    );
    assert!(lines.contains("  stderr | \\u{1b}[31mpanic"), "{lines}");
    assert_eq!(
        result.full_detail(),
        "exited 1\n  stderr tail (may contain secrets: masking is best effort, review before \
         sharing):\n    \u{1b}[31mpanic\u{202e}\n    a\nb\rc\u{2028}d"
    );
    result.stderr_tail = Some(Vec::new());
    assert_eq!(result.full_detail(), "exited 1\n  (no stderr captured)");
    assert_eq!(
        human_lines("[FAIL]", &result),
        "[FAIL] Backend tool: exited 1\n  (no stderr captured)\n"
    );
    result.stderr_tail = None;
    assert_eq!(
        human_lines("[FAIL]", &result),
        "[FAIL] Backend tool: exited 1\n"
    );
}

/// A backend printing a result-shaped stderr line cannot pass it off as a
/// doctor result: the line starts with the gateway's marker.
#[test]
fn a_stderr_line_cannot_forge_a_result_line() {
    let mut result = CheckResult::fail("Backend tool", "exited 1");
    result.stderr_tail = Some(vec!["\u{2713} all checks passed".to_string()]);
    let lines = human_lines("[FAIL]", &result);
    let forged = lines
        .lines()
        .find(|line| line.contains("all checks passed"))
        .expect("the stderr line is shown");
    assert!(forged.starts_with("  stderr | "), "{lines}");
}

/// A server name holding a line break cannot print a fake result line: the
/// detail stays one line, its break shown as `\u{a}`.
#[test]
fn a_line_break_in_a_name_cannot_forge_a_result_line() {
    let result = CheckResult::warn(
        "ShadowRadar tool",
        "tool\n\u{2713} all checks passed is unmanaged via stdio.",
    );
    let lines = human_lines("[WARN]", &result);
    assert_eq!(lines.lines().count(), 1, "{lines:?}");
    assert!(
        lines.contains("tool\\u{a}\u{2713} all checks passed"),
        "{lines}"
    );
}
