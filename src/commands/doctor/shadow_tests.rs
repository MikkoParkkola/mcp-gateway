use super::*;

#[test]
fn dlp_rules_has_ten_entries() {
    assert_eq!(DLP_RULES.len(), 10, "RFC-0132 specifies 10 DLP patterns");
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
    assert!(out.contains("RFC-0132"), "must cite RFC-0132");
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
    let grep_lines: Vec<&str> = out.lines().filter(|l| l.starts_with("grep -EP")).collect();
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
fn render_nginx_contains_each_rule_as_if_block() {
    let out = render_nginx(DLP_RULES);
    for rule in DLP_RULES {
        assert!(
            out.contains(rule.regex),
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
