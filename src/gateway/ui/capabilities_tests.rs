// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the capability management helpers.

use super::*;

// ── is_safe_name ──────────────────────────────────────────────────────────

#[test]
fn safe_name_accepts_lowercase_alphanumeric_hyphen_underscore() {
    assert!(is_safe_name("my-tool"));
    assert!(is_safe_name("github_create_issue"));
    assert!(is_safe_name("tool123"));
    assert!(is_safe_name("a"));
}

#[test]
fn safe_name_rejects_path_traversal_patterns() {
    // Classic path traversal
    assert!(!is_safe_name("../etc/passwd"));
    assert!(!is_safe_name("../../secrets"));
    assert!(!is_safe_name("foo/bar"));
    assert!(!is_safe_name("foo\\bar"));
    assert!(!is_safe_name(".hidden"));
    assert!(!is_safe_name("foo.yaml"));
}

#[test]
fn safe_name_rejects_uppercase_and_special_chars() {
    assert!(!is_safe_name("MyTool"));
    assert!(!is_safe_name("tool name"));
    assert!(!is_safe_name("tool!"));
    assert!(!is_safe_name("tool@example"));
    assert!(!is_safe_name("<script>"));
}

#[test]
fn safe_name_rejects_empty_and_too_long() {
    assert!(!is_safe_name(""));
    assert!(!is_safe_name(&"a".repeat(129)));
}

#[test]
fn safe_name_accepts_max_length_128() {
    let name = "a".repeat(128);
    assert!(is_safe_name(&name));
}

#[test]
fn safe_name_rejects_null_bytes() {
    assert!(!is_safe_name("foo\0bar"));
}

// ── validate_yaml_body ────────────────────────────────────────────────────

/// The editor's validation as one message, the shape these tests were
/// written against before validation became the loader's (D3).
fn validate_yaml_body(yaml: &str) -> Option<String> {
    file_writer::validate(yaml, Path::new("capability.yaml"), None)
        .err()
        .map(|errors| {
            errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
}

#[test]
fn validate_yaml_body_rejects_empty() {
    assert!(validate_yaml_body("").is_some());
    assert!(validate_yaml_body("   ").is_some());
}

#[test]
fn validate_yaml_body_rejects_syntax_errors() {
    let bad = "name: foo\n  bad indent\n::broken";
    assert!(validate_yaml_body(bad).is_some());
}

#[test]
fn validate_yaml_body_accepts_valid_capability() {
    let yaml = r#"
fulcrum: "1.0"
name: test_tool
description: A test capability
providers:
  primary:
service: rest
config:
  base_url: https://api.example.com
  path: /test
"#;
    // parse_capability may warn but should not error on this minimal input
    // (validate_capability requires providers.primary which is present)
    let result = validate_yaml_body(yaml);
    assert!(result.is_none(), "Expected no error, got: {result:?}");
}

/// A text with a `name:` key that does not deserialize as a capability
/// is refused: the parse error was computed and then discarded.
#[test]
fn validate_yaml_body_refuses_text_that_does_not_parse() {
    let result = validate_yaml_body("name: kept\nproviders: 5\n");
    assert!(
        result
            .as_deref()
            .is_some_and(|e| e.contains("Failed to parse capability YAML")),
        "expected the parse error, got: {result:?}"
    );
}

#[test]
fn validate_yaml_body_requires_name_key() {
    let yaml = "description: no name here\n";
    let result = validate_yaml_body(yaml);
    assert!(result.is_some());
}

// ── count_tools ───────────────────────────────────────────────────────────

#[test]
fn count_tools_returns_zero_for_invalid_yaml() {
    // A document that is syntactically unparseable (bad indentation / tab char)
    let bad = "key:\n\t- broken\n  - [unterminated";
    assert_eq!(count_tools(bad), 0);
}

#[test]
fn count_tools_returns_one_for_single_provider() {
    let yaml = r"
name: t
providers:
  primary:
service: rest
";
    assert_eq!(count_tools(yaml), 1);
}

#[test]
fn count_tools_counts_named_providers() {
    let yaml = r"
name: t
providers:
  primary:
service: rest
  secondary:
service: rest
";
    assert_eq!(count_tools(yaml), 2);
}

// ── extract_description ───────────────────────────────────────────────────

#[test]
fn extract_description_returns_none_when_absent() {
    let yaml = "name: foo\n";
    assert_eq!(extract_description(yaml), None);
}

#[test]
fn extract_description_returns_value_when_present() {
    let yaml = "name: foo\ndescription: Does something useful.\n";
    assert_eq!(
        extract_description(yaml),
        Some("Does something useful.".to_owned())
    );
}

// ── find_capability_file ──────────────────────────────────────────────────

#[test]
fn find_capability_file_returns_none_when_no_dirs() {
    let result = find_capability_file(&[], "my-tool");
    assert!(result.is_none());
}

#[test]
fn find_capability_file_returns_none_for_missing_file() {
    let result = find_capability_file(&["/nonexistent/dir".to_owned()], "my-tool");
    assert!(result.is_none());
}

// ── Nesting depth ──────────────────────────────────────────────────────

#[test]
fn validate_yaml_body_refuses_deep_unread_field() {
    let deep = format!(
        "name: probe\nprobe: {}1{}\n",
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    let err = validate_yaml_body(&deep).expect("10k-deep YAML must be refused");
    assert!(err.contains("nesting deeper than 128"), "got: {err}");
}
