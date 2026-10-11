// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Code Mode tool definitions, tool references, glob matching and match JSON.

use super::*;

// ── Code Mode: build_code_mode_tools ─────────────────────────────────────

#[test]
fn build_code_mode_tools_returns_exactly_two_tools() {
    // GIVEN: code mode is active
    // WHEN: building the code mode tool list
    // THEN: exactly two tools are returned
    let tools = build_code_mode_tools();
    assert_eq!(tools.len(), 2);
}

#[test]
fn build_code_mode_tools_first_is_gateway_search() {
    // GIVEN/WHEN: building code mode tools
    // THEN: first tool is gateway_search
    let tools = build_code_mode_tools();
    assert_eq!(tools[0].name, "gateway_search");
}

#[test]
fn build_code_mode_tools_second_is_gateway_execute() {
    // GIVEN/WHEN: building code mode tools
    // THEN: second tool is gateway_execute
    let tools = build_code_mode_tools();
    assert_eq!(tools[1].name, "gateway_execute");
}

#[test]
fn build_code_mode_search_tool_has_query_parameter() {
    // GIVEN: code mode search tool definition
    // WHEN: inspecting the input schema
    // THEN: 'query' is a required string parameter
    let tool = build_code_mode_search_tool();
    assert_eq!(tool.input_schema["properties"]["query"]["type"], "string");
    assert_eq!(tool.input_schema["required"][0], "query");
}

#[test]
fn build_code_mode_search_tool_has_limit_parameter() {
    // GIVEN: code mode search tool definition
    // WHEN: inspecting the input schema
    // THEN: 'limit' parameter with default 10 is present
    let tool = build_code_mode_search_tool();
    assert_eq!(tool.input_schema["properties"]["limit"]["type"], "integer");
    assert_eq!(tool.input_schema["properties"]["limit"]["default"], 10);
}

#[test]
fn build_code_mode_search_tool_has_include_schema_parameter() {
    // GIVEN: code mode search tool definition
    // WHEN: inspecting the input schema
    // THEN: deprecated include_schema is still present, without a true default
    let tool = build_code_mode_search_tool();
    assert_eq!(
        tool.input_schema["properties"]["include_schema"]["type"],
        "boolean"
    );
    assert!(
        tool.input_schema["properties"]["include_schema"]
            .get("default")
            .is_none()
    );
    let desc = tool.input_schema["properties"]["include_schema"]["description"]
        .as_str()
        .unwrap();
    assert!(desc.to_ascii_lowercase().contains("deprecated"), "{desc}");
}

#[test]
fn build_code_mode_search_tool_documents_tier_ladder() {
    let tool = build_code_mode_search_tool();
    let desc = tool.description.as_deref().unwrap();
    for needle in ["L0", "l1", "l2", "explain"] {
        assert!(desc.contains(needle), "missing {needle} in: {desc}");
    }
    assert_eq!(
        tool.input_schema["properties"]["detail"]["enum"],
        json!(["l0", "l1", "l2"])
    );
    assert_eq!(tool.input_schema["properties"]["detail"]["default"], "l0");
    assert_eq!(tool.input_schema["properties"]["explain"]["default"], false);
}

#[test]
fn build_code_mode_execute_tool_has_tool_parameter() {
    // GIVEN: code mode execute tool definition
    // WHEN: inspecting the input schema
    // THEN: 'tool' string parameter is present (no 'required' constraint — chain is also valid)
    let tool = build_code_mode_execute_tool();
    assert_eq!(tool.input_schema["properties"]["tool"]["type"], "string");
}

#[test]
fn build_code_mode_execute_tool_has_chain_parameter() {
    // GIVEN: code mode execute tool definition
    // WHEN: inspecting the input schema
    // THEN: 'chain' array parameter is present
    let tool = build_code_mode_execute_tool();
    assert_eq!(tool.input_schema["properties"]["chain"]["type"], "array");
}

#[test]
fn build_code_mode_execute_tool_has_arguments_parameter() {
    // GIVEN: code mode execute tool definition
    // WHEN: inspecting the input schema
    // THEN: 'arguments' object parameter is present
    let tool = build_code_mode_execute_tool();
    assert_eq!(
        tool.input_schema["properties"]["arguments"]["type"],
        "object"
    );
}

#[test]
fn build_code_mode_tools_both_have_descriptions() {
    // GIVEN/WHEN: building code mode tools
    // THEN: both have non-empty descriptions
    for tool in build_code_mode_tools() {
        assert!(
            tool.description.as_deref().is_some_and(|d| !d.is_empty()),
            "Tool {} missing description",
            tool.name
        );
    }
}

// ── Code Mode: parse_code_mode_tool_ref ──────────────────────────────────

#[test]
fn parse_code_mode_tool_ref_with_colon_splits_correctly() {
    // GIVEN: tool ref with server prefix
    // WHEN: parsing
    // THEN: (tool_name, Some(server))
    let (tool, server) = parse_code_mode_tool_ref("my-server:my_tool");
    assert_eq!(tool, "my_tool");
    assert_eq!(server, Some("my-server"));
}

#[test]
fn parse_code_mode_tool_ref_without_colon_returns_none_server() {
    // GIVEN: bare tool name
    // WHEN: parsing
    // THEN: (tool_name, None)
    let (tool, server) = parse_code_mode_tool_ref("my_tool");
    assert_eq!(tool, "my_tool");
    assert!(server.is_none());
}

#[test]
fn parse_code_mode_tool_ref_uses_first_colon_only() {
    // GIVEN: tool ref with multiple colons (e.g. tool name contains a colon)
    // WHEN: parsing
    // THEN: splits on the first colon
    let (tool, server) = parse_code_mode_tool_ref("srv:tool:extra");
    assert_eq!(tool, "tool:extra");
    assert_eq!(server, Some("srv"));
}

// ── Code Mode: is_glob_pattern ────────────────────────────────────────────

#[test]
fn is_glob_pattern_detects_star() {
    assert!(is_glob_pattern("file_*"));
    assert!(is_glob_pattern("*search*"));
    assert!(is_glob_pattern("*"));
}

#[test]
fn is_glob_pattern_detects_question_mark() {
    assert!(is_glob_pattern("file_?"));
    assert!(is_glob_pattern("search?"));
}

#[test]
fn is_glob_pattern_returns_false_for_plain_query() {
    assert!(!is_glob_pattern("search"));
    assert!(!is_glob_pattern("file read"));
    assert!(!is_glob_pattern(""));
}

// ── Code Mode: tool_name_matches_glob + tool_matches_glob ────────────────

#[test]
fn tool_name_matches_glob_star_prefix() {
    // GIVEN: pattern "*search*"
    // WHEN: matching against "brave_search"
    // THEN: matches
    assert!(tool_name_matches_glob("brave_search", "*search*"));
}

#[test]
fn tool_name_matches_glob_star_suffix() {
    // GIVEN: pattern "file_*"
    // WHEN: matching against "file_read" and "file_write"
    // THEN: both match
    assert!(tool_name_matches_glob("file_read", "file_*"));
    assert!(tool_name_matches_glob("file_write", "file_*"));
}

#[test]
fn tool_name_matches_glob_star_no_match() {
    // GIVEN: pattern "file_*"
    // WHEN: matching against "db_read"
    // THEN: does not match
    assert!(!tool_name_matches_glob("db_read", "file_*"));
}

#[test]
fn tool_name_matches_glob_question_mark_single_char() {
    // GIVEN: pattern "file_?ead"
    // WHEN: matching against "file_read"
    // THEN: matches (? = 'r')
    assert!(tool_name_matches_glob("file_read", "file_?ead"));
}

#[test]
fn tool_name_matches_glob_question_mark_no_match_multiple_chars() {
    // GIVEN: pattern "file_?ead"
    // WHEN: matching against "file_bread"
    // THEN: does not match (? can only match one char)
    assert!(!tool_name_matches_glob("file_bread", "file_?ead"));
}

#[test]
fn tool_name_matches_glob_exact_match() {
    // GIVEN: exact pattern with no wildcards
    // WHEN: matching against the same string
    // THEN: matches
    assert!(tool_name_matches_glob("gateway_search", "gateway_search"));
}

#[test]
fn tool_name_matches_glob_case_insensitive() {
    // GIVEN: mixed-case pattern
    // WHEN: matching against lower-case tool name
    // THEN: matches (case-insensitive)
    assert!(tool_name_matches_glob("FILE_READ", "file_*"));
    assert!(tool_name_matches_glob("brave_SEARCH", "*search*"));
}

#[test]
fn tool_name_matches_glob_star_matches_empty() {
    // GIVEN: pattern "prefix*" where text equals prefix
    // WHEN: matching
    // THEN: star matches empty string — succeeds
    assert!(tool_name_matches_glob("prefix", "prefix*"));
}

#[test]
fn tool_name_matches_glob_star_star_matches_any() {
    // GIVEN: pattern "**" (double star)
    // WHEN: matching any string
    // THEN: matches
    assert!(tool_name_matches_glob("anything_here", "**"));
    assert!(tool_name_matches_glob("", "**"));
}

#[test]
fn tool_matches_glob_delegates_to_name() {
    // GIVEN: a tool and a glob pattern matching its name
    // WHEN: using tool_matches_glob
    // THEN: returns true
    let tool = make_tool("brave_search", Some("Web search API"));
    assert!(tool_matches_glob(&tool, "*search*"));
    // Description is NOT checked for glob matching (name-only)
    assert!(!tool_matches_glob(&tool, "*web*"));
}

// ── Code Mode: build_code_mode_match_json ────────────────────────────────

#[test]
fn build_code_mode_match_json_includes_schema_when_requested() {
    // GIVEN: a tool with a non-trivial input schema
    let mut tool = make_tool("my_tool", Some("Does stuff"));
    tool.input_schema = json!({
        "type": "object",
        "properties": {"q": {"type": "string"}},
        "required": ["q"]
    });
    // WHEN: building with include_schema=true
    let result = build_code_mode_match_json("srv", &tool, true);
    // THEN: input_schema field is present
    assert!(result.get("input_schema").is_some());
    assert_eq!(result["input_schema"]["properties"]["q"]["type"], "string");
}

#[test]
fn build_code_mode_match_json_omits_schema_when_not_requested() {
    // GIVEN: a tool
    let tool = make_tool("my_tool", Some("Does stuff"));
    // WHEN: building with include_schema=false
    let result = build_code_mode_match_json("srv", &tool, false);
    // THEN: no input_schema field
    assert!(result.get("input_schema").is_none());
}

#[test]
fn build_code_mode_match_json_tool_ref_format_is_server_colon_name() {
    // GIVEN: server "my-backend" and tool "do_work"
    let tool = make_tool("do_work", Some("Work"));
    // WHEN: building the match json
    let result = build_code_mode_match_json("my-backend", &tool, false);
    // THEN: "tool" field is "my-backend:do_work"
    assert_eq!(result["tool"], "my-backend:do_work");
}

#[test]
fn build_code_mode_match_json_truncates_long_descriptions() {
    // GIVEN: description longer than 500 chars
    let long_desc = "z".repeat(600);
    let tool = make_tool("tool", Some(&long_desc));
    // WHEN: building match json
    let result = build_code_mode_match_json("srv", &tool, false);
    // THEN: description truncated to 500 chars
    assert_eq!(result["description"].as_str().unwrap().len(), 500);
}

#[test]
fn build_code_mode_match_json_handles_none_description() {
    // GIVEN: tool with no description
    let tool = make_tool("tool", None);
    // WHEN: building match json
    let result = build_code_mode_match_json("srv", &tool, false);
    // THEN: description is empty string
    assert_eq!(result["description"], "");
}

// ── Code Mode: glob_match_chars edge cases ───────────────────────────────

#[test]
fn glob_match_empty_pattern_matches_empty_text() {
    assert!(tool_name_matches_glob("", ""));
}

#[test]
fn glob_match_empty_pattern_rejects_non_empty_text() {
    assert!(!tool_name_matches_glob("abc", ""));
}

#[test]
fn glob_match_star_only_matches_everything() {
    assert!(tool_name_matches_glob("", "*"));
    assert!(tool_name_matches_glob("anything", "*"));
}

#[test]
fn glob_match_question_mark_only_matches_single_char() {
    assert!(tool_name_matches_glob("a", "?"));
    assert!(!tool_name_matches_glob("", "?"));
    assert!(!tool_name_matches_glob("ab", "?"));
}

#[test]
fn glob_match_multiple_question_marks() {
    // GIVEN: pattern "??_??" matches exactly 5-char string with underscore in middle
    assert!(tool_name_matches_glob("ab_cd", "??_??"));
    assert!(!tool_name_matches_glob("a_cd", "??_??"));
}

// ── Code Mode: config deserialization ───────────────────────────────────

#[test]
fn code_mode_config_defaults_to_disabled() {
    // GIVEN: empty config YAML
    // WHEN: deserializing
    // THEN: code_mode.enabled defaults to false
    let config: crate::config::Config = serde_yaml::from_str("{}").unwrap();
    assert!(!config.code_mode.enabled);
}

#[test]
fn code_mode_config_can_be_enabled_via_yaml() {
    // GIVEN: YAML with code_mode.enabled: true
    let yaml = "code_mode:\n  enabled: true\n";
    // WHEN: deserializing
    let config: crate::config::Config = serde_yaml::from_str(yaml).unwrap();
    // THEN: code_mode.enabled is true
    assert!(config.code_mode.enabled);
}

#[test]
fn code_mode_config_can_be_explicitly_disabled_via_yaml() {
    // GIVEN: YAML with code_mode.enabled: false
    let yaml = "code_mode:\n  enabled: false\n";
    // WHEN: deserializing
    let config: crate::config::Config = serde_yaml::from_str(yaml).unwrap();
    // THEN: code_mode.enabled is false
    assert!(!config.code_mode.enabled);
}
