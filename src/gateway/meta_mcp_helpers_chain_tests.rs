use super::*;

// Helper to build a Tool for testing
fn make_tool(name: &str, description: Option<&str>) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: description.map(ToString::to_string),
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: None,
    }
}

// ── build_suggestions ───────────────────────────────────────────────

#[test]
fn build_suggestions_empty_when_no_tags() {
    // GIVEN: no tags in the index
    // WHEN: building suggestions
    // THEN: empty result
    let suggestions = build_suggestions("xyzzy", &[]);
    assert!(suggestions.is_empty());
}

#[test]
fn build_suggestions_finds_tags_containing_query_word() {
    // GIVEN: tags include "searching" and query is "search"
    let tags = vec!["searching".to_string(), "weather".to_string()];
    let suggestions = build_suggestions("search", &tags);
    assert!(suggestions.contains(&"searching".to_string()));
    assert!(!suggestions.contains(&"weather".to_string()));
}

#[test]
fn build_suggestions_finds_tags_by_prefix() {
    // GIVEN: tags include "scraping" and query word "scr" (3+ chars prefix match)
    let tags = vec![
        "scraping".to_string(),
        "scripting".to_string(),
        "other".to_string(),
    ];
    let suggestions = build_suggestions("scr", &tags);
    assert!(suggestions.contains(&"scraping".to_string()));
    assert!(suggestions.contains(&"scripting".to_string()));
}

#[test]
fn build_suggestions_limits_to_five_results() {
    // GIVEN: 10 tags all matching the query
    let tags: Vec<String> = (0..10).map(|i| format!("search{i}")).collect();
    let suggestions = build_suggestions("search", &tags);
    assert!(suggestions.len() <= 5);
}

#[test]
fn build_suggestions_returns_sorted_results() {
    // GIVEN: tags in random order that all match
    let tags = vec![
        "scrape".to_string(),
        "analyze".to_string(),
        "audit".to_string(),
    ];
    // query matches "audit" and "analyze" (prefix "ana"/"aud" — both start with 3+ chars)
    let suggestions = build_suggestions("aud", &tags);
    // Verify sorted
    let mut sorted = suggestions.clone();
    sorted.sort();
    assert_eq!(suggestions, sorted);
}

#[test]
fn build_suggestions_deduplicates_results() {
    // GIVEN: duplicate tags
    let tags = vec![
        "search".to_string(),
        "search".to_string(),
        "lookup".to_string(),
    ];
    let suggestions = build_suggestions("search", &tags);
    let unique_count = suggestions
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(suggestions.len(), unique_count);
}

#[test]
fn build_suggestions_no_match_for_short_query_word_prefix() {
    // GIVEN: query word < 3 chars, relies only on substring match
    let tags = vec!["xy_tool".to_string()];
    // "xy" won't match via prefix (needs 3+), but "xy" IS a substring of "xy_tool"
    let suggestions = build_suggestions("xy", &tags);
    // Substring match still works
    assert!(suggestions.contains(&"xy_tool".to_string()));
}

// ── build_suggestions edge cases (T1.6) ─────────────────────────────

#[test]
fn build_suggestions_multi_word_query_with_partial_match() {
    // GIVEN: query "entity discovery" and tags where only "entity" matches some tags
    // WHEN: building suggestions
    // THEN: tags containing "entity" are returned (partial match works)
    let tags = vec![
        "entity-type".to_string(),
        "entity-list".to_string(),
        "weather".to_string(),
        "calendar".to_string(),
    ];
    let suggestions = build_suggestions("entity discovery", &tags);
    // At least the entity tags should appear
    assert!(
        suggestions.contains(&"entity-type".to_string())
            || suggestions.contains(&"entity-list".to_string()),
        "expected entity tags in suggestions; got {suggestions:?}"
    );
    // Tags with no overlap to either word should be absent
    assert!(!suggestions.contains(&"weather".to_string()));
    assert!(!suggestions.contains(&"calendar".to_string()));
}

#[test]
fn build_suggestions_hyphenated_tags_match_component_word() {
    // GIVEN: query "entity" and tags containing "entity-discovery"
    // WHEN: building suggestions
    // THEN: the hyphenated tag is returned because it contains the word "entity" as substring
    let tags = vec![
        "entity-discovery".to_string(),
        "entity-search".to_string(),
        "unrelated-tag".to_string(),
    ];
    let suggestions = build_suggestions("entity", &tags);
    assert!(
        suggestions.contains(&"entity-discovery".to_string()),
        "hyphenated tag 'entity-discovery' should match query 'entity'"
    );
    assert!(
        suggestions.contains(&"entity-search".to_string()),
        "hyphenated tag 'entity-search' should match query 'entity'"
    );
    assert!(
        !suggestions.contains(&"unrelated-tag".to_string()),
        "'unrelated-tag' should not match query 'entity'"
    );
}

#[test]
fn build_suggestions_empty_query_returns_empty() {
    // GIVEN: an empty query string
    // WHEN: building suggestions against any tag set
    // THEN: returns empty (no query words means no match predicate fires)
    let tags = vec![
        "search".to_string(),
        "entity".to_string(),
        "weather".to_string(),
    ];
    let suggestions = build_suggestions("", &tags);
    assert!(
        suggestions.is_empty(),
        "empty query should produce no suggestions; got {suggestions:?}"
    );
}

// ── build_match_json_with_chains ────────────────────────────────────

#[test]
fn build_match_json_with_chains_omits_field_when_empty() {
    // GIVEN: a tool with no chains_with
    // WHEN: building match JSON with empty chains
    // THEN: no "chains_with" key in output
    let tool = make_tool("linear_get_teams", Some("List teams"));
    let result = build_match_json_with_chains("cap", &tool, &[]);
    assert_eq!(result["server"], "cap");
    assert_eq!(result["tool"], "linear_get_teams");
    assert!(result.get("chains_with").is_none());
}

#[test]
fn build_match_json_with_chains_includes_field_when_non_empty() {
    // GIVEN: a tool that chains into two downstream tools
    // WHEN: building match JSON with chains
    // THEN: "chains_with" array is present with correct values
    let tool = make_tool("linear_get_teams", Some("List teams"));
    let chains = vec![
        "linear_create_issue".to_string(),
        "linear_list_projects".to_string(),
    ];
    let result = build_match_json_with_chains("cap", &tool, &chains);
    let chains_val = result["chains_with"].as_array().unwrap();
    assert_eq!(chains_val.len(), 2);
    assert_eq!(chains_val[0], "linear_create_issue");
    assert_eq!(chains_val[1], "linear_list_projects");
}

#[test]
fn build_match_json_delegates_to_build_match_json_with_chains() {
    // GIVEN: a tool
    // WHEN: using the simple build_match_json helper
    // THEN: result is identical to build_match_json_with_chains(..., &[])
    let tool = make_tool("my_tool", Some("Does something"));
    let simple = build_match_json("srv", &tool);
    let explicit = build_match_json_with_chains("srv", &tool, &[]);
    assert_eq!(simple, explicit);
}

#[test]
fn build_match_json_with_chains_truncates_long_description() {
    // GIVEN: tool description longer than 500 chars
    // WHEN: building match JSON
    // THEN: description is truncated to 500 chars
    let long_desc = "x".repeat(600);
    let tool = make_tool("verbose_tool", Some(&long_desc));
    let result = build_match_json_with_chains("srv", &tool, &[]);
    assert_eq!(result["description"].as_str().unwrap().len(), 500);
}

// ── build_routing_instructions with chains ──────────────────────────

#[test]
fn build_routing_instructions_includes_chain_section_when_chains_present() {
    // GIVEN: capabilities where one declares chains_with
    use crate::capability::{
        AuthConfig, CacheConfig, CapabilityDefinition, CapabilityMetadata, ProvidersConfig,
        SchemaDefinition,
    };
    use crate::transform::TransformConfig;
    use std::collections::HashMap;

    let make_cap = |name: &str, category: &str, chains: Vec<&str>| CapabilityDefinition {
        fulcrum: "1.0".to_string(),
        name: name.to_string(),
        description: format!("{name} description"),
        schema: SchemaDefinition::default(),
        providers: ProvidersConfig::default(),
        auth: AuthConfig::default(),
        cache: CacheConfig::default(),
        metadata: CapabilityMetadata {
            category: category.to_string(),
            chains_with: chains.into_iter().map(ToString::to_string).collect(),
            ..Default::default()
        },
        transform: TransformConfig::default(),
        webhooks: HashMap::new(),
    };

    let caps = vec![
        make_cap(
            "linear_get_teams",
            "productivity",
            vec!["linear_create_issue"],
        ),
        make_cap("linear_create_issue", "productivity", vec![]),
    ];

    let instructions = build_routing_instructions(&caps, "cap");
    assert!(instructions.contains("Composition chains"));
    assert!(instructions.contains("linear_get_teams -> linear_create_issue"));
}

#[test]
fn build_routing_instructions_omits_chain_section_when_no_chains() {
    // GIVEN: capabilities with no chains_with set
    use crate::capability::{
        AuthConfig, CacheConfig, CapabilityDefinition, CapabilityMetadata, ProvidersConfig,
        SchemaDefinition,
    };
    use crate::transform::TransformConfig;
    use std::collections::HashMap;

    let cap = CapabilityDefinition {
        fulcrum: "1.0".to_string(),
        name: "tool_a".to_string(),
        description: "Tool A".to_string(),
        schema: SchemaDefinition::default(),
        providers: ProvidersConfig::default(),
        auth: AuthConfig::default(),
        cache: CacheConfig::default(),
        metadata: CapabilityMetadata {
            category: "general".to_string(),
            chains_with: vec![],
            ..Default::default()
        },
        transform: TransformConfig::default(),
        webhooks: HashMap::new(),
    };

    let instructions = build_routing_instructions(&[cap], "cap");
    assert!(!instructions.contains("Composition chains"));
}

// ── CapabilityMetadata deserialization (produces/consumes/chains_with) ──

#[test]
fn capability_metadata_deserializes_composition_fields_from_yaml() {
    // GIVEN: YAML with produces, consumes, and chains_with
    // WHEN: deserializing
    // THEN: all three fields are populated correctly
    let yaml = r"
category: productivity
produces: [teamId, issueId]
consumes: [teamId]
chains_with: [linear_create_issue, linear_update_issue]
";
    let meta: crate::capability::CapabilityMetadata = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(meta.produces, vec!["teamId", "issueId"]);
    assert_eq!(meta.consumes, vec!["teamId"]);
    assert_eq!(
        meta.chains_with,
        vec!["linear_create_issue", "linear_update_issue"]
    );
}

#[test]
fn capability_metadata_defaults_composition_fields_to_empty() {
    // GIVEN: YAML with no composition fields
    // WHEN: deserializing
    // THEN: produces, consumes, chains_with default to empty Vec
    let yaml = "category: search
";
    let meta: crate::capability::CapabilityMetadata = serde_yaml::from_str(yaml).unwrap();
    assert!(meta.produces.is_empty());
    assert!(meta.consumes.is_empty());
    assert!(meta.chains_with.is_empty());
}

// ── build_server_safety_status ─────────────────────────────────────────

#[test]
fn build_server_safety_status_live_server() {
    // GIVEN: a live server with 10% error rate
    let status = build_server_safety_status("my-backend", false, 0.10, 9, 1);
    // THEN: killed is false, error_rate formatted, window counts correct
    assert_eq!(status["server"], "my-backend");
    assert_eq!(status["killed"], false);
    assert_eq!(status["error_rate"], "10.0%");
    assert_eq!(status["window"]["successes"], 9);
    assert_eq!(status["window"]["failures"], 1);
}

#[test]
fn build_server_safety_status_killed_server() {
    // GIVEN: a killed server with 100% error rate
    let status = build_server_safety_status("bad-backend", true, 1.0, 0, 5);
    assert_eq!(status["killed"], true);
    assert_eq!(status["error_rate"], "100.0%");
}

#[test]
fn build_kill_server_tool_has_required_server_param() {
    let tool = build_kill_server_tool();
    assert_eq!(tool.name, "gateway_kill_server");
    assert_eq!(tool.input_schema["required"][0], "server");
}

#[test]
fn build_revive_server_tool_has_required_server_param() {
    let tool = build_revive_server_tool();
    assert_eq!(tool.name, "gateway_revive_server");
    assert_eq!(tool.input_schema["required"][0], "server");
}

// ── build_circuit_breaker_stats_json ──────────────────────────────────

fn make_cb_stats_closed() -> CircuitBreakerStats {
    CircuitBreakerStats {
        state: crate::failsafe::CircuitState::Closed,
        trips_count: 0,
        last_trip_ms: 0,
        retry_after_ms: 0,
        current_failures: 0,
        failure_threshold: 5,
    }
}

fn make_cb_stats_open() -> CircuitBreakerStats {
    CircuitBreakerStats {
        state: crate::failsafe::CircuitState::Open,
        trips_count: 3,
        last_trip_ms: 1_717_000_000_000,
        retry_after_ms: 29_000,
        current_failures: 5,
        failure_threshold: 5,
    }
}

#[test]
fn build_circuit_breaker_stats_json_closed_state() {
    // GIVEN: a closed circuit breaker stats snapshot
    let stats = make_cb_stats_closed();
    // WHEN: building JSON
    let json = build_circuit_breaker_stats_json("my-backend", &stats);
    // THEN: all fields are present with correct values
    assert_eq!(json["server"], "my-backend");
    assert_eq!(json["state"], "closed");
    assert_eq!(json["trips_count"], 0);
    assert_eq!(json["last_trip_ms"], 0);
    assert_eq!(json["retry_after_ms"], 0);
    assert_eq!(json["current_failures"], 0);
    assert_eq!(json["failure_threshold"], 5);
}

#[test]
fn build_circuit_breaker_stats_json_open_state_shows_retry_after() {
    // GIVEN: an open circuit breaker with 3 trips and retry_after_ms set
    let stats = make_cb_stats_open();
    // WHEN: building JSON
    let json = build_circuit_breaker_stats_json("my-backend", &stats);
    // THEN: state is "open" and retry_after_ms is non-zero
    assert_eq!(json["state"], "open");
    assert_eq!(json["trips_count"], 3);
    assert_eq!(json["retry_after_ms"], 29_000_u64);
    assert_eq!(json["current_failures"], 5);
}

#[test]
fn build_circuit_breaker_stats_json_half_open_state() {
    // GIVEN: a half-open circuit breaker
    let stats = CircuitBreakerStats {
        state: crate::failsafe::CircuitState::HalfOpen,
        trips_count: 1,
        last_trip_ms: 1_717_000_000_000,
        retry_after_ms: 0,
        current_failures: 0,
        failure_threshold: 5,
    };
    // WHEN: building JSON
    let json = build_circuit_breaker_stats_json("probing-backend", &stats);
    // THEN: state is "half_open"
    assert_eq!(json["state"], "half_open");
    assert_eq!(json["trips_count"], 1);
    assert_eq!(json["retry_after_ms"], 0);
}

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
    // THEN: 'include_schema' boolean parameter with default true is present
    let tool = build_code_mode_search_tool();
    assert_eq!(
        tool.input_schema["properties"]["include_schema"]["type"],
        "boolean"
    );
    assert_eq!(
        tool.input_schema["properties"]["include_schema"]["default"],
        true
    );
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
