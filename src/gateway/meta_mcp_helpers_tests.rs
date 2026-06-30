use super::*;
use crate::ranking::SearchResult;

#[path = "meta_mcp_helpers_tests/response.rs"]
mod response;

// Helper to build a Tool for testing
fn make_tool(name: &str, description: Option<&str>) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: description.map(ToString::to_string),
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

// ── extract_client_version ──────────────────────────────────────────

#[test]
fn extract_client_version_from_valid_params() {
    let params = json!({"protocolVersion": "2025-06-18"});
    assert_eq!(extract_client_version(Some(&params)), "2025-06-18");
}

#[test]
fn extract_client_version_returns_default_when_none() {
    assert_eq!(extract_client_version(None), "2024-11-05");
}

#[test]
fn extract_client_version_returns_default_when_missing_key() {
    let params = json!({"clientInfo": {"name": "test"}});
    assert_eq!(extract_client_version(Some(&params)), "2024-11-05");
}

#[test]
fn extract_client_version_returns_default_when_not_string() {
    let params = json!({"protocolVersion": 42});
    assert_eq!(extract_client_version(Some(&params)), "2024-11-05");
}

// ── extract_optional_str ─────────────────────────────────────────────

#[test]
fn extract_optional_str_returns_value_when_present() {
    let args = json!({"server": "backend-1"});
    assert_eq!(extract_optional_str(&args, "server"), Some("backend-1"));
}

#[test]
fn extract_optional_str_returns_none_for_missing_or_non_string() {
    assert_eq!(extract_optional_str(&json!({}), "server"), None);
    assert_eq!(extract_optional_str(&json!({"server": 42}), "server"), None);
}

// ── extract_nested_optional_str ──────────────────────────────────────

#[test]
fn extract_nested_optional_str_returns_value_when_present() {
    let params = json!({"uri": "gateway://guides/quickstart"});
    assert_eq!(
        extract_nested_optional_str(Some(&params), "uri"),
        Some("gateway://guides/quickstart")
    );
}

#[test]
fn extract_nested_optional_str_returns_none_for_missing_params_or_key() {
    assert_eq!(extract_nested_optional_str(None, "uri"), None);
    assert_eq!(extract_nested_optional_str(Some(&json!({})), "uri"), None);
}

// ── missing_parameter_response ───────────────────────────────────────

#[test]
fn missing_parameter_response_preserves_invalid_params_contract() {
    let response = missing_parameter_response(&RequestId::Number(7), "uri");
    let error = response.error.expect("expected JSON-RPC error");
    assert_eq!(error.code, -32602);
    assert_eq!(error.message, "Missing 'uri' parameter");
}

// ── extract_bool_or ──────────────────────────────────────────────────

#[test]
fn extract_bool_or_respects_custom_value_and_default() {
    assert!(extract_bool_or(&json!({"enabled": true}), "enabled", false));
    assert!(extract_bool_or(&json!({}), "enabled", true));
}

#[test]
fn extract_bool_or_ignores_non_bool_values() {
    assert!(!extract_bool_or(
        &json!({"enabled": "yes"}),
        "enabled",
        false
    ));
}

// ── extract_u64_or ───────────────────────────────────────────────────

#[test]
fn extract_u64_or_respects_custom_value_and_default() {
    assert_eq!(extract_u64_or(&json!({"limit": 25}), "limit", 10), 25);
    assert_eq!(extract_u64_or(&json!({}), "limit", 10), 10);
}

#[test]
fn extract_u64_or_ignores_non_integer_values() {
    assert_eq!(extract_u64_or(&json!({"limit": "many"}), "limit", 10), 10);
}

// ── extract_f64_or ───────────────────────────────────────────────────

#[test]
fn extract_f64_or_respects_custom_value_and_default() {
    assert!((extract_f64_or(&json!({"price": 3.5}), "price", 15.0) - 3.5).abs() < f64::EPSILON);
    assert!((extract_f64_or(&json!({}), "price", 15.0) - 15.0).abs() < f64::EPSILON);
}

#[test]
fn extract_f64_or_ignores_non_number_values() {
    assert!((extract_f64_or(&json!({"price": "free"}), "price", 15.0) - 15.0).abs() < f64::EPSILON);
}

// ── build_initialize_result ─────────────────────────────────────────

const TEST_INSTRUCTIONS: &str = "test instructions";

#[test]
fn build_initialize_result_has_correct_version() {
    let result = build_initialize_result("2025-11-25", TEST_INSTRUCTIONS);
    assert_eq!(result.protocol_version, "2025-11-25");
}

#[test]
fn build_initialize_result_has_tools_capability() {
    let result = build_initialize_result("2024-11-05", TEST_INSTRUCTIONS);
    assert!(result.capabilities.tools.is_some());
    assert!(result.capabilities.tools.unwrap().list_changed);
}

#[test]
fn build_initialize_result_has_resources_capability() {
    let result = build_initialize_result("2025-11-25", TEST_INSTRUCTIONS);
    let resources = result.capabilities.resources.unwrap();
    assert!(resources.subscribe);
    assert!(resources.list_changed);
}

#[test]
fn build_initialize_result_has_prompts_capability() {
    let result = build_initialize_result("2025-11-25", TEST_INSTRUCTIONS);
    let prompts = result.capabilities.prompts.unwrap();
    assert!(prompts.list_changed);
}

#[test]
fn build_initialize_result_has_logging_capability() {
    let result = build_initialize_result("2025-11-25", TEST_INSTRUCTIONS);
    assert!(result.capabilities.logging.is_some());
}

#[test]
fn build_initialize_result_advertises_four_capabilities() {
    let result = build_initialize_result("2025-11-25", TEST_INSTRUCTIONS);
    assert!(result.capabilities.tools.is_some(), "missing tools");
    assert!(result.capabilities.resources.is_some(), "missing resources");
    assert!(result.capabilities.prompts.is_some(), "missing prompts");
    assert!(result.capabilities.logging.is_some(), "missing logging");
}

#[test]
fn build_initialize_result_has_server_info() {
    let result = build_initialize_result("2024-11-05", TEST_INSTRUCTIONS);
    assert_eq!(result.server_info.name, "mcp-gateway");
    assert!(result.server_info.title.is_some());
    assert!(result.server_info.description.is_some());
}

#[test]
fn build_initialize_result_passes_instructions_through() {
    let instructions = "custom routing guide";
    let result = build_initialize_result("2024-11-05", instructions);
    assert_eq!(result.instructions.as_deref(), Some(instructions));
}

// ── build_discovery_preamble ────────────────────────────────────────

#[test]
fn discovery_preamble_contains_all_four_meta_tools() {
    let preamble = build_discovery_preamble(10, 2);
    assert!(preamble.contains("gateway_search_tools"));
    assert!(preamble.contains("gateway_list_tools"));
    assert!(preamble.contains("gateway_list_servers"));
    assert!(preamble.contains("gateway_invoke"));
}

#[test]
fn discovery_preamble_contains_first_keyword() {
    // GIVEN: any tool/server counts
    // WHEN: building the preamble
    // THEN: "FIRST" appears to emphasize search-before-invoke pattern
    let preamble = build_discovery_preamble(0, 0);
    assert!(
        preamble.contains("FIRST"),
        "preamble must include FIRST to guide agent behavior"
    );
}

#[test]
fn discovery_preamble_includes_tool_count() {
    // GIVEN: 42 tools across 3 backends
    let preamble = build_discovery_preamble(42, 3);
    // THEN: the count appears in the text
    assert!(
        preamble.contains("42 tools"),
        "preamble must include tool count"
    );
}

#[test]
fn discovery_preamble_includes_server_count() {
    // GIVEN: 42 tools across 3 backends
    let preamble = build_discovery_preamble(42, 3);
    assert!(
        preamble.contains("3 backends"),
        "preamble must include backend/server count"
    );
}

#[test]
fn discovery_preamble_with_zero_counts_is_valid() {
    // GIVEN: no tools or backends yet (empty gateway)
    let preamble = build_discovery_preamble(0, 0);
    assert!(preamble.contains("0 tools"));
    assert!(preamble.contains("0 backends"));
}

// ── levenshtein ─────────────────────────────────────────────────────

#[test]
fn levenshtein_identical_strings_is_zero() {
    assert_eq!(levenshtein("gateway_invoke", "gateway_invoke"), 0);
}

#[test]
fn levenshtein_empty_strings_is_zero() {
    assert_eq!(levenshtein("", ""), 0);
}

#[test]
fn levenshtein_empty_vs_nonempty_is_length() {
    assert_eq!(levenshtein("", "abc"), 3);
    assert_eq!(levenshtein("abc", ""), 3);
}

#[test]
fn levenshtein_single_insertion() {
    // "gateway_invokee" has one extra 'e'
    assert_eq!(levenshtein("gateway_invokee", "gateway_invoke"), 1);
}

#[test]
fn levenshtein_single_deletion() {
    // "gatway_invoke" is missing 'e'
    assert_eq!(levenshtein("gatway_invoke", "gateway_invoke"), 1);
}

#[test]
fn levenshtein_single_substitution() {
    // "gateway_xnvoke" has 'x' instead of 'i'
    assert_eq!(levenshtein("gateway_xnvoke", "gateway_invoke"), 1);
}

#[test]
fn levenshtein_transposition_costs_two() {
    // Standard Levenshtein (not Damerau): "ab" -> "ba" requires 2 ops
    assert_eq!(levenshtein("ba", "ab"), 2);
}

#[test]
fn levenshtein_completely_different_strings() {
    assert_eq!(levenshtein("abc", "xyz"), 3);
}

// ── did_you_mean ────────────────────────────────────────────────────

#[test]
fn did_you_mean_exact_match_returns_that_name() {
    // GIVEN: the exact tool name is in the candidates
    let candidates = ["gateway_invoke", "gateway_search_tools"];
    let hint = did_you_mean("gateway_invoke", &candidates, 3, 3);
    // THEN: returns a suggestion containing the exact match
    assert!(hint.is_some());
    assert!(hint.unwrap().contains("gateway_invoke"));
}

#[test]
fn did_you_mean_one_char_typo_returns_suggestion() {
    // GIVEN: "gateway_invokee" is off by one character
    let candidates = [
        "gateway_search_tools",
        "gateway_list_tools",
        "gateway_list_servers",
        "gateway_invoke",
    ];
    let hint = did_you_mean("gateway_invokee", &candidates, 3, 3);
    assert!(hint.is_some_and(|m| m.contains("gateway_invoke")));
}

#[test]
fn did_you_mean_far_typo_returns_none() {
    // GIVEN: "completely_wrong" has no close match
    let candidates = ["gateway_invoke", "gateway_search_tools"];
    let hint = did_you_mean("completely_wrong", &candidates, 3, 3);
    assert!(hint.is_none());
}

#[test]
fn did_you_mean_returns_at_most_max_suggestions() {
    // GIVEN: three close candidates (all distance 1) and max=2
    let candidates = ["gateway_a", "gateway_b", "gateway_c"];
    let hint = did_you_mean("gateway_x", &candidates, 2, 2);
    if let Some(msg) = hint {
        // The message should mention at most 2 names separated by ", "
        let names: Vec<&str> = msg
            .strip_prefix("Did you mean: ")
            .unwrap_or(&msg)
            .strip_suffix('?')
            .unwrap_or(&msg)
            .split(", ")
            .collect();
        assert!(names.len() <= 2);
    }
}

#[test]
fn did_you_mean_sorts_by_ascending_distance() {
    // GIVEN: two candidates — one is an exact match (dist 0), one is farther
    let candidates = ["gateway_invoke", "gateway_invoke_extra"];
    let hint = did_you_mean("gateway_invoke", &candidates, 6, 3).unwrap();
    // The exact match must appear first
    let first = hint
        .strip_prefix("Did you mean: ")
        .unwrap_or(&hint)
        .split(", ")
        .next()
        .unwrap()
        .trim_end_matches('?');
    assert_eq!(first, "gateway_invoke");
}

// ── build_routing_instructions ──────────────────────────────────────

fn make_capability_def(
    name: &str,
    category: &str,
    tags: &[&str],
) -> crate::capability::CapabilityDefinition {
    use crate::capability::{
        AuthConfig, CacheConfig, CapabilityMetadata, ProvidersConfig, SchemaDefinition,
    };
    use crate::transform::TransformConfig;

    crate::capability::CapabilityDefinition {
        fulcrum: "1.0".to_string(),
        name: name.to_string(),
        description: format!("{name} description"),
        schema: SchemaDefinition::default(),
        providers: ProvidersConfig::default(),
        auth: AuthConfig::default(),
        cache: CacheConfig::default(),
        metadata: CapabilityMetadata {
            category: category.to_string(),
            tags: tags.iter().map(ToString::to_string).collect(),
            ..CapabilityMetadata::default()
        },
        transform: TransformConfig::default(),
        response_transform: TransformConfig::default(),
        projection: None,
        visible_in_states: vec![],
        webhooks: std::collections::HashMap::new(),
        sha256: None,
    }
}

#[test]
fn routing_instructions_empty_for_no_capabilities() {
    let result = build_routing_instructions(&[], "fulcrum");
    assert!(result.is_empty());
}

#[test]
fn routing_instructions_groups_by_category() {
    let caps = vec![
        make_capability_def("brave_search", "search", &["search", "web"]),
        make_capability_def("brave_news", "search", &["news"]),
        make_capability_def("uuid_generate", "utility", &["uuid"]),
    ];
    let result = build_routing_instructions(&caps, "fulcrum");
    assert!(result.contains("search"));
    assert!(result.contains("utility"));
    assert!(result.contains("fulcrum/brave_search"));
    assert!(result.contains("fulcrum/uuid_generate"));
}

#[test]
fn routing_instructions_omits_per_category_search_keywords() {
    let caps = vec![make_capability_def(
        "brave_search",
        "search",
        &["search", "web", "brave"],
    )];
    let result = build_routing_instructions(&caps, "fulcrum");
    assert!(result.contains("search"));
    assert!(result.contains("fulcrum/brave_search"));
    assert!(!result.contains("Search keywords:"));
    assert!(!result.contains("web"));
}

#[test]
fn routing_instructions_dense_catalog_stays_below_initialize_budget() {
    let mut caps = Vec::new();
    for category_index in 0..40 {
        for tool_index in 0..10 {
            caps.push(make_capability_def(
                &format!("tool_{category_index}_{tool_index}_with_long_descriptive_name"),
                &format!("category_{category_index}"),
                &[
                    "aggregator",
                    "astronomy",
                    "biodiversity",
                    "climate",
                    "forecast",
                    "historical",
                    "observation",
                    "temperature",
                    "weather",
                    "workflow",
                ],
            ));
        }
    }

    let result = build_routing_instructions(&caps, "fulcrum");

    assert!(
        result.len() < 6_000,
        "routing guide was {} bytes",
        result.len()
    );
    assert!(!result.contains("Search keywords:"));
}

#[test]
fn routing_instructions_truncates_tools_to_two_per_category() {
    let caps = vec![
        make_capability_def("tool_a", "search", &[]),
        make_capability_def("tool_b", "search", &[]),
        make_capability_def("tool_c", "search", &[]),
        make_capability_def("tool_d", "search", &[]),
    ];
    let result = build_routing_instructions(&caps, "fulcrum");
    assert!(result.contains("(+2)"), "Should show overflow count");
}

#[test]
fn routing_instructions_uses_general_for_empty_category() {
    let caps = vec![make_capability_def("my_tool", "", &[])];
    let result = build_routing_instructions(&caps, "backend");
    assert!(result.contains("general"));
}

// ── build_meta_tools ────────────────────────────────────────────────

#[test]
fn build_meta_tools_returns_base_plus_playbook_and_kill_tools_without_stats_or_webhooks() {
    let tools = build_meta_tools(false, false, false, false, 0, 0);
    // 4 base + 1 playbook + 2 kill-switch + 2 profile (set/get) + 1 disabled-caps + 1 list-profiles + 1 set-state + 1 reload-capabilities = 13
    assert_eq!(tools.len(), 13);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_list_servers"));
    assert!(names.contains(&"gateway_list_tools"));
    assert!(names.contains(&"gateway_search_tools"));
    assert!(names.contains(&"gateway_invoke"));
    assert!(names.contains(&"gateway_run_playbook"));
    assert!(names.contains(&"gateway_kill_server"));
    assert!(names.contains(&"gateway_revive_server"));
    assert!(names.contains(&"gateway_set_profile"));
    assert!(names.contains(&"gateway_get_profile"));
    assert!(names.contains(&"gateway_list_disabled_capabilities"));
    assert!(names.contains(&"gateway_list_profiles"));
    assert!(!names.contains(&"gateway_webhook_status"));
    assert!(!names.contains(&"gateway_reload_config"));
}

#[test]
fn build_meta_tools_returns_all_tools_with_stats_and_webhooks() {
    let tools = build_meta_tools(true, true, false, false, 0, 0);
    // 4 base + 1 stats + 1 webhooks + 1 playbook + 2 kill-switch + 2 profile (set/get) + 1 disabled-caps + 1 list-profiles + 1 set-state + 1 reload-capabilities = 15
    assert_eq!(tools.len(), 15);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_get_stats"));
    assert!(names.contains(&"gateway_webhook_status"));
    assert!(names.contains(&"gateway_run_playbook"));
    assert!(names.contains(&"gateway_kill_server"));
    assert!(names.contains(&"gateway_revive_server"));
    assert!(names.contains(&"gateway_set_profile"));
    assert!(names.contains(&"gateway_get_profile"));
    assert!(names.contains(&"gateway_list_disabled_capabilities"));
    assert!(names.contains(&"gateway_list_profiles"));
}

#[test]
fn build_meta_tools_webhooks_only_without_stats() {
    // GIVEN: webhooks enabled but stats disabled
    // WHEN: building tool list
    // THEN: webhook tool present, stats tool absent
    let tools = build_meta_tools(false, true, false, false, 0, 0);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_webhook_status"));
    assert!(names.contains(&"gateway_list_disabled_capabilities"));
    assert!(names.contains(&"gateway_list_profiles"));
    assert!(!names.contains(&"gateway_get_stats"));
}

#[test]
fn build_meta_tools_includes_reload_when_enabled() {
    // GIVEN: reload context enabled
    let tools = build_meta_tools(false, false, true, false, 0, 0);
    // 4 base + 1 playbook + 2 kill-switch + 2 profile (set/get) + 1 disabled-caps + 1 list-profiles + 1 reload + 1 set-state + 1 reload-capabilities = 14
    assert_eq!(tools.len(), 14);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_reload_config"));
    assert!(names.contains(&"gateway_set_profile"));
    assert!(names.contains(&"gateway_get_profile"));
    assert!(names.contains(&"gateway_list_disabled_capabilities"));
    assert!(names.contains(&"gateway_list_profiles"));
}

#[test]
fn build_meta_tools_all_enabled_includes_reload() {
    // GIVEN: all optional tools enabled
    let tools = build_meta_tools(true, true, true, false, 0, 0);
    // 4 base + 1 stats + 1 webhooks + 1 playbook + 2 kill-switch + 2 profile (set/get) + 1 disabled-caps + 1 list-profiles + 1 reload + 1 set-state + 1 reload-capabilities = 16
    assert_eq!(tools.len(), 16);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_reload_config"));
    assert!(names.contains(&"gateway_get_stats"));
    assert!(names.contains(&"gateway_webhook_status"));
    assert!(names.contains(&"gateway_set_profile"));
    assert!(names.contains(&"gateway_get_profile"));
    assert!(names.contains(&"gateway_list_disabled_capabilities"));
    assert!(names.contains(&"gateway_list_profiles"));
}

#[test]
fn build_base_tools_all_have_descriptions() {
    let tools = build_base_tools(10, 2);
    for tool in &tools {
        assert!(
            tool.description.is_some(),
            "Tool {} missing description",
            tool.name
        );
    }
}

#[test]
fn build_base_tools_all_have_object_input_schema() {
    let tools = build_base_tools(10, 2);
    for tool in &tools {
        assert_eq!(
            tool.input_schema["type"], "object",
            "Tool {} has non-object schema",
            tool.name
        );
    }
}

#[test]
fn build_stats_tool_has_price_parameter() {
    let tool = build_stats_tool();
    assert_eq!(tool.name, "gateway_get_stats");
    assert!(tool.input_schema["properties"]["price_per_million"].is_object());
}

// ── tool_matches_query ──────────────────────────────────────────────

#[test]
fn tool_matches_query_by_name() {
    let tool = make_tool("gateway_search_tools", Some("Search stuff"));
    assert!(tool_matches_query(&tool, "search"));
}

#[test]
fn tool_matches_query_by_description() {
    let tool = make_tool("my_tool", Some("Weather forecast service"));
    assert!(tool_matches_query(&tool, "weather"));
}

#[test]
fn tool_matches_query_case_insensitive() {
    let tool = make_tool("MyTool", Some("Advanced Analytics"));
    assert!(tool_matches_query(&tool, "mytool"));
    assert!(tool_matches_query(&tool, "analytics"));
}

#[test]
fn tool_does_not_match_unrelated_query() {
    let tool = make_tool("gateway_invoke", Some("Invoke a tool"));
    assert!(!tool_matches_query(&tool, "weather"));
}

#[test]
fn tool_matches_query_with_no_description() {
    let tool = make_tool("search_engine", None);
    assert!(tool_matches_query(&tool, "search"));
    assert!(!tool_matches_query(&tool, "weather"));
}

#[test]
fn tool_matches_multi_word_query_any_word_in_name() {
    // GIVEN: a tool named "brave_search" and query "batch search"
    let tool = make_tool("brave_search", Some("Web search tool"));
    // WHEN: querying with two words
    // THEN: matches because "search" is in the name
    assert!(tool_matches_query(&tool, "batch search"));
}

#[test]
fn tool_matches_multi_word_query_any_word_in_description() {
    // GIVEN: a tool with "research" only in description, query "batch research"
    let tool = make_tool("parallel_task", Some("Run deep research tasks in parallel"));
    // WHEN: querying "batch research"
    // THEN: matches because "research" is in the description
    assert!(tool_matches_query(&tool, "batch research"));
}

#[test]
fn tool_no_match_when_no_word_found() {
    // GIVEN: a tool unrelated to either query word
    let tool = make_tool("weather_api", Some("Returns current temperature"));
    // WHEN: searching for "batch search"
    // THEN: no match
    assert!(!tool_matches_query(&tool, "batch search"));
}

#[test]
fn tool_matches_keyword_tag_in_description() {
    // GIVEN: tool description includes [keywords: search, web, brave]
    let tool = make_tool(
        "brave_query",
        Some("Query the internet [keywords: search, web, brave]"),
    );
    // WHEN: querying "web"
    // THEN: matches because "web" appears in the description
    assert!(tool_matches_query(&tool, "web"));
}

#[test]
fn tool_matches_multi_word_where_one_word_is_tag() {
    // GIVEN: description has [keywords: monitor, alert]
    let tool = make_tool(
        "watch_service",
        Some("Watch endpoints [keywords: monitor, alert]"),
    );
    // WHEN: "batch monitor"
    // THEN: matches because "monitor" is in description (as keyword tag)
    assert!(tool_matches_query(&tool, "batch monitor"));
}

// ── build_match_json ────────────────────────────────────────────────

#[test]
fn build_match_json_has_correct_fields() {
    let tool = make_tool("my_tool", Some("Does things"));
    let result = build_match_json("backend-1", &tool);
    assert_eq!(result["server"], "backend-1");
    assert_eq!(result["tool"], "my_tool");
    assert_eq!(result["description"], "Does things");
}

#[test]
fn build_match_json_truncates_long_descriptions() {
    let long_desc = "a".repeat(600);
    let tool = make_tool("tool", Some(&long_desc));
    let result = build_match_json("srv", &tool);
    let desc = result["description"].as_str().unwrap();
    assert_eq!(desc.len(), 500);
}

#[test]
fn build_match_json_uses_empty_string_for_none_description() {
    let tool = make_tool("tool", None);
    let result = build_match_json("srv", &tool);
    assert_eq!(result["description"], "");
}

// ── ranked_results_to_json ──────────────────────────────────────────

#[test]
fn ranked_results_to_json_converts_correctly() {
    let results = vec![
        SearchResult {
            server: "s1".to_string(),
            tool: "t1".to_string(),
            description: "desc1".to_string(),
            score: 0.95,
            ..SearchResult::new("s1", "t1", "desc1")
        },
        SearchResult {
            server: "s2".to_string(),
            tool: "t2".to_string(),
            description: "desc2".to_string(),
            score: 0.80,
            ..SearchResult::new("s2", "t2", "desc2")
        },
    ];
    let json_results = ranked_results_to_json(results);
    assert_eq!(json_results.len(), 2);
    assert_eq!(json_results[0]["server"], "s1");
    assert_eq!(json_results[0]["score"], 0.95);
    assert_eq!(json_results[0]["ranking"]["included"], true);
    assert_eq!(json_results[1]["tool"], "t2");
}

#[test]
fn ranked_results_to_json_empty_input() {
    let json_results = ranked_results_to_json(vec![]);
    assert!(json_results.is_empty());
}
