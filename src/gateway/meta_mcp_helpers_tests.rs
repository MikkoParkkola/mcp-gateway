use super::*;
use crate::ranking::SearchResult;
use crate::stats::StatsSnapshot;

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
    let preamble = build_discovery_preamble();
    assert!(preamble.contains("gateway_search_tools"));
    assert!(preamble.contains("gateway_list_tools"));
    assert!(preamble.contains("gateway_list_servers"));
    assert!(preamble.contains("gateway_invoke"));
}

#[test]
fn discovery_preamble_mentions_multi_word_search() {
    let preamble = build_discovery_preamble();
    assert!(preamble.contains("multi-word") || preamble.contains("batch research"));
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
        webhooks: std::collections::HashMap::new(),
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
fn routing_instructions_includes_tags_as_keywords() {
    let caps = vec![make_capability_def(
        "brave_search",
        "search",
        &["search", "web", "brave"],
    )];
    let result = build_routing_instructions(&caps, "fulcrum");
    assert!(result.contains("search"));
    assert!(result.contains("web"));
    assert!(result.contains("brave"));
}

#[test]
fn routing_instructions_truncates_tools_to_three_per_category() {
    let caps = vec![
        make_capability_def("tool_a", "search", &[]),
        make_capability_def("tool_b", "search", &[]),
        make_capability_def("tool_c", "search", &[]),
        make_capability_def("tool_d", "search", &[]),
    ];
    let result = build_routing_instructions(&caps, "fulcrum");
    assert!(result.contains("(+1)"), "Should show overflow count");
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
    // 4 base + 1 playbook + 2 kill-switch + 2 profile (set/get) + 1 disabled-caps + 1 list-profiles = 11
    assert_eq!(tools.len(), 11);
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
    // 4 base + 1 stats + 1 webhooks + 1 playbook + 2 kill-switch + 2 profile (set/get) + 1 disabled-caps + 1 list-profiles = 13
    assert_eq!(tools.len(), 13);
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
    // 4 base + 1 playbook + 2 kill-switch + 2 profile (set/get) + 1 disabled-caps + 1 list-profiles + 1 reload = 12
    assert_eq!(tools.len(), 12);
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
    // 4 base + 1 stats + 1 webhooks + 1 playbook + 2 kill-switch + 2 profile (set/get) + 1 disabled-caps + 1 list-profiles + 1 reload = 14
    assert_eq!(tools.len(), 14);
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
        },
        SearchResult {
            server: "s2".to_string(),
            tool: "t2".to_string(),
            description: "desc2".to_string(),
            score: 0.80,
        },
    ];
    let json_results = ranked_results_to_json(results);
    assert_eq!(json_results.len(), 2);
    assert_eq!(json_results[0]["server"], "s1");
    assert_eq!(json_results[0]["score"], 0.95);
    assert_eq!(json_results[1]["tool"], "t2");
}

#[test]
fn ranked_results_to_json_empty_input() {
    let json_results = ranked_results_to_json(vec![]);
    assert!(json_results.is_empty());
}

// ── build_search_response ───────────────────────────────────────────

#[test]
fn build_search_response_structure() {
    let matches = vec![json!({"tool": "a"}), json!({"tool": "b"})];
    let resp = build_search_response("test", &matches, 2, &[]);
    assert_eq!(resp["query"], "test");
    assert_eq!(resp["total"], 2);
    assert_eq!(resp["total_available"], 2);
    assert_eq!(resp["matches"].as_array().unwrap().len(), 2);
}

#[test]
fn build_search_response_empty_matches_no_suggestions() {
    // GIVEN: no matches and no suggestions
    // WHEN: building the response
    // THEN: no suggestions field emitted
    let resp = build_search_response("nothing", &[], 0, &[]);
    assert_eq!(resp["total"], 0);
    assert_eq!(resp["total_available"], 0);
    assert!(resp["matches"].as_array().unwrap().is_empty());
    assert!(resp.get("suggestions").is_none());
}

#[test]
fn build_search_response_total_available_exceeds_returned() {
    let matches = vec![json!({"tool": "a"})];
    let resp = build_search_response("test", &matches, 5, &[]);
    assert_eq!(resp["total"], 1);
    assert_eq!(resp["total_available"], 5);
}

#[test]
fn build_search_response_includes_suggestions_when_empty_matches() {
    // GIVEN: no matches but suggestions available
    // WHEN: building the response
    // THEN: suggestions field is emitted
    let suggestions = vec!["search".to_string(), "lookup".to_string()];
    let resp = build_search_response("xyzzy", &[], 0, &suggestions);
    let sugg = resp["suggestions"].as_array().unwrap();
    assert_eq!(sugg.len(), 2);
    assert_eq!(sugg[0], "search");
    assert_eq!(sugg[1], "lookup");
}

#[test]
fn build_search_response_suppresses_suggestions_when_matches_present() {
    // GIVEN: matches exist alongside suggestions
    // WHEN: building the response
    // THEN: suggestions field is NOT emitted (matches win)
    let matches = vec![json!({"tool": "a"})];
    let suggestions = vec!["other".to_string()];
    let resp = build_search_response("test", &matches, 1, &suggestions);
    assert!(resp.get("suggestions").is_none());
}

// ── extract_search_limit ────────────────────────────────────────────

#[test]
fn extract_search_limit_default_is_10() {
    let args = json!({});
    assert_eq!(extract_search_limit(&args), 10);
}

#[test]
fn extract_search_limit_respects_custom_value() {
    let args = json!({"limit": 25});
    assert_eq!(extract_search_limit(&args), 25);
}

#[test]
fn extract_search_limit_ignores_non_integer() {
    let args = json!({"limit": "not a number"});
    assert_eq!(extract_search_limit(&args), 10);
}

// ── extract_required_str ────────────────────────────────────────────

#[test]
fn extract_required_str_succeeds() {
    let args = json!({"server": "backend-1"});
    assert_eq!(extract_required_str(&args, "server").unwrap(), "backend-1");
}

#[test]
fn extract_required_str_fails_on_missing_key() {
    let args = json!({});
    let err = extract_required_str(&args, "server").unwrap_err();
    assert!(err.to_string().contains("Missing 'server' parameter"));
}

#[test]
fn extract_required_str_fails_on_non_string_value() {
    let args = json!({"server": 42});
    let err = extract_required_str(&args, "server").unwrap_err();
    assert!(err.to_string().contains("Missing 'server' parameter"));
}

// ── parse_tool_arguments ────────────────────────────────────────────

#[test]
fn parse_tool_arguments_with_object() {
    let args = json!({"arguments": {"key": "value"}});
    let result = parse_tool_arguments(&args).unwrap();
    assert_eq!(result["key"], "value");
}

#[test]
fn parse_tool_arguments_defaults_to_empty_object() {
    let args = json!({});
    let result = parse_tool_arguments(&args).unwrap();
    assert!(result.is_object());
    assert!(result.as_object().unwrap().is_empty());
}

#[test]
fn parse_tool_arguments_parses_json_string() {
    let args = json!({"arguments": r#"{"key": "value"}"#});
    let result = parse_tool_arguments(&args).unwrap();
    assert_eq!(result["key"], "value");
}

#[test]
fn parse_tool_arguments_rejects_invalid_json_string() {
    let args = json!({"arguments": "not valid json"});
    let err = parse_tool_arguments(&args).unwrap_err();
    assert!(err.to_string().contains("Invalid 'arguments' JSON string"));
}

#[test]
fn parse_tool_arguments_rejects_non_object_types() {
    let args = json!({"arguments": [1, 2, 3]});
    let err = parse_tool_arguments(&args).unwrap_err();
    assert!(err.to_string().contains("expected object"));
}

#[test]
fn parse_tool_arguments_rejects_number() {
    let args = json!({"arguments": 42});
    let err = parse_tool_arguments(&args).unwrap_err();
    assert!(err.to_string().contains("expected object"));
}

#[test]
fn parse_tool_arguments_rejects_boolean() {
    let args = json!({"arguments": true});
    let err = parse_tool_arguments(&args).unwrap_err();
    assert!(err.to_string().contains("expected object"));
}

#[test]
fn parse_tool_arguments_accepts_stringified_nested_object() {
    let args = json!({"arguments": r#"{"nested": {"deep": true}}"#});
    let result = parse_tool_arguments(&args).unwrap();
    assert_eq!(result["nested"]["deep"], true);
}

// ── extract_price_per_million ───────────────────────────────────────

#[test]
fn extract_price_per_million_default_is_15() {
    let args = json!({});
    let price = extract_price_per_million(&args);
    assert!((price - 15.0).abs() < f64::EPSILON);
}

#[test]
fn extract_price_per_million_custom_value() {
    let args = json!({"price_per_million": 3.5});
    let price = extract_price_per_million(&args);
    assert!((price - 3.5).abs() < f64::EPSILON);
}

#[test]
fn extract_price_per_million_ignores_non_number() {
    let args = json!({"price_per_million": "free"});
    let price = extract_price_per_million(&args);
    assert!((price - 15.0).abs() < f64::EPSILON);
}

// ── build_stats_response ────────────────────────────────────────────

#[test]
fn build_stats_response_fields() {
    let snapshot = StatsSnapshot {
        invocations: 100,
        cache_hits: 30,
        cache_hit_rate: 0.30,
        tools_discovered: 50,
        tools_available: 200,
        tokens_saved: 500_000,
        top_tools: vec![],
        total_cached_tokens: 0,
        cached_tokens_by_server: vec![],
    };
    let resp = build_stats_response(&snapshot, 15.0);
    assert_eq!(resp["invocations"], 100);
    assert_eq!(resp["cache_hits"], 30);
    assert_eq!(resp["cache_hit_rate"], "30.0%");
    assert_eq!(resp["tools_discovered"], 50);
    assert_eq!(resp["tools_available"], 200);
    assert_eq!(resp["tokens_saved"], 500_000);
    assert_eq!(resp["estimated_savings_usd"], "$7.50");
}

#[test]
fn build_stats_response_zero_values() {
    let snapshot = StatsSnapshot {
        invocations: 0,
        cache_hits: 0,
        cache_hit_rate: 0.0,
        tools_discovered: 0,
        tools_available: 0,
        tokens_saved: 0,
        top_tools: vec![],
        total_cached_tokens: 0,
        cached_tokens_by_server: vec![],
    };
    let resp = build_stats_response(&snapshot, 15.0);
    assert_eq!(resp["invocations"], 0);
    assert_eq!(resp["estimated_savings_usd"], "$0.00");
}

#[test]
fn build_stats_response_custom_price() {
    let snapshot = StatsSnapshot {
        invocations: 10,
        cache_hits: 5,
        cache_hit_rate: 0.5,
        tools_discovered: 20,
        tools_available: 100,
        tokens_saved: 1_000_000,
        top_tools: vec![],
        total_cached_tokens: 0,
        cached_tokens_by_server: vec![],
    };
    let resp = build_stats_response(&snapshot, 3.0);
    assert_eq!(resp["estimated_savings_usd"], "$3.00");
    assert_eq!(resp["cache_hit_rate"], "50.0%");
}

// ── wrap_tool_success ───────────────────────────────────────────────

#[test]
fn wrap_tool_success_produces_valid_response() {
    let id = RequestId::Number(1);
    let content = json!({"servers": []});
    let response = wrap_tool_success(id, &content);
    assert!(response.error.is_none());
    assert!(response.result.is_some());

    let result: ToolsCallResult = serde_json::from_value(response.result.unwrap()).unwrap();
    assert!(!result.is_error);
    assert_eq!(result.content.len(), 1);
}

#[test]
fn wrap_tool_success_content_is_pretty_json() {
    let id = RequestId::Number(42);
    let content = json!({"key": "value"});
    let response = wrap_tool_success(id, &content);

    let result: ToolsCallResult = serde_json::from_value(response.result.unwrap()).unwrap();
    if let Content::Text { text, .. } = &result.content[0] {
        // Pretty-printed JSON contains newlines
        assert!(text.contains('\n'));
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["key"], "value");
    } else {
        panic!("Expected text content");
    }
}

// ── tool_matches_query synonym expansion ────────────────────────────

#[test]
fn tool_matches_query_synonym_in_name() {
    // GIVEN: tool name contains "search", query word is "find" (synonym)
    // WHEN: matching
    // THEN: matches via synonym expansion
    let tool = make_tool("search_companies", Some("Find business entities"));
    assert!(
        tool_matches_query(&tool, "find"),
        "'find' should match tool with 'search' via synonym"
    );
}

#[test]
fn tool_matches_query_synonym_in_description() {
    // GIVEN: description has "monitor", query word is "watch" (synonym)
    let tool = make_tool("uptimer", Some("Continuously monitor your services"));
    assert!(
        tool_matches_query(&tool, "watch"),
        "'watch' should match tool with 'monitor' via synonym"
    );
}

#[test]
fn tool_matches_query_no_false_positive_for_unrelated_synonym_group() {
    // GIVEN: a weather tool, query word is "find" whose synonyms are all search-related
    let tool = make_tool("weather_api", Some("Get current temperature and humidity"));
    // None of the search-group words appear in either name or desc
    assert!(
        !tool_matches_query(&tool, "find"),
        "should not match a tool with no search-related words"
    );
}

#[test]
fn tool_matches_query_multi_word_uses_synonym_for_one_word() {
    // GIVEN: query "find weather", tool has "search" (synonym of "find") in name
    let tool = make_tool("search_weather", Some("Get forecasts"));
    assert!(
        tool_matches_query(&tool, "find weather"),
        "should match: 'weather' in name, 'find'≈'search' in name"
    );
}
