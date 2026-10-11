// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use crate::gateway::meta_mcp_tool_defs::MetaToolGates;

#[path = "meta_mcp_helpers_tests/abbreviations.rs"]
mod abbreviations;

#[path = "meta_mcp_helpers_tests/response.rs"]
mod response;

#[path = "meta_mcp_helpers_tests/routing_instructions.rs"]
mod routing_instructions;

#[path = "meta_mcp_helpers_tests/suggestions.rs"]
mod suggestions;

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

// ── build_initialize_result ─────────────────────────────────────────

const TEST_INSTRUCTIONS: &str = "test instructions";

/// A legacy `initialize` result as the HTTP server builds it.
fn init(version: &str, instructions: &str) -> crate::protocol::InitializeResult {
    build_initialize_result(
        version,
        instructions,
        crate::protocol::meta::Era::Legacy,
        crate::gateway::ChangeFeed::Http,
    )
}

#[test]
fn build_initialize_result_has_correct_version() {
    let result = init("2025-11-25", TEST_INSTRUCTIONS);
    assert_eq!(result.protocol_version, "2025-11-25");
}

#[test]
fn build_initialize_result_has_tools_capability() {
    let result = init("2024-11-05", TEST_INSTRUCTIONS);
    assert!(result.capabilities.tools.is_some());
    assert!(result.capabilities.tools.unwrap().list_changed);
}

#[test]
fn build_initialize_result_has_resources_capability() {
    let result = init("2025-11-25", TEST_INSTRUCTIONS);
    let resources = result.capabilities.resources.unwrap();
    // F24: nothing delivers resources/updated or resources/list_changed.
    assert!(!resources.subscribe);
    assert!(!resources.list_changed);
}

#[test]
fn build_initialize_result_has_prompts_capability() {
    let result = init("2025-11-25", TEST_INSTRUCTIONS);
    let prompts = result.capabilities.prompts.unwrap();
    assert!(
        !prompts.list_changed,
        "F24: nothing delivers prompts/list_changed"
    );
}

#[test]
fn build_initialize_result_has_logging_capability() {
    let result = init("2025-11-25", TEST_INSTRUCTIONS);
    assert!(result.capabilities.logging.is_some());
}

#[test]
fn build_initialize_result_advertises_four_capabilities() {
    let result = init("2025-11-25", TEST_INSTRUCTIONS);
    assert!(result.capabilities.tools.is_some(), "missing tools");
    assert!(result.capabilities.resources.is_some(), "missing resources");
    assert!(result.capabilities.prompts.is_some(), "missing prompts");
    assert!(result.capabilities.logging.is_some(), "missing logging");
}

#[test]
fn build_initialize_result_has_server_info() {
    let result = init("2024-11-05", TEST_INSTRUCTIONS);
    assert_eq!(result.server_info.name, "mcp-gateway");
    assert!(result.server_info.title.is_some());
    assert!(result.server_info.description.is_some());
}

#[test]
fn build_initialize_result_passes_instructions_through() {
    let instructions = "custom routing guide";
    let result = init("2024-11-05", instructions);
    assert_eq!(result.instructions.as_deref(), Some(instructions));
}

// ── build_discovery_preamble ────────────────────────────────────────

#[test]
fn discovery_preamble_contains_all_four_meta_tools() {
    let preamble =
        build_discovery_preamble(ToolTotal::Exact(10), 2, &MetaToolExposure::expose_all());
    assert!(preamble.contains("gateway_search_tools"));
    assert!(preamble.contains("gateway_list_tools"));
    assert!(preamble.contains("gateway_list_servers"));
    assert!(preamble.contains("gateway_invoke"));
}

#[test]
fn discovery_preamble_contains_first_keyword() {
    let preamble =
        build_discovery_preamble(ToolTotal::Exact(0), 0, &MetaToolExposure::expose_all());
    assert!(
        preamble.contains("FIRST"),
        "preamble must include FIRST to guide agent behavior"
    );
}

#[test]
fn discovery_preamble_includes_tool_count() {
    // GIVEN: 42 tools across 3 backends
    let preamble =
        build_discovery_preamble(ToolTotal::Exact(42), 3, &MetaToolExposure::expose_all());
    // THEN: the count appears in the text
    assert!(
        preamble.contains("42 tools"),
        "preamble must include tool count"
    );
}

#[test]
fn discovery_preamble_omits_the_total_when_nothing_is_enumerated() {
    // GIVEN: no backend has been enumerated, so no total is known yet
    let preamble = build_discovery_preamble(ToolTotal::Unknown, 3, &MetaToolExposure::expose_all());
    // THEN: the backend count is still stated — it is always real — but no tool
    // total is asserted, because "0 tools" would read as an empty gateway.
    assert!(
        preamble.contains("3 backends"),
        "backend count does not depend on enumeration"
    );
    assert!(
        !preamble.contains("0 tools"),
        "an unknown total must not be reported as zero"
    );
    assert!(
        preamble.contains("manages tools across"),
        "the preamble must still say the fleet has tools"
    );
}

#[test]
fn discovery_preamble_states_a_floor_when_only_some_backends_are_enumerated() {
    // GIVEN: two of three backends enumerated, contributing 42 tools between them
    let preamble =
        build_discovery_preamble(ToolTotal::AtLeast(42), 3, &MetaToolExposure::expose_all());

    assert!(
        preamble.contains("at least 42 tools"),
        "a partial total must be stated as a floor, not omitted: {preamble}"
    );
    assert!(preamble.contains("3 backends"));
}

#[test]
fn discovery_preamble_states_the_exact_total_once_every_backend_is_enumerated() {
    // GIVEN: every backend enumerated
    let preamble =
        build_discovery_preamble(ToolTotal::Exact(42), 3, &MetaToolExposure::expose_all());
    // THEN: no hedging language — this is the real total
    assert!(preamble.contains("42 tools"));
    assert!(!preamble.contains("at least"));
}

#[test]
fn tool_total_phrase_distinguishes_the_three_states() {
    assert_eq!(ToolTotal::Unknown.phrase(), "tools");
    assert_eq!(ToolTotal::AtLeast(7).phrase(), "at least 7 tools");
    assert_eq!(ToolTotal::Exact(7).phrase(), "7 tools");
}

#[test]
fn tool_total_plus_widens_a_known_total_but_never_invents_one() {
    // Capability tools are known independently of the backend cache, so they
    // widen an existing floor and the exact total alike...
    assert_eq!(ToolTotal::AtLeast(7).plus(3), ToolTotal::AtLeast(10));
    assert_eq!(ToolTotal::Exact(7).plus(3), ToolTotal::Exact(10));
    // ...but a gateway with nothing enumerated still has no number to state.
    assert_eq!(ToolTotal::Unknown.plus(3), ToolTotal::Unknown);
}

#[test]
fn discovery_preamble_includes_server_count() {
    // GIVEN: 42 tools across 3 backends
    let preamble =
        build_discovery_preamble(ToolTotal::Exact(42), 3, &MetaToolExposure::expose_all());
    assert!(
        preamble.contains("3 backends"),
        "preamble must include backend/server count"
    );
}

#[test]
fn discovery_preamble_with_zero_counts_is_valid() {
    // GIVEN: no tools or backends yet (empty gateway)
    let preamble =
        build_discovery_preamble(ToolTotal::Exact(0), 0, &MetaToolExposure::expose_all());
    assert!(preamble.contains("0 tools"));
    assert!(preamble.contains("0 backends"));
}

// ── build_meta_tools ────────────────────────────────────────────────

/// The floor of the `NFR.PERF.4` band: every gate off.
#[test]
fn build_meta_tools_returns_only_the_ungated_surface_with_every_gate_off() {
    let tools = build_meta_tools(
        MetaToolGates {
            stats: false,
            reload: false,
            cost_report: false,
            webhook_status: false,
            playbooks: false,
            profiles: false,
        },
        ToolTotal::Exact(0),
        0,
    );
    // 4 base + 2 kill-switch + 1 disabled-caps + 1 set-state + 1 reload-capabilities = 9
    assert_eq!(tools.len(), 9);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_list_servers"));
    assert!(names.contains(&"gateway_list_tools"));
    assert!(names.contains(&"gateway_search_tools"));
    assert!(names.contains(&"gateway_invoke"));
    assert!(names.contains(&"gateway_kill_server"));
    assert!(names.contains(&"gateway_revive_server"));
    assert!(names.contains(&"gateway_list_disabled_capabilities"));
    assert!(!names.contains(&"gateway_run_playbook"));
    assert!(!names.contains(&"gateway_set_profile"));
    assert!(!names.contains(&"gateway_get_profile"));
    assert!(!names.contains(&"gateway_list_profiles"));
    assert!(!names.contains(&"gateway_webhook_status"));
    assert!(!names.contains(&"gateway_reload_config"));
}

/// The stats-enabled surface with no webhook registry attached.
///
/// This is the stdio shape: `run_stdio` never calls `set_webhook_registry`, so
/// the tool is absent from the listing there however `webhooks.enabled` is set.
/// The attached case is swept in `meta_mcp_tool_defs_tests.rs`.
#[test]
fn build_meta_tools_with_stats_enumerates_everything_but_webhook_status() {
    let tools = build_meta_tools(
        MetaToolGates {
            stats: true,
            reload: false,
            cost_report: false,
            webhook_status: false,
            playbooks: false,
            profiles: false,
        },
        ToolTotal::Exact(0),
        0,
    );
    // 4 base + 1 stats + 2 kill-switch + 1 disabled-caps + 1 set-state + 1 reload-capabilities = 10
    assert_eq!(tools.len(), 10);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_get_stats"));
    assert!(
        !names.contains(&"gateway_webhook_status"),
        "webhook status must stay off the enumerated surface (NFR.PERF.4)"
    );
    assert!(names.contains(&"gateway_kill_server"));
    assert!(names.contains(&"gateway_revive_server"));
    assert!(names.contains(&"gateway_list_disabled_capabilities"));
}

#[test]
fn build_meta_tools_includes_reload_when_enabled() {
    // GIVEN: reload context enabled
    let tools = build_meta_tools(
        MetaToolGates {
            stats: false,
            reload: true,
            cost_report: false,
            webhook_status: false,
            playbooks: false,
            profiles: false,
        },
        ToolTotal::Exact(0),
        0,
    );
    // 4 base + 2 kill-switch + 1 disabled-caps + 1 reload + 1 set-state + 1 reload-capabilities = 10
    assert_eq!(tools.len(), 10);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_reload_config"));
    assert!(names.contains(&"gateway_list_disabled_capabilities"));
}

#[test]
fn build_meta_tools_all_enabled_includes_reload() {
    // GIVEN: stats and reload enabled
    let tools = build_meta_tools(
        MetaToolGates {
            stats: true,
            reload: true,
            cost_report: false,
            webhook_status: false,
            playbooks: false,
            profiles: false,
        },
        ToolTotal::Exact(0),
        0,
    );
    // 4 base + 1 stats + 2 kill-switch + 1 disabled-caps + 1 reload + 1 set-state + 1 reload-capabilities = 11
    assert_eq!(tools.len(), 11);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_reload_config"));
    assert!(names.contains(&"gateway_get_stats"));
    assert!(names.contains(&"gateway_list_disabled_capabilities"));
    assert!(!names.contains(&"gateway_set_profile"));
    assert!(!names.contains(&"gateway_get_profile"));
    assert!(!names.contains(&"gateway_list_profiles"));
}

#[test]
fn build_base_tools_all_have_descriptions() {
    let tools = build_base_tools(ToolTotal::Exact(10), 2);
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
    let tools = build_base_tools(ToolTotal::Exact(10), 2);
    for tool in &tools {
        assert_eq!(
            tool.input_schema["type"], "object",
            "Tool {} has non-object schema",
            tool.name
        );
    }
}

#[test]
fn build_stats_tool_has_no_unmeasured_savings_parameter() {
    let tool = build_stats_tool();
    assert_eq!(tool.name, "gateway_get_stats");
    assert_eq!(tool.input_schema["properties"], json!({}));
}

// ── tool_matches_query ──────────────────────────────────────────────

#[test]
fn tool_matches_query_by_name() {
    let tool = make_tool("gateway_search_tools", Some("Search stuff"));
    assert!(tool_matches_query("testserver", &tool, "search"));
}

#[test]
fn tool_matches_query_by_description() {
    let tool = make_tool("my_tool", Some("Weather forecast service"));
    assert!(tool_matches_query("testserver", &tool, "weather"));
}

#[test]
fn tool_matches_query_case_insensitive() {
    let tool = make_tool("MyTool", Some("Advanced Analytics"));
    assert!(tool_matches_query("testserver", &tool, "mytool"));
    assert!(tool_matches_query("testserver", &tool, "analytics"));
}

#[test]
fn tool_does_not_match_unrelated_query() {
    let tool = make_tool("gateway_invoke", Some("Invoke a tool"));
    assert!(!tool_matches_query("testserver", &tool, "weather"));
}

#[test]
fn tool_matches_query_with_no_description() {
    let tool = make_tool("search_engine", None);
    assert!(tool_matches_query("testserver", &tool, "search"));
    assert!(!tool_matches_query("testserver", &tool, "weather"));
}

#[test]
fn tool_matches_multi_word_query_any_word_in_name() {
    // GIVEN: a tool named "brave_search" and query "batch search"
    let tool = make_tool("brave_search", Some("Web search tool"));
    // WHEN: querying with two words
    // THEN: matches because "search" is in the name
    assert!(tool_matches_query("testserver", &tool, "batch search"));
}

#[test]
fn tool_matches_multi_word_query_any_word_in_description() {
    // GIVEN: a tool with "research" only in description, query "batch research"
    let tool = make_tool("parallel_task", Some("Run deep research tasks in parallel"));
    // WHEN: querying "batch research"
    // THEN: matches because "research" is in the description
    assert!(tool_matches_query("testserver", &tool, "batch research"));
}

#[test]
fn tool_no_match_when_no_word_found() {
    // GIVEN: a tool unrelated to either query word
    let tool = make_tool("weather_api", Some("Returns current temperature"));
    // WHEN: searching for "batch search"
    // THEN: no match
    assert!(!tool_matches_query("testserver", &tool, "batch search"));
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
    assert!(tool_matches_query("testserver", &tool, "web"));
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
    assert!(tool_matches_query("testserver", &tool, "batch monitor"));
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

#[path = "meta_mcp_helpers_tests/ranked_json.rs"]
mod ranked_json;

#[test]
fn expose_all_reproduces_the_unfiltered_preamble() {
    // The conditional assembly must be byte-identical to the single `format!`
    // it replaced. Every other assertion here is `contains`, so a dropped line
    // or a lost newline on the default path would pass all of them.
    let expected = "This server manages 42 tools across 3 backends.\n\
         Use gateway_search_tools FIRST to find relevant tools by keyword before invoking.\n\
         Tool schemas are not listed directly so the prompt stays compact.\n\
         \n\
         Discovery pattern:\n\
         1. gateway_search_tools(query=\"your keyword\") -- find tools matching your need\n\
         2. gateway_invoke(server=\"X\", tool=\"Y\", arguments={...}) -- call the tool\n\
         \n\
         Direct listing (when you know the backend):\n\
         - gateway_list_tools(server=\"brave\") -- list tools from a specific backend\n\
         - gateway_list_servers -- list all backends with status\n";

    assert_eq!(
        build_discovery_preamble(ToolTotal::Exact(42), 3, &MetaToolExposure::expose_all()),
        expected
    );
}

// ---------------------------------------------------------------------------
// Extensions capability (`io.modelcontextprotocol/extensions`)
// ---------------------------------------------------------------------------

#[test]
fn extensions_reach_the_wire_when_the_gateway_implements_one() {
    // `build_server_capabilities` takes the extension source as a parameter for
    // exactly this assertion: perturb the input, observe the serialized value.
    // Without it, a capabilities struct left at its `Default` is indistinguishable
    // from one that is correctly populated, because both are empty today.
    let mut implemented = std::collections::HashMap::new();
    implemented.insert(
        "io.modelcontextprotocol/tasks".to_string(),
        serde_json::json!({}),
    );

    let wire = serde_json::to_value(build_server_capabilities(
        implemented,
        crate::gateway::ChangeFeed::Http,
    ))
    .unwrap();

    assert_eq!(
        wire.get("extensions")
            .and_then(|e| e.get("io.modelcontextprotocol/tasks")),
        Some(&serde_json::json!({})),
        "an implemented extension must appear in the serialized capabilities; \
         it is how a client learns the mechanism is honoured"
    );
}

#[test]
fn empty_extensions_are_omitted_so_discovery_stays_additive() {
    // MIK-7217 AC discover-3 requires the initialize result to be unchanged for a
    // client asking for an already-supported revision. An always-present
    // `"extensions": {}` breaks that: a key that appears for every client is a
    // handshake change, not an additive one. Serializing it unconditionally is
    // what turned that AC red, so this pins the omission rather than the default.
    let wire = serde_json::to_value(build_server_capabilities(
        initialize_extensions(crate::protocol::meta::Era::Legacy),
        crate::gateway::ChangeFeed::Http,
    ))
    .unwrap();

    assert!(
        wire.get("extensions").is_none(),
        "capabilities must not carry an extensions key while none is implemented, got: {wire}"
    );
}

#[test]
fn ac_ext_1_a_the_builder_serializes_the_map_it_was_given() {
    let mut probe = std::collections::HashMap::new();
    probe.insert("example.test/probe".to_string(), serde_json::json!({}));

    // WHEN: the builder serializes those capabilities.
    let wire = serde_json::to_value(build_server_capabilities(
        probe,
        crate::gateway::ChangeFeed::Http,
    ))
    .unwrap();

    let extensions = wire
        .get("extensions")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("capabilities must carry the injected extensions, got: {wire}"));

    assert_eq!(
        extensions.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["example.test/probe"],
        "the builder must serialize the map it was given and nothing else; \
         any other key means the extension source is read from somewhere \
         other than the parameter"
    );
}
