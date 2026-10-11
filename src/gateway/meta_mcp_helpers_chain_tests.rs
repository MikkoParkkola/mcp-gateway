// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use serde_json::json;

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
        response_transform: TransformConfig::default(),
        projection: None,
        visible_in_states: vec![],
        webhooks: HashMap::new(),
        sha256: None,
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
        response_transform: TransformConfig::default(),
        projection: None,
        visible_in_states: vec![],
        webhooks: HashMap::new(),
        sha256: None,
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

#[path = "meta_mcp_helpers_chain_tests/code_mode_tests.rs"]
mod code_mode_tests;
