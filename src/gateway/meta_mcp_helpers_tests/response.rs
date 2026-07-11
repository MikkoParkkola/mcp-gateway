// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use crate::stats::StatsSnapshot;

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
    let suggestions = vec!["search".to_string(), "lookup".to_string()];
    let resp = build_search_response("xyzzy", &[], 0, &suggestions);
    let sugg = resp["suggestions"].as_array().unwrap();
    assert_eq!(sugg.len(), 2);
    assert_eq!(sugg[0], "search");
    assert_eq!(sugg[1], "lookup");
}

#[test]
fn build_search_response_suppresses_suggestions_when_matches_present() {
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
fn extract_search_limit_clamps_large_values() {
    let args = json!({"limit": 500});
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
    let response = wrap_tool_success(id, &content, false);
    assert!(response.error.is_none());
    assert!(response.result.is_some());

    let result: ToolsCallResult = serde_json::from_value(response.result.unwrap()).unwrap();
    assert!(!result.is_error);
    assert_eq!(result.content.len(), 1);
    assert!(result.structured_content.is_none());
}

#[test]
fn wrap_tool_success_content_is_pretty_json() {
    let id = RequestId::Number(42);
    let content = json!({"key": "value"});
    let response = wrap_tool_success(id, &content, false);

    let result: ToolsCallResult = serde_json::from_value(response.result.unwrap()).unwrap();
    if let Content::Text { text, .. } = &result.content[0] {
        assert!(text.contains('\n'));
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["key"], "value");
    } else {
        panic!("Expected text content");
    }
}

#[test]
fn wrap_tool_success_with_output_schema_includes_structured_content() {
    let id = RequestId::Number(99);
    let content = json!({"matches": [{"server": "ado", "tool": "list_projects", "description": "List projects", "score": 1.0}]});
    let response = wrap_tool_success(id, &content, true);

    let result: ToolsCallResult = serde_json::from_value(response.result.unwrap()).unwrap();
    assert!(!result.is_error);
    assert_eq!(result.content.len(), 1);
    let sc = result
        .structured_content
        .expect("structuredContent must be present when has_output_schema is true");
    assert_eq!(sc["matches"][0]["server"], "ado");
}

// ── tool_matches_query synonym expansion ────────────────────────────

#[test]
fn tool_matches_query_synonym_in_name() {
    let tool = make_tool("search_companies", Some("Find business entities"));
    assert!(
        tool_matches_query(&tool, "find"),
        "'find' should match tool with 'search' via synonym"
    );
}

#[test]
fn tool_matches_query_synonym_in_description() {
    let tool = make_tool("uptimer", Some("Continuously monitor your services"));
    assert!(
        tool_matches_query(&tool, "watch"),
        "'watch' should match tool with 'monitor' via synonym"
    );
}

#[test]
fn tool_matches_query_no_false_positive_for_unrelated_synonym_group() {
    let tool = make_tool("weather_api", Some("Get current temperature and humidity"));
    assert!(
        !tool_matches_query(&tool, "find"),
        "should not match a tool with no search-related words"
    );
}

#[test]
fn tool_matches_query_multi_word_uses_synonym_for_one_word() {
    let tool = make_tool("search_weather", Some("Get forecasts"));
    assert!(
        tool_matches_query(&tool, "find weather"),
        "should match: 'weather' in name, 'find'~'search' in name"
    );
}
