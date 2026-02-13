//! Pure helper functions for Meta-MCP, extracted for testability.
//!
//! These are stateless functions with no async or backend dependencies.

use serde_json::{Value, json};

use crate::protocol::{
    Content, Info, InitializeResult, JsonRpcResponse, RequestId, ServerCapabilities, Tool,
    ToolsCallResult, ToolsCapability,
};
use crate::ranking::SearchResult;
use crate::stats::StatsSnapshot;
use crate::{Error, Result};

// ============================================================================
// Pure functions (testable without async or backends)
// ============================================================================

/// Extract the client protocol version from initialize params.
///
/// Returns `"2024-11-05"` when params are `None` or missing `protocolVersion`.
pub(crate) fn extract_client_version(params: Option<&Value>) -> &str {
    params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or("2024-11-05")
}

/// Build the `InitializeResult` for a given negotiated protocol version.
pub(crate) fn build_initialize_result(negotiated_version: &str) -> InitializeResult {
    InitializeResult {
        protocol_version: negotiated_version.to_string(),
        capabilities: ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: true }),
            ..Default::default()
        },
        server_info: Info {
            name: "mcp-gateway".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            title: Some("MCP Gateway".to_string()),
            description: Some(
                "Universal MCP Gateway with Meta-MCP for dynamic tool discovery".to_string(),
            ),
        },
        instructions: Some(
            "Use gateway_list_servers to discover backends, \
             gateway_list_tools to get tools from a backend, \
             gateway_search_tools to search, and \
             gateway_invoke to call tools."
                .to_string(),
        ),
    }
}

/// Build the base set of 4 meta-tools.
fn build_base_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "gateway_list_servers".to_string(),
            title: Some("List Servers".to_string()),
            description: Some("List all available MCP backend servers".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            output_schema: None,
            annotations: None,
        },
        Tool {
            name: "gateway_list_tools".to_string(),
            title: Some("List Tools".to_string()),
            description: Some("List all tools from a specific backend server".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "description": "Name of the backend server"
                    }
                },
                "required": ["server"]
            }),
            output_schema: None,
            annotations: None,
        },
        Tool {
            name: "gateway_search_tools".to_string(),
            title: Some("Search Tools".to_string()),
            description: Some("Search for tools across all backends by keyword".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search keyword"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default 10)",
                        "default": 10
                    }
                },
                "required": ["query"]
            }),
            output_schema: None,
            annotations: None,
        },
        Tool {
            name: "gateway_invoke".to_string(),
            title: Some("Invoke Tool".to_string()),
            description: Some("Invoke a tool on a specific backend".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "description": "Backend server name"
                    },
                    "tool": {
                        "type": "string",
                        "description": "Tool name to invoke"
                    },
                    "arguments": {
                        "type": "object",
                        "description": "Tool arguments",
                        "default": {}
                    }
                },
                "required": ["server", "tool"]
            }),
            output_schema: None,
            annotations: None,
        },
    ]
}

/// Build the optional stats tool definition.
fn build_stats_tool() -> Tool {
    Tool {
        name: "gateway_get_stats".to_string(),
        title: Some("Get Gateway Statistics".to_string()),
        description: Some(
            "Get usage statistics including invocations, cache hits, \
             token savings, and top tools"
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "price_per_million": {
                    "type": "number",
                    "description": "Token price per million for cost calculations (default 15.0 for Opus 4.6)",
                    "default": 15.0
                }
            },
            "required": []
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the playbook runner meta-tool definition.
fn build_playbook_tool() -> Tool {
    Tool {
        name: "gateway_run_playbook".to_string(),
        title: Some("Run Playbook".to_string()),
        description: Some(
            "Execute a multi-step playbook (collapses multiple tool calls into one invocation)"
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Playbook name to execute"
                },
                "arguments": {
                    "type": "object",
                    "description": "Playbook input arguments",
                    "default": {}
                }
            },
            "required": ["name"]
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Construct the full meta-tool list, optionally including stats and playbooks.
pub(crate) fn build_meta_tools(stats_enabled: bool) -> Vec<Tool> {
    let mut tools = build_base_tools();
    if stats_enabled {
        tools.push(build_stats_tool());
    }
    tools.push(build_playbook_tool());
    tools
}

/// Check whether a tool matches a lowercased search query by name or description.
pub(crate) fn tool_matches_query(tool: &Tool, query: &str) -> bool {
    let name_match = tool.name.to_lowercase().contains(query);
    let desc_match = tool
        .description
        .as_ref()
        .is_some_and(|d| d.to_lowercase().contains(query));
    name_match || desc_match
}

/// Build a search match JSON object from a tool and server name.
///
/// Truncates description to 200 characters.
pub(crate) fn build_match_json(server: &str, tool: &Tool) -> Value {
    json!({
        "server": server,
        "tool": tool.name,
        "description": tool.description.as_deref()
            .unwrap_or("")
            .chars()
            .take(200)
            .collect::<String>()
    })
}

/// Convert ranked `SearchResult` items to JSON.
pub(crate) fn ranked_results_to_json(ranked: Vec<SearchResult>) -> Vec<Value> {
    ranked
        .into_iter()
        .map(|r| {
            json!({
                "server": r.server,
                "tool": r.tool,
                "description": r.description,
                "score": r.score
            })
        })
        .collect()
}

/// Build the final search response JSON.
pub(crate) fn build_search_response(query: &str, matches: &[Value]) -> Value {
    json!({
        "query": query,
        "matches": matches,
        "total": matches.len()
    })
}

/// Extract the search limit from arguments, defaulting to 10.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn extract_search_limit(args: &Value) -> usize {
    args.get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(10) as usize
}

/// Extract a required string parameter from JSON arguments.
pub(crate) fn extract_required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::json_rpc(-32602, format!("Missing '{key}' parameter")))
}

/// Parse and validate tool invocation arguments.
///
/// Handles both JSON objects and stringified JSON objects (OpenAI-style).
/// Returns an error if arguments are neither.
pub(crate) fn parse_tool_arguments(args: &Value) -> Result<Value> {
    let mut arguments = args.get("arguments").cloned().unwrap_or(json!({}));

    // Accept OpenAI-style tool arguments passed as a JSON string.
    if let Value::String(raw) = &arguments {
        let parsed: Value = serde_json::from_str(raw).map_err(|e| {
            Error::json_rpc(-32602, format!("Invalid 'arguments' JSON string: {e}"))
        })?;
        arguments = parsed;
    }

    if !arguments.is_object() {
        return Err(Error::json_rpc(
            -32602,
            "Invalid 'arguments': expected object or JSON object string",
        ));
    }

    Ok(arguments)
}

/// Extract the price per million from stats arguments, defaulting to 15.0.
pub(crate) fn extract_price_per_million(args: &Value) -> f64 {
    args.get("price_per_million")
        .and_then(Value::as_f64)
        .unwrap_or(15.0)
}

/// Build the stats response JSON from a snapshot.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn build_stats_response(snapshot: &StatsSnapshot, price_per_million: f64) -> Value {
    let estimated_savings = snapshot.estimated_savings_usd(price_per_million);

    json!({
        "invocations": snapshot.invocations,
        "cache_hits": snapshot.cache_hits,
        "cache_hit_rate": format!("{:.1}%", snapshot.cache_hit_rate * 100.0),
        "tools_discovered": snapshot.tools_discovered,
        "tools_available": snapshot.tools_available,
        "tokens_saved": snapshot.tokens_saved,
        "estimated_savings_usd": format!("${:.2}", estimated_savings),
        "top_tools": snapshot.top_tools
    })
}

/// Wrap a successful tool result `Value` into a `JsonRpcResponse`.
pub(crate) fn wrap_tool_success(id: RequestId, content: &Value) -> JsonRpcResponse {
    let result = ToolsCallResult {
        content: vec![Content::Text {
            text: serde_json::to_string_pretty(content).unwrap_or_default(),
            annotations: None,
        }],
        is_error: false,
    };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
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

    #[test]
    fn build_initialize_result_has_correct_version() {
        let result = build_initialize_result("2025-11-25");
        assert_eq!(result.protocol_version, "2025-11-25");
    }

    #[test]
    fn build_initialize_result_has_tools_capability() {
        let result = build_initialize_result("2024-11-05");
        assert!(result.capabilities.tools.is_some());
        assert!(result.capabilities.tools.unwrap().list_changed);
    }

    #[test]
    fn build_initialize_result_has_server_info() {
        let result = build_initialize_result("2024-11-05");
        assert_eq!(result.server_info.name, "mcp-gateway");
        assert!(result.server_info.title.is_some());
        assert!(result.server_info.description.is_some());
    }

    #[test]
    fn build_initialize_result_has_instructions() {
        let result = build_initialize_result("2024-11-05");
        let instructions = result.instructions.as_ref().unwrap();
        assert!(instructions.contains("gateway_list_servers"));
        assert!(instructions.contains("gateway_invoke"));
    }

    // ── build_meta_tools ────────────────────────────────────────────────

    #[test]
    fn build_meta_tools_returns_base_plus_playbook_without_stats() {
        let tools = build_meta_tools(false);
        assert_eq!(tools.len(), 5); // 4 base + 1 playbook
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"gateway_list_servers"));
        assert!(names.contains(&"gateway_list_tools"));
        assert!(names.contains(&"gateway_search_tools"));
        assert!(names.contains(&"gateway_invoke"));
        assert!(names.contains(&"gateway_run_playbook"));
    }

    #[test]
    fn build_meta_tools_returns_all_tools_with_stats() {
        let tools = build_meta_tools(true);
        assert_eq!(tools.len(), 6); // 4 base + 1 stats + 1 playbook
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"gateway_get_stats"));
        assert!(names.contains(&"gateway_run_playbook"));
    }

    #[test]
    fn build_base_tools_all_have_descriptions() {
        let tools = build_base_tools();
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
        let tools = build_base_tools();
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
        let long_desc = "a".repeat(300);
        let tool = make_tool("tool", Some(&long_desc));
        let result = build_match_json("srv", &tool);
        let desc = result["description"].as_str().unwrap();
        assert_eq!(desc.len(), 200);
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
        let resp = build_search_response("test", &matches);
        assert_eq!(resp["query"], "test");
        assert_eq!(resp["total"], 2);
        assert_eq!(resp["matches"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn build_search_response_empty_matches() {
        let resp = build_search_response("nothing", &[]);
        assert_eq!(resp["total"], 0);
        assert!(resp["matches"].as_array().unwrap().is_empty());
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

        let result: ToolsCallResult =
            serde_json::from_value(response.result.unwrap()).unwrap();
        assert!(!result.is_error);
        assert_eq!(result.content.len(), 1);
    }

    #[test]
    fn wrap_tool_success_content_is_pretty_json() {
        let id = RequestId::Number(42);
        let content = json!({"key": "value"});
        let response = wrap_tool_success(id, &content);

        let result: ToolsCallResult =
            serde_json::from_value(response.result.unwrap()).unwrap();
        if let Content::Text { text, .. } = &result.content[0] {
            // Pretty-printed JSON contains newlines
            assert!(text.contains('\n'));
            let parsed: Value = serde_json::from_str(text).unwrap();
            assert_eq!(parsed["key"], "value");
        } else {
            panic!("Expected text content");
        }
    }
}
