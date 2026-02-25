//! Pure helper functions for Meta-MCP, extracted for testability.
//!
//! These are stateless functions with no async or backend dependencies.

use serde_json::{Value, json};

use crate::failsafe::CircuitBreakerStats;
use crate::protocol::{
    Content, Info, InitializeResult, JsonRpcResponse, PromptsCapability, RequestId,
    ResourcesCapability, ServerCapabilities, Tool, ToolsCallResult, ToolsCapability,
};
use crate::ranking::{SearchResult, expand_synonyms};
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
///
/// `instructions` is appended after the static preamble; pass an empty string
/// to get the minimal discovery-only text.
pub(crate) fn build_initialize_result(negotiated_version: &str, instructions: &str) -> InitializeResult {
    InitializeResult {
        protocol_version: negotiated_version.to_string(),
        capabilities: ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: true }),
            resources: Some(ResourcesCapability {
                subscribe: true,
                list_changed: true,
            }),
            prompts: Some(PromptsCapability { list_changed: true }),
            logging: Some(std::collections::HashMap::new()),
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
        instructions: Some(instructions.to_string()),
    }
}

/// Build the static discovery preamble shared by all initialize responses.
pub(crate) fn build_discovery_preamble() -> String {
    "Tool Discovery:\n\
     - gateway_search_tools: Search by keyword (supports multi-word: \"batch research\")\n\
     - gateway_list_tools: List all tools from a specific backend (omit server for ALL)\n\
     - gateway_list_servers: List all available backends\n\
     - gateway_invoke: Call any tool on any backend\n"
        .to_string()
}

/// Build dynamic routing instructions from capability metadata.
///
/// Groups capabilities by `metadata.category`, listing representative tools
/// and the union of their tags as search keywords. Returns an empty string
/// when no capabilities are provided.
pub(crate) fn build_routing_instructions(
    capabilities: &[crate::capability::CapabilityDefinition],
    capability_backend_name: &str,
) -> String {
    use std::collections::{BTreeMap, BTreeSet};

    if capabilities.is_empty() {
        return String::new();
    }

    // Group tools by category, preserving insertion order via BTreeMap
    let mut by_category: BTreeMap<String, (Vec<String>, BTreeSet<String>)> = BTreeMap::new();

    for cap in capabilities {
        let category = if cap.metadata.category.is_empty() {
            "general".to_string()
        } else {
            cap.metadata.category.clone()
        };

        let entry = by_category.entry(category).or_default();
        entry.0.push(format!("{}/{}", capability_backend_name, cap.name));
        for tag in &cap.metadata.tags {
            entry.1.insert(tag.clone());
        }
    }

    // Also track chains_with hints per category: source_tool -> [downstream_tools]
    let mut chains: Vec<(String, Vec<String>)> = Vec::new();
    for cap in capabilities {
        if !cap.metadata.chains_with.is_empty() {
            chains.push((cap.name.clone(), cap.metadata.chains_with.clone()));
        }
    }

    let mut lines = vec!["\nRouting Guide (by task type):".to_string()];

    for (category, (tools, tags)) in &by_category {
        let tool_sample = tools.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
        let suffix = if tools.len() > 3 {
            format!(" (+{})", tools.len() - 3)
        } else {
            String::new()
        };
        lines.push(format!("- {category}: {tool_sample}{suffix}"));

        if !tags.is_empty() {
            let tag_list = tags.iter().cloned().collect::<Vec<_>>().join(", ");
            lines.push(format!("  Search keywords: {tag_list}"));
        }
    }

    if !chains.is_empty() {
        lines.push("\nComposition chains (tool -> next steps):".to_string());
        for (source, targets) in &chains {
            lines.push(format!("  {source} -> {}", targets.join(", ")));
        }
    }

    lines.join("\n")
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
            description: Some(
                "List tools from a backend server. Omit server to list ALL tools across all backends."
                    .to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "description": "Name of backend server. Omit to list ALL tools across all backends."
                    }
                },
                "required": []
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

/// Build the webhook status meta-tool definition.
pub(crate) fn build_webhook_status_tool() -> Tool {
    Tool {
        name: "gateway_webhook_status".to_string(),
        title: Some("Webhook Status".to_string()),
        description: Some(
            "List registered webhook endpoints and their delivery statistics \
             (received, delivered, failures, last event)"
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_kill_server` meta-tool definition.
fn build_kill_server_tool() -> Tool {
    Tool {
        name: "gateway_kill_server".to_string(),
        title: Some("Kill Server".to_string()),
        description: Some(
            "Immediately disable routing to a backend server (operator kill switch). \
             The server's tools remain visible in search/list but are marked as disabled."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server": {
                    "type": "string",
                    "description": "Name of the backend server to disable"
                }
            },
            "required": ["server"]
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_revive_server` meta-tool definition.
fn build_revive_server_tool() -> Tool {
    Tool {
        name: "gateway_revive_server".to_string(),
        title: Some("Revive Server".to_string()),
        description: Some(
            "Re-enable routing to a previously disabled backend server. \
             Also resets the error budget so the server gets a clean slate."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server": {
                    "type": "string",
                    "description": "Name of the backend server to re-enable"
                }
            },
            "required": ["server"]
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_set_profile` meta-tool definition.
fn build_set_profile_tool() -> Tool {
    Tool {
        name: "gateway_set_profile".to_string(),
        title: Some("Set Routing Profile".to_string()),
        description: Some(
            "Switch the active routing profile for this session. \
             A routing profile restricts which tools and backends are available."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "profile": {
                    "type": "string",
                    "description": "Name of the routing profile to activate (e.g. \"research\", \"coding\")"
                }
            },
            "required": ["profile"]
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_get_profile` meta-tool definition.
fn build_get_profile_tool() -> Tool {
    Tool {
        name: "gateway_get_profile".to_string(),
        title: Some("Get Routing Profile".to_string()),
        description: Some(
            "Show the active routing profile for this session and what it allows or denies."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_reload_config` meta-tool definition.
pub(crate) fn build_reload_config_tool() -> Tool {
    Tool {
        name: "gateway_reload_config".to_string(),
        title: Some("Reload Config".to_string()),
        description: Some(
            "Trigger an immediate reload of config.yaml from disk without restarting the gateway. \
             Returns a summary of what changed (backends added/removed/modified, profile updates). \
             Server host/port changes require a restart and are reported but not applied."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Construct the full meta-tool list, optionally including stats, webhooks, playbooks, and reload.
pub(crate) fn build_meta_tools(
    stats_enabled: bool,
    webhooks_enabled: bool,
    reload_enabled: bool,
) -> Vec<Tool> {
    let mut tools = build_base_tools();
    if stats_enabled {
        tools.push(build_stats_tool());
    }
    if webhooks_enabled {
        tools.push(build_webhook_status_tool());
    }
    tools.push(build_playbook_tool());
    tools.push(build_kill_server_tool());
    tools.push(build_revive_server_tool());
    tools.push(build_set_profile_tool());
    tools.push(build_get_profile_tool());
    if reload_enabled {
        tools.push(build_reload_config_tool());
    }
    tools
}

/// Check whether a tool matches a search query by name or description.
///
/// The `query` may contain multiple whitespace-separated words. A tool
/// matches if **any** query word (or any of its synonyms) appears
/// case-insensitively in the tool name or description (including keyword tags).
/// Single-word queries behave identically to the previous substring match.
pub(crate) fn tool_matches_query(tool: &Tool, query: &str) -> bool {
    let name_lower = tool.name.to_lowercase();
    let desc_lower = tool.description.as_deref().unwrap_or("").to_lowercase();

    query.split_whitespace().any(|word| {
        word_matches_text(word, &name_lower) || word_matches_text(word, &desc_lower)
    })
}

/// Return `true` if `word` or any of its synonyms appears as a substring of `text`.
fn word_matches_text(word: &str, text: &str) -> bool {
    if text.contains(word) {
        return true;
    }
    expand_synonyms(word)
        .iter()
        .any(|syn| *syn != word && text.contains(*syn))
}

/// Build suggestions from the tag index when a search returns zero results.
///
/// Finds tags that share a common prefix with any query word (length ≥ 3) or
/// that contain any query word as a substring. Returns at most 5 suggestions,
/// alphabetically sorted, with duplicates removed.
///
/// # Arguments
///
/// * `query` — the original (lowercased) search query
/// * `all_tags` — union of all keyword tags available across backends
pub(crate) fn build_suggestions(query: &str, all_tags: &[String]) -> Vec<String> {
    const MIN_PREFIX_LEN: usize = 3;
    const MAX_SUGGESTIONS: usize = 5;

    let words: Vec<&str> = query.split_whitespace().collect();

    let mut seen = std::collections::BTreeSet::new();

    for tag in all_tags {
        let tag_lower = tag.to_lowercase();
        let is_match = words.iter().any(|word| {
            // Substring: tag contains the word
            tag_lower.contains(*word)
            // Or: word is long enough and shares a common prefix with the tag
            || (word.len() >= MIN_PREFIX_LEN
                && tag_lower.starts_with(&word[..MIN_PREFIX_LEN]))
        });
        if is_match {
            seen.insert(tag_lower);
        }
    }

    seen.into_iter().take(MAX_SUGGESTIONS).collect()
}

/// Build a search match JSON object from a tool and server name.
///
/// Truncates description to 500 characters. When `chains_with` is non-empty,
/// a `"chains_with"` array is included to surface composition hints to the caller.
pub(crate) fn build_match_json(server: &str, tool: &Tool) -> Value {
    build_match_json_with_chains(server, tool, &[])
}

/// Build a search match JSON object with optional tool composition hints.
///
/// Like [`build_match_json`] but includes a `"chains_with"` field when the
/// capability declares downstream tools it commonly chains into.
pub(crate) fn build_match_json_with_chains(
    server: &str,
    tool: &Tool,
    chains_with: &[String],
) -> Value {
    let description = tool
        .description
        .as_deref()
        .unwrap_or("")
        .chars()
        .take(500)
        .collect::<String>();

    if chains_with.is_empty() {
        json!({
            "server": server,
            "tool": tool.name,
            "description": description
        })
    } else {
        json!({
            "server": server,
            "tool": tool.name,
            "description": description,
            "chains_with": chains_with
        })
    }
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
///
/// `total_found` is the number of matches across ALL backends (before truncation).
/// `matches` may be truncated to the requested limit.
/// `suggestions` is only emitted (and only non-empty) when `matches` is empty —
/// callers should pass `&[]` when there are matches.
pub(crate) fn build_search_response(
    query: &str,
    matches: &[Value],
    total_found: usize,
    suggestions: &[String],
) -> Value {
    if matches.is_empty() && !suggestions.is_empty() {
        json!({
            "query": query,
            "matches": [],
            "total": 0,
            "total_available": total_found,
            "suggestions": suggestions
        })
    } else {
        json!({
            "query": query,
            "matches": matches,
            "total": matches.len(),
            "total_available": total_found
        })
    }
}

/// Extract the search limit from arguments, defaulting to 10.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn extract_search_limit(args: &Value) -> usize {
    args.get("limit").and_then(Value::as_u64).unwrap_or(10) as usize
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

/// Build the kill-switch / error-budget status entry for a single server.
///
/// Returned object shape:
/// ```json
/// {
///   "server": "my-backend",
///   "killed": false,
///   "error_rate": "12.5%",
///   "window": { "successes": 7, "failures": 1 }
/// }
/// ```
pub(crate) fn build_server_safety_status(
    server: &str,
    killed: bool,
    error_rate: f64,
    successes: usize,
    failures: usize,
) -> Value {
    json!({
        "server": server,
        "killed": killed,
        "error_rate": format!("{:.1}%", error_rate * 100.0),
        "window": {
            "successes": successes,
            "failures": failures
        }
    })
}

/// Build a JSON representation of circuit-breaker stats for a single backend.
///
/// Returned object shape:
/// ```json
/// {
///   "server": "my-backend",
///   "state": "open",
///   "trips_count": 3,
///   "last_trip_ms": 1717000000000,
///   "retry_after_ms": 29500,
///   "current_failures": 5,
///   "failure_threshold": 5
/// }
/// ```
pub(crate) fn build_circuit_breaker_stats_json(server: &str, stats: &CircuitBreakerStats) -> Value {
    json!({
        "server": server,
        "state": stats.state.as_str(),
        "trips_count": stats.trips_count,
        "last_trip_ms": stats.last_trip_ms,
        "retry_after_ms": stats.retry_after_ms,
        "current_failures": stats.current_failures,
        "failure_threshold": stats.failure_threshold
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
        let tools = build_meta_tools(false, false, false);
        // 4 base + 1 playbook + 2 kill-switch + 2 profile = 9
        assert_eq!(tools.len(), 9);
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
        assert!(!names.contains(&"gateway_webhook_status"));
        assert!(!names.contains(&"gateway_reload_config"));
    }

    #[test]
    fn build_meta_tools_returns_all_tools_with_stats_and_webhooks() {
        let tools = build_meta_tools(true, true, false);
        // 4 base + 1 stats + 1 webhooks + 1 playbook + 2 kill-switch + 2 profile = 11
        assert_eq!(tools.len(), 11);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"gateway_get_stats"));
        assert!(names.contains(&"gateway_webhook_status"));
        assert!(names.contains(&"gateway_run_playbook"));
        assert!(names.contains(&"gateway_kill_server"));
        assert!(names.contains(&"gateway_revive_server"));
        assert!(names.contains(&"gateway_set_profile"));
        assert!(names.contains(&"gateway_get_profile"));
    }

    #[test]
    fn build_meta_tools_webhooks_only_without_stats() {
        // GIVEN: webhooks enabled but stats disabled
        // WHEN: building tool list
        // THEN: webhook tool present, stats tool absent
        let tools = build_meta_tools(false, true, false);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"gateway_webhook_status"));
        assert!(!names.contains(&"gateway_get_stats"));
    }

    #[test]
    fn build_meta_tools_includes_reload_when_enabled() {
        // GIVEN: reload context enabled
        let tools = build_meta_tools(false, false, true);
        // 4 base + 1 playbook + 2 kill-switch + 2 profile + 1 reload = 10
        assert_eq!(tools.len(), 10);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"gateway_reload_config"));
        assert!(names.contains(&"gateway_set_profile"));
        assert!(names.contains(&"gateway_get_profile"));
    }

    #[test]
    fn build_meta_tools_all_enabled_includes_reload() {
        // GIVEN: all optional tools enabled
        let tools = build_meta_tools(true, true, true);
        // 4 base + 1 stats + 1 webhooks + 1 playbook + 2 kill-switch + 2 profile + 1 reload = 12
        assert_eq!(tools.len(), 12);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"gateway_reload_config"));
        assert!(names.contains(&"gateway_get_stats"));
        assert!(names.contains(&"gateway_webhook_status"));
        assert!(names.contains(&"gateway_set_profile"));
        assert!(names.contains(&"gateway_get_profile"));
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
        let tags = vec!["scraping".to_string(), "scripting".to_string(), "other".to_string()];
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
        let tags = vec!["search".to_string(), "search".to_string(), "lookup".to_string()];
        let suggestions = build_suggestions("search", &tags);
        let unique_count = suggestions.iter().collect::<std::collections::HashSet<_>>().len();
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
        let chains = vec!["linear_create_issue".to_string(), "linear_list_projects".to_string()];
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

        let make_cap = |name: &str, category: &str, chains: Vec<&str>| {
            CapabilityDefinition {
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
            }
        };

        let caps = vec![
            make_cap("linear_get_teams", "productivity", vec!["linear_create_issue"]),
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
        assert_eq!(meta.chains_with, vec!["linear_create_issue", "linear_update_issue"]);
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
}
