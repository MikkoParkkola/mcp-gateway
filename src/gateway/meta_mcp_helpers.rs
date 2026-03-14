//! Pure helper functions for Meta-MCP, extracted for testability.
//!
//! These are stateless functions with no async or backend dependencies.
//! Tool schema definitions live in [`super::meta_mcp_tool_defs`].

use serde_json::{Value, json};

use crate::failsafe::CircuitBreakerStats;
use crate::protocol::{
    Content, Info, InitializeResult, JsonRpcResponse, PromptsCapability, RequestId,
    ResourcesCapability, ServerCapabilities, Tool, ToolsCallResult, ToolsCapability,
};
use crate::ranking::{SearchResult, expand_synonyms};
use crate::stats::StatsSnapshot;
use crate::{Error, Result};

// Re-export tool definitions so callers need only one import.
// The individual builders are used via `super::*` in the tests sub-module.
#[allow(unused_imports)]
pub(crate) use super::meta_mcp_tool_defs::{
    build_base_tools, build_code_mode_execute_tool, build_code_mode_search_tool,
    build_code_mode_tools, build_kill_server_tool, build_list_disabled_capabilities_tool,
    build_meta_tools, build_reload_config_tool, build_revive_server_tool, build_stats_tool,
    build_webhook_status_tool,
};

// ============================================================================
// Pure functions (testable without async or backends)
// ============================================================================

/// Compute the Levenshtein edit distance between two strings.
///
/// Returns `0` for identical strings, `1` for a single insertion, deletion,
/// or substitution, and so on. Uses the standard two-row DP formulation for
/// O(b_len) space.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(levenshtein("gateway_invoke", "gateway_invoke"), 0);
/// assert_eq!(levenshtein("gateway_invokee", "gateway_invoke"), 1);
/// assert_eq!(levenshtein("gatway_invoke", "gateway_invoke"), 1);
/// ```
pub(crate) fn levenshtein(a: &str, b: &str) -> usize {
    let b_len = b.len();
    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0; b_len + 1];
    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j] + cost)
                .min(prev[j + 1] + 1)
                .min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_len]
}

/// Build a "Did you mean?" suggestion message for an unknown tool name.
///
/// Searches `candidates` for names within Levenshtein distance ≤ `threshold`
/// of `tool_name`, returns up to `max_suggestions` sorted by ascending
/// distance. Returns `None` when no candidate is close enough.
///
/// # Examples
///
/// ```ignore
/// let candidates = ["gateway_invoke", "gateway_search_tools", "gateway_list_tools"];
/// let msg = did_you_mean("gateway_invokee", &candidates, 3, 3);
/// assert!(msg.is_some_and(|m: &str| m.contains("gateway_invoke")));
/// ```
pub(crate) fn did_you_mean(
    tool_name: &str,
    candidates: &[&str],
    threshold: usize,
    max_suggestions: usize,
) -> Option<String> {
    let mut suggestions: Vec<(&str, usize)> = candidates
        .iter()
        .map(|name| (*name, levenshtein(tool_name, name)))
        .filter(|(_, dist)| *dist <= threshold)
        .collect();
    suggestions.sort_by_key(|(_, d)| *d);
    suggestions.truncate(max_suggestions);

    if suggestions.is_empty() {
        return None;
    }

    let names: Vec<&str> = suggestions.iter().map(|(n, _)| *n).collect();
    Some(format!("Did you mean: {}?", names.join(", ")))
}

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
pub(crate) fn build_initialize_result(
    negotiated_version: &str,
    instructions: &str,
) -> InitializeResult {
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

/// Build the dynamic discovery preamble shared by all initialize responses.
///
/// Includes the live tool and server counts so the agent understands the
/// scope of what is available without listing all schemas (which would cost
/// ~95% more tokens).
///
/// # Arguments
///
/// * `tool_count`   — total number of tools currently cached across all backends
/// * `server_count` — number of registered backends (running or not)
///
/// # Examples
///
/// ```ignore
/// let preamble = build_discovery_preamble(42, 3);
/// assert!(preamble.contains("42 tools"));
/// assert!(preamble.contains("3 backends"));
/// assert!(preamble.contains("FIRST"));
/// ```
pub(crate) fn build_discovery_preamble(tool_count: usize, server_count: usize) -> String {
    format!(
        "This server manages {tool_count} tools across {server_count} backends.\n\
         Use gateway_search_tools FIRST to find relevant tools by keyword before invoking.\n\
         Tool schemas are not listed directly to save context (~95% token reduction).\n\
         \n\
         Discovery pattern:\n\
         1. gateway_search_tools(query=\"your keyword\") -- find tools matching your need\n\
         2. gateway_invoke(server=\"X\", tool=\"Y\", arguments={{...}}) -- call the tool\n\
         \n\
         Direct listing (when you know the backend):\n\
         - gateway_list_tools(server=\"brave\") -- list tools from a specific backend\n\
         - gateway_list_servers -- list all backends with status\n"
    )
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
        entry
            .0
            .push(format!("{}/{}", capability_backend_name, cap.name));
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

/// Parse a Code Mode tool reference into `(tool_name, server)`.
///
/// Accepts two formats:
/// - `"server:tool_name"` — explicit server prefix (colon-separated)
/// - `"tool_name"` — bare name (server is `None`, caller must resolve)
pub(crate) fn parse_code_mode_tool_ref(tool_ref: &str) -> (&str, Option<&str>) {
    match tool_ref.split_once(':') {
        Some((server, tool)) => (tool, Some(server)),
        None => (tool_ref, None),
    }
}

/// Return `true` when `query` is a glob pattern (contains `*` or `?`).
pub(crate) fn is_glob_pattern(query: &str) -> bool {
    query.contains('*') || query.contains('?')
}

/// Match a tool name against a glob pattern.
///
/// Supports:
/// - `*` — matches any sequence of characters (including empty)
/// - `?` — matches exactly one character
///
/// The match is case-insensitive.
pub(crate) fn tool_name_matches_glob(tool_name: &str, pattern: &str) -> bool {
    let name = tool_name.to_lowercase();
    let pat = pattern.to_lowercase();
    glob_match_impl(&name, &pat)
}

/// Check whether a tool matches a glob pattern on its **name only**.
///
/// Returns `true` when the tool name (lowercased) matches the given glob
/// pattern (also lowercased).  Use this instead of [`tool_matches_query`]
/// when the query contains `*` or `?` characters.
pub(crate) fn tool_matches_glob(tool: &Tool, pattern: &str) -> bool {
    tool_name_matches_glob(&tool.name, pattern)
}

/// Glob matching implementation using char slices for clean recursion.
///
/// Both `text` and `pattern` must already be lowercased by the caller.
/// Delegates immediately to the char-slice helper to avoid repeated
/// `chars().collect()` allocations on every recursive call.
fn glob_match_impl(text: &str, pattern: &str) -> bool {
    let text_chars: Vec<char> = text.chars().collect();
    let pat_chars: Vec<char> = pattern.chars().collect();
    glob_match_chars(&text_chars, &pat_chars)
}

/// Recursive char-slice glob matcher.
///
/// Supports `*` (zero or more chars) and `?` (exactly one char).
/// Pattern and text must already be normalized (lowercased) by the caller.
fn glob_match_chars(text: &[char], pattern: &[char]) -> bool {
    match (text.first(), pattern.first()) {
        // Both exhausted: success
        (None, None) => true,
        // Pattern has a trailing star that matches empty: skip it
        (None, Some('*')) => glob_match_chars(text, &pattern[1..]),
        // Text exhausted with non-star pattern remaining, or text remains but pattern exhausted
        (None, _) | (Some(_), None) => false,
        // Star: try matching zero chars (advance pattern) or one char (advance text)
        (Some(_), Some('*')) => {
            glob_match_chars(text, &pattern[1..]) || glob_match_chars(&text[1..], pattern)
        }
        // Question mark: matches any single char
        (Some(_), Some('?')) => glob_match_chars(&text[1..], &pattern[1..]),
        // Literal: must equal
        (Some(t), Some(p)) => *t == *p && glob_match_chars(&text[1..], &pattern[1..]),
    }
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

    query
        .split_whitespace()
        .any(|word| word_matches_text(word, &name_lower) || word_matches_text(word, &desc_lower))
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

/// Build a Code Mode search match JSON object.
///
/// Like [`build_match_json`] but optionally includes the full `input_schema`
/// so that the agent can immediately construct valid `gateway_execute` calls
/// without a separate schema-fetch step.
///
/// The tool reference format is `"server:tool_name"` — matching the
/// `gateway_execute` `"tool"` parameter convention.
pub(crate) fn build_code_mode_match_json(server: &str, tool: &Tool, include_schema: bool) -> Value {
    let description = tool
        .description
        .as_deref()
        .unwrap_or("")
        .chars()
        .take(500)
        .collect::<String>();

    let tool_ref = format!("{server}:{}", tool.name);

    if include_schema {
        json!({
            "tool": tool_ref,
            "description": description,
            "input_schema": tool.input_schema
        })
    } else {
        json!({
            "tool": tool_ref,
            "description": description
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
        "top_tools": snapshot.top_tools,
        "total_cached_tokens": snapshot.total_cached_tokens,
        "cached_tokens_by_server": snapshot.cached_tokens_by_server
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
#[path = "meta_mcp_helpers_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "meta_mcp_helpers_chain_tests.rs"]
mod chain_tests;
