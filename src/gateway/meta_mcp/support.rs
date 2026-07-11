// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Standalone helpers and the `ToolInvoker` bridge for `MetaMcp`.
//!
//! Contains idempotency key resolution, tag collection, Code Mode result
//! conversion, the `MetaMcpInvoker` bridge, and response augmentation.

use serde_json::{Value, json};

use crate::Result;
use crate::idempotency::{IdempotencyCache, derive_key};
use crate::playbook::ToolInvoker;

use super::super::meta_mcp_helpers::extract_optional_str;
use super::MetaMcp;

// ============================================================================
// Idempotency
// ============================================================================

/// Resolve the idempotency key for a `gateway_invoke` call.
///
/// Priority:
/// 1. Explicit `"idempotency_key"` string in `args` — used verbatim.
/// 2. Auto-derived from `(server, tool, arguments)` when an `IdempotencyCache`
///    is active.  This protects against exact-duplicate LLM retries even when
///    the client supplies no key.
///
/// Returns `None` when no idempotency cache is configured.
pub(super) fn resolve_idempotency_key(
    args: &Value,
    server: &str,
    tool: &str,
    arguments: &Value,
    idem_cache: Option<&std::sync::Arc<IdempotencyCache>>,
) -> Option<String> {
    idem_cache?;
    // Explicit key takes precedence.
    if let Some(key) = extract_optional_str(args, "idempotency_key") {
        return Some(key.to_string());
    }
    // Auto-derive from (server, tool, arguments) — stable, deterministic.
    let combined = format!("{server}:{tool}");
    Some(derive_key(&combined, arguments))
}

// ============================================================================
// Tag collection
// ============================================================================

/// Extract keyword tags from a tool's description into `out`.
///
/// Tags are parsed from the `[keywords: tag1, tag2, ...]` suffix appended by
/// `CapabilityDefinition::to_mcp_tool()`. Tags are lowercased and hyphen-split
/// parts are also collected so both "entity-discovery" and "entity" are indexed.
pub(super) fn collect_tool_tags(tool: &crate::protocol::Tool, out: &mut Vec<String>) {
    let Some(desc) = tool.description.as_deref() else {
        return;
    };
    let Some(kw_start) = desc.find("[keywords:") else {
        return;
    };
    let section = &desc[kw_start..];
    let inner = section
        .trim_start_matches("[keywords:")
        .trim_end_matches(']');
    for tag in inner.split(',') {
        let tag = tag.trim().to_lowercase();
        if !tag.is_empty() {
            // Also push hyphen-split parts (e.g. "entity-discovery" → "entity", "discovery")
            for part in tag.split('-') {
                let part = part.trim();
                if !part.is_empty() {
                    out.push(part.to_string());
                }
            }
            out.push(tag);
        }
    }
}

/// Tag collector for Code Mode search (alias; delegates to the existing implementation).
///
/// Exists so that `code_mode_search` can call a descriptively named function without
/// duplicating the tag-parsing logic from `collect_tool_tags`.
pub(super) fn collect_tool_tags_for_code_mode(tool: &crate::protocol::Tool, out: &mut Vec<String>) {
    collect_tool_tags(tool, out);
}

// ============================================================================
// Code Mode JSON conversion
// ============================================================================

/// Convert a Code Mode search result JSON object into a [`crate::ranking::SearchResult`].
///
/// Code Mode matches use `"tool": "server:name"` format; this function splits
/// on the first `:` to recover server and `tool_name` for the ranker.
pub(super) fn json_to_code_mode_search_result(v: &Value) -> Option<crate::ranking::SearchResult> {
    use crate::gateway::meta_mcp_helpers::parse_code_mode_tool_ref;
    let tool_ref = v.get("tool")?.as_str()?;
    let description = v.get("description")?.as_str().unwrap_or("").to_string();
    let (tool_name, server_opt) = parse_code_mode_tool_ref(tool_ref);
    let server = server_opt?.to_string();
    let mut result = crate::ranking::SearchResult::new(server, tool_name, description);
    result.signals = crate::ranking::RankingSignals::from_json(v);
    Some(result)
}

/// Reconstruct ranked Code Mode results from ranked `SearchResult` objects.
///
/// After ranking, the schema must be re-fetched from the original matches list
/// (the ranker only carries name/description/score). This function rebuilds each
/// match JSON by looking up the original entry by its `"tool"` field.
pub(super) fn ranked_results_to_code_mode_json(
    ranked: Vec<crate::ranking::SearchResult>,
    _include_schema: bool,
    originals: &[Value],
) -> Vec<Value> {
    ranked
        .into_iter()
        .filter_map(|r| {
            let tool_ref = format!("{}:{}", r.server, r.tool);
            // Find the original entry to preserve the schema field
            originals
                .iter()
                .find(|v| v.get("tool").and_then(Value::as_str) == Some(&tool_ref))
                .cloned()
                .map(|mut value| {
                    if let Value::Object(ref mut map) = value {
                        map.insert("score".to_string(), json!(r.score));
                        map.insert(
                            "ranking".to_string(),
                            json!({
                                "included": r.explanation.included,
                                "reasons": r.explanation.reasons,
                                "signals": r.signals
                            }),
                        );
                    }
                    value
                })
        })
        .collect()
}

// ============================================================================
// ToolInvoker bridge
// ============================================================================

/// Bridges `MetaMcp::invoke_tool` to the `ToolInvoker` trait for playbook execution.
pub(super) struct MetaMcpInvoker<'a> {
    pub(super) meta: &'a MetaMcp,
}

#[async_trait::async_trait]
impl ToolInvoker for MetaMcpInvoker<'_> {
    async fn invoke(&self, server: &str, tool: &str, arguments: Value) -> Result<Value> {
        let args = internal_invoke_args(server, tool, arguments);
        // Playbook steps are internal invocations with no caller agent.
        self.meta
            .invoke_tool(&args, None, None, None, None, None)
            .await
    }
}

/// Build the `invoke_tool` argument envelope for an internal (chain / playbook)
/// invocation.
///
/// Internal orchestration consumes the raw backend payload: steps reference
/// prior outputs by their original field paths (`$step.issue.id`). Canonical
/// projection (MIK-3534) is a client-presentation layer that would move those
/// fields under `_raw` and silently break interpolation, so internal calls opt
/// out via `_full`.
///
/// The directive is read (and stripped) from INSIDE the `arguments` map by
/// `invoke_tool_traced`, so it MUST be injected there — placing it as an outer
/// sibling of `arguments` leaves it invisible to `want_full`. Non-object
/// arguments are passed through unchanged (no data loss).
fn internal_invoke_args(server: &str, tool: &str, arguments: Value) -> Value {
    let arguments = match arguments {
        Value::Object(mut map) => {
            map.insert("_full".to_string(), Value::Bool(true));
            Value::Object(map)
        }
        other => other,
    };
    json!({
        "server": server,
        "tool": tool,
        "arguments": arguments
    })
}

// ============================================================================
// Response augmentation
// ============================================================================

/// Attach `predicted_next` to an invoke result when predictions are available.
///
/// If `predictions` is empty the original `result` is returned unchanged,
/// preserving the zero-cost fast path for sessions without enough history.
pub(super) fn augment_with_predictions(mut result: Value, predictions: Vec<Value>) -> Value {
    if predictions.is_empty() {
        return result;
    }
    if let Value::Object(ref mut map) = result {
        map.insert("predicted_next".to_string(), Value::Array(predictions));
    }
    result
}

/// Attach `trace_id` to an invoke result so callers can correlate gateway logs
/// with backend logs.
///
/// The `trace_id` is always inserted; this function never returns the original
/// `result` unmodified (the contract guarantees the field is present).
pub(super) fn augment_with_trace(mut result: Value, trace_id: &str) -> Value {
    if let Value::Object(ref mut map) = result {
        map.insert("trace_id".to_string(), json!(trace_id));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::internal_invoke_args;
    use serde_json::json;

    /// The projection opt-out (`_full`) for internal chain/playbook invocations
    /// MUST live INSIDE `arguments` — that is where `invoke_tool_traced` reads
    /// `want_full`. Placing it as an outer sibling (the original bug) left it
    /// invisible and projection still ran on chain step outputs, breaking
    /// `$step.field` interpolation. This guards that nesting.
    #[test]
    fn internal_invoke_args_injects_full_inside_arguments() {
        let args = internal_invoke_args("linear", "create_issue", json!({"title": "x"}));
        assert_eq!(
            args["arguments"]["_full"],
            json!(true),
            "_full must be inside arguments where want_full is read"
        );
        assert_eq!(
            args["arguments"]["title"],
            json!("x"),
            "caller args preserved"
        );
        assert_eq!(args["server"], json!("linear"));
        assert_eq!(args["tool"], json!("create_issue"));
        assert!(
            args.get("_full").is_none(),
            "_full must NOT be an outer sibling (would be ignored by want_full)"
        );
    }

    /// Non-object arguments pass through unchanged — no data loss, no panic.
    #[test]
    fn internal_invoke_args_preserves_non_object_arguments() {
        let args = internal_invoke_args("s", "t", json!("scalar"));
        assert_eq!(args["arguments"], json!("scalar"));
    }
}
