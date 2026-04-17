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
    Some(crate::ranking::SearchResult {
        server,
        tool: tool_name.to_string(),
        description,
        score: 0.0,
    })
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
        let args = json!({
            "server": server,
            "tool": tool,
            "arguments": arguments
        });
        // Playbook steps are internal invocations with no caller agent.
        self.meta.invoke_tool(&args, None, None, None).await
    }
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
