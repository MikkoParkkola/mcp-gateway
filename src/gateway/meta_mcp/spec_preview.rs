//! Phase 3 spec-preview handlers — SEP-1821 filtered tools/list, SEP-1862 tools/resolve,
//! and dynamic tool promotion (§5.10).
//!
//! Every item in this file is compiled only when the `spec-preview` feature is
//! enabled.  This ensures zero leakage into default builds.

use serde_json::{Value, json};
use tracing::debug;

use crate::autotag;
use crate::protocol::{JsonRpcResponse, RequestId, Tool, ToolsListResult};

use super::super::meta_mcp_helpers::did_you_mean;
use super::MAX_PROMOTED_PER_SESSION;
use super::MetaMcp;

// ============================================================================
// SEP-1821: Filtered tools/list
// ============================================================================

impl MetaMcp {
    /// Handle `tools/list` with an optional `query` parameter (SEP-1821).
    ///
    /// When `query` is provided, runs keyword search across all backend caches
    /// and returns full `Tool` objects (with `inputSchema`) for all matches.
    /// The meta-tools are NOT included in filtered responses — only backend tools
    /// that match the query.
    ///
    /// This matches the expected SEP-1821 semantic: the client knows it wants
    /// backend tools and is narrowing the result set.
    ///
    /// When `query` is empty or blank, falls back to the standard tools/list.
    pub(super) fn handle_tools_list_filtered(
        &self,
        id: RequestId,
        query: &str,
        session_id: Option<&str>,
    ) -> JsonRpcResponse {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return self.handle_tools_list_for_session(id, session_id);
        }

        let profile = self.active_profile(session_id);
        let tools: Vec<Tool> = self.collect_filtered_backend_tools(&query, session_id, &profile);

        debug!(
            query = %query,
            count = tools.len(),
            "SEP-1821 filtered tools/list"
        );

        let result = ToolsListResult {
            tools,
            next_cursor: None,
        };
        JsonRpcResponse::success_serialized(id, result)
    }

    /// Collect all backend tools whose name or description contains `query`.
    ///
    /// Respects routing profile filtering.  Only backends with cached tools are
    /// searched (no blocking network calls).
    fn collect_filtered_backend_tools(
        &self,
        query: &str,
        session_id: Option<&str>,
        profile: &crate::routing_profile::RoutingProfile,
    ) -> Vec<Tool> {
        let mut tools = Vec::new();

        // Capability backend tools
        if let Some(cap) = self.get_capabilities()
            && profile.backend_allowed(&cap.name)
        {
            for t in cap.get_tools() {
                if profile.tool_allowed(&t.name) && tool_text_matches(&t, query) {
                    tools.push(t);
                }
            }
        }

        // MCP backend tools (cached only)
        for backend in self.backends.all() {
            if !backend.has_cached_tools() || !profile.backend_allowed(&backend.name) {
                continue;
            }
            let cache_guard = backend.get_cached_tools_snapshot();
            for tool in cache_guard.iter() {
                let mut t = tool.clone();
                if !profile.tool_allowed(&t.name) {
                    continue;
                }
                // Enrich description with auto-tags before matching
                if let Some(ref desc) = t.description {
                    t.description = Some(autotag::enrich_description(desc));
                }
                if tool_text_matches(&t, query) {
                    tools.push(t);
                }
            }
        }

        // Include session-promoted tools that match the query and aren't already listed
        let promoted = self.promoted_tools_for_session(session_id);
        for t in promoted {
            let already = tools.iter().any(|x| x.name == t.name);
            if !already && tool_text_matches(&t, query) {
                tools.push(t);
            }
        }

        tools
    }
}

// ============================================================================
// SEP-1862: tools/resolve
// ============================================================================

impl MetaMcp {
    /// Handle `tools/resolve` — return the full `Tool` with `inputSchema` for a given name.
    ///
    /// Searches the capability backend and all MCP backend caches.  Returns a
    /// JSON-RPC error when the tool is not found in any cache, with a "did you mean?"
    /// suggestion when the name is a close misspelling of a known tool.
    pub async fn handle_tools_resolve(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let tool_name = params.and_then(|p| p.get("name")).and_then(Value::as_str);

        let Some(name) = tool_name else {
            return JsonRpcResponse::error(
                Some(id),
                -32602,
                "tools/resolve requires a 'name' parameter".to_string(),
            );
        };

        if let Some(tool) = self.resolve_tool_by_name(name) {
            let result = json!({ "tool": tool });
            JsonRpcResponse::success(id, result)
        } else {
            let msg = self.build_tool_not_found_message(name);
            JsonRpcResponse::error(Some(id), -32601, msg)
        }
    }

    /// Find a `Tool` by exact name across all backend caches.
    ///
    /// Checks the capability backend first, then MCP backends in registry order.
    /// Returns `None` when the tool is not cached on any backend.
    fn resolve_tool_by_name(&self, name: &str) -> Option<Tool> {
        // Check capability backend
        if let Some(cap) = self.get_capabilities() {
            let found = cap.get_tools().into_iter().find(|t| t.name == name);
            if found.is_some() {
                return found;
            }
        }

        // Check MCP backends
        for backend in self.backends.all() {
            if let Some(tool) = backend.get_cached_tool(name) {
                return Some(tool);
            }
        }

        None
    }

    /// Build a "not found" error message, optionally including Levenshtein suggestions.
    fn build_tool_not_found_message(&self, name: &str) -> String {
        let all_names: Vec<String> = self.collect_all_cached_tool_names();
        let candidates: Vec<&str> = all_names.iter().map(String::as_str).collect();

        match did_you_mean(name, &candidates, 3, 3) {
            Some(hint) => format!("Tool '{name}' not found. {hint}"),
            None => format!("Tool '{name}' not found in any backend cache"),
        }
    }

    /// Collect tool names from every cached backend (for suggestions).
    fn collect_all_cached_tool_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if let Some(cap) = self.get_capabilities() {
            names.extend(cap.get_tools().into_iter().map(|t| t.name));
        }
        for backend in self.backends.all() {
            names.extend(backend.get_cached_tool_names());
        }
        names
    }
}

// ============================================================================
// Dynamic promotion (§5.10)
// ============================================================================

impl MetaMcp {
    /// Promote a tool to the session-scoped surfaced set after a successful invocation.
    ///
    /// Called from the `invoke_tool_traced` success path.  Idempotent: re-invoking
    /// an already-promoted tool does not duplicate the entry.  When the session's
    /// promoted list is full (≥ `MAX_PROMOTED_PER_SESSION`), the oldest entry is
    /// evicted (FIFO) to make room.
    ///
    /// The `tool_key` must be formatted as `"server:tool_name"`.
    pub(super) fn promote_tool_for_session(&self, session_id: &str, tool_key: &str) {
        let mut entry = self
            .session_promoted
            .entry(session_id.to_string())
            .or_default();

        // Idempotency: skip if already promoted
        if entry.iter().any(|k| k == tool_key) {
            return;
        }

        // Evict oldest when at capacity (FIFO)
        if entry.len() >= MAX_PROMOTED_PER_SESSION {
            entry.remove(0);
        }

        entry.push(tool_key.to_string());
        debug!(
            session_id,
            tool_key, "Promoted tool to session surfaced set"
        );
    }
}

// ============================================================================
// Private helpers
// ============================================================================

/// Return `true` when `query` appears in the tool's name or description (case-insensitive).
fn tool_text_matches(tool: &Tool, query: &str) -> bool {
    if tool.name.to_lowercase().contains(query) {
        return true;
    }
    tool.description
        .as_deref()
        .is_some_and(|d| d.to_lowercase().contains(query))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use crate::backend::BackendRegistry;
    use crate::gateway::meta_mcp::MAX_PROMOTED_PER_SESSION;
    use crate::protocol::{RequestId, Tool};

    use super::super::MetaMcp;

    fn meta() -> MetaMcp {
        MetaMcp::new(Arc::new(BackendRegistry::new()))
    }

    // ── tool_text_matches ──────────────────────────────────────────────────

    #[test]
    fn tool_text_matches_name_substring() {
        // GIVEN: tool whose name contains the query
        let tool = Tool {
            name: "brave_web_search".to_string(),
            title: None,
            description: None,
            input_schema: json!({}),
            output_schema: None,
            annotations: None,
        };
        // WHEN: query is a substring of the name
        // THEN: match
        assert!(super::tool_text_matches(&tool, "web"));
    }

    #[test]
    fn tool_text_matches_description_substring() {
        // GIVEN: tool whose description contains the query
        let tool = Tool {
            name: "my_tool".to_string(),
            title: None,
            description: Some("Searches the internet using Brave Search".to_string()),
            input_schema: json!({}),
            output_schema: None,
            annotations: None,
        };
        // WHEN: query matches description word
        // THEN: match
        assert!(super::tool_text_matches(&tool, "brave"));
    }

    #[test]
    fn tool_text_matches_no_match_returns_false() {
        // GIVEN: tool with unrelated name and description
        let tool = Tool {
            name: "email_send".to_string(),
            title: None,
            description: Some("Send an email".to_string()),
            input_schema: json!({}),
            output_schema: None,
            annotations: None,
        };
        // WHEN: query doesn't match anything
        // THEN: no match
        assert!(!super::tool_text_matches(&tool, "calendar"));
    }

    #[test]
    fn tool_text_matches_case_insensitive() {
        // GIVEN: tool name is uppercase
        let tool = Tool {
            name: "BRAVE_SEARCH".to_string(),
            title: None,
            description: None,
            input_schema: json!({}),
            output_schema: None,
            annotations: None,
        };
        // WHEN: query is lowercase
        // THEN: case-insensitive match
        assert!(super::tool_text_matches(&tool, "brave"));
    }

    // ── handle_tools_list_filtered (empty registry) ────────────────────────

    #[test]
    fn handle_tools_list_filtered_empty_query_falls_back_to_standard() {
        // GIVEN: MetaMcp with no backends and an empty query
        let m = meta();
        // WHEN: filtered list is called with blank query
        let resp = m.handle_tools_list_filtered(RequestId::Number(1), "  ", None);
        // THEN: no error, returns the standard meta-tool list
        assert!(resp.error.is_none());
        let tools = resp.result.unwrap()["tools"].as_array().unwrap().len();
        // Standard list has >0 tools (meta-tools)
        assert!(tools > 0);
    }

    #[test]
    fn handle_tools_list_filtered_non_empty_query_returns_empty_for_empty_backends() {
        // GIVEN: MetaMcp with no backends
        let m = meta();
        // WHEN: filtered list is called with a real query
        let resp = m.handle_tools_list_filtered(RequestId::Number(2), "search", None);
        // THEN: no error, zero tools (no backends cached)
        assert!(resp.error.is_none());
        let tools = resp.result.unwrap()["tools"].as_array().unwrap().len();
        assert_eq!(tools, 0);
    }

    // ── handle_tools_list_with_params ──────────────────────────────────────

    #[test]
    fn handle_tools_list_with_params_no_query_uses_standard_path() {
        // GIVEN: no query in params
        let m = meta();
        let resp = m.handle_tools_list_with_params(RequestId::Number(3), None, None);
        // THEN: returns standard tools/list (meta-tools present)
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let names: Vec<_> = result["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&"gateway_invoke"));
    }

    #[test]
    fn handle_tools_list_with_params_with_query_uses_filtered_path() {
        // GIVEN: query param present
        let m = meta();
        let params = json!({ "query": "totally_nonexistent_xyz" });
        let resp = m.handle_tools_list_with_params(RequestId::Number(4), Some(&params), None);
        // THEN: no error, no meta-tools returned (filtered path, no backends)
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let names: Vec<_> = result["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        // gateway_invoke must NOT appear — filtered list excludes meta-tools
        assert!(!names.contains(&"gateway_invoke"));
    }

    // ── handle_tools_resolve ───────────────────────────────────────────────

    #[tokio::test]
    async fn handle_tools_resolve_missing_name_returns_error() {
        // GIVEN: params without 'name'
        let m = meta();
        let resp = m.handle_tools_resolve(RequestId::Number(5), None).await;
        // THEN: JSON-RPC error -32602
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn handle_tools_resolve_unknown_tool_returns_not_found_error() {
        // GIVEN: params with a name that doesn't exist in any backend
        let m = meta();
        let params = json!({ "name": "nonexistent_tool_xyz" });
        let resp = m
            .handle_tools_resolve(RequestId::Number(6), Some(&params))
            .await;
        // THEN: JSON-RPC error -32601 with descriptive message
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert!(
            err.message.contains("not found"),
            "Expected 'not found' in: {}",
            err.message
        );
    }

    // ── dynamic promotion ─────────────────────────────────────────────────

    #[test]
    fn promote_tool_for_session_adds_to_session_map() {
        // GIVEN: MetaMcp and a session
        let m = meta();
        // WHEN: a tool is promoted
        m.promote_tool_for_session("sess-1", "brave:brave_web_search");
        // THEN: session_promoted contains the key
        let entry = m.session_promoted.get("sess-1").unwrap();
        assert!(entry.contains(&"brave:brave_web_search".to_string()));
    }

    #[test]
    fn promote_tool_for_session_is_idempotent() {
        // GIVEN: MetaMcp
        let m = meta();
        // WHEN: same tool promoted twice
        m.promote_tool_for_session("sess-2", "ecb:exchange_rates");
        m.promote_tool_for_session("sess-2", "ecb:exchange_rates");
        // THEN: only one entry stored
        let entry = m.session_promoted.get("sess-2").unwrap();
        assert_eq!(entry.len(), 1);
    }

    #[test]
    fn promote_tool_evicts_oldest_when_at_capacity() {
        // GIVEN: session already at MAX_PROMOTED_PER_SESSION
        let m = meta();
        for i in 0..MAX_PROMOTED_PER_SESSION {
            m.promote_tool_for_session("sess-3", &format!("server:tool_{i}"));
        }
        // WHEN: one more promotion
        m.promote_tool_for_session("sess-3", "server:new_tool");
        // THEN: total stays at MAX_PROMOTED_PER_SESSION and oldest is gone
        let entry = m.session_promoted.get("sess-3").unwrap();
        assert_eq!(entry.len(), MAX_PROMOTED_PER_SESSION);
        assert!(
            !entry.contains(&"server:tool_0".to_string()),
            "oldest should be evicted"
        );
        assert!(
            entry.contains(&"server:new_tool".to_string()),
            "new tool should be present"
        );
    }

    #[test]
    fn clear_session_promoted_removes_session_entry() {
        // GIVEN: session with promoted tools
        let m = meta();
        m.promote_tool_for_session("sess-4", "brave:brave_web_search");
        // WHEN: clear is called
        m.clear_session_promoted("sess-4");
        // THEN: session is gone
        assert!(m.session_promoted.get("sess-4").is_none());
    }

    #[test]
    fn promoted_tools_for_session_returns_empty_for_unknown_session() {
        // GIVEN: no promotions
        let m = meta();
        // WHEN: querying an unknown session
        let tools = m.promoted_tools_for_session(Some("unknown-session"));
        // THEN: empty vec
        assert!(tools.is_empty());
    }

    #[test]
    fn promoted_tools_for_session_returns_empty_for_none() {
        // GIVEN: MetaMcp
        let m = meta();
        // WHEN: session_id is None
        let tools = m.promoted_tools_for_session(None);
        // THEN: empty vec
        assert!(tools.is_empty());
    }

    // ── feature-gate: capabilities advertised when feature enabled ─────────

    #[test]
    fn build_initialize_result_advertises_filtering_and_resolve_capabilities() {
        // GIVEN: MetaMcp (spec-preview feature is enabled in this test build)
        let m = meta();
        let resp = m.handle_initialize(RequestId::Number(99), None, None, None);
        // THEN: capabilities.tools.filtering = true and resolve = true
        let result = resp.result.unwrap();
        let filtering = &result["capabilities"]["tools"]["filtering"];
        let resolve = &result["capabilities"]["tools"]["resolve"];
        assert_eq!(
            filtering,
            &serde_json::json!(true),
            "filtering capability must be true"
        );
        assert_eq!(
            resolve,
            &serde_json::json!(true),
            "resolve capability must be true"
        );
    }
}
