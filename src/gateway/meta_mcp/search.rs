//! Tool search and listing handlers.
//!
//! Implements `gateway_search` (Code Mode), `gateway_execute` (Code Mode),
//! `gateway_list_tools`, `gateway_search_tools`, and the chain executor.

use std::sync::Arc;

use serde_json::{Value, json};
use tracing::debug;

use crate::autotag;
use crate::backend::Backend;
use crate::projection::Role;
use crate::protocol::Tool;
use crate::ranking::json_to_search_result;
use crate::routing_profile::RoutingProfile;
use crate::{Error, Result};

use super::super::differential::annotate_differential;
use super::super::meta_mcp_helpers::{
    build_code_mode_match_json, build_match_json, build_match_json_with_chains,
    build_search_response, build_suggestions, extract_bool_or, extract_optional_str,
    extract_required_str, extract_search_limit, is_glob_pattern, parse_code_mode_tool_ref,
    parse_tool_arguments, ranked_results_to_json, tool_matches_glob, tool_matches_query,
    tool_name_matches_glob,
};
use super::MetaMcp;
use super::support::{
    collect_tool_tags, collect_tool_tags_for_code_mode, json_to_code_mode_search_result,
    ranked_results_to_code_mode_json,
};

#[derive(Clone, Copy)]
struct CodeModeSearchOptions {
    include_schema: bool,
    use_glob: bool,
}

/// Infer a tool's role from its name and annotations when it carries no explicit
/// `role` tag (MIK-3532). Conservative: only read-only tools whose name clearly
/// signals selection or extraction are tagged as such; everything else defaults
/// to [`Role::Action`] (the safe assumption — a tool may have side effects).
fn infer_role(tool: &Tool) -> Role {
    let read_only = tool
        .annotations
        .as_ref()
        .and_then(|a| a.read_only_hint)
        .unwrap_or(false);
    if !read_only {
        return Role::Action;
    }
    let name = tool.name.to_ascii_lowercase();
    let is = |needles: &[&str]| needles.iter().any(|n| name.contains(n));
    if is(&["search", "list", "find", "query", "discover", "browse"]) {
        Role::Selector
    } else if is(&[
        "get", "read", "fetch", "show", "describe", "inspect", "view",
    ]) {
        Role::Extractor
    } else {
        // Read-only but not obviously selector/extractor: treat as an extractor
        // rather than an action.
        Role::Extractor
    }
}

/// A tool's effective role: its explicit tag if present, otherwise inferred.
fn effective_role(tool: &Tool) -> Role {
    tool.role.unwrap_or_else(|| infer_role(tool))
}

/// Whether `tool` matches the optionally-requested role. `None` matches every
/// tool (no filter).
fn tool_matches_role(tool: &Tool, want: Option<Role>) -> bool {
    want.is_none_or(|r| effective_role(tool) == r)
}

/// Parse a role filter argument (case-insensitive). Absent / null means no
/// filter; a typo or a non-string value is rejected so it fails fast rather
/// than silently returning everything.
fn parse_role_filter(args: &Value) -> Result<Option<Role>> {
    match args.get("role") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "selector" => Ok(Some(Role::Selector)),
            "extractor" => Ok(Some(Role::Extractor)),
            "enricher" => Ok(Some(Role::Enricher)),
            "action" => Ok(Some(Role::Action)),
            bad => Err(Error::Protocol(format!(
                "Invalid role filter '{bad}' (expected selector|extractor|enricher|action)"
            ))),
        },
        Some(_) => Err(Error::Protocol(
            "role filter must be a string (selector|extractor|enricher|action)".to_string(),
        )),
    }
}

impl MetaMcp {
    async fn backend_tools_for_discovery(
        backend: &Arc<Backend>,
        allow_empty_cache_fetch: bool,
    ) -> Option<Arc<Vec<Tool>>> {
        let tools = backend.get_cached_tools_snapshot();
        if !tools.is_empty() {
            Self::refresh_stale_backend_tools_in_background(backend);
            return Some(tools);
        }

        if allow_empty_cache_fetch {
            return match backend.get_tools_shared().await {
                Ok(tools) if !tools.is_empty() => Some(tools),
                Ok(_) => None,
                Err(e) => {
                    debug!(
                        backend = %backend.name,
                        error = %e,
                        "On-demand backend tool-cache fill failed"
                    );
                    None
                }
            };
        }

        None
    }

    fn code_mode_backend_candidates(&self, query: &str) -> (Vec<Arc<Backend>>, bool) {
        if let Some((server, _)) = query.split_once(':')
            && !server.is_empty()
            && !server.contains('*')
            && !server.contains('?')
        {
            return self
                .backends
                .get(server)
                .map_or_else(|| (Vec::new(), false), |backend| (vec![backend], true));
        }

        (self.backends.all(), false)
    }

    async fn refresh_stale_backend_tools(backend: Arc<Backend>) {
        if let Err(e) = backend.get_tools_shared().await {
            debug!(
                backend = %backend.name,
                error = %e,
                "Background backend tool-cache refresh failed"
            );
        }
    }

    fn refresh_stale_backend_tools_in_background(backend: &Arc<Backend>) {
        if !backend.has_cached_tools() {
            let backend = Arc::clone(backend);
            tokio::spawn(Self::refresh_stale_backend_tools(backend));
        }
    }

    fn current_search_state(&self, session_id: Option<&str>) -> String {
        session_id.map_or_else(
            || crate::gateway::state::DEFAULT_STATE.to_string(),
            |sid| self.session_state.get_state(sid),
        )
    }

    fn code_mode_tool_matches(
        server: &str,
        tool: &crate::protocol::Tool,
        query: &str,
        use_glob: bool,
    ) -> bool {
        let tool_ref = format!("{server}:{}", tool.name).to_lowercase();
        if use_glob {
            tool_matches_glob(tool, query) || tool_name_matches_glob(&tool_ref, query)
        } else {
            tool_matches_query(tool, query) || tool_ref.contains(query)
        }
    }

    fn collect_code_mode_capability_matches(
        &self,
        query: &str,
        current_state: &str,
        profile: &RoutingProfile,
        options: CodeModeSearchOptions,
        matches: &mut Vec<Value>,
        all_tags: &mut Vec<String>,
    ) {
        if let Some(cap) = self.get_capabilities()
            && profile.backend_allowed(&cap.name)
        {
            let cap_killed = self.kill_switch.is_killed(&cap.name);
            for capability in cap.list_capabilities() {
                if !capability.visible_in_states.is_empty()
                    && !capability
                        .visible_in_states
                        .iter()
                        .any(|s| s == current_state)
                {
                    continue;
                }
                let tool = capability.to_mcp_tool();
                if !profile.tool_allowed(&tool.name) {
                    continue;
                }
                collect_tool_tags_for_code_mode(&tool, all_tags);
                if Self::code_mode_tool_matches(&cap.name, &tool, query, options.use_glob) {
                    let mut entry =
                        build_code_mode_match_json(&cap.name, &tool, options.include_schema);
                    if cap_killed {
                        entry["status"] = json!("disabled");
                    }
                    matches.push(entry);
                }
            }
        }
    }

    async fn collect_code_mode_backend_matches(
        &self,
        query: &str,
        profile: &RoutingProfile,
        options: CodeModeSearchOptions,
        matches: &mut Vec<Value>,
        all_tags: &mut Vec<String>,
    ) {
        let (backends, allow_empty_cache_fetch) = self.code_mode_backend_candidates(query);
        for backend in backends {
            if !profile.backend_allowed(&backend.name) {
                continue;
            }
            // INV-2 (ADR-008, MIK-6742): never cold-fetch or serve an isolated
            // backend's tool metadata via the static gateway OAuth token on a
            // multi-user gateway. Skip BEFORE backend_tools_for_discovery so the
            // guard precedes any network round-trip (fail-closed = omit).
            if self.meta_route_isolation_refused(&backend) {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Some(tools) =
                Self::backend_tools_for_discovery(&backend, allow_empty_cache_fetch).await
            {
                let enriched: Vec<_> = tools
                    .iter()
                    .filter(|t| profile.tool_allowed(&t.name))
                    .map(|tool| {
                        let mut t = tool.clone();
                        if let Some(ref desc) = t.description {
                            t.description = Some(autotag::enrich_description(desc));
                        }
                        t
                    })
                    .collect();

                for tool in &enriched {
                    collect_tool_tags_for_code_mode(tool, all_tags);
                }
                for tool in enriched {
                    if Self::code_mode_tool_matches(&backend.name, &tool, query, options.use_glob) {
                        let mut entry = build_code_mode_match_json(
                            &backend.name,
                            &tool,
                            options.include_schema,
                        );
                        if backend_killed {
                            entry["status"] = json!("disabled");
                        }
                        matches.push(entry);
                    }
                }
            }
        }
    }

    fn collect_search_capability_matches(
        &self,
        query: &str,
        current_state: &str,
        profile: &RoutingProfile,
        matches: &mut Vec<Value>,
        all_tags: &mut Vec<String>,
    ) {
        if let Some(cap) = self.get_capabilities()
            && profile.backend_allowed(&cap.name)
        {
            let cap_killed = self.kill_switch.is_killed(&cap.name);
            for capability in cap.list_capabilities() {
                if !capability.visible_in_states.is_empty()
                    && !capability
                        .visible_in_states
                        .iter()
                        .any(|s| s == current_state)
                {
                    continue;
                }
                let tool = capability.to_mcp_tool();
                if !profile.tool_allowed(&tool.name) {
                    continue;
                }
                collect_tool_tags(&tool, all_tags);
                if tool_matches_query(&tool, query) {
                    let mut entry = build_match_json_with_chains(
                        &cap.name,
                        &tool,
                        &capability.metadata.chains_with,
                    );
                    if cap_killed {
                        entry["status"] = json!("disabled");
                    }
                    matches.push(entry);
                }
            }
        }
    }

    async fn collect_search_backend_matches(
        &self,
        query: &str,
        profile: &RoutingProfile,
        matches: &mut Vec<Value>,
        all_tags: &mut Vec<String>,
    ) {
        for backend in self.backends.all() {
            if !profile.backend_allowed(&backend.name) {
                continue;
            }
            // INV-2 (MIK-6742): omit isolated backends from tool discovery on a
            // multi-user gateway (fail-closed = omit, not leak).
            if self.meta_route_isolation_refused(&backend) {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Some(tools) = Self::backend_tools_for_discovery(&backend, false).await {
                let enriched: Vec<_> = tools
                    .iter()
                    .filter(|t| profile.tool_allowed(&t.name))
                    .map(|tool| {
                        let mut t = tool.clone();
                        if let Some(ref desc) = t.description {
                            t.description = Some(autotag::enrich_description(desc));
                        }
                        t
                    })
                    .collect();

                for tool in &enriched {
                    collect_tool_tags(tool, all_tags);
                }
                for tool in enriched {
                    if tool_matches_query(&tool, query) {
                        let mut entry = build_match_json(&backend.name, &tool);
                        if backend_killed {
                            entry["status"] = json!("disabled");
                        }
                        matches.push(entry);
                    }
                }
            }
        }
    }

    /// Handle `gateway_search` — Code Mode tool search with glob and schema support.
    ///
    /// Behaves like `search_tools` but:
    /// - Supports glob patterns (`*`, `?`) on tool names in addition to keyword matching.
    /// - Returns tool references in `"server:tool_name"` format (for use with `gateway_execute`).
    /// - Optionally includes the full `input_schema` for each result (`include_schema`, default `true`).
    pub(super) async fn code_mode_search(
        &self,
        args: &Value,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let raw_query = extract_required_str(args, "query")?;
        let query = raw_query.to_lowercase();
        let limit = extract_search_limit(args);
        let include_schema = extract_bool_or(args, "include_schema", true);
        let profile = self.active_profile(session_id);
        let use_glob = is_glob_pattern(&query);
        let current_state = self.current_search_state(session_id);
        let options = CodeModeSearchOptions {
            include_schema,
            use_glob,
        };

        let mut matches: Vec<Value> = Vec::new();
        let mut all_tags: Vec<String> = Vec::new();

        self.collect_code_mode_capability_matches(
            &query,
            &current_state,
            &profile,
            options,
            &mut matches,
            &mut all_tags,
        );
        self.collect_code_mode_backend_matches(
            &query,
            &profile,
            options,
            &mut matches,
            &mut all_tags,
        )
        .await;

        let total_found = matches.len();

        // Apply ranking for keyword queries (not glob — glob already filters precisely)
        if !use_glob && let Some(ref ranker) = self.ranker {
            let search_results: Vec<_> = matches
                .iter()
                .filter_map(json_to_code_mode_search_result)
                .collect();
            let ranked = ranker.rank(search_results, &query);
            matches = ranked_results_to_code_mode_json(ranked, include_schema, &matches);
        }

        matches.truncate(limit);

        let suggestions = if matches.is_empty() && !use_glob {
            build_suggestions(&query, &all_tags)
        } else {
            Vec::new()
        };

        Ok(build_search_response(
            &query,
            &matches,
            total_found,
            &suggestions,
        ))
    }

    /// Handle `gateway_execute` — Code Mode single-tool or chain execution.
    ///
    /// Single tool: requires `"tool"` (format `"server:tool_name"`) and optional
    /// `"arguments"`. Delegates to `invoke_tool` internally.
    ///
    /// Chain: requires `"chain"` array of `{tool, arguments}` objects. Each step
    /// is executed sequentially; results flow through naturally.
    pub(super) async fn code_mode_execute(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &super::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        // Chain mode: sequential execution
        if let Some(chain) = args.get("chain").and_then(Value::as_array) {
            return self.execute_chain(chain.clone(), session_id, caller).await;
        }

        // Single tool execution
        let tool_ref = extract_required_str(args, "tool")?;
        let (tool_name, server_opt) = parse_code_mode_tool_ref(tool_ref);

        let server = server_opt.ok_or_else(|| {
            Error::json_rpc(
                -32602,
                format!(
                    "Tool reference '{tool_ref}' is missing server prefix. \
                     Use format 'server:tool_name' from gateway_search results."
                ),
            )
        })?;

        let arguments = parse_tool_arguments(args)?;
        let invoke_args = json!({
            "server": server,
            "tool": tool_name,
            "arguments": arguments,
        });

        // Code Mode carries the caller's identity + attribution through to
        // dispatch, so an identity-required backend gets the per-user credential
        // just like the direct gateway_invoke path (MIK-6734).
        self.invoke_tool(
            &invoke_args,
            session_id,
            caller.api_key_name,
            caller.agent_id,
            caller.grant_subject.clone(),
            caller.verified_identity,
        )
        .await
    }

    /// Execute a sequential chain of `{tool, arguments}` steps.
    ///
    /// Returns a JSON array of per-step results. Stops at the first error
    /// and surfaces the failing step index in the error message.
    async fn execute_chain(
        &self,
        chain: Vec<Value>,
        session_id: Option<&str>,
        caller: &super::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        if chain.is_empty() {
            return Err(Error::json_rpc(-32602, "Chain must not be empty"));
        }

        let mut results: Vec<Value> = Vec::with_capacity(chain.len());

        for (idx, step) in chain.iter().enumerate() {
            let tool_ref = extract_optional_str(step, "tool").ok_or_else(|| {
                Error::json_rpc(-32602, format!("Chain step {idx}: missing 'tool' field"))
            })?;

            let (tool_name, server_opt) = parse_code_mode_tool_ref(tool_ref);
            let server = server_opt.ok_or_else(|| {
                Error::json_rpc(
                    -32602,
                    format!(
                        "Chain step {idx}: tool reference '{tool_ref}' is missing server prefix. \
                         Use format 'server:tool_name'."
                    ),
                )
            })?;

            let arguments = step.get("arguments").cloned().unwrap_or(json!({}));

            let invoke_args = json!({
                "server": server,
                "tool": tool_name,
                "arguments": arguments,
            });

            match self
                .invoke_tool(
                    &invoke_args,
                    session_id,
                    caller.api_key_name,
                    caller.agent_id,
                    caller.grant_subject.clone(),
                    caller.verified_identity,
                )
                .await
            {
                Ok(result) => results.push(json!({
                    "step": idx,
                    "tool": tool_ref,
                    "result": result,
                })),
                Err(e) => {
                    return Err(Error::json_rpc(
                        -32603,
                        format!("Chain step {idx} ({tool_ref}) failed: {e}"),
                    ));
                }
            }
        }

        Ok(json!({
            "steps": results.len(),
            "results": results,
        }))
    }

    /// List tools from a specific server, or ALL tools if server is omitted.
    ///
    /// Tools from killed servers are still returned but include `"status": "disabled"`
    /// so that the LLM knows the tool exists but cannot be invoked right now.
    ///
    /// Results are filtered by the session's active routing profile.
    /// Tools for a single named backend (the `server` argument of `gateway_list_tools`).
    /// Extracted from `list_tools` to keep both functions within the line budget.
    async fn list_tools_single_server(
        &self,
        server: &str,
        role_filter: Option<Role>,
        profile: &crate::routing_profile::RoutingProfile,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let killed = self.kill_switch.is_killed(server);

        // Backend-level profile check for single-server queries
        if !profile.backend_allowed(server) {
            return Err(Error::Protocol(format!(
                "Backend '{server}' is not available in the '{}' routing profile",
                profile.name
            )));
        }

        // Check if it's the capability backend
        if let Some(cap) = self.get_capabilities()
            && server == cap.name
        {
            let current_state = session_id.map_or_else(
                || crate::gateway::state::DEFAULT_STATE.to_string(),
                |sid| self.session_state.get_state(sid),
            );
            let tools: Vec<_> = cap
                .get_tools_for_state(&current_state)
                .into_iter()
                .filter(|t| profile.tool_allowed(&t.name) && tool_matches_role(t, role_filter))
                .collect();
            let mut out = json!({
                "server": server,
                "status": if killed { "disabled" } else { "active" },
                "tools": tools
            });
            self.scan_tool_list_value(&mut out);
            return Ok(out);
        }

        // Otherwise, look in MCP backends
        let backend = self
            .backends
            .get(server)
            .ok_or_else(|| Error::BackendNotFound(server.to_string()))?;

        // INV-2 (MIK-6742): an isolated backend must be indistinguishable from
        // absent on a multi-user gateway; refuse rather than fetch its
        // tools/list with the static gateway OAuth token.
        if self.meta_route_isolation_refused(&backend) {
            return Err(Error::BackendNotFound(server.to_string()));
        }

        let tools: Vec<_> = backend
            .get_tools()
            .await?
            .into_iter()
            .filter(|t| profile.tool_allowed(&t.name) && tool_matches_role(t, role_filter))
            .collect();

        let mut out = json!({
            "server": server,
            "status": if killed { "disabled" } else { "active" },
            "tools": tools
        });
        self.scan_tool_list_value(&mut out);
        Ok(out)
    }

    pub(super) async fn list_tools(&self, args: &Value, session_id: Option<&str>) -> Result<Value> {
        let profile = self.active_profile(session_id);
        // Optional role filter (MIK-3532): None = all tools; Some(role) keeps
        // only tools whose effective role (explicit tag, else inferred) matches.
        let role_filter = parse_role_filter(args)?;

        // If server is specified, return tools from that single backend (existing behavior)
        if let Some(server) = extract_optional_str(args, "server") {
            return self
                .list_tools_single_server(server, role_filter, &profile, session_id)
                .await;
        }

        // No server specified: aggregate ALL tools (fast — tools are prefetched at startup)
        let mut all_tools: Vec<Value> = Vec::new();

        // Capability tools (instant, in memory) — filtered by FSM state
        if let Some(cap) = self.get_capabilities()
            && profile.backend_allowed(&cap.name)
        {
            let current_state = session_id.map_or_else(
                || crate::gateway::state::DEFAULT_STATE.to_string(),
                |sid| self.session_state.get_state(sid),
            );
            let cap_killed = self.kill_switch.is_killed(&cap.name);
            for tool in cap.get_tools_for_state(&current_state) {
                if !profile.tool_allowed(&tool.name) || !tool_matches_role(&tool, role_filter) {
                    continue;
                }
                let mut entry = json!({
                    "server": cap.name,
                    "name": tool.name,
                    "description": tool.description.as_deref().unwrap_or("")
                });
                if cap_killed {
                    entry["status"] = json!("disabled");
                }
                all_tools.push(entry);
            }
        }

        // MCP backend tools use cached/warm-started snapshots. Stale non-empty
        // snapshots stay visible while a background refresh updates the cache.
        for backend in self.backends.all() {
            if !profile.backend_allowed(&backend.name) {
                continue;
            }
            // INV-2 (MIK-6742): omit isolated backends from tool discovery on a
            // multi-user gateway (fail-closed = omit, not leak).
            if self.meta_route_isolation_refused(&backend) {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Some(tools) = Self::backend_tools_for_discovery(&backend, false).await {
                for tool in tools.iter() {
                    if !profile.tool_allowed(&tool.name) || !tool_matches_role(tool, role_filter) {
                        continue;
                    }
                    let desc =
                        autotag::enrich_description(tool.description.as_deref().unwrap_or(""));
                    let mut entry = json!({
                        "server": &backend.name,
                        "name": &tool.name,
                        "description": desc
                    });
                    if backend_killed {
                        entry["status"] = json!("disabled");
                    }
                    all_tools.push(entry);
                }
            }
        }

        let mut out = json!({
            "tools": all_tools,
            "total": all_tools.len()
        });
        self.scan_tool_list_value(&mut out);
        Ok(out)
    }

    /// Search tools across all backends.
    ///
    /// Capability tools are searched exhaustively (fast, local). MCP backends
    /// with cached tools are also searched exhaustively. All matches are
    /// collected first, ranked, and THEN truncated to the requested limit.
    /// This ensures the best matches always surface regardless of iteration order.
    ///
    /// When zero matches are found, keyword tags from all backends are collected
    /// and used to generate related query suggestions.
    ///
    /// Results are filtered by the session's active routing profile.
    pub(super) async fn search_tools(
        &self,
        args: &Value,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let query = extract_required_str(args, "query")?.to_lowercase();
        let limit = extract_search_limit(args);
        let profile = self.active_profile(session_id);
        let search_start = std::time::Instant::now();
        let current_state = self.current_search_state(session_id);

        let mut matches = Vec::new();
        // Collect all available tags for suggestion generation (only used on zero-result queries).
        let mut all_tags: Vec<String> = Vec::new();

        self.collect_search_capability_matches(
            &query,
            &current_state,
            &profile,
            &mut matches,
            &mut all_tags,
        );
        self.collect_search_backend_matches(&query, &profile, &mut matches, &mut all_tags)
            .await;

        let total_found = matches.len();

        // Record search stats
        if let Some(ref stats) = self.stats {
            #[allow(clippy::cast_possible_truncation)]
            stats.record_search(total_found as u64);
        }
        telemetry_metrics::counter!("mcp_search_total").increment(1);
        telemetry_metrics::histogram!("mcp_search_duration_seconds")
            .record(search_start.elapsed().as_secs_f64());

        // Apply ranking if enabled, then truncate to limit
        if let Some(ref ranker) = self.ranker {
            let search_results: Vec<_> = matches.iter().filter_map(json_to_search_result).collect();
            let ranked = ranker.rank(search_results, &query);
            matches = ranked_results_to_json(ranked);
        }

        // Truncate to requested limit AFTER ranking
        matches.truncate(limit);

        // Annotate tool families with differential descriptions so LLMs can
        // distinguish siblings (e.g. gmail_search vs gmail_send vs gmail_batch_modify).
        annotate_differential(&mut matches);

        // Build suggestions only when no results were found
        let suggestions = if matches.is_empty() {
            build_suggestions(&query, &all_tags)
        } else {
            Vec::new()
        };

        let mut out = build_search_response(&query, &matches, total_found, &suggestions);
        self.scan_tool_list_value(&mut out);
        Ok(out)
    }
}

#[cfg(test)]
mod role_filter_tests {
    use super::{effective_role, infer_role, parse_role_filter, tool_matches_role};
    use crate::projection::Role;
    use crate::protocol::{Tool, ToolAnnotations};
    use serde_json::json;

    fn tool(name: &str, read_only: Option<bool>, role: Option<Role>) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: None,
            annotations: read_only.map(|ro| ToolAnnotations {
                read_only_hint: Some(ro),
                ..Default::default()
            }),
            role,
            projection: None,
        }
    }

    #[test]
    fn infer_role_from_name_and_readonly() {
        assert_eq!(
            infer_role(&tool("search_issues", Some(true), None)),
            Role::Selector
        );
        assert_eq!(
            infer_role(&tool("list_repos", Some(true), None)),
            Role::Selector
        );
        assert_eq!(
            infer_role(&tool("get_issue", Some(true), None)),
            Role::Extractor
        );
        assert_eq!(
            infer_role(&tool("read_file", Some(true), None)),
            Role::Extractor
        );
        // read-only but unclear name -> extractor (still not an action)
        assert_eq!(
            infer_role(&tool("weather", Some(true), None)),
            Role::Extractor
        );
        // not read-only -> action regardless of name
        assert_eq!(
            infer_role(&tool("search_and_delete", Some(false), None)),
            Role::Action
        );
        // no annotations -> action (safe default)
        assert_eq!(infer_role(&tool("mystery", None, None)), Role::Action);
    }

    #[test]
    fn effective_role_prefers_explicit_tag_over_inference() {
        // A tool named "search" but explicitly tagged Action stays Action.
        let t = tool("search_x", Some(true), Some(Role::Action));
        assert_eq!(effective_role(&t), Role::Action);
    }

    #[test]
    fn tool_matches_role_filter() {
        let selector = tool("search_x", Some(true), None);
        let action = tool("create_x", Some(false), None);
        // None = no filter, matches everything
        assert!(tool_matches_role(&selector, None));
        assert!(tool_matches_role(&action, None));
        // Some filters by effective role
        assert!(tool_matches_role(&selector, Some(Role::Selector)));
        assert!(!tool_matches_role(&selector, Some(Role::Action)));
        assert!(tool_matches_role(&action, Some(Role::Action)));
        assert!(!tool_matches_role(&action, Some(Role::Selector)));
    }

    #[test]
    fn parse_role_filter_handles_case_missing_and_invalid() {
        assert_eq!(parse_role_filter(&json!({})).unwrap(), None);
        assert_eq!(
            parse_role_filter(&json!({"role": "Selector"})).unwrap(),
            Some(Role::Selector)
        );
        assert_eq!(
            parse_role_filter(&json!({"role": "action"})).unwrap(),
            Some(Role::Action)
        );
        assert!(parse_role_filter(&json!({"role": "bogus"})).is_err());
        // Absent / null = no filter; present-but-non-string must fail fast.
        assert_eq!(parse_role_filter(&json!({"role": null})).unwrap(), None);
        assert!(parse_role_filter(&json!({"role": 123})).is_err());
        assert!(parse_role_filter(&json!({"role": ["selector"]})).is_err());
    }
}
