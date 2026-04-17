//! Tool search and listing handlers.
//!
//! Implements `gateway_search` (Code Mode), `gateway_execute` (Code Mode),
//! `gateway_list_tools`, `gateway_search_tools`, and the chain executor.

use serde_json::{Value, json};

use crate::autotag;
use crate::ranking::json_to_search_result;
use crate::routing_profile::RoutingProfile;
use crate::{Error, Result};

use super::super::differential::annotate_differential;
use super::super::meta_mcp_helpers::{
    build_code_mode_match_json, build_match_json, build_match_json_with_chains,
    build_search_response, build_suggestions, extract_bool_or, extract_optional_str,
    extract_required_str, extract_search_limit, is_glob_pattern, parse_code_mode_tool_ref,
    parse_tool_arguments, ranked_results_to_json, tool_matches_glob, tool_matches_query,
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

impl MetaMcp {
    fn current_search_state(&self, session_id: Option<&str>) -> String {
        session_id.map_or_else(
            || crate::gateway::state::DEFAULT_STATE.to_string(),
            |sid| self.session_state.get_state(sid),
        )
    }

    fn code_mode_tool_matches(tool: &crate::protocol::Tool, query: &str, use_glob: bool) -> bool {
        if use_glob {
            tool_matches_glob(tool, query)
        } else {
            tool_matches_query(tool, query)
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
                if Self::code_mode_tool_matches(&tool, query, options.use_glob) {
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
        for backend in self.backends.all() {
            if !backend.has_cached_tools() || !profile.backend_allowed(&backend.name) {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Ok(tools) = backend.get_tools_shared().await {
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
                    if Self::code_mode_tool_matches(&tool, query, options.use_glob) {
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
            if !backend.has_cached_tools() || !profile.backend_allowed(&backend.name) {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Ok(tools) = backend.get_tools_shared().await {
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
    ) -> Result<Value> {
        // Chain mode: sequential execution
        if let Some(chain) = args.get("chain").and_then(Value::as_array) {
            return self.execute_chain(chain.clone(), session_id).await;
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

        // agent_id is None: code-mode execution is an internal operation.
        self.invoke_tool(&invoke_args, session_id, None, None).await
    }

    /// Execute a sequential chain of `{tool, arguments}` steps.
    ///
    /// Returns a JSON array of per-step results. Stops at the first error
    /// and surfaces the failing step index in the error message.
    async fn execute_chain(&self, chain: Vec<Value>, session_id: Option<&str>) -> Result<Value> {
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

            match self.invoke_tool(&invoke_args, session_id, None, None).await {
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
    pub(super) async fn list_tools(&self, args: &Value, session_id: Option<&str>) -> Result<Value> {
        let profile = self.active_profile(session_id);

        // If server is specified, return tools from that single backend (existing behavior)
        if let Some(server) = extract_optional_str(args, "server") {
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
                    .filter(|t| profile.tool_allowed(&t.name))
                    .collect();
                return Ok(json!({
                    "server": server,
                    "status": if killed { "disabled" } else { "active" },
                    "tools": tools
                }));
            }

            // Otherwise, look in MCP backends
            let backend = self
                .backends
                .get(server)
                .ok_or_else(|| Error::BackendNotFound(server.to_string()))?;

            let tools: Vec<_> = backend
                .get_tools()
                .await?
                .into_iter()
                .filter(|t| profile.tool_allowed(&t.name))
                .collect();

            return Ok(json!({
                "server": server,
                "status": if killed { "disabled" } else { "active" },
                "tools": tools
            }));
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
                if !profile.tool_allowed(&tool.name) {
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

        // MCP backend tools (only from cached/warm-started backends — no blocking starts)
        for backend in self.backends.all() {
            if !backend.has_cached_tools() {
                continue;
            }
            if !profile.backend_allowed(&backend.name) {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Ok(tools) = backend.get_tools_shared().await {
                for tool in tools.iter() {
                    if !profile.tool_allowed(&tool.name) {
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

        Ok(json!({
            "tools": all_tools,
            "total": all_tools.len()
        }))
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

        Ok(build_search_response(
            &query,
            &matches,
            total_found,
            &suggestions,
        ))
    }
}
