// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `gateway_list_tools` / `gateway_search_tools` definitions.

use super::tool_total::ToolTotal;
use crate::protocol::Tool;
use serde_json::json;

use super::meta_mcp_tool_defs::read_only_annotations;

/// Build the `gateway_list_tools` meta-tool definition.
pub(crate) fn build_list_tools_tool(tool_count: ToolTotal, server_count: usize) -> Tool {
    Tool {
        name: "gateway_list_tools".to_string(),
        title: Some("List Tools".to_string()),
        description: Some(format!(
            "List tools from a specific backend, or omit server to list all {} across \
         {server_count} backends. Returns names and descriptions — use \
         gateway_search_tools for ranked results with full schemas.",
            tool_count.phrase()
        )),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server": {
                    "type": "string",
                    "description": "Name of backend server. Omit to list ALL tools across all backends."
                },
                "role": {
                    "type": "string",
                    "enum": ["selector", "extractor", "enricher", "action"],
                    "description": "Optional: only return tools of this role. selector=search/list, extractor=get/read, enricher=adds context, action=mutates state. Untagged tools are classified by name + read-only hint."
                }
            },
            "required": []
        }),
        output_schema: None,
        annotations: Some(read_only_annotations("List Tools")),
        role: Some(crate::projection::Role::Selector),
        projection: None,
    }
}

/// JSON output schema describing the `gateway_search_tools` response structure.
fn search_tools_output_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "matches": {
                "type": "array",
                "description": "Ranked list of matching tools",
                "items": {
                    "type": "object",
                    "properties": {
                        "server":      { "type": "string", "description": "Backend server name" },
                        "tool":        { "type": "string", "description": "Tool name" },
                        "description": { "type": "string", "description": "Tool description" },
                        "score":       { "type": "number", "description": "Relevance score (higher is more relevant)" }
                    },
                    "required": ["server", "tool", "description", "score"]
                }
            }
        },
        "required": ["matches"]
    })
}

/// Build the `gateway_search_tools` meta-tool definition.
pub(crate) fn build_search_tools_tool(tool_count: ToolTotal, server_count: usize) -> Tool {
    Tool {
        name: "gateway_search_tools".to_string(),
        title: Some("Search Tools".to_string()),
        description: Some(format!(
            "Search {} across {server_count} servers by keyword. Returns ranked \
         matches (name, description, score) while avoiding the prompt bloat of loading every tool \
         definition upfront. Ranking diagnostics are omitted unless explain is true. \
         Supports multi-word queries and synonym expansion.",
            tool_count.phrase()
        )),
        input_schema: json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Search keyword" },
                "limit": { "type": "integer", "description": "Maximum results (default 10)", "default": 10 },
                "explain": {
                    "type": "boolean",
                    "description": "Include ranking diagnostics (reasons and signals). Default false.",
                    "default": false
                }
            },
            "required": ["query"]
        }),
        output_schema: Some(search_tools_output_schema()),
        annotations: Some(read_only_annotations("Search Tools")),
        role: None,
        projection: None,
    }
}
