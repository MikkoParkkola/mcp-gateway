// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The output schema `gateway_search_tools` publishes.
//!
//! A search answer holds tool rows and, with events enabled, event rows
//! (MIK-7819). Each row is one or the other, so `items` is an `anyOf` of the
//! two, each with its own required fields: a strict client accepts every
//! answer the gateway sends, and an event is never dressed up as a tool.

use serde_json::{Value, json};

/// JSON output schema describing the `gateway_search_tools` response structure.
pub(super) fn search_tools_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "matches": {
                "type": "array",
                "description": "Ranked list of matching tools, then matching events",
                "items": {
                    "anyOf": [
                        {
                            "type": "object",
                            "properties": {
                                "server":      { "type": "string", "description": "Backend server name" },
                                "tool":        { "type": "string", "description": "Tool name" },
                                "description": { "type": "string", "description": "Tool description" },
                                "score":       { "type": "number", "description": "Relevance score (higher is more relevant)" }
                            },
                            "required": ["server", "tool", "description", "score"]
                        },
                        crate::events::EventsHub::search_row_schema()
                    ]
                }
            }
        },
        "required": ["matches"]
    })
}
