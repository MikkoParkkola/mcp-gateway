//! gateway-core — MCP tool discovery and routing primitives.
//!
//! Core library providing tool registry, search, and execution
//! primitives. Used by botnaut for direct (zero-IPC) MCP tool access.
//!
//! ## License
//! PolyForm Noncommercial 1.0.0 — free for noncommercial use.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An MCP tool definition with input/output schemas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub server: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Tool search result with relevance score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMatch {
    pub tool: ToolDef,
    pub score: f64,
}

/// Registry of available MCP tools across servers.
#[derive(Debug, Default)]
pub struct ToolRegistry {
    tools: HashMap<String, ToolDef>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, server: &str, tool: ToolDef) {
        let key = format!("{}_{}", server, tool.name);
        self.tools.insert(key, tool);
    }

    pub fn search(&self, query: &str) -> Vec<ToolMatch> {
        let q = query.to_lowercase();
        let mut matches: Vec<ToolMatch> = self
            .tools
            .values()
            .filter_map(|t| {
                let score = if t.name.to_lowercase().contains(&q) {
                    0.8
                } else if t.description.to_lowercase().contains(&q) {
                    0.5
                } else {
                    0.0
                };
                if score > 0.0 {
                    Some(ToolMatch {
                        tool: t.clone(),
                        score,
                    })
                } else {
                    None
                }
            })
            .collect();
        matches.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        matches
    }

    pub fn list(&self) -> Vec<&ToolDef> {
        self.tools.values().collect()
    }
}

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_search() {
        let mut reg = ToolRegistry::new();
        reg.register(
            "test",
            ToolDef {
                name: "test_tool".into(),
                server: "test".into(),
                description: "A test tool".into(),
                input_schema: serde_json::json!({}),
            },
        );
        let results = reg.search("test");
        assert!(!results.is_empty());
    }
}
