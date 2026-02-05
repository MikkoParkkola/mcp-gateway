//! Example demonstrating the Agent-UX Validator
//!
//! This example shows how to validate MCP tool definitions against
//! agent-UX best practices.
//!
//! Run with: cargo run --example validator_demo

use mcp_gateway::protocol::Tool;
use mcp_gateway::validator::{AgentUxValidator, Severity};
use serde_json::json;

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║     MCP Server Design Validator - Agent-UX Compliance       ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Create validator
    let validator = AgentUxValidator::new();

    // Example 1: Good tool design
    let good_tool = Tool {
        name: "github_search_issues".to_string(),
        title: Some("GitHub Issue Search".to_string()),
        description: Some(
            "Search and analyze GitHub issues using semantic search with filters. \
             Use this when you need to find relevant issues, bugs, or feature requests. \
             Returns a curated list of issues with relevance scores and key metadata."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query string"
                },
                "repository": {
                    "type": "string",
                    "description": "Repository in format owner/repo"
                },
                "state": {
                    "type": "string",
                    "enum": ["open", "closed", "all"],
                    "description": "Filter by issue state"
                },
                "limit": {
                    "type": "number",
                    "description": "Maximum number of results (default: 10)"
                }
            },
            "required": ["query", "repository"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "issues": {
                    "type": "array",
                    "items": {
                        "type": "object"
                    }
                },
                "total_count": {
                    "type": "number"
                },
                "has_more": {
                    "type": "boolean"
                }
            }
        })),
        annotations: None,
    };

    // Example 2: Bad tool design (CRUD operation)
    let bad_tool = Tool {
        name: "get_user".to_string(),
        title: None,
        description: Some("Calls the API endpoint to retrieve user data".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "filter": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"}
                    }
                }
            }
        }),
        output_schema: None,
        annotations: None,
    };

    // Example 3: Short description
    let short_desc_tool = Tool {
        name: "search".to_string(),
        title: None,
        description: Some("Search".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "q": {"type": "string"}
            }
        }),
        output_schema: None,
        annotations: None,
    };

    // Validate all tools
    let tools = vec![good_tool, bad_tool, short_desc_tool];
    match validator.validate_tools(&tools) {
        Ok(report) => {
            println!("{}", report.format_text());

            // Show JSON output example
            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!("║ JSON OUTPUT (for programmatic use)                          ║");
            println!("╚══════════════════════════════════════════════════════════════╝\n");

            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("Failed to serialize report: {}", e),
            }

            // Show score breakdown
            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!("║ SCORE BREAKDOWN                                              ║");
            println!("╚══════════════════════════════════════════════════════════════╝\n");

            for result in &report.results {
                let status = match result.severity {
                    Severity::Pass => "✓ PASS",
                    Severity::Info => "ℹ INFO",
                    Severity::Warn => "⚠ WARN",
                    Severity::Fail => "✗ FAIL",
                };
                println!(
                    "{:10} [{:6}] {:30} - {:.0}%",
                    status,
                    result.rule_code,
                    format!("{} ({})", result.rule_name, result.tool_name),
                    result.score * 100.0
                );
            }
        }
        Err(e) => {
            eprintln!("Validation failed: {}", e);
        }
    }
}
