use super::*;
use serde_json::json;

fn create_tool(name: &str, description: &str, input_schema: serde_json::Value) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(description.to_string()),
        input_schema,
        output_schema: None,
        annotations: None,
    }
}

#[test]
fn test_outcome_oriented_rule_pass() {
    let rule = OutcomeOrientedRule;
    let tool = create_tool(
        "github_search_issues",
        "Find and analyze GitHub issues matching search criteria",
        json!({"type": "object", "properties": {}}),
    );

    let result = rule.check(&tool).unwrap();
    assert!(result.score > 0.8);
}

#[test]
fn test_outcome_oriented_rule_fail() {
    let rule = OutcomeOrientedRule;
    let tool = create_tool(
        "get_user",
        "Calls the API endpoint to retrieve user data",
        json!({"type": "object", "properties": {}}),
    );

    let result = rule.check(&tool).unwrap();
    assert!(result.score < 0.5);
    assert!(!result.issues.is_empty());
}

#[test]
fn test_flat_arguments_rule_pass() {
    let rule = FlatArgumentsRule;
    let tool = create_tool(
        "search",
        "Search",
        json!({
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "number"}
            }
        }),
    );

    let result = rule.check(&tool).unwrap();
    assert!(result.score > 0.9);
}

#[test]
fn test_flat_arguments_rule_fail() {
    let rule = FlatArgumentsRule;
    let tool = create_tool(
        "search",
        "Search",
        json!({
            "type": "object",
            "properties": {
                "filter": {
                    "type": "object",
                    "properties": {"field": {"type": "string"}}
                }
            }
        }),
    );

    let result = rule.check(&tool).unwrap();
    assert!(result.score < 0.8);
    assert!(!result.issues.is_empty());
}

#[test]
fn test_documentation_quality_good() {
    let rule = DocumentationQualityRule;
    let tool = create_tool(
        "search",
        "Search the knowledge base for relevant documents. Use this when you need to find information about a specific topic. Returns a list of matching documents with relevance scores.",
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query string"
                }
            }
        }),
    );

    let result = rule.check(&tool).unwrap();
    assert!(result.score > 0.8);
}

#[test]
fn test_naming_discovery_good() {
    let rule = NamingDiscoveryRule;
    let tool = create_tool(
        "github_search_issues",
        "Search GitHub issues",
        json!({"type": "object"}),
    );

    let result = rule.check(&tool).unwrap();
    assert!(result.score > 0.8);
}

#[test]
fn test_naming_discovery_bad() {
    let rule = NamingDiscoveryRule;
    let tool = create_tool("search", "Search", json!({"type": "object"}));

    let result = rule.check(&tool).unwrap();
    assert!(result.score < 0.7);
}

#[test]
fn test_pagination_rule_list_operation() {
    let rule = PaginationRule;
    let tool = create_tool(
        "list_users",
        "List all users",
        json!({
            "type": "object",
            "properties": {
                "limit": {"type": "number"},
                "offset": {"type": "number"}
            }
        }),
    );

    let result = rule.check(&tool).unwrap();
    // Has pagination params but no output schema
    assert!(result.score > 0.4);
}
