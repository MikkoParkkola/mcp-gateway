//! Per-client tool scope tests
//!
//! Tests the per-client tool access control functionality including:
//! - Allowlist enforcement (only specified tools accessible)
//! - Denylist enforcement (specified tools blocked)
//! - Glob pattern matching
//! - Interaction with global tool policy

use mcp_gateway::config::ApiKeyConfig;
use mcp_gateway::gateway::auth::AuthenticatedClient;

/// Test that no restrictions allows all tools (fallback to global policy)
#[test]
fn test_no_tool_restrictions() {
    let client = AuthenticatedClient {
        name: "unrestricted".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: None,
        denied_tools: None,
    };

    // All tools should be allowed (fallback to global policy)
    assert!(client.check_tool_scope("server", "search_web").is_ok());
    assert!(client.check_tool_scope("server", "write_file").is_ok());
    assert!(client.check_tool_scope("server", "any_tool").is_ok());
}

/// Test allowlist with exact tool names
#[test]
fn test_allowlist_exact_match() {
    let client = AuthenticatedClient {
        name: "frontend".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: Some(vec![
            "search_web".to_string(),
            "read_file".to_string(),
            "list_directory".to_string(),
        ]),
        denied_tools: None,
    };

    // Tools in allowlist should be permitted
    assert!(client.check_tool_scope("tavily", "search_web").is_ok());
    assert!(client.check_tool_scope("filesystem", "read_file").is_ok());
    assert!(client.check_tool_scope("filesystem", "list_directory").is_ok());

    // Tools NOT in allowlist should be denied
    let result = client.check_tool_scope("filesystem", "write_file");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("write_file"));
    assert!(err.contains("allowlist"));
    assert!(err.contains("frontend"));

    let result = client.check_tool_scope("server", "execute_command");
    assert!(result.is_err());
}

/// Test allowlist with glob patterns
#[test]
fn test_allowlist_glob_patterns() {
    let client = AuthenticatedClient {
        name: "search_only".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: Some(vec![
            "search_*".to_string(),
            "read_*".to_string(),
        ]),
        denied_tools: None,
    };

    // Tools matching glob patterns should be allowed
    assert!(client.check_tool_scope("tavily", "search_web").is_ok());
    assert!(client.check_tool_scope("brave", "search_local").is_ok());
    assert!(client.check_tool_scope("filesystem", "read_file").is_ok());
    assert!(client.check_tool_scope("database", "read_query").is_ok());

    // Tools NOT matching patterns should be denied
    assert!(client.check_tool_scope("filesystem", "write_file").is_err());
    assert!(client.check_tool_scope("server", "execute_command").is_err());
    assert!(client.check_tool_scope("database", "write_query").is_err());
}

/// Test denylist with exact tool names
#[test]
fn test_denylist_exact_match() {
    let client = AuthenticatedClient {
        name: "no_writes".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: None,
        denied_tools: Some(vec![
            "write_file".to_string(),
            "delete_file".to_string(),
            "execute_command".to_string(),
        ]),
    };

    // Tools in denylist should be blocked
    let result = client.check_tool_scope("filesystem", "write_file");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("write_file"));
    assert!(err.contains("blocked"));
    assert!(err.contains("no_writes"));

    assert!(client.check_tool_scope("filesystem", "delete_file").is_err());
    assert!(client.check_tool_scope("server", "execute_command").is_err());

    // Tools NOT in denylist should be allowed
    assert!(client.check_tool_scope("filesystem", "read_file").is_ok());
    assert!(client.check_tool_scope("tavily", "search_web").is_ok());
}

/// Test denylist with glob patterns
#[test]
fn test_denylist_glob_patterns() {
    let client = AuthenticatedClient {
        name: "no_filesystem".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: None,
        denied_tools: Some(vec![
            "filesystem_*".to_string(),
            "exec_*".to_string(),
        ]),
    };

    // Tools matching deny patterns should be blocked
    assert!(client.check_tool_scope("server", "filesystem_read").is_err());
    assert!(client.check_tool_scope("server", "filesystem_write").is_err());
    assert!(client.check_tool_scope("server", "exec_command").is_err());
    assert!(client.check_tool_scope("server", "exec_shell").is_err());

    // Tools NOT matching deny patterns should be allowed
    assert!(client.check_tool_scope("tavily", "search_web").is_ok());
    assert!(client.check_tool_scope("database", "query").is_ok());
}

/// Test qualified name matching (server:tool)
#[test]
fn test_qualified_name_matching() {
    let client = AuthenticatedClient {
        name: "specific_server".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: Some(vec![
            "filesystem:read_file".to_string(),
            "database:*".to_string(),
        ]),
        denied_tools: None,
    };

    // Qualified match: filesystem:read_file allowed, but not on other servers
    assert!(client.check_tool_scope("filesystem", "read_file").is_ok());
    assert!(client.check_tool_scope("other_server", "read_file").is_err());

    // Qualified glob: database:* allows all tools on database server
    assert!(client.check_tool_scope("database", "query").is_ok());
    assert!(client.check_tool_scope("database", "insert").is_ok());
    assert!(client.check_tool_scope("database", "delete").is_ok());

    // But not on other servers
    assert!(client.check_tool_scope("filesystem", "query").is_err());
}

/// Test combination of allowlist and denylist
#[test]
fn test_allowlist_and_denylist_combination() {
    let client = AuthenticatedClient {
        name: "complex".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: Some(vec![
            "filesystem_*".to_string(),
            "search_*".to_string(),
        ]),
        denied_tools: Some(vec![
            "filesystem_write".to_string(),
            "filesystem_delete".to_string(),
        ]),
    };

    // In allowlist AND NOT in denylist: allowed
    assert!(client.check_tool_scope("server", "filesystem_read").is_ok());
    assert!(client.check_tool_scope("server", "search_web").is_ok());

    // In allowlist BUT in denylist: denylist takes precedence
    assert!(client.check_tool_scope("server", "filesystem_write").is_err());
    assert!(client.check_tool_scope("server", "filesystem_delete").is_err());

    // NOT in allowlist: denied (even if not in denylist)
    assert!(client.check_tool_scope("server", "execute_command").is_err());
}

/// Test ApiKeyConfig with tool scopes (config layer)
#[test]
fn test_api_key_config_with_tool_scopes() {
    let config = ApiKeyConfig {
        key: "test-key".to_string(),
        name: "Frontend App".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: Some(vec!["search_*".to_string(), "read_*".to_string()]),
        denied_tools: Some(vec!["read_secrets".to_string()]),
    };

    // Verify config fields are set correctly
    assert_eq!(config.name, "Frontend App");
    assert!(config.allowed_tools.is_some());
    assert_eq!(config.allowed_tools.as_ref().unwrap().len(), 2);
    assert!(config.denied_tools.is_some());
    assert_eq!(config.denied_tools.as_ref().unwrap().len(), 1);
}

/// Test empty allowlist (deny all)
#[test]
fn test_empty_allowlist() {
    let client = AuthenticatedClient {
        name: "deny_all".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: Some(vec![]), // Empty allowlist = nothing allowed
        denied_tools: None,
    };

    // All tools should be denied with empty allowlist
    assert!(client.check_tool_scope("server", "search_web").is_err());
    assert!(client.check_tool_scope("server", "read_file").is_err());
}

/// Test empty denylist (allow all that pass other checks)
#[test]
fn test_empty_denylist() {
    let client = AuthenticatedClient {
        name: "allow_all".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: None,
        denied_tools: Some(vec![]), // Empty denylist = no additional blocks
    };

    // Empty denylist should not block anything (falls back to global policy)
    assert!(client.check_tool_scope("server", "search_web").is_ok());
    assert!(client.check_tool_scope("server", "read_file").is_ok());
}

/// Test pattern matching edge cases
#[test]
fn test_pattern_matching_edge_cases() {
    let client = AuthenticatedClient {
        name: "edge_cases".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: Some(vec![
            "a*".to_string(),
            "exact_match".to_string(),
            "*ends_with_this".to_string(), // This should NOT match (only suffix * supported)
        ]),
        denied_tools: None,
    };

    // Prefix glob works
    assert!(client.check_tool_scope("server", "abc").is_ok());
    assert!(client.check_tool_scope("server", "a").is_ok());

    // Exact match works
    assert!(client.check_tool_scope("server", "exact_match").is_ok());

    // Prefix/suffix glob (only suffix * is implemented, so this is exact match)
    // The pattern "*ends_with_this" will only match if tool name is exactly "*ends_with_this"
    assert!(client.check_tool_scope("server", "starts_with_this_ends_with_this").is_err());

    // Not matching any pattern
    assert!(client.check_tool_scope("server", "b").is_err());
}
