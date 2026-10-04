// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Security audit tests for MCP Gateway (Issue #100)
//!
//! Tests proving the security properties of the gateway hold against the
//! attack vectors identified by Doyensec's MCP AuthN/Z research:
//!
//! 1. Tool poisoning (rug pulls) — malicious backend mutates tool definitions
//! 2. Gateway bypass — clients call backends directly without policy enforcement
//! 3. Input injection — tool arguments contain dangerous payloads
//! 4. Scope namespace collision — backends register identical tool names
//! 5. Response prompt injection — upstream embeds malicious instructions
//! 6. Policy enforcement — tool access control cannot be circumvented
//!
//! # References
//!
//! - [Doyensec MCP AuthN/Z research](https://blog.doyensec.com/2026/03/05/mcp-nightmare.html)
//! - OWASP MCP Top 10
//! - GitHub Issue #100

#[path = "security_tests/bypass_and_input.rs"]
mod bypass_and_input;
#[path = "security_tests/combined_and_edge.rs"]
mod combined_and_edge;
#[path = "security_tests/finding02.rs"]
mod finding02;
#[path = "security_tests/response_injection.rs"]
mod response_injection;
#[path = "security_tests/tool_poisoning.rs"]
mod tool_poisoning;

use mcp_gateway::protocol::Tool;
use mcp_gateway::security::policy::PolicyAction;
use mcp_gateway::security::response_scanner::ResponseScanner;
use mcp_gateway::security::scope_collision::validate_tool_name;
use mcp_gateway::security::tool_integrity::ToolIntegrityChecker;
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig, sanitize_json_value};
use serde_json::json;

// ============================================================================
// Helpers
// ============================================================================

fn make_tool(name: &str, desc: &str, schema: serde_json::Value) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(desc.to_string()),
        input_schema: schema,
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

fn make_policy(
    allow: &[&str],
    deny: &[&str],
    default: PolicyAction,
    use_defaults: bool,
) -> ToolPolicy {
    let config = ToolPolicyConfig {
        enabled: true,
        default_action: default,
        allow: allow.iter().map(|s| (*s).to_string()).collect(),
        deny: deny.iter().map(|s| (*s).to_string()).collect(),
        use_default_deny: use_defaults,
        log_denied: false,
    };
    ToolPolicy::from_config(&config)
}

use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig};
use std::time::Duration;
