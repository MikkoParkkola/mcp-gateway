//! Scope collision detection for MCP gateway tool namespaces.
//!
//! When multiple upstream MCP servers register tools with identical names,
//! the gateway must detect and report the collision to prevent ambiguous routing.
//!
//! # Attack Vector
//!
//! A malicious backend could register a tool with the same name as a legitimate
//! tool on another backend, causing the gateway to route calls to the wrong
//! (attacker-controlled) server.
//!
//! # Reference
//!
//! - [Doyensec MCP AuthN/Z research](https://blog.doyensec.com/2026/03/05/mcp-nightmare.html)
//! - OWASP MCP Top 10: Scope Namespace Collision

use std::collections::HashMap;

use tracing::warn;

use crate::protocol::Tool;

/// Shell metacharacters that are rejected in tool names (denylist, defense-in-depth).
///
/// The primary check in [`validate_tool_name`] is an **allowlist** — only
/// `[A-Za-z0-9_-]` characters are accepted.  This constant is kept as a
/// secondary safeguard and for documentation purposes.
const DANGEROUS_TOOL_NAME_CHARS: &[char] = &[
    '`', '$', '|', ';', '&', '>', '<', '!', '{', '}', '(', ')', '[', ']', '\'', '"', '\n', '\r',
];

/// A detected collision between tool names across backends.
#[derive(Debug, Clone)]
pub struct ScopeCollision {
    /// The tool name that collides.
    pub tool_name: String,
    /// All backends that expose a tool with this name.
    pub backends: Vec<String>,
}

/// Detect tool name collisions across multiple backends.
///
/// Takes a slice of `(backend_name, tools)` pairs and returns all
/// tool names that appear in more than one backend.
///
/// # Example
///
/// ```rust
/// use mcp_gateway::security::scope_collision::detect_collisions;
/// use mcp_gateway::protocol::Tool;
/// use serde_json::json;
///
/// let tools_a = vec![Tool {
///     name: "search".to_string(),
///     title: None,
///     description: None,
///     input_schema: json!({}),
///     output_schema: None,
///     annotations: None,
/// }];
/// let tools_b = vec![Tool {
///     name: "search".to_string(),
///     title: None,
///     description: None,
///     input_schema: json!({}),
///     output_schema: None,
///     annotations: None,
/// }];
///
/// let backends = vec![
///     ("backend_a".to_string(), tools_a),
///     ("backend_b".to_string(), tools_b),
/// ];
///
/// let collisions = detect_collisions(&backends);
/// assert_eq!(collisions.len(), 1);
/// assert_eq!(collisions[0].tool_name, "search");
/// ```
pub fn detect_collisions(backends: &[(String, Vec<Tool>)]) -> Vec<ScopeCollision> {
    // Map: tool_name -> list of backends exposing that tool
    let mut tool_owners: HashMap<&str, Vec<&str>> = HashMap::new();

    for (backend_name, tools) in backends {
        for tool in tools {
            tool_owners
                .entry(tool.name.as_str())
                .or_default()
                .push(backend_name.as_str());
        }
    }

    let mut collisions: Vec<ScopeCollision> = tool_owners
        .into_iter()
        .filter(|(_, owners)| owners.len() > 1)
        .map(|(name, owners)| {
            let collision = ScopeCollision {
                tool_name: name.to_string(),
                backends: owners.into_iter().map(String::from).collect(),
            };
            warn!(
                tool = collision.tool_name.as_str(),
                backends = ?collision.backends,
                "SECURITY: Tool name collision detected across backends"
            );
            collision
        })
        .collect();

    // Sort for deterministic output
    collisions.sort_by(|a, b| a.tool_name.cmp(&b.tool_name));
    collisions
}

/// Validate that a tool name is safe to persist to session state and invoke.
///
/// Uses an **allowlist** approach: only `[A-Za-z0-9_-]` characters are
/// accepted.  This is stricter than a denylist and prevents session
/// corruption from malformed tool names sneaked in by a compromised backend.
///
/// # Rules
///
/// - Non-empty.
/// - Maximum 128 characters.
/// - Must start with `[A-Za-z0-9_]` (not `-`).
/// - All characters in `[A-Za-z0-9_-]`.
///
/// # Errors
///
/// Returns `Err(reason)` describing the first violated rule.
pub fn validate_tool_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Tool name must not be empty".to_string());
    }

    if name.len() > 128 {
        return Err(format!(
            "Tool name exceeds maximum length of 128 characters (got {})",
            name.len()
        ));
    }

    // Allowlist: A-Z, a-z, 0-9, underscore, hyphen only.
    // Any character outside this set is rejected — this covers path traversal
    // (`/`, `\`, `..`), null bytes, control characters, shell metacharacters,
    // template markers, whitespace, and all other injection vectors in one pass.
    let invalid_char = name
        .chars()
        .find(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-'));

    if let Some(bad) = invalid_char {
        return Err(format!(
            "Tool name '{name}' contains disallowed character '{bad}' \
             (only [A-Za-z0-9_-] is permitted)"
        ));
    }

    // Must start with alphanumeric or underscore (not a leading hyphen).
    if let Some(first) = name.chars().next() {
        if first == '-' {
            return Err(format!(
                "Tool name '{name}' must start with [A-Za-z0-9_], not '-'"
            ));
        }
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: None,
            input_schema: json!({}),
            output_schema: None,
            annotations: None,
        }
    }

    // -- detect_collisions --

    #[test]
    fn no_collisions_when_names_are_unique() {
        let backends = vec![
            ("a".to_string(), vec![make_tool("tool_a")]),
            ("b".to_string(), vec![make_tool("tool_b")]),
        ];
        let collisions = detect_collisions(&backends);
        assert!(collisions.is_empty());
    }

    #[test]
    fn detects_collision_between_two_backends() {
        let backends = vec![
            ("a".to_string(), vec![make_tool("search")]),
            ("b".to_string(), vec![make_tool("search")]),
        ];
        let collisions = detect_collisions(&backends);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].tool_name, "search");
        assert_eq!(collisions[0].backends.len(), 2);
    }

    #[test]
    fn detects_collision_across_three_backends() {
        let backends = vec![
            ("a".to_string(), vec![make_tool("read")]),
            ("b".to_string(), vec![make_tool("read")]),
            ("c".to_string(), vec![make_tool("read")]),
        ];
        let collisions = detect_collisions(&backends);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].backends.len(), 3);
    }

    #[test]
    fn multiple_collisions_detected() {
        let backends = vec![
            (
                "a".to_string(),
                vec![make_tool("search"), make_tool("read")],
            ),
            (
                "b".to_string(),
                vec![make_tool("search"), make_tool("read")],
            ),
        ];
        let collisions = detect_collisions(&backends);
        assert_eq!(collisions.len(), 2);
        assert_eq!(collisions[0].tool_name, "read");
        assert_eq!(collisions[1].tool_name, "search");
    }

    #[test]
    fn empty_backends_no_collisions() {
        let backends: Vec<(String, Vec<Tool>)> = vec![];
        let collisions = detect_collisions(&backends);
        assert!(collisions.is_empty());
    }

    #[test]
    fn single_backend_no_collisions() {
        let backends = vec![("a".to_string(), vec![make_tool("t1"), make_tool("t2")])];
        let collisions = detect_collisions(&backends);
        assert!(collisions.is_empty());
    }

    // -- validate_tool_name --

    #[test]
    fn valid_tool_names() {
        // Allowlist: A-Za-z0-9_- starting with A-Za-z0-9_
        assert!(validate_tool_name("search_web").is_ok());
        assert!(validate_tool_name("read_file").is_ok());
        assert!(validate_tool_name("gateway_invoke").is_ok());
        assert!(validate_tool_name("_private_tool").is_ok());
        assert!(validate_tool_name("tool123").is_ok());
        assert!(validate_tool_name("my-tool").is_ok());
        assert!(validate_tool_name("UPPER_CASE").is_ok());
        assert!(validate_tool_name("a").is_ok());
    }

    #[test]
    fn rejects_dot_separated_name() {
        // '.' is outside the allowlist — use '_' or '-' instead
        assert!(validate_tool_name("ns.tool").is_err());
    }

    #[test]
    fn rejects_empty_name() {
        assert!(validate_tool_name("").is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        // '/', '\\', '.' are all outside the allowlist
        assert!(validate_tool_name("../../../etc/passwd").is_err());
        assert!(validate_tool_name("tool/subpath").is_err());
        assert!(validate_tool_name("tool\\name").is_err());
        assert!(validate_tool_name("..").is_err());
    }

    #[test]
    fn rejects_shell_metacharacters() {
        assert!(validate_tool_name("tool`whoami`").is_err());
        assert!(validate_tool_name("tool$(id)").is_err());
        assert!(validate_tool_name("tool|cat").is_err());
        assert!(validate_tool_name("tool;rm").is_err());
        assert!(validate_tool_name("tool&bg").is_err());
        assert!(validate_tool_name("tool>output").is_err());
    }

    #[test]
    fn rejects_template_markers() {
        // Braces used in prompt-injection via tool names
        assert!(validate_tool_name("tool{inject}").is_err());
        assert!(validate_tool_name("{system}").is_err());
    }

    #[test]
    fn rejects_whitespace() {
        assert!(validate_tool_name("tool name").is_err());
        assert!(validate_tool_name("tool\tname").is_err());
        assert!(validate_tool_name("tool\nname").is_err());
    }

    #[test]
    fn rejects_null_bytes() {
        assert!(validate_tool_name("tool\0name").is_err());
    }

    #[test]
    fn rejects_control_characters() {
        assert!(validate_tool_name("tool\x07name").is_err());
        assert!(validate_tool_name("tool\x1Bname").is_err());
    }

    #[test]
    fn rejects_unicode_outside_allowlist() {
        // Unicode letters are not in the [A-Za-z0-9_-] allowlist
        assert!(validate_tool_name("tööl").is_err());
        assert!(validate_tool_name("工具").is_err());
    }

    #[test]
    fn rejects_too_long_name() {
        let long_name = "a".repeat(129);
        assert!(validate_tool_name(&long_name).is_err());
        let ok_name = "a".repeat(128);
        assert!(validate_tool_name(&ok_name).is_ok());
    }

    #[test]
    fn rejects_leading_hyphen() {
        assert!(validate_tool_name("-tool").is_err());
    }

    #[test]
    fn rejects_other_leading_specials() {
        // '.' is outside allowlist entirely; space is too
        assert!(validate_tool_name(".tool").is_err());
        assert!(validate_tool_name(" tool").is_err());
    }

    #[test]
    fn allowlist_error_message_names_bad_char() {
        let err = validate_tool_name("my.tool").unwrap_err();
        assert!(
            err.contains("disallowed character '.'"),
            "error should name the bad char: {err}"
        );
    }
}
