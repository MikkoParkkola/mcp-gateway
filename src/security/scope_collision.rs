// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Tool-name validation for MCP gateway tool namespaces.
//!
//! Every backend tool is addressed as backend plus tool name, so two backends
//! sharing a tool name do not collide on any served surface. What remains is
//! the name itself: [`validate_tool_name`] keeps a malformed name out of
//! session state.
//!
//! # Reference
//!
//! - [Doyensec MCP AuthN/Z research](https://blog.doyensec.com/2026/03/05/mcp-nightmare.html)
//! - OWASP MCP Top 10: Scope Namespace Collision

/// Shell metacharacters that are rejected in tool names (denylist, defense-in-depth).
///
/// The primary check in [`validate_tool_name`] is an **allowlist** — only
/// `[A-Za-z0-9_-]` characters are accepted.  This constant is kept as a
/// secondary safeguard and for documentation purposes.
#[allow(dead_code)] // kept as secondary safeguard and documentation
const DANGEROUS_TOOL_NAME_CHARS: &[char] = &[
    '`', '$', '|', ';', '&', '>', '<', '!', '{', '}', '(', ')', '[', ']', '\'', '"', '\n', '\r',
];

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
    if let Some(first) = name.chars().next()
        && first == '-'
    {
        return Err(format!(
            "Tool name '{name}' must start with [A-Za-z0-9_], not '-'"
        ));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
