// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Sections 2 and 3: gateway bypass and input injection.

use super::*;

// ============================================================================
// 2. Gateway Bypass Tests
// ============================================================================
//
// Attack: Client attempts to bypass gateway auth/policy by directly invoking
// backend tools without going through the gateway_invoke meta-tool.
//
// Defense: The auth middleware runs on all routes. The tool policy enforces
// access control. The backend_handler at /mcp/{name} checks
// can_access_backend but notably does NOT apply tool_policy or
// sanitize_input — this is documented as a known gap.
//
// These tests verify the policy layer works correctly at the function level.

#[test]
fn gateway_bypass_policy_blocks_dangerous_tools() {
    // GIVEN: default tool policy with standard deny list
    let policy = ToolPolicy::default();

    // THEN: dangerous tools are blocked regardless of server name
    let dangerous = [
        "write_file",
        "delete_file",
        "run_command",
        "execute_command",
        "shell_exec",
        "eval",
        "drop_table",
        "drop_database",
        "kill_process",
    ];
    for tool in &dangerous {
        assert!(
            policy.check("any_server", tool).is_err(),
            "Tool '{tool}' should be blocked by default policy"
        );
    }
}

#[test]
fn gateway_bypass_policy_blocks_regardless_of_server() {
    // Attack: try different server names to bypass policy
    let policy = ToolPolicy::default();
    let servers = [
        "legitimate_server",
        "attacker_server",
        "",
        "../../../etc",
        "localhost",
        "127.0.0.1",
    ];
    for server in &servers {
        assert!(
            policy.check(server, "run_command").is_err(),
            "run_command should be blocked on server '{server}'"
        );
    }
}

#[test]
fn gateway_bypass_allow_cannot_override_when_not_configured() {
    // GIVEN: default policy (use_default_deny=true, no explicit allows)
    let policy = ToolPolicy::default();

    // THEN: write_file is blocked even though nothing explicitly denies it
    // (it's in DEFAULT_DENIED_PATTERNS)
    assert!(policy.check("server", "write_file").is_err());
}

#[test]
fn gateway_bypass_explicit_allow_required_for_dangerous_tools() {
    // Only an explicit allow can unblock a default-denied tool
    let policy = make_policy(
        &["write_file"], // explicitly allow
        &[],
        PolicyAction::Allow,
        true, // keep default deny
    );
    assert!(
        policy.check("server", "write_file").is_ok(),
        "Explicit allow should unblock"
    );
    assert!(
        policy.check("server", "delete_file").is_err(),
        "Other dangerous tools still blocked"
    );
}

#[test]
fn gateway_bypass_default_deny_mode_blocks_unknown_tools() {
    // In deny-by-default mode, only explicitly allowed tools pass
    let policy = make_policy(
        &["search", "read_file"],
        &[],
        PolicyAction::Deny, // default deny
        false,
    );
    assert!(policy.check("server", "search").is_ok());
    assert!(policy.check("server", "read_file").is_ok());
    assert!(policy.check("server", "unknown_tool").is_err());
    assert!(policy.check("server", "run_command").is_err());
}

#[test]
fn gateway_bypass_disabled_policy_allows_everything() {
    // SECURITY FINDING: When policy is disabled, ALL tools are allowed
    // This is intentional but must be documented as a risk
    let config = ToolPolicyConfig {
        enabled: false,
        ..Default::default()
    };
    let policy = ToolPolicy::from_config(&config);
    assert!(policy.check("server", "drop_database").is_ok());
    assert!(policy.check("server", "run_command").is_ok());
}

// ============================================================================
// 3. Input Injection Tests
// ============================================================================
//
// Attack: Client sends tool arguments containing dangerous payloads
// (null bytes, control characters, zero-width chars, shell metacharacters).
//
// Defense: sanitize_json_value strips/rejects dangerous content.
// validate_tool_name rejects suspicious tool names.

#[test]
fn input_injection_null_byte_in_arguments_rejected() {
    let payload = json!({"path": "/etc/passwd\0", "content": "malicious"});
    let result = sanitize_json_value(&payload);
    assert!(result.is_err(), "Null bytes in arguments must be rejected");
}

#[test]
fn input_injection_null_byte_in_nested_arguments_rejected() {
    let payload = json!({
        "command": {
            "args": ["--flag", "value\0injected"],
            "env": {"PATH": "/usr/bin\0:/attacker/bin"}
        }
    });
    let result = sanitize_json_value(&payload);
    assert!(
        result.is_err(),
        "Null bytes anywhere in JSON tree must be rejected"
    );
}

#[test]
fn input_injection_control_chars_stripped() {
    // Control characters are stripped (not rejected) to maintain availability
    let payload = json!({"query": "normal\x07query\x1B[31m"});
    let result = sanitize_json_value(&payload).unwrap();
    assert_eq!(result["query"], "normalquery[31m");
}

#[test]
fn input_injection_zero_width_chars_stripped() {
    // Zero-width chars can be used for homograph attacks
    let payload = json!({"tool_name": "rea\u{200B}d_file"});
    let result = sanitize_json_value(&payload).unwrap();
    assert_eq!(
        result["tool_name"], "read_file",
        "Zero-width space must be stripped"
    );
}

#[test]
fn input_injection_unicode_line_separators_stripped() {
    let payload = json!({"query": "line1\u{2028}line2\u{2029}line3"});
    let result = sanitize_json_value(&payload).unwrap();
    assert_eq!(result["query"], "line1line2line3");
}

#[test]
fn input_injection_tool_name_path_traversal_rejected() {
    // Attack: tool name contains path traversal to access filesystem
    assert!(validate_tool_name("../../../etc/passwd").is_err());
    assert!(validate_tool_name("tool/../../secret").is_err());
    assert!(validate_tool_name("tool\\..\\..\\windows\\system32").is_err());
}

#[test]
fn input_injection_tool_name_shell_injection_rejected() {
    // Attack: tool name contains shell metacharacters for command injection
    assert!(validate_tool_name("tool`id`").is_err());
    assert!(validate_tool_name("tool$(whoami)").is_err());
    assert!(validate_tool_name("tool|cat /etc/shadow").is_err());
    assert!(validate_tool_name("tool;rm -rf /").is_err());
    assert!(validate_tool_name("tool&background_process").is_err());
    assert!(validate_tool_name("tool>output_file").is_err());
    assert!(validate_tool_name("tool<input_file").is_err());
}

#[test]
fn input_injection_tool_name_null_byte_rejected() {
    assert!(validate_tool_name("tool\0name").is_err());
}

#[test]
fn input_injection_tool_name_control_chars_rejected() {
    assert!(validate_tool_name("tool\x07name").is_err());
    assert!(validate_tool_name("tool\x1Bname").is_err());
    assert!(validate_tool_name("\x01start").is_err());
}

#[test]
fn input_injection_tool_name_length_overflow_rejected() {
    // Extremely long names could cause DoS or buffer issues
    let name = "a".repeat(129);
    assert!(validate_tool_name(&name).is_err());
}

#[test]
fn input_injection_tool_name_empty_rejected() {
    assert!(validate_tool_name("").is_err());
}

#[test]
fn input_injection_sanitize_preserves_valid_input() {
    // Sanitization must not corrupt legitimate data
    let valid = json!({
        "query": "Helsinki weather forecast",
        "language": "en",
        "count": 10,
        "nested": {
            "key": "value with spaces and UTF-8: \u{00E4}\u{00F6}\u{00FC}"
        },
        "array": ["item1", "item2"],
        "boolean": true,
        "null_value": null
    });
    let result = sanitize_json_value(&valid).unwrap();
    assert_eq!(result, valid, "Valid input must pass through unchanged");
}

#[test]
fn input_injection_deeply_nested_null_byte_detected() {
    // Attack: hide null byte deep in nested structure hoping sanitizer gives up
    let payload = json!({
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "level5": "innocent\0malicious"
                    }
                }
            }
        }
    });
    assert!(sanitize_json_value(&payload).is_err());
}

#[test]
fn input_injection_null_byte_in_json_key_rejected() {
    // Attack: null byte in key name, not value
    let mut map = serde_json::Map::new();
    map.insert("clean_key".to_string(), json!("clean_value"));
    map.insert("key_with\0null".to_string(), json!("value"));
    let payload = serde_json::Value::Object(map);
    assert!(sanitize_json_value(&payload).is_err());
}
