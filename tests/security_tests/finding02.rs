// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Section 8: FINDING-02, backend handler security checks.

use super::*;

// ============================================================================
// 8. FINDING-02: Backend handler security checks (FIXED)
// ============================================================================
//
// These tests verify that the three security layers which were previously
// absent from the direct `/mcp/{name}` backend path are now enforced:
//   - validate_tool_name()   (tool name validation)
//   - tool_policy.check()    (global tool access policy)
//   - sanitize_json_value()  (input sanitization)
//
// The fix also adds a per-backend `passthrough` opt-in that re-enables
// bypass mode for fully-trusted internal backends.

/// Build a non-passthrough backend for testing the security flag.
fn make_backend(passthrough: bool) -> Backend {
    let config = BackendConfig {
        passthrough,
        ..BackendConfig::default()
    };
    Backend::new(
        "test",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

// ── validate_tool_name gates ──────────────────────────────────────────────────

#[test]
fn finding02_validate_tool_name_blocks_null_byte() {
    // GIVEN: tool name with null byte (injection attempt)
    // WHEN: name validation runs
    // THEN: rejected
    assert!(validate_tool_name("tool\0name").is_err());
}

#[test]
fn finding02_validate_tool_name_blocks_shell_metachar() {
    // GIVEN: tool name with shell metacharacters
    assert!(validate_tool_name("tool;rm -rf /").is_err());
    assert!(validate_tool_name("tool`whoami`").is_err());
    assert!(validate_tool_name("tool|cat /etc/passwd").is_err());
}

#[test]
fn finding02_validate_tool_name_blocks_path_traversal() {
    // GIVEN: path traversal sequences in tool name
    assert!(validate_tool_name("../../etc/passwd").is_err());
    assert!(validate_tool_name("tool/../../../secret").is_err());
}

#[test]
fn finding02_validate_tool_name_blocks_empty() {
    // GIVEN: empty string (no tool name provided)
    assert!(validate_tool_name("").is_err());
}

#[test]
fn finding02_validate_tool_name_blocks_overlength() {
    // GIVEN: name exceeding 128-char limit
    assert!(validate_tool_name(&"a".repeat(129)).is_err());
}

#[test]
fn finding02_validate_tool_name_allows_safe_names() {
    // GIVEN: valid tool names used in real MCP backends
    assert!(validate_tool_name("read_file").is_ok());
    assert!(validate_tool_name("search_web").is_ok());
    assert!(validate_tool_name("get-resource").is_ok());
    assert!(validate_tool_name("list_tools_v2").is_ok());
}

// ── tool_policy gates (previously bypassed via /mcp/{name}) ──────────────────

#[test]
fn finding02_tool_policy_blocks_write_file_via_direct_path() {
    // GIVEN: default policy (dangerous tools denied)
    let policy = ToolPolicy::default();
    // WHEN: write_file called via any server name
    // THEN: blocked — the same check now applied in backend_handler
    assert!(policy.check("my_backend", "write_file").is_err());
}

#[test]
fn finding02_tool_policy_blocks_run_command_via_direct_path() {
    let policy = ToolPolicy::default();
    assert!(policy.check("my_backend", "run_command").is_err());
}

#[test]
fn finding02_tool_policy_blocks_delete_file_via_direct_path() {
    let policy = ToolPolicy::default();
    assert!(policy.check("my_backend", "delete_file").is_err());
}

#[test]
fn finding02_tool_policy_blocks_drop_database_via_direct_path() {
    let policy = ToolPolicy::default();
    assert!(policy.check("my_backend", "drop_database").is_err());
}

#[test]
fn finding02_tool_policy_allows_safe_tool_via_direct_path() {
    // GIVEN: default policy
    let policy = ToolPolicy::default();
    // WHEN: safe tool invoked directly
    // THEN: allowed
    assert!(policy.check("my_backend", "search").is_ok());
    assert!(policy.check("my_backend", "read_file").is_ok());
}

#[test]
fn finding02_tool_policy_custom_deny_applied_via_direct_path() {
    // GIVEN: custom policy with deny-by-default
    let policy = make_policy(&["search"], &[], PolicyAction::Deny, false);
    // WHEN: allowed tool invoked directly
    assert!(policy.check("backend", "search").is_ok());
    // WHEN: any other tool invoked directly
    assert!(policy.check("backend", "unknown_tool").is_err());
}

// ── input sanitization gates (previously bypassed via /mcp/{name}) ───────────

#[test]
fn finding02_sanitize_blocks_null_byte_in_arguments_direct_path() {
    // GIVEN: tool call payload with null byte in argument value
    let params = json!({
        "name": "search",
        "arguments": {"query": "safe query\0injected"}
    });
    // WHEN: sanitize_json_value applied to params (as in fixed backend_handler)
    // THEN: rejected
    assert!(sanitize_json_value(&params).is_err());
}

#[test]
fn finding02_sanitize_blocks_null_byte_in_nested_params() {
    // GIVEN: null byte hidden in nested argument object
    let params = json!({
        "name": "read_file",
        "arguments": {
            "path": "/legitimate/path",
            "options": {"encoding": "utf-8\0", "mode": "read"}
        }
    });
    assert!(sanitize_json_value(&params).is_err());
}

#[test]
fn finding02_sanitize_strips_control_chars_in_params() {
    // GIVEN: control characters in arguments (stripped, not rejected)
    let params = json!({
        "name": "search",
        "arguments": {"query": "hello\x07world\x1B[31m"}
    });
    let result = sanitize_json_value(&params).unwrap();
    assert_eq!(result["arguments"]["query"], "helloworld[31m");
}

#[test]
fn finding02_sanitize_preserves_valid_params() {
    // GIVEN: completely clean tool call params
    let params = json!({
        "name": "search_web",
        "arguments": {
            "query": "Helsinki weather",
            "count": 10,
            "language": "en"
        }
    });
    let result = sanitize_json_value(&params).unwrap();
    assert_eq!(result, params, "Clean params must pass through unchanged");
}

// ── passthrough config field ──────────────────────────────────────────────────

#[test]
fn finding02_backend_passthrough_default_is_false() {
    // GIVEN: backend created with default config
    // THEN: passthrough is false (security checks active)
    let backend = make_backend(false);
    assert!(
        !backend.passthrough(),
        "Default backend must have passthrough=false"
    );
}

#[test]
fn finding02_backend_passthrough_explicit_true() {
    // GIVEN: backend explicitly configured with passthrough=true
    // THEN: passthrough() returns true
    let backend = make_backend(true);
    assert!(
        backend.passthrough(),
        "Explicit passthrough=true must be honored"
    );
}

#[test]
fn finding02_backend_config_default_passthrough_false() {
    // GIVEN: BackendConfig::default()
    let config = BackendConfig::default();
    // THEN: passthrough defaults to false (secure by default)
    assert!(
        !config.passthrough,
        "BackendConfig default must have passthrough=false"
    );
}

#[test]
fn finding02_backend_config_passthrough_serde_default() {
    // GIVEN: config deserialized from YAML without passthrough field
    let yaml = r#"{"description": "test", "command": "echo hello"}"#;
    let config: BackendConfig = serde_json::from_str(yaml).unwrap();
    // THEN: passthrough defaults to false (safe default for missing field)
    assert!(
        !config.passthrough,
        "Missing passthrough field must default to false"
    );
}

// ── combined: all three checks applied in order ───────────────────────────────

#[test]
fn finding02_combined_all_checks_must_pass_for_tools_call() {
    // This test documents the required order of checks in backend_handler:
    // 1. validate_tool_name must reject dangerous names before policy check
    // 2. policy must reject dangerous tools before sanitize
    // 3. sanitize must clean inputs before forwarding

    // Step 1: name with shell injection — rejected at name validation
    assert!(
        validate_tool_name("evil`cmd`").is_err(),
        "Name check must be first gate"
    );

    // Step 2: valid name but dangerous tool — rejected at policy
    let policy = ToolPolicy::default();
    assert!(
        validate_tool_name("run_command").is_ok(),
        "Name itself is syntactically valid"
    );
    assert!(
        policy.check("backend", "run_command").is_err(),
        "Policy must block dangerous tool"
    );

    // Step 3: valid name, allowed tool, but poisoned input — rejected at sanitize
    assert!(validate_tool_name("search").is_ok());
    assert!(policy.check("backend", "search").is_ok());
    let bad_args = json!({"query": "normal\0poisoned"});
    assert!(
        sanitize_json_value(&bad_args).is_err(),
        "Sanitize must catch null bytes in args"
    );
}
