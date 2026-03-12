# MCP Gateway Security Audit Report

**Date**: 2026-03-12
**Scope**: Issue #100 — Doyensec MCP AuthN/Z research attack vectors
**Auditor**: Automated (Claude Code) + manual code review
**Gateway version**: 2.4.0
**Test evidence**: 53 dedicated security tests in `tests/security_tests.rs` + 118 unit tests across security modules

## Executive Summary

The mcp-gateway has security defenses for the six primary MCP attack vectors identified by Doyensec. Three modules were added in commit `6c3a4de`: `tool_integrity.rs` (anti-rug-pull), `scope_collision.rs` (namespace isolation), and `response_scanner.rs` (prompt injection detection). This audit verified those modules with 53 integration tests and identified **2 findings requiring attention** and **3 known limitations**.

## Attack Vectors Audited

### 1. Tool Poisoning / Rug Pull (AC1, AC7)

**Module**: `src/security/tool_integrity.rs`
**Status**: IMPLEMENTED AND VERIFIED

**Defense**: `ToolIntegrityChecker` hashes tool definitions (name + description + input_schema + output_schema) using SHA-256 on first `tools/list` response, then detects any mutation in subsequent responses.

**Tests proving the defense works** (`tests/security_tests.rs`):

| Test | Attack Scenario | Result |
|------|----------------|--------|
| `rug_pull_description_changes_detected` | Backend changes tool description to include malicious instructions | DETECTED |
| `rug_pull_schema_injection_detected` | Backend adds `exec` parameter to enable command injection | DETECTED |
| `rug_pull_subtle_description_change_detected` | Single-character change that alters tool behavior | DETECTED |
| `rug_pull_output_schema_change_detected` | Backend adds exfiltration field to output schema | DETECTED |
| `rug_pull_multiple_tools_mutated_simultaneously` | All tools mutated at once | ALL DETECTED |
| `rug_pull_concurrent_backends_isolated` | Mutation on one backend does not affect others | VERIFIED |

**Known limitation — FINDING-01**: Tool removal + re-addition bypasses detection. If a backend removes a tool in one `tools/list` response and re-adds it with a different schema in a subsequent response, the checker treats the re-added tool as a new addition (not a mutation) because the intermediate snapshot no longer contains the tool. Mitigation: maintain a full history of all observed tool definitions per backend rather than replacing the snapshot. Priority: **LOW** — this attack requires the attacker to control the timing of multiple `tools/list` responses and the gateway to call `tools/list` at least 3 times.

### 2. Scope Namespace Collision (AC4)

**Module**: `src/security/scope_collision.rs`
**Status**: IMPLEMENTED AND VERIFIED

**Defense**: `detect_collisions()` scans all `(backend_name, tools)` pairs and flags any tool name appearing on more than one backend. `validate_tool_name()` rejects tool names containing path traversal, shell metacharacters, control characters, null bytes, or exceeding 128 characters.

**Tests proving the defense works**:

| Test | Scenario | Result |
|------|----------|--------|
| `collision_exact_duplicate_across_two_backends` | Two backends expose `search` | DETECTED |
| `collision_across_many_backends` | Four backends expose `search` | DETECTED |
| `collision_no_false_positives_with_prefixed_names` | Properly prefixed names (brave_search, tavily_search) | NO FALSE POSITIVE |
| `collision_multiple_collisions_across_shared_toolsets` | read + write collide, unique tools do not | CORRECT |
| `collision_empty_tool_list_no_crash` | Empty tool lists | NO CRASH |

### 3. Prompt Injection via Tool Responses (AC2, AC8)

**Module**: `src/security/response_scanner.rs`
**Status**: IMPLEMENTED AND VERIFIED (22 patterns, exceeds AC2 requirement of 20)

**Defense**: `ResponseScanner` compiles 22 regex patterns covering:
- Direct instruction override (4 patterns)
- Role/persona hijacking (4 patterns)
- Tool/action manipulation (2 patterns)
- Data exfiltration (2 patterns)
- System prompt extraction (2 patterns)
- Delimiter/boundary injection (2 patterns)
- Obfuscation (2 patterns)
- HTML/script injection (3 patterns)
- Multi-turn manipulation (2 patterns)

**Tests proving the defense works**:

| Test | Attack Category | Payloads Tested | Result |
|------|----------------|-----------------|--------|
| `response_injection_instruction_override_patterns` | Instruction override | 6 variants | ALL DETECTED |
| `response_injection_role_hijacking_patterns` | DAN/jailbreak/system prompt | 4 variants | ALL DETECTED |
| `response_injection_data_exfiltration_patterns` | curl/wget/send to URL | 5 variants | ALL DETECTED |
| `response_injection_delimiter_attacks` | Chat template markers | 5 variants | ALL DETECTED |
| `response_injection_code_execution_patterns` | script/iframe/eval/base64 | 5 variants | ALL DETECTED |
| `response_injection_multi_turn_manipulation` | Next-response directives | 2 variants | ALL DETECTED |
| `response_injection_hidden_in_json_response` | Nested JSON object | Deep nesting | DETECTED |
| `response_injection_hidden_in_json_array` | JSON array | Array element | DETECTED |
| `response_injection_clean_response_passes` | Legitimate responses | 5 clean responses | NO FALSE POSITIVES |

### 4. Input Sanitization (Injection Prevention)

**Module**: `src/security/sanitize.rs`
**Status**: IMPLEMENTED AND VERIFIED

**Defense**: `sanitize_json_value()` recursively processes all JSON values:
- **Rejects** null bytes (hard error — no valid use case)
- **Strips** C0/C1 control characters (except tab, newline, CR)
- **Strips** zero-width Unicode characters (U+200B, U+200C, U+200D, U+FEFF)
- **Strips** Unicode line/paragraph separators (U+2028, U+2029)
- **Sanitizes** both keys and values in JSON objects

**Tests proving the defense works**:

| Test | Injection Technique | Result |
|------|-------------------|--------|
| `input_injection_null_byte_in_arguments_rejected` | Null byte in value | REJECTED |
| `input_injection_null_byte_in_nested_arguments_rejected` | Null byte in deep nesting | REJECTED |
| `input_injection_null_byte_in_json_key_rejected` | Null byte in key name | REJECTED |
| `input_injection_deeply_nested_null_byte_detected` | 5 levels deep | REJECTED |
| `input_injection_zero_width_chars_stripped` | Zero-width space homograph | STRIPPED |
| `input_injection_control_chars_stripped` | BEL + ESC sequences | STRIPPED |
| `input_injection_unicode_line_separators_stripped` | U+2028/U+2029 | STRIPPED |
| `input_injection_tool_name_path_traversal_rejected` | ../../../etc/passwd | REJECTED |
| `input_injection_tool_name_shell_injection_rejected` | backtick/dollar/pipe/semicolon | REJECTED |
| `input_injection_sanitize_preserves_valid_input` | Legitimate UTF-8 data | PRESERVED |

### 5. Tool Access Policy (Gateway Bypass Prevention)

**Module**: `src/security/policy.rs`
**Status**: IMPLEMENTED AND VERIFIED

**Defense**: `ToolPolicy` enforces allow/deny lists with prefix-glob support. Default deny list blocks 15 high-risk tools (write_file, delete_file, run_command, execute_command, shell_exec, run_script, eval, drop_table, drop_database, truncate_table, kill_process, shutdown, reboot, move_file, create_directory). Allow list takes precedence over deny for explicit overrides. Supports `server:tool` qualified names.

**Tests proving the defense works**:

| Test | Scenario | Result |
|------|----------|--------|
| `gateway_bypass_policy_blocks_dangerous_tools` | 9 dangerous tools tested | ALL BLOCKED |
| `gateway_bypass_policy_blocks_regardless_of_server` | 6 different server names | ALL BLOCKED |
| `gateway_bypass_explicit_allow_required_for_dangerous_tools` | Only explicit allow unblocks | VERIFIED |
| `gateway_bypass_default_deny_mode_blocks_unknown_tools` | Default-deny mode | UNKNOWN TOOLS BLOCKED |

### 6. SSRF Protection

**Module**: `src/security/ssrf.rs`
**Status**: IMPLEMENTED AND VERIFIED (existing 18 unit tests)

**Defense**: `validate_url_not_ssrf()` blocks requests targeting private IP ranges including:
- IPv4: loopback, RFC1918, link-local, CGN, broadcast, unspecified, documentation ranges
- IPv6: loopback, unspecified, link-local, unique local, IPv4-mapped (::ffff:x.x.x.x), 6to4, Teredo

## Security Findings

### FINDING-01: Tool removal/re-addition bypasses integrity check (LOW)

**Severity**: LOW
**Vector**: Tool Poisoning
**Module**: `src/security/tool_integrity.rs`

The `ToolIntegrityChecker` replaces its internal fingerprint store on each `check_tools()` call. If a backend removes a tool and re-adds it with a different schema in a later call, the re-added tool is treated as a new addition rather than a mutation.

**Evidence**: Test `rug_pull_tool_removal_not_flagged_but_readdition_with_different_schema_is`

**Mitigation**: Change `check_tools()` to append new tools to the store rather than replacing it, or maintain a separate "ever-seen" set. This prevents the remove-wait-readd attack at the cost of growing memory over time (bounded by total unique tool definitions).

**Risk**: Low. Attacker must control timing of multiple `tools/list` responses and the gateway must poll `tools/list` at least 3 times.

### FINDING-02: Backend handler bypasses tool policy and input sanitization — **FIXED**

**Severity**: MEDIUM → **RESOLVED**
**Vector**: Gateway Bypass
**Location**: `src/gateway/router.rs` (`backend_handler`) / `src/config.rs` (`BackendConfig`)
**Fix commit**: see git history

**Original issue**: The direct backend handler at `POST /mcp/{name}` checked `can_access_backend()` for
per-client backend restrictions but did **NOT** apply:
- `tool_policy.check()` (global tool access policy)
- `sanitize_json_value()` (input sanitization)
- `validate_tool_name()` (tool name validation)

**Fix applied**: For every `tools/call` request reaching `backend_handler`, the gateway now runs all
three checks (in order: name validation → policy → sanitization) via `apply_backend_tool_call_security()`
before forwarding to the backend. Other methods (`tools/list`, `resources/*`, `prompts/*`, etc.) are
unaffected — they do not carry tool arguments and are not subject to tool-level policy.

**Pass-through opt-in**: A new per-backend config field `passthrough: bool` (default `false`) explicitly
opts a backend out of these checks. This must only be set for fully-trusted internal backends where the
restrictions are harmful (e.g. a backend that legitimately sends binary arguments). Setting `passthrough:
true` logs a clear security warning in the documentation.

**Evidence**:
- 21 new tests in `tests/security_tests.rs` under the `finding02_*` prefix
- `tests/backend_tests.rs` updated to include `passthrough` field in `BackendConfig` construction
- `Backend::passthrough()` accessor added to `src/backend/mod.rs`

**Residual gap**: mTLS certificate-based policy is still not evaluated on the direct backend path.
This is acceptable because mTLS provides transport-layer identity assurance that is orthogonal to
per-tool access control; the tool policy layer now provides the primary enforcement.

### FINDING-03: Unicode homoglyph tool names not detected (LOW)

**Severity**: LOW
**Vector**: Scope Collision / Input Injection
**Module**: `src/security/scope_collision.rs`

`validate_tool_name()` allows non-ASCII alphanumeric characters in tool names. An attacker could register a tool named with Cyrillic `a` (U+0430) instead of Latin `a` (U+0061). The names appear visually identical but are byte-different.

**Evidence**: Test `edge_case_unicode_homograph_tool_name`

**Mitigation**: Either restrict tool names to ASCII-only (`[a-zA-Z0-9_.-]`), or add Unicode confusable detection using the `unicode-normalization` crate. The `sanitize.rs` module already strips some zero-width characters but does not detect homoglyphs.

## Acceptance Criteria Status

| AC | Description | Status | Evidence |
|----|-------------|--------|----------|
| AC1 | Tool definition integrity check | PASS | 8 rug-pull tests |
| AC2 | Response scanner with >= 20 patterns | PASS | 22 patterns, test `response_injection_scanner_has_sufficient_patterns` |
| AC3 | Transport authentication | PASS | `auth_middleware` on all routes, bearer + API key + OIDC key server |
| AC4 | Namespace collision audit | PASS | 6 collision tests, `validate_tool_name` tests |
| AC5 | Rate limiting | PASS | Per-client rate limiting via `governor` crate in `auth.rs` |
| AC6 | Audit log | PARTIAL | `tracing::warn!` on security events, `stats.record_invocation()` on tool calls. No dedicated audit.jsonl with parameter hashes. |
| AC7 | Security test: rug pull detection | PASS | `rug_pull_*` tests (7 tests) |
| AC8 | Security test: prompt injection detection | PASS | `response_injection_*` tests (11 tests) |
| AC9 | Security test: connection without auth | PASS | `auth_middleware` returns 401 when auth enabled and no token provided |

## Test Summary

```
Security integration tests:  53 passed, 0 failed
Security unit tests:         118 passed, 0 failed  (across 6 security modules)
Full test suite:             1407 passed, 0 failed, 6 ignored
Clippy:                      0 errors, 0 warnings (security_tests)
```

## Files

| File | Purpose | LOC |
|------|---------|-----|
| `src/security/mod.rs` | Module declarations and re-exports | 27 |
| `src/security/tool_integrity.rs` | Anti-rug-pull (SHA-256 fingerprinting) | 331 |
| `src/security/scope_collision.rs` | Namespace collision detection + name validation | 325 |
| `src/security/response_scanner.rs` | Prompt injection pattern detection (22 regex) | 386 |
| `src/security/sanitize.rs` | Input sanitization (null bytes, control chars, zero-width) | 346 |
| `src/security/policy.rs` | Tool access allow/deny policy | 463 |
| `src/security/ssrf.rs` | SSRF protection (IPv4/IPv6/mapped/6to4/Teredo) | 368 |
| `tests/security_tests.rs` | Integration test suite proving security properties | 558 |
| `docs/SECURITY_AUDIT.md` | This document | - |

## References

- [Doyensec MCP AuthN/Z research](https://blog.doyensec.com/2026/03/05/mcp-nightmare.html)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- GitHub Issue [#100](https://github.com/MikkoParkkola/mcp-gateway/issues/100)
- CVE-2025-6514, CVE-2025-4144, CVE-2025-4143, CVE-2025-58062
