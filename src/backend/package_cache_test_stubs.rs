// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `sh` stand-ins for a backend that the package-cache retry tests start.
//!
//! Each script appends one line per spawn to `$MCP_GATEWAY_TEST_SPAWN_LOG`, so
//! the log's length is the number of starts. A child of the retry tests'
//! module, kept in its own file so the scripts can change without the test
//! file growing.

/// Answers the handshake, injects the failure as a JSON-RPC error frame, and
/// counts its own spawns in `$SPAWN_LOG` so the *number of calls to the inner
/// start* is observable from outside the transport.
pub(super) const STUB: &str = r#"count=0
if [ -f "$MCP_GATEWAY_TEST_SPAWN_LOG" ]; then
    count=$(wc -l < "$MCP_GATEWAY_TEST_SPAWN_LOG")
fi
printf 'spawned\n' >> "$MCP_GATEWAY_TEST_SPAWN_LOG"
count=$((count + 1))
if [ "$count" -gt 1 ] && [ -n "${MCP_GATEWAY_TEST_RETRY_DELAY:-}" ]; then
    sleep "$MCP_GATEWAY_TEST_RETRY_DELAY"
fi

while IFS= read -r request; do
    case "$request" in
    *'"method":"initialize"'*)
        id=${request#*'"id":'}
        id=${id%%,*}
        fail=0
        case "$MCP_GATEWAY_TEST_SPAWN_MODE" in
        always-fail) fail=1 ;;
        fail-once) if [ "$count" -eq 1 ]; then fail=1; fi ;;
        esac
        if [ "$fail" -eq 1 ]; then
            printf '%s attempt %s\n' "$MCP_GATEWAY_TEST_SPAWN_FAILURE" "$count" >&2
            printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"%s attempt %s"}}\n' "$id" "$MCP_GATEWAY_TEST_SPAWN_FAILURE" "$count"
        else
            printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25"}}\n' "$id"
        fi
        ;;
    esac
done
"#;

/// Dies before the handshake, reporting the same cache-shaped text on stderr.
pub(super) const DYING_STUB: &str = r#"printf 'spawned\n' >> "$MCP_GATEWAY_TEST_SPAWN_LOG"
printf 'Error: Cannot find module %s\n' "'/cache/_npx/1/node_modules/zod/v3/index.js'" >&2
exit 1
"#;

/// Dies before the handshake, naming an install failure and a credential the
/// way a package manager that failed mid-authentication does.
pub(super) const LEAKY_DYING_STUB: &str = r#"printf 'spawned\n' >> "$MCP_GATEWAY_TEST_SPAWN_LOG"
printf 'npm error code %s\n' "MODULE_NOT_FOUND" >&2
printf 'Authorization: token %s\n' "ghp_SENTINELSENTINELSENTINELSENTINEL01" >&2
exit 3
"#;

/// Dies before the handshake for a reason no install can fix.
pub(super) const DYING_UNRELATED_STUB: &str = r#"printf 'spawned\n' >> "$MCP_GATEWAY_TEST_SPAWN_LOG"
printf 'Error: %s\n' "$MCP_GATEWAY_TEST_SPAWN_FAILURE" >&2
exit 1
"#;
