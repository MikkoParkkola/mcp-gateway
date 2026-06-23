#!/bin/sh
# gateway-attribution PreToolUse hook (production)
# Registered by the mcp-gateway Claude Code plugin (MIK-4625.PLUGIN.3).
#
# This hook is invoked by Claude Code for PreToolUse events when the
# mcp-gateway MCP server is active. It provides attribution for tool
# invocations routed through the single Meta-MCP gateway endpoint.
#
# In full production (e.g. in botnaut-client constellation) this can:
# - emit B1-IDENT telemetry for gateway tool calls
# - annotate transcript with gateway version / config bundle id
# - enforce lightweight policy before gateway_invoke
#
# Contract: consume event JSON from stdin (if any), exit 0 to allow,
# non-zero or stderr to block the tool call (fail-closed).
#
# Path reference in plugin manifest uses ${CLAUDE_PLUGIN_ROOT} expansion.

set -eu

# Consume stdin without blocking (event may be provided).
if [ -p /dev/stdin ] || [ -t 0 ]; then
  cat >/dev/null 2>&1 || true
fi

# Attribution marker (visible in logs when hook debugging enabled).
# Do not write to stdout (would corrupt protocol); use stderr only for diagnostics.
printf '[mcp-gateway][gateway-attribution] PreToolUse hook active (plugin v1.0.0, gateway >=2.12.1)\n' >&2

exit 0
