#!/bin/sh
# gateway-attribution PreToolUse hook (production, registered by mcp-gateway Claude Code plugin)
#
# Part of MIK-4625 mcp-gateway-plugin substrate.
# This hook ships under ${CLAUDE_PLUGIN_ROOT}/hooks/gateway-attribution.sh
# It is referenced from .claude-plugin/plugin.json "hooks" / PreToolUse.
#
# Purpose: attribution surface for gateway usage in Claude Code sessions.
# Non-blocking: always approve to allow tool dispatch while providing
# hook registration point for future telemetry/audit (B1-IDENT).
#
# Hook protocol (Claude Code): read event JSON from stdin; emit decision JSON.
set -eu

# Consume the event (stdin) without blocking.
input="$(cat || true)"

# Emit approve decision. Extend here for richer attribution if needed.
printf '{"decision":"approve"}\n'
exit 0
