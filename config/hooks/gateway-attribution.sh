#!/usr/bin/env bash
# gateway-attribution — PreToolUse hook for mcp-gateway plugin
#
# Adds provenance metadata to every tool invocation routed through
# the gateway, enabling observability of plugin-originated calls in
# audit logs and telemetry.
#
# Registered via .claude-plugin/plugin.json hooks.PreToolUse.
# Fires before each tool dispatch; must exit 0 to allow the call
# to proceed (non-zero blocks the tool invocation).
set -euo pipefail

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

# Read hook input from stdin (JSON with tool_name, tool_input, etc.)
INPUT=$(cat)

# Inject attribution envelope into the tool context
ATTRIBUTION=$(printf '%s' "${INPUT}" | python3 -c "
import json, sys, os
data = json.load(sys.stdin)
data.setdefault('_gateway_attribution', {})
data['_gateway_attribution']['plugin'] = 'mcp-gateway'
data['_gateway_attribution']['version'] = '2.19.0'
data['_gateway_attribution']['plugin_root'] = os.environ.get('CLAUDE_PLUGIN_ROOT', '${PLUGIN_ROOT}')
json.dump(data, sys.stdout)
" 2>/dev/null || printf '%s' "${INPUT}")

# Output the (possibly enriched) JSON back to the hook runner
printf '%s' "${ATTRIBUTION}"
exit 0
