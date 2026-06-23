# Rollback — mcp-gateway plugin uninstall

## Overview

This document describes the rollback procedure for the `mcp-gateway`
Claude Code plugin. Uninstalling the plugin must restore the gateway
to its pre-install state without leaving residual configuration or
orphaned processes.

## Uninstall Procedure

### 1. Plugin Manager Uninstall

```bash
claude plugin uninstall mcp-gateway
```

This command:
- Removes the plugin directory from `~/.claude/plugins/mcp-gateway/`
- Removes the plugin's `mcpServers` entry from the client configuration
- Stops any running gateway process spawned by the plugin
- Removes registered hooks from the hook registry

### 2. State Restoration

After uninstall, the following state must be clean:

| State                  | Expected After Uninstall                          |
|------------------------|---------------------------------------------------|
| Plugin directory       | Removed                                           |
| Gateway process (PID)  | Terminated (SIGTERM → SIGKILL after 5s timeout)   |
| mcpServers config      | Entry removed from client settings                |
| Hook registry          | PreToolUse attribution hook deregistered           |
| Backend processes      | All 29 backend subprocesses terminated             |
| Cache files            | `~/.mcp-gateway/cache/` preserved (user data)     |
| Config files           | `~/.mcp-gateway/` user configs preserved          |

### 3. Verification

```bash
# Verify no gateway process remains
pgrep -f "mcp-gateway" && echo "WARN: gateway still running" || echo "OK: clean"

# Verify plugin directory removed
test -d ~/.claude/plugins/mcp-gateway && echo "WARN: dir exists" || echo "OK: clean"

# Verify config restored
grep -q "mcp-gateway" ~/.claude/settings.json && echo "WARN: entry remains" || echo "OK: clean"
```

## Manual Rollback (Emergency)

If the plugin manager fails to clean up:

```bash
# 1. Kill any running gateway processes
pkill -f "mcp-gateway" 2>/dev/null || true

# 2. Remove plugin directory
rm -rf ~/.claude/plugins/mcp-gateway

# 3. Remove mcpServers entry from settings
# (edit ~/.claude/settings.json and remove the mcp-gateway key)

# 4. Remove hooks
# (edit ~/.claude/settings.json and remove PreToolUse hook entries
#  referencing gateway-attribution.sh)
```

## Data Preservation

The following user data is intentionally **NOT** removed during uninstall:

- `~/.mcp-gateway/.env` — environment secrets
- `~/.mcp-gateway/cache/` — response cache
- `~/.mcp-gateway/*.yaml` — user configuration files

This ensures reinstalling the plugin restores the user's working state
without requiring reconfiguration.

## Test Coverage

Rollback semantics are tested in `tests/plugin_rollback.rs`:

- `uninstall_restores_state` — verifies that removing the plugin manifest
  directory cleanly represents an uninstalled state (no residual references
  in the manifest path).
