# mcp-gateway Claude Plugin Rollback

Addresses MIK-4625.AC.6: rollback uses normal `claude plugin uninstall`
semantics plus restoration of gateway state from the operator-owned backup.

Runnable check:

```sh
set -eu
STATE_DIR="${MCP_GATEWAY_STATE_DIR:-$HOME/.mcp-gateway}"
BACKUP_DIR="${STATE_DIR}.backup-before-plugin-uninstall"

if [ -d "$STATE_DIR" ]; then
  rm -rf "$BACKUP_DIR"
  cp -R "$STATE_DIR" "$BACKUP_DIR"
fi

claude plugin uninstall mcp-gateway

if [ -d "$BACKUP_DIR" ]; then
  rm -rf "$STATE_DIR"
  cp -R "$BACKUP_DIR" "$STATE_DIR"
fi
```

The uninstall removes the Claude plugin registration. Restoring `STATE_DIR`
preserves gateway-local configuration, cached tool metadata, and operator
state that lives outside the plugin package.
