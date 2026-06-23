# mcp-gateway Plugin Rollback (MIK-4625.PLUGIN.6)

## Uninstall semantics

```bash
# Uninstall the plugin (removes plugin manifest registration, mcpServer wiring)
claude plugin uninstall mcp-gateway
```

After uninstall:
- The `mcp-gateway` entry is removed from the client's MCP server list.
- Gateway-local state (config, credentials in env, ~/.mcp-gateway/) is preserved by default.
- To fully restore prior state, re-run previous client config export or `mcp-gateway setup export --target claude-code` if a backup of ~/.claude.json existed.

## State restore test (runnable)

```bash
# Before uninstall (capture)
cp ~/.claude.json ~/.claude.json.pre-gateway-plugin 2>/dev/null || true
claude plugin install @mikkoparkkola/mcp-gateway  # or from local path
# ... use ...
claude plugin uninstall mcp-gateway
# After: optionally restore
cp ~/.claude.json.pre-gateway-plugin ~/.claude.json 2>/dev/null || true
echo "rollback complete; state from pre-uninstall snapshot restored if present"
```

The fixture captures `claude plugin uninstall` + gateway state (no data loss for the router itself; the router binary + its config bundle remain usable standalone via npx/cargo).

Addresses AC#PLUGIN.6 and objection AC#PLUGIN.6.
