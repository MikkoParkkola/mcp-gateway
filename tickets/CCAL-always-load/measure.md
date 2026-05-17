# MIK-3639 alwaysLoad measurement log

## Current slice

Status: `CONFIGURED_PENDING_FRESH_SESSION_MEASUREMENT`.

Configured pins:

- `~/.claude.json` `mcpServers.gateway.alwaysLoad = true`
- `~/.claude.json` direct `mcpServers.hebb.alwaysLoad = true`
- `~/.codex/mcp.json` `servers.gateway.alwaysLoad = true`
- `~/.claude/mcp_servers/mcp-gateway-rs/servers.yaml` `meta_mcp.warm_start` includes `hebb`
- `~/.claude/mcp_servers/mcp-gateway-rs/servers.yaml` `meta_mcp.warm_start` includes `linear`

## Measurement method for the next fresh Claude Code session

1. Start a new Claude Code session on v2.1.121 or newer.
2. Before any `gateway_search`, call a direct hot-path tool such as `mcp__hebb__remember` or inspect the loaded tool list for the direct Hebb surface.
3. Record time-to-first-call for that always-loaded tool.
4. Call a deliberately deferred long-tail tool through the gateway search/invoke path and record time-to-first-call.
5. Target: always-loaded first call at least 10x faster than the deferred search plus invoke path.

## Why no wall-clock claim yet

The current running session cannot reload Claude Code MCP server policy, and `alwaysLoad` is a client-side loading feature. This file intentionally records configuration and a reproducible measurement plan without claiming the 10x target before a fresh-session check.
