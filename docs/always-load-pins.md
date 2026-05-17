# alwaysLoad hot-path pins

MIK-3639 captures the first Claude Code v2.1.121 adoption slice for the `alwaysLoad` MCP server option. The rule is deliberately narrow: only servers that are invoked on nearly every operator session, or that unlock the router itself, should bypass tool-search deferral. Long-tail servers stay deferred so mcp-gateway keeps its context-savings story.

## Pin set

| Surface | Config location | Decision | Rationale | Rollback |
|---|---|---|---|---|
| Claude Code `gateway` server | `~/.claude.json` `mcpServers.gateway` | `alwaysLoad: true` | Gateway-core meta-tools are the control plane for discovering and invoking the long-tail portfolio tools. Loading this small surface directly avoids a gateway-search loop before gateway use. | Remove the one `alwaysLoad` field. |
| Codex `gateway` server | `~/.codex/mcp.json` `servers.gateway` | `alwaysLoad: true` | Same control-plane rationale for Codex sessions that route through the local gateway. | Remove the one `alwaysLoad` field. |
| Gateway backend `hebb` | `~/.claude/mcp_servers/mcp-gateway-rs/servers.yaml` `meta_mcp.warm_start` | warm-started | Hebb memory is mandated by portfolio workflow for meaningful turns, and the HTTP daemon is already resident at `127.0.0.1:39400`. Gateway backend configs do not implement `alwaysLoad`; warm-start is the supported backend prefetch mechanism. | Remove `hebb` from `warm_start`. |
| Gateway backend `linear` | `~/.claude/mcp_servers/mcp-gateway-rs/servers.yaml` `meta_mcp.warm_start` | warm-started | Linear is the primary backlog surface in elite-loop runs and fires on every `MIK-` issue operation. Gateway backend configs do not implement `alwaysLoad`; warm-start is the supported backend prefetch mechanism. | Remove `linear` from `warm_start`. |
| `apple-calendar` | no gateway backend found in current `servers.yaml` | defer | Apple Calendar is implemented as a skill/local CLI path in this environment, not as a gateway backend in the audited config. | N/A. |
| Other backends | current `servers.yaml` | defer | Search, browser, media, infra, and provider-specific tools remain long-tail and should keep tool-search deferral. | N/A. |

## Audit notes

- `~/.mcp.json` does not exist on this host; the active Claude Code global MCP config is `~/.claude.json`.
- Project `.mcp.json` files under `~/github` either configure unrelated legal workspaces or project-local tools such as `trvl` and `nab`; none referenced `gateway`, `hebb`, or `linear`, so no per-project hot-path edit was made.
- `~/.claude/mcp_servers/mcp-gateway-rs/servers.yaml` is the live gateway backend config on port `39401` and now carries the supported gateway warm-start intent for `hebb` and `linear`.
- Backups were created before global config edits using the suffix `.bak-mik3639-<UTC timestamp>`.

## Verification boundary

Static validation can confirm the client `alwaysLoad` fields and gateway `warm_start` entries are present and the JSON/YAML parse surface is intact. A true `mcp__hebb__remember` no-search availability check requires a fresh Claude Code session running v2.1.121 or newer because `alwaysLoad` is a client-side loading policy, not an mcp-gateway runtime behavior.
