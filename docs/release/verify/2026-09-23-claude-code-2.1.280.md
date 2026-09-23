# Verified against: Claude Code 2.1.280 on a 4.0.0 build (2026-09-23)

One run of a named client product against a 4.0.0 gateway, recorded for the
`Verified against` list in `docs/release/v4.0.0-supported-matrix.md`.

| Field | Value |
|---|---|
| Client | Claude Code (CLI), `claude --version` → `2.1.280 (Claude Code)` |
| Gateway | `mcp-gateway --version` → `mcp-gateway 4.0.0`, built `cargo build --release` at `e3c8645f` (release line) |
| Binary | sha256 prefix `1ee8fe97783b7760` |
| Date | 2026-09-23 (UTC 00:05) |
| Owner | Mikko Parkkola; run by a Claude Code agent session on his machine |
| Transport | Streamable HTTP, `http://127.0.0.1:39477/mcp` |

## What was run

Gateway config: `server.host: 127.0.0.1`, `server.port: 39477`, `meta_mcp.enabled: true`,
capabilities from `./capabilities`, no MCP backends.

Client config, in the `mcpServers` shape the Claude Code row of the matrix names:

```json
{ "mcpServers": { "gw4": { "type": "http", "url": "http://127.0.0.1:39477/mcp" } } }
```

```
claude -p "<load the schema of mcp__gw4__gateway_list_servers, call it, quote the result, list every gw4 tool>" \
  --mcp-config claude-mcp.json --strict-mcp-config \
  --allowedTools mcp__gw4 ToolSearch --model haiku --output-format json
```

`--strict-mcp-config` loads only this server, so every MCP call the client made went
to the 4.0.0 gateway.

## What each side recorded

The client (`--output-format json`, session `0a08a531-0731-4de3-b6b0-ef12ed96965b`)
finished with `is_error: false`. It listed seven gateway tools
(`gateway_invoke`, `gateway_list_disabled_capabilities`, `gateway_list_servers`,
`gateway_list_tools`, `gateway_search_tools`, `gateway_set_state`,
`gateway_webhook_status`) and quoted the raw `gateway_list_servers` result:

```json
{"servers":[{"circuit_breaker":"closed","name":"gateway","running":true,
  "status":"active","tools_count":125,"tools_known":true,"transport":"capability"}]}
```

The gateway log (`RUST_LOG=info,mcp_gateway=debug`) recorded the client arriving on the
current protocol revision, `protocol_revision="2026-07-28"`, opening with
`server/discover` rather than a legacy `initialize`. Across both client runs:

| Method | Count |
|---|---|
| `server/discover` | 2 |
| `tools/list` | 2 |
| `tools/call` | 2 |
| `resources/list` | 2 |
| `prompts/list` | 2 |
| `subscriptions/listen` | 8 |

No gateway ERROR lines. The first run discovered and listed tools but made no call,
because its prompt forbade the client's own schema-loading step; the second allowed it
and made both calls. The two `tools/call` entries are the second run's
`gateway_list_servers` and `gateway_list_tools`.

## What this does not cover

- **Authentication.** The run used a loopback-only, unauthenticated gateway; the gateway
  logged `AUTHENTICATION disabled` at startup. Bearer and OAuth paths were not exercised.
- **The config file location.** The client read its server entry through
  `--mcp-config`, which exercises the `mcpServers` key but not the `~/.claude.json`
  location the matrix row names.
- **Backends.** No MCP backend was configured; the tools called are the gateway's own
  meta-tools over its capability catalogue.
- **Any other client.** One row, for the version above only.
