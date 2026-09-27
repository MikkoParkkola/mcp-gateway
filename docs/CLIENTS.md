# Supported clients

Which AI clients the gateway supports, and which of them have been seen working
against a 4.0.0 gateway.

The gateway supports a client's **config contract**: the settings key and file
that `mcp-gateway setup export` writes, and an MCP transport the client speaks
(stdio or streamable HTTP). It does not pin client builds: a matching key and
file is what export relies on, and a client that renames either breaks. That a
given client version then works is shown only by a verified row below.
The reasoning is in the
[supported matrix](release/v4.0.0-supported-matrix.md#reference-clients).

A **verified** row names a client version that was run against a 4.0.0 gateway,
with the date, the owner of the run, the gateway commit and a link to the
recorded run. Every other row is **Unverified**: no recorded run meets the rule
in [Adding a verified row](#adding-a-verified-row). For the export targets,
that leaves tests against fixture config files only.

## Clients with an export target

`mcp-gateway setup export --target <target>` writes the gateway entry into the
file below. An existing file is backed up first and the rollback command is
printed. A client whose directory does not exist is skipped: a workspace client
needs its folder (`.cursor`, `.vscode` or `.cline`) in the current directory, and Claude
Desktop, Windsurf and Zed count as not installed.

| Client | Target | Config key | Location | Status |
|---|---|---|---|---|
| Claude Code | `claude-code` | `mcpServers` | `~/.claude.json` | Verified: 2.1.280, 2026-09-23, owner Mikko Parkkola, gateway `e3c8645f`, streamable HTTP ([run](release/verify/2026-09-23-claude-code-2.1.280.md)). The run loaded the server with `--mcp-config`, so it did not exercise `~/.claude.json` |
| Claude Desktop | `claude-desktop` | `mcpServers` | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Linux `~/.config/Claude/claude_desktop_config.json`, Windows `~/AppData/Roaming/Claude/claude_desktop_config.json` | Unverified |
| Cursor | `cursor` | `mcpServers` | `.cursor/mcp.json` in the workspace | Unverified |
| VS Code Copilot | `vs-code-copilot` | `servers` | `.vscode/mcp.json` in the workspace | Unverified |
| Windsurf (Devin Desktop) | `windsurf` | `mcpServers` | `~/.codeium/windsurf/mcp_config.json` | Unverified |
| Cline | `cline-code` | `mcpServers` | `.cline/mcp_servers.json` in the workspace | Unverified |
| Zed | `zed` | `context_servers` | macOS `~/Library/Application Support/Zed/settings.json`, elsewhere `~/.config/zed/settings.json` | Unverified. With `--mode stdio`, export writes `command` as a string, while the gateway's own Zed importer reads `command.path`; one of the two shapes is wrong for Zed, and no run has settled which |

`--target generic` prints the entry to stdout, under `mcpServers`, for any
other client, and `--target all` writes every file above that is not skipped.

## Clients without an export target

| Client | How it connects | Status |
|---|---|---|
| Open WebUI | An MCP tool connection to the gateway's `/mcp` URL with an API key; per-user accounts through the hosted consent journey ([MULTI_USER.md](MULTI_USER.md#open-webui-side)) | Unverified. A recorded run exists: Open WebUI 0.11.4 sent a real `tools/call` through gateway `e2c34b78` on 2026-09-24 ([run, row 25](release/verify/2026-09-24-journey-1-live.md)), but the record names no owner, so it does not meet the rule below |

Codex CLI, Gemini CLI, JetBrains, Goose, Continue and Warp speak MCP and have
no export target. They are not claimed. Any client that speaks stdio or
streamable HTTP can be pointed at the gateway by hand; that is unverified.

## Adding a verified row

A row becomes verified only from a real run of a named client version against
a 4.0.0 gateway, recorded under `docs/release/verify/` with the client version,
the date, the owner, the gateway commit and what was called. No cell may be
inferred, and none may read "latest". Add the same row to the
[supported matrix](release/v4.0.0-supported-matrix.md#verified-against).
`tests/client_matrix_claims.rs` checks that every verified row points at a
recorded run carrying each of those values, and that both tables agree.
