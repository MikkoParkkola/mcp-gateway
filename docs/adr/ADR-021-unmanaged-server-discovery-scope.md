# ADR-021: Where 4.0.0 looks for servers outside the gateway

- **Status**: Proposed, 2026-10-25
- **Ticket**: MIK-8839 (ADR.5); unblocks U7 (MIK-8859) and the adopt decision in To do (frames 44d, 44e)
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

To do's third decision is "Adopt an unmanaged server": an MCP server agents can call directly, outside the gateway's firewall and receipts.

| # | Fact | Where |
|---|---|---|
| F1 | The gateway already scans MCP client config files on this host (Claude Desktop, Cursor, VS Code, Windsurf, Continue and others). | `src/discovery/config_scanner.rs` and its tests |
| F2 | It already scans running processes on this host for MCP servers. | `src/discovery/process_scanner.rs` |
| F3 | The shadow radar combines these into findings. | `src/discovery/shadow.rs` |
| F4 | Nothing scans a network. | `src/discovery/` (no network scanner) |

## Options

1. **Client config files only, for 4.0.0.** The adopt decision draws on the config files of MCP clients on the gateway's host (F1). The process scanner (F2) keeps its current uses and does not feed To do.
2. **Add a network scan.** Probing a subnet for MCP endpoints finds servers no local config names, but it is a new capability with consent (scanning networks the operator may not own), SSRF exposure (the gateway making connections an attacker can steer), and false positives.

## Decision

Option 1, as the ticket's ADR.5 criterion states. A network scan is out of 4.0.0 and filed for v4.1.0 with consent, SSRF and false positives as its acceptance.

## Consequences

- An unmanaged server is found only if a client config on this host names it.
- Frame 44d's example must read as a local find (named in a client config on this host), not as a network find; the design repo changes that copy.
- The "Not behind the gateway" group on Servers lists only local finds in 4.0.0.
