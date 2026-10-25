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

1. **Local only for 4.0.0.** Client config files and running processes on the gateway's host (F1-F3).
2. **Add a network scan.** Probing a subnet for MCP endpoints finds servers no local config names, but it is a new capability with consent (scanning networks the operator may not own), SSRF exposure (the gateway making connections an attacker can steer), and false positives.

## Decision

Option 1. A network scan is out of 4.0.0 and filed for v4.1.0 with those three questions as its acceptance.

## Consequences

- An unmanaged server is found only if a client on this host names it or it runs on this host.
- Frame 44d's example must read as a local find (named in a client config on this host), not as a network find; the design repo changes that copy.
- The "Not behind the gateway" group on Servers lists only local finds in 4.0.0.
