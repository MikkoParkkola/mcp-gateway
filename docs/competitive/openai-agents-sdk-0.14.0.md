# OpenAI Agents SDK 0.14.0 vs mcp-gateway

**Status**: competitive scan, 2026-05-19 | **Verdict**: complement, not competitor | **Ticket**: MIK-2933

## TL;DR

OpenAI Agents SDK 0.14.0 ships an **agent-loop + sandbox + manifest** runtime. mcp-gateway is a **capability-routing + policy + observability** plane. Overlap is shallow (manifest shape, MCP transport); the load-bearing pieces (572-tool catalog, identity-bound dispatch, evidence ledger, cost routing) have no counterpart. Position: gateway sits **behind** the SDK as the tool/capability backplane an agent loop calls into.

## What 0.14.0 actually adds

1. **7 sandbox providers** — local subprocess, Docker, Firecracker, gVisor, Modal, E2B, Daytona. Execution isolation only; nothing about tool selection, auth, or cost.
2. **Manifest abstraction** — JSON-schema agent spec (model, tools, guardrails, handoffs). Declarative agent shape, not capability inventory.
3. **MCP client** — consumes MCP servers as tool sources; mirrors Claude Code / Cursor pattern.
4. Tracing UI, structured handoffs, eval harness.

Sources: openai/openai-agents-python GitHub release notes 0.14.0; SDK docs `/sandboxes` and `/mcp` sections (read 2026-05-19).

## Overlap map (where surfaces touch)

| Surface | OpenAI SDK 0.14.0 | mcp-gateway | Overlap |
|---|---|---|---|
| Tool transport | MCP client | MCP server + 28 backends | Yes — gateway is a valid SDK tool source |
| Agent loop | Yes (in-SDK) | No | None |
| Sandbox/exec isolation | 7 providers | None (delegates to caller) | None |
| Manifest | Agent-shape JSON | Capability catalog + policy | Shallow (both JSON, different domains) |
| Identity/attribution | Per-run trace id | Per-tool dispatch identity (B1) | None |
| Cost routing | None | T0/T1/T2 tiering | None |
| Evidence/audit ledger | Tracing UI | Read-ledger + DoD evidence gate | None |
| Policy guards | Guardrails (pre/post LLM) | Pre/post tool-use hooks, scope-before-treatment | Adjacent, different layer |

## Position vs complement

- **Complement**: gateway exposes its 572-tool catalog over MCP → SDK agents consume it as one tool source. Gateway's identity-bound dispatch + cost routing run beneath the SDK's loop.
- **Not competitor**: SDK ships an agent runtime; gateway ships a capability plane. Different bets (B4 Platform vs agent framework).
- **Sandbox gap is real**: gateway has no execution isolation primitive. If we ever need one (e.g. user-code tools), the SDK's sandbox abstraction is the prior art to port from, not reinvent (H1).

## So-what / actions

1. **No build response required** — SDK does not encroach on routing/policy/ledger moat.
2. **Integration spike (P2)**: ship a `mcp-gateway` recipe in OpenAI Agents SDK examples → distribution win, ~1-2 day effort. ROI ~10× (reach × low cost).
3. **Watch**: if SDK adds capability search / cost routing in 0.15+, re-score. Trigger: SDK release notes mention "tool selection" or "cost-aware routing".
4. **Sandbox decision deferred**: do not adopt sandbox abstraction until a concrete gateway use case appears (KILL by default per fail-fast).

## References

- openai/openai-agents-python release 0.14.0 (GitHub)
- SDK docs: agents, mcp, sandboxes, tracing sections
- mcp-gateway ARCHITECTURE.md (capability catalog, dispatch identity)
- Bet stack: B1 identity, B4 platform (CLAUDE.md)
