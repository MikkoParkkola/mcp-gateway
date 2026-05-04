# ADR-003: MCP Tool Annotation Policy

**Date**: 2026-05-03
**Status**: Accepted
**Deciders**: Mikko Parkkola
**References**: MIK-2985, MCP 2025-11-25 tool annotations

---

## Context

mcp-gateway exposes two kinds of tools:

1. Gateway-owned meta-tools such as `gateway_search_tools`, `gateway_invoke`,
   `gateway_search`, and `gateway_execute`.
2. Backend tools discovered from downstream MCP servers and surfaced through
   list/search/proxy paths.

MCP 2025-11-25 clients can use `title`, `readOnlyHint`, `destructiveHint`,
`idempotentHint`, and `openWorldHint` to decide which tools are safe to call,
how prominently to display them, and whether user confirmation is needed.
These annotation bytes count against the same context budget as every other
tool definition, so the policy needs to be explicit and compact.

---

## Decision

Use a hybrid policy.

- Gateway-owned meta-tools are annotated by mcp-gateway. They must always carry
  `title`, `readOnlyHint`, `destructiveHint`, `idempotentHint`, and
  `openWorldHint`.
- Backend tools pass through downstream annotations unchanged when the backend
  already supplied a field.
- Backend tools with missing hints are filled by the gateway using conservative
  name and backend heuristics. This keeps old or sparse backends usable without
  overwriting newer servers that provide better semantic metadata.
- The gateway does not apply one global override to all backend tools. A global
  override would hide useful downstream semantics and would be wrong for
  local-only backends, networked APIs, and destructive operator tools.

---

## Consequences

- Meta-MCP clients can rely on gateway meta-tools having a complete annotation
  shape in both normal and Code Mode surfaces.
- Downstream servers remain the source of truth for their own explicit
  annotation decisions.
- The gateway still protects older backends by filling missing hints before
  tools reach discovery, direct proxy, UI, or search-cache paths.
- Tests must cover both sides of the contract: complete gateway meta-tool
  annotations and downstream annotation pass-through.
