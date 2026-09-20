# ADR-015: The 4.0.0 client tool surface stays classic; code mode stays opt-in

- Status: Accepted
- Date: 2026-09-16
- Supersedes: nothing
- Related: [RFC-0081](../design/RFC-0081-intelligent-tool-surfacing.md)

## Context

Two tool surfaces exist in the tree at the 4.0.0 tip:

- The **classic surface** — 9-17 meta-tools listed directly in `tools/list`, each with
  its own schema, each individually gated.
- **Code mode** — two tools, `gateway_search` and `gateway_execute`, where the
  client searches a registry and then names a target by string.

`code_mode.enabled` is `false` in the shipped example config
(`gateway.example.yaml:125-126`), so the classic surface is what an operator gets
today. The open question for 4.0.0 was whether to flip that default, and whether
administrative operations should become reachable *through* the two-tool surface
(a nested meta call: `gateway_execute` naming a meta-tool as its target).

The proposal was written up as a design brief and sent for independent review
before any code was written.

## Decision

**4.0.0 ships the classic surface as the default. `code_mode.enabled`
stays `false`. No nested meta routing is added in 4.0.0** — `gateway_execute`
does not gain the ability to name a meta-tool as its target.

The flip is re-opened for a later minor release, gated on the three entry
conditions below.

## Why

Three defects in the proposal, two of them confirmed against source:

1. **The reserved name is already taken.** The proposal reserves `gateway` as the
   meta target namespace. `CapabilityConfig::default()` already sets
   `name: "gateway"` with `enabled: true`
   (`src/config/features/capability.rs:23-25`), and that name is what
   `gateway_list_servers` shows. Overloading it makes capability calls either
   misroute or become unaddressable. An explicit discriminated target is needed,
   not a reserved backend name.

2. **The two-tool surface is not lossless.** The proposal claims a client can
   reach everything through search. It cannot reach the meta-tools:
   `code_mode_search` collects capability matches and backend matches only
   (`src/gateway/meta_mcp/search.rs:391-401`; the two collectors are at `:190`
   and `:228`). There is no meta-tool index and no meta-tool schema in the search
   result, so every management operation is invisible to an agent driving the
   two-tool surface. Flipping the default today would hide the classic surface behind a
   search that does not know they exist.

3. **Nested routing has no security design.** Reaching an admin operation through
   a generic execute tool has to clear the same exposure, admin, confirmation and
   admission gates as the direct call, with the *original* caller's context, for
   both single and chained calls. Backend ACL hooks do not cover this — they run
   below the meta layer. Nothing in the proposal routes nested calls through the
   central meta-tool gate, so a non-admin client could reach shared-state
   management operations.

Defect 3 alone is a release blocker for a flip. Defects 1 and 2 mean the flip
would also be a functional regression, not just a risk.

## Entry conditions for re-opening

All four, before the default flips in any release:

1. A discriminated meta target that does not collide with a configurable backend
   name, with a test asserting a backend named `gateway` still routes correctly.
2. Meta-tools indexed in `gateway_search` with their schemas, filtered by
   exposure and by caller standing.
3. Every nested meta call routed through the central meta-tool gate carrying the
   original caller context, with tests covering both a single call and a chain.
4. A measurement, not a tool count: serialized and tokenized cost of a classic
   `tools/list` against a complete code-mode `search` → `execute` workflow, plus
   task success rate, wrong-tool calls and round trips across the supported
   clients. The context-reduction claim is currently an argument from tool count
   alone.

Migration tests belong with the flip: omitted `code_mode` config, explicit
`false`, and an upgraded config must each behave predictably, since changing the
default is a breaking change for anyone who never set the key.

## Review record

- `gpt-review`, design stage, verdict **SHIP-WITH-FIXES** — the fixes are the
  three defects above. Run file:
  `~/.claude/data/reviews/runs/gpt-20260916T004124Z-23867.md`.
- The second reviewer produced no valid verdict (the model emitted raw tool-call
  tokens instead of a review), so this decision rests on one independent review
  plus source verification of its two citable claims. Both were confirmed at the
  cited lines.

## Consequences

- 4.0.0's client-facing surface is unchanged from what operators already run.
  No migration note is needed and no breaking-change entry is added.
- Code mode remains available to operators who opt in, with the known limitation
  that meta-tools are not reachable through it. That limitation is pre-existing,
  not introduced here.
- The tool-surface question leaves the 4.0.0 critical path. It does not block the
  release and it is not counted as an open 4.0.0 criterion.
