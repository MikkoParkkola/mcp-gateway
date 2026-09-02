# NFR.PERF.4 — how the 17th meta-tool stops counting

§P1 design note. No code. Reviewed by two vendors before an edit.

## FOR / OUT (§P0)

**FOR:** the mechanism that holds the Meta-MCP surface at 14–16 tools, given that
`gateway_webhook_status` currently makes it 17 when webhooks are enabled.

**OUT:**

- Whether the ceiling is 14–16. Ruled on by the operator on 2026-09-02: it stands, and the
  requirement is *not* widened to 14–17. Widening would raise the ceiling to match whatever
  shipped, which is the drift the claims file exists to catch.
- Whether webhook status should be *reachable*. It should. This note is about what is
  **enumerated to a model**, not about capability.
- The token-savings arithmetic in `benchmarks/public_claims.json`.

## What the criterion says, and what actually ships

> `NFR.PERF.4` — The Meta-MCP surface MUST remain 14–16 tools. `server/discover` is a
> protocol RPC, never enumerated to a model, and does not count against it.
> (`RELEASE-4.0.0-requirements.md:283`)

`benchmarks/public_claims.json:3-7` records `minimum: 14`, `readme_benchmark: 16`,
`with_webhook_status: 17`. The 17th is `gateway_webhook_status`, pushed at
`src/gateway/meta_mcp_tool_defs.rs:565` behind `webhooks_enabled`.

## The existing test does not hold the ceiling, and it is worth being precise about why

`tests/public_claims_validation.rs:247-256` looks like the mechanism and is not:

```
let actual = live_meta_tool_counts();
assert_eq!(actual, claims.meta_tools, "public claims file should track the live ...");
```

It asserts the **JSON equals reality**. It is a drift detector for the published claims, and
it is a good one — but it passes at 17, and it would pass at 30, because the pinned value
moves with whatever ships. Nothing anywhere compares the model-facing count against the
ceiling the requirement states. That absence is the finding, not the 17 itself.

This distinction is the whole row: `NFR.PERF.4` is marked ABSENT because *nothing clamps the
count*, and a test that records the count is not a test that clamps it.

## The criterion already contains its own answer

The requirement exempts `server/discover` on a stated principle: it is *"never enumerated to
a model"*. That is the exemption's whole basis — not that it is unimportant, but that a model
never sees it, so it costs no context, and context is the entire value proposition
(`CLAUDE.md`, locked decision: *"Meta-MCP surface is compact — context-token savings are the
entire value proposition"*).

So the mechanism is not invented here; it is applied. **A thing counts against the ceiling
exactly when a model is shown it.** The question becomes narrow and decidable: is
`gateway_webhook_status` shown to a model?

Today, yes — it is pushed into the `tools/list` result. That is why it counts, and no
declaration can make it stop counting while that remains true.

## Options, and why the others are rejected

| option | verdict |
|---|---|
| **A. Remove it from the enumerated surface; serve webhook status through dynamic discovery** | **chosen** |
| B. Declare it exempt, as `server/discover` is | rejected — `server/discover` is exempt *because* it is not enumerated. Exempting an enumerated tool by declaration keeps the context cost and deletes only the evidence of it. It makes the criterion unfalsifiable. |
| C. Widen the ceiling to 14–17 | rejected by the operator on 2026-09-02, and it reverses a locked decision. |
| D. Keep 17 and note it as residual risk | rejected — a MUST with a stated limit against it is an unmet requirement, not an accepted one. |

Option A is also what the repo's own anti-pattern list already prescribes: *"Bloating the
Meta-MCP surface — default to dynamic discovery; add a meta-tool only if the user-visible
workflow demands it."* A status query is the named example of a meta-tool that could be
dynamic discovery.

Under A the surface is 14–16 in **every** configuration, the conditional 17th disappears,
and no exemption machinery has to exist. The finding stops being statable rather than
becoming permitted — which is the elimination test.

## The mechanism that then holds it

One assertion the suite does not currently have: the live model-facing count, in every
configuration the test already builds, is `<= 16`. Stated against the ceiling directly, not
against a pinned number, so it cannot drift with what ships. The existing equality assertion
stays — the two answer different questions and both are wanted.

## Open questions (§P1)

Questions 1 and 2 are checkable and were run. Question 3 is askable and is open.

**1 — Does any client workflow depend on `gateway_webhook_status` being *enumerated*
rather than merely callable?** — `rg -n "gateway_webhook_status" --hidden -g '!target' .` —
eight hits, all internal: the builder (`meta_mcp_tool_defs.rs:242`), the conditional push
(`:565`), the dispatch arm and fallback list (`meta_mcp/mod.rs:1404`, `:1425`), the registry
wiring (`server/mod.rs:947`), four test assertions, and this release's own planning
documents. No README, capability document or client-facing workflow names it. — **Changed
nothing about the decision**, which is the useful answer: there is no documented usage to
migrate, so there is no migration story to write.

**2 — Is webhook status still reachable once removed from the enumerated surface, or is
enumeration its only route?** — read `meta_mcp/mod.rs:1392-1435` — `handle_tools_call`
dispatches on a `match tool_name` whose arm `"gateway_webhook_status" => self.webhook_status()`
is written independently of the list built in `meta_mcp_tool_defs.rs`. Nothing on the call
path consults the enumeration. — **Changed the shape of the work, and shrank it.** The note
anticipated that option A might be a *move* needing a discovery path built first. It is not:
deleting the push at `:565` leaves the tool callable by name on both transports. The 17th
tool stops being shown to a model and stays available to anything that asks for it — the
`server/discover` exemption's own principle, applied rather than declared.

Two mechanical consequences belong to the implementation:

- The name stays in the fallback list at `meta_mcp/mod.rs:1425`, which recognises meta-tool
  names for error handling. A still-callable tool must stay recognised there, or a working
  call starts reporting no such tool.
- The surface is spelled in three places — the enumeration, the dispatch `match`, and that
  fallback list. Only the first is model-facing and only the first changes. Worth stating
  because the other two look like the surface and are not; the ceiling assertion must count
  the enumeration or it measures the wrong list.

**3 — Does removing an enumerated tool count as a breaking change, requiring the same
treatment as `exposed_meta_tools`?** — *askable, open, asked before implementation.* The
operator ruled `exposed_meta_tools` enforcement acceptable as breaking on 2026-09-02;
whether this rides that decision or needs its own is theirs to make. Question 2 narrows the
stake: the tool stays callable, so the break is confined to a client that enumerates and
matches on the list rather than calling by name.

## Residual risk, stated

Removing an enumerated tool is visible to any client that named it. Question 3 exists because
that is the operator's call, not the design's. If the answer is that it must stay enumerated,
option A fails and the row returns to the operator with only option C — widening — remaining,
which they have already rejected once with reasons that would then need revisiting.
