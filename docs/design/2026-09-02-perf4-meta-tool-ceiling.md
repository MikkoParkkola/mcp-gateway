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

## Open questions, each scheduled (§P1)

| # | question | form | resolves by |
|---|---|---|---|
| 1 | Does any client workflow depend on `gateway_webhook_status` being enumerated, rather than discoverable? | checkable | grep the repo, README and capability docs for callers and documented usage; a documented workflow that names it changes the migration story, not the decision |
| 2 | Is webhook status reachable through dynamic discovery once removed from the surface, or is enumeration currently its only route? | checkable | trace whether the underlying handler is registered anywhere but `meta_mcp_tool_defs.rs:565`; if enumeration is the only route, option A requires a discovery path first and that work belongs to this row |
| 3 | Does removing an enumerated tool count as breaking, requiring the same treatment as the `exposed_meta_tools` change? | askable | the operator ruled `exposed_meta_tools` enforcement acceptable as a breaking change on 2026-09-02; whether this one rides that decision or needs its own is a call only they make, and it is asked before implementation, not after |

Question 2 can change the shape: if enumeration is the only route to webhook status, option A
is not a deletion but a move, and the move is the work.

## Residual risk, stated

Removing an enumerated tool is visible to any client that named it. Question 3 exists because
that is the operator's call, not the design's. If the answer is that it must stay enumerated,
option A fails and the row returns to the operator with only option C — widening — remaining,
which they have already rejected once with reasons that would then need revisiting.
