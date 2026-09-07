# NFR.PERF.4 — restore the webhook diagnostic, correct the band

## Decision

`gateway_webhook_status` returns to the enumerated meta-tool surface, gated on the
webhook registry actually being attached. The documented band moves from 14-16 to
14-17.

Operator ruling, 2026-09-08, on whether deleting the push (`6e81ba74`) was a breaking
change: the question was the wrong one. The deletion made a documented number true by
removing a feature's only diagnostic.

## Why the deletion was the wrong repair

`webhooks.enabled` defaults to **true** (`src/config/features/webhooks.rs:31`). The
17-tool surface was therefore the shipped default, not an exotic gate combination. The
`14-16` claim in the README, the badges and `benchmarks/public_claims.json` was already
inaccurate for a normal install. Deleting the push corrected the number by damaging the
product rather than correcting the claim.

## What the tool is for

External services POST to `/webhooks/*`; the gateway validates the HMAC signature,
transforms the payload, and pushes it to connected clients as MCP notifications over SSE
(`docs/WEBHOOKS.md`). The assistant learns that a Linear issue moved without polling.

A push pipeline's characteristic failure is silence. A rotated secret makes signature
validation reject everything and events simply stop; nothing throws and nothing goes red.
`gateway_webhook_status` (received, delivered, failures, last event) is the only surface
answering "are events still arriving". A diagnostic for a silent-failure pipeline that the
assistant cannot see is a diagnostic that does not exist.

## The gate is registry attachment, not the config flag

`run_stdio` never calls `set_webhook_registry`, so over stdio the handler refuses the call
whatever the configuration says (`src/gateway/meta_mcp_tool_defs.rs:547`). This predates
the cap and is not a defect to repair: webhooks need an HTTP endpoint to receive on, so the
tool is correctly unanswerable over stdio.

Enumerating on `webhooks_enabled` alone would therefore advertise a tool that cannot answer
on the most common local transport. The gate is whether the registry is attached — exactly
the condition `webhook_status` already checks before doing any work.

Consequence for the band: stdio deployments stay at 14-16. An HTTP deployment with webhooks
enabled reaches 17.

## Scope

FOR: restoring the conditional push under a registry-attached gate; moving the documented
band to 14-17 everywhere it is claimed.

OUT: the stdio registry gap (pre-existing, separately tracked). Any change to what
`webhook_status` returns. Any other meta-tool.

## Work required

- `build_meta_tools` takes a webhook-status flag and pushes the tool when set
- the caller that knows whether `set_webhook_registry` ran supplies it
- `tests/nfr_perf_4_meta_tool_band.rs:60` asserts `14..=17` and covers the new gate as a
  fourth dimension, including the case that produces 17
- README, badges, `benchmarks/public_claims.json` and its CI drift check move to 14-17
- `governed_meta_tool_names()` keeps the name governed; the allow-list tests at
  `src/gateway/meta_mcp_tool_defs_tests.rs:496,509` must still pass with the tool
  enumerated rather than unenumerated
- the `NFR.PERF.4` ledger row records the corrected band

## Open questions

- **Does the caller of `build_meta_tools` know whether the registry is attached?** — not
  yet checked. `src/gateway/server/mod.rs:976` attaches it after construction, so the flag
  may have to be read at list time rather than passed at build time. This is load-bearing
  for the shape of the change and is the one question to settle first.
- **Does `honest_task_tokens` in the benchmark move on a 17th tool?** — not yet measured.
  The claim file has a CI drift check that will say.
