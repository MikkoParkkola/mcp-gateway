<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# MIK-7272.SUB.4 — wiring idempotency enforcement

Status: **design, awaiting review**. No code written.

## Scope (§P0, frozen)

FOR: making a side-effecting call that is re-issued after a broken stream with a
new request id actually reach an idempotency guard, so `MIK-7272.SUB.4` moves
from UNWIRED to MET.

OUT: the tasks extension (`MIK-7272.TASK.1`, ABSENT — the criterion's other
branch, separately scoped); the key's composition and its fingerprint binding
(settled by ADR-008 INV-3 and MRTR.10, unchanged here); the response cache;
distributed idempotency across gateway processes; any new metric name.

## Problem

Every part of the mechanism exists and none of it runs.

- `IdempotencyCache`, `enforce`, `IdempotencyReservation` and
  `spawn_cleanup_task` are complete in `src/idempotency.rs` and unit-tested.
- The meta route's enforcement logic is complete and correct at
  `meta_mcp/invoke.rs:1148-1180`: it reads the client's key from
  `caller.retry.idempotency_key`, suffixes it with the projection and identity
  bindings, fingerprints the call with `derive_key` plus the retry
  discriminator, and holds an `IdempotencyReservation` whose `Drop` releases the
  entry.
- `MetaMcp::idempotency_cache` is initialised `None` (`meta_mcp/mod.rs:437`).
- The only populator, `MetaMcp::enable_idempotency` (`meta_mcp/mod.rs:656`),
  carries `#[allow(dead_code)]` and has zero production callers — the sole hit
  outside its own definition is `meta_mcp/tests.rs:3515`.
- So `idempotency_key_for` returns `None` at its first line (`support.rs:44`,
  `idem_cache?`), the `if let` at `invoke.rs:1174` takes the `None` branch, and
  the guard cannot fire in any deployment.
- No config key gates any of it: `rg 'idempotenc' src/config/` returns nothing.
- The direct route `POST /mcp/{name}` (`backend_handlers.rs`) never calls
  `idempotency_key_for`; its only call site is `invoke.rs:1148`.

**This is one missing constructor call plus its configuration.** Not a missing
capability, and not a policy question about what makes two calls "the same" —
that was decided in ADR-008 INV-3 and is already implemented.

The measured constraint that shapes the fix: the assembly point
`MetaMcp::with_features` (`gateway/server/mod.rs:539`) already runs four
`enable_*` calls in exactly the shape this needs (`:637`, `:657`, `:691`,
`:708`), each behind a config flag and each using
`Arc::get_mut(&mut meta_mcp).expect("no other Arc references at this point")`.

## Options (G6)

**(a) Meta route only.** One `enable_idempotency` call. REJECTED as the whole
answer: `POST /mcp/{name}` stays unguarded, and that is the route a client most
plausibly retries after a broken stream, being the thin path with no aggregation
layer to resume. Two routes would then disagree about whether a replay is a
replay.

**(b) Config-gated, default OFF.** REJECTED. `SUB.4` is a MUST; a guard off in
the default deployment satisfies it only for operators who opt in, which is the
present defect with a config key in front of it. Off-by-default is the right
posture for a feature whose cost the operator must accept — and here there is no
such cost, per the decision below.

**(c) CHOSEN — default ON, both routes, one shared guard.** Add
`IdempotencyConfig` under `config/features/` defaulting `enabled: true`; call
`enable_idempotency` from `server/mod.rs` in the existing `enable_*` chain; at
the direct route, parse `RetryFields` with the same parser the meta route uses
(`protocol/mrtr.rs:117`) and call the same `idempotency::enforce`, the pattern
`MIK-7212.MRTR.10b` established for `cacheable::is_final`.

Sharing the guard function is *not* by itself enough to give the policy a single
owner, and the first version of this design claimed it was. `idempotency_key_for`
takes an already-formatted `identity_suffix`, and that formatting is hand-written
at the call site (`invoke.rs:1128-1132`, `format!("|idp:{b}")`), where it has
exactly one consumer (`rg -n 'identity_suffix' src/gateway/meta_mcp/invoke.rs`
-> `:1128`, `:1138` comment, `:1151`). A second call site reproducing that
expression is a second derivation, and two derivations of one key is precisely
the failure the function's own doc comment warns about for the response cache:
"a write that lands under a key no read computes is a cache that never hits while
looking exactly like one that does" (`support.rs:48-51`).

So the derivation moves INTO the function rather than being duplicated beside it:
`idempotency_key_for` takes `cache_binding: Option<&str>` and formats the suffix
itself. After that change there is no second derivation to diverge — the defect
stops being describable rather than being tested for. `projection_key_suffix`
stays a parameter: it has three consumers (`:1150`, `:1218`, `:1791`) and one
producer (`crate::projection::projection_key_suffix`), so it is already
single-owner and folding it in would couple the idempotency key to the response
cache's argument list.

## Decision: default ON is not a behaviour change (§P3, named)

Turning this on changes nothing for a client that sends no idempotency key.
`idempotency_key_for` returns `None` when `client_key` is `None`
(`support.rs:45`, `let key = client_key?`), independently of whether the cache
exists, so the `if let` at `invoke.rs:1174` still takes the `None` branch and
the call dispatches exactly as today. The only clients whose behaviour changes
are those already sending a key — which they can only be doing in the
expectation that it is honoured.

This is named as a design decision anyway, because "default on" for a guard that
can return 409 is the kind of choice that must be visible rather than inferred
from a config default.

## Risks (G8)

1. **A 409 where callers previously saw a success.** `enforce` returns 409 on a
   live in-flight duplicate and on a key bound to a different fingerprint, and
   503 at `MAX_ENTRIES`. A client sending keys today gets none of these. This is
   the criterion's intent, and it is still a new failure mode reaching clients
   that never saw it.
2. **The direct route's parse is new surface.** The meta route's key handling is
   proven; the direct route's is not, and a wrong fingerprint there is worse
   than no guard — it serves one call's result to another. Mitigated by the
   shared parser, the shared `enforce`, and by hoisting the identity-suffix
   formatting into `idempotency_key_for` so the direct route cannot express a
   different key at all.
3. **In-process only.** Two gateway processes behind a load balancer do not
   share the cache. Out of scope, not a regression: nothing is shared today.

## Open questions, resolved by source check (§P1)

- *Does the direct route already carry retry fields?* — `rg -n 'idempotency_key|RetryFields|retry' src/gateway/router/backend_handlers.rs` — **no output** — so option (c) must add the parse; it is not a one-line call there as it is on the meta route. This is what makes (a) tempting and why it is rejected explicitly rather than by omission.
- *Does enabling the cache alter a keyless call?* — read `support.rs:44-46` — `idem_cache?` then `client_key?` — **no**; this is the load-bearing claim of the decision above.
- *Is a cleanup task required, or does the cache self-evict?* — read `idempotency.rs:355,605` — `evict_expired` exists but is only driven by `spawn_cleanup_task`, which `enable_idempotency` already spawns — **no separate wiring needed**.

## Deferred (owner, trigger, fallback)

- **Distributed idempotency across processes.** Owner: `MIK-7272`. Resolves when
  a multi-process deployment is supported. Trigger: the first HA deployment
  request. If it resolves badly (i.e. HA ships first), the fallback is sticky
  routing by idempotency key at the load balancer. Nothing in this change
  depends on the answer.

## Exit criteria (G18)

MET when all four behavioural tests pass:

1. A keyed call driven twice through the meta route dispatches once.
2. A keyed call driven twice through the direct route dispatches once.
3. The same logical call with the same client key, driven once through each
   route, hits ONE cache entry — the cross-route key-equivalence test. This is
   the falsifier for the divergent-derivation defect above; without it the
   single-owner claim is structural inference, and the hoist could be reverted
   with every other test still green.
4. A keyless call is unaffected on both routes, and a key bound to a different
   fingerprint returns 409 on each route.

NOT a criterion: `rg 'enable_idempotency' src/` finding a production caller. It
passes the moment the line is typed and can never fail while the change exists,
so it measures nothing. The criteria count moving from 28 blocking to 27 is an
administrative consequence of these tests passing, not evidence that they did.

KILL if: the direct-route parse turns out to require changing ADR-008 rung 2's
routing decision. That is a separate design with a separate review, and this
change would ship as option (a) plus a recorded, narrowed criterion.

## Review round 1 (§P4)

- **Codex/GPT** — leg 1 produced no verdict: the first run exited with an empty
  output file and no live process, and was relaunched. Recorded here rather than
  scraped from body text (§PA: a verdict is a ledger row and an exit status).
- **Kimi** — `SHIP-WITH-FIXES`. Run:
  `~/.claude/data/reviews/runs/synthetic-20260906T210035Z-60804.md`.

Findings and disposal:

| finding | verified at source | response |
|---|---|---|
| The single-owner claim is false: key derivation lives at the call site | CONFIRMED — `invoke.rs:1128-1132` formats `identity_suffix` by hand; `support.rs:35-44` takes it pre-formatted | ELIMINATED, not patched — derivation hoisted into `idempotency_key_for`. The finding is no longer statable. |
| Exit criteria lack a cross-route key-equivalence test and a per-route 409 test | CONFIRMED by reading the criteria as written | Both added as criteria 3 and 4. |
| The grep-based MET criterion passes by construction | CONFIRMED — `rg` for a line the change itself adds cannot fail | Removed, and its removal stated rather than silent. |
| The cited `rg` outputs are unreproducible from the reviewer's position | Accurate about the review position, not a defect in the design | Noted: the reviewer has no filesystem access, so every citation here is evidence only to a reader who can run it. The commands are recorded with their outputs above for exactly that reason. |
