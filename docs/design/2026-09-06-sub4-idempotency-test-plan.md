# MIK-7272.SUB.4 — idempotency wiring, test plan (§P2)

Status: plan, pre-implementation. Reviewed by both legs before any test code is
written. Design: `docs/design/2026-09-06-sub4-idempotency-wiring.md`.

## §P0 SCOPE

FOR: proving that the idempotency guard is reachable on both routes, keyed on
one derivation, and inert for callers that send no key.

OUT:
- the guard's internal admission logic (`IdempotencyCache::admit`, TTL, eviction,
  `MAX_ENTRIES` refusal) — already covered by `src/idempotency.rs` unit tests;
  this change wires an existing guard, it does not modify it.
- distributed idempotency across processes (deferred, owner `MIK-7272`).
- the response cache's own keying (`tests/…response_cache…`) — it shares the
  principal but not this criterion.

## Cases

One row per exit criterion. `Level` is the V-model level; `Type` is the test
kind. Every row names how it fails, because a case that cannot fail is not a
case.

| # | Criterion | Level | Type | Case | How it fails |
|---|---|---|---|---|---|
| 1 | keyed call twice on the meta route dispatches once | integration | behavioural | drive `gateway_invoke` twice with the same `_meta` idempotency key against a counting backend; assert the backend saw ONE call and the second response equals the first | the guard is never constructed (config default off, or `enable_idempotency` unreachable from the server build) → backend sees TWO calls |
| 2 | keyed call twice on the direct route dispatches once | integration | behavioural | same, driven through the direct backend handler | the direct route never parses `RetryFields` or never calls `enforce` → TWO calls. This is the criterion the current code fails; it is the whole change. |
| 3 | one key, one call per route, keys differ ONLY in the route discriminator, at every principal rung | integration | behavioural | parameterized over the four principal rungs (propagated `cache_binding`, OIDC subject, static-key digest, anonymous `None`): per rung, drive the same logical call once per route holding principal and projection equal; read both keys out of the cache; assert two entries, and that the two key strings differ only by the discriminator substring | a hand-rolled second derivation on the direct route drops the projection suffix or the principal → the keys differ in more than the discriminator. A shared single entry → one entry, not two. A derivation that resolves the rung correctly on one route and falls through to a different rung on the other fails at that rung only, which is why one rung is not enough. |
| 4a | a keyless call is unaffected on both routes | integration | behavioural | drive the same call twice with no key on each route; assert TWO dispatches per route | a derived-key regression (deriving a key from server+tool+arguments) makes the second call return the first's result → ONE dispatch |
| 4b | a key bound to a different fingerprint returns 409 on each route | integration | behavioural | reuse one key for a call with different arguments on each route; assert 409 with the fingerprint-mismatch error on both | the fingerprint is not passed, or is computed from the key rather than the request → the second call succeeds |

## Q1 — does every criterion have a case?

Yes: criteria 1, 2, 3 map to rows 1, 2, 3; criterion 4 is two independent
assertions and is split into 4a and 4b rather than folded into one row, because a
row that asserts both passes while only one holds.

## Q2 — can each case actually fail?

Rows 1, 2, 4a and 4b fail today, before any implementation exists: the direct
route has no `enforce` call at all, so row 2 fails on the count and rows 3, 4b
fail on the direct leg. Row 1 fails only if the config default is off — which is
this change's decision to make it on, so the row is a genuine check of that
decision and not of the guard. Row 4a is the one row expected to pass BEFORE the
change as well as after; it is a regression guard, and it earns its place because
the design's keyless no-op claim is load-bearing (`support.rs:45`) and a future
edit adding a derived key would silently break every unkeyed caller.

No row's fixture constructs the condition it observes: the dispatch counter lives
in the test backend, not in the guard, and the key strings in row 3 are read out
of the cache rather than recomputed by the test. A test that recomputed the key
by calling `idempotency_key_for` would agree with the implementation by
construction and prove nothing.

## Placement

`tests/mik_7272_sub4_acs.rs`, following the existing per-criterion convention
(`tests/mik_7272_task_1_acs.rs`, `tests/idem_p1_p3_p6_acs.rs`). No new harness:
the counting-backend fixture already exists in the integration suite.
