# CACHE.4 policy epoch — test plan (§P2, before any test code)

Design receipt: `docs/design/2026-09-06-cache4-policy-epoch.md`.
Criteria: `docs/requirements/RELEASE-4.0.0-criteria-status.md:93` (CACHE.4a, PARTIAL) and
`:94` (CACHE.4b, ABSENT, release-blocking).
Plan rows in scope: 4.d, 4.e, 4.f.1, 4.f.2, 4.f.3, 4.g of
`docs/design/2026-08-31-cluster-f-response-cache-keying-test-plan.md`.

Every row below answers both plan-review questions: **does this criterion have a case, or a
stated reason it has none**, and **can that case actually fail**. An empty cell is the finding;
none are empty, and three rows say "none, because —" rather than inventing a case. The last of
those three is not a plan row at all but a property the design asserts in prose, carried here so
that a claimed guarantee with no case is visible rather than absent.

## Rows

| row | case | V-model level | type | can it actually fail? |
|---|---|---|---|---|
| **4.d** routing profile in the key | **already exists** — `tests/mik_7213_acs.rs:506` `ac_cache_4a_two_routing_profiles_do_not_share_an_entry`. **Verify, do not build.** | component (pure key function) | equivalence, key-level | Not by a free failure — it is retrofitted, so it has none. What gives it a way to be wrong is the **determinism control** it already carries (`:535`): an `assert_ne!` over a key that is merely different every call passes vacuously, and the control is the assertion that catches that. Verified as read, not re-derived. |
| **4.e** protocol revision in the key | **new, and labelled** — `ac_cache_4e_seam_guard_only_this_does_not_close_the_criterion`. The label lives in the **function name** and in a comment, not only the comment. | component (pure key function) | seam guard | At the **seam**, yes: remove `protocol_revision` from the digest object (`src/cache.rs:119-125`) and it goes red. In **production**, no: both call sites pass `None` unconditionally, so nothing downstream can distinguish. That gap is the whole reason for the name — an unlabelled seam guard becomes evidence for 4.e within a week. **This case does not close 4.e** (U5, deferred). |
| **4.f.1** grant change strands prior entries | **new** — `authz_cache_4b_a_grant_change_strands_the_prior_entry`, in `src/gateway/meta_mcp/authz_tests.rs`, modelled on `authz_12_refused_caller_is_not_served_a_cached_result` (`:648`): `counted_backend("alpha")` + `MetaMcp::with_features(registry, Some(ResponseCache::new()), None, None, 300s)`. Prime (count 1), check the hit lands (still 1 — the cache is real), mutate the grant store through `MetaMcp::set_identity_grants`, invoke again, assert the backend **dispatched** (count 2). | component-integration (`MetaMcp` + `ResponseCache` + a registered backend) | behavioural, state-transition | Yes, and for free: no epoch writer exists today, so the third call is served from cache and the count stays 1. The observable is the **call counter**, not body text — the counter is what `authz_12` already uses and it cannot be satisfied by a body that merely looks different. **Binding fixture constraint** (parent plan L113): the swapped-in grant store MUST leave the principal **authorized**. A revoking mutation fails authz *before* the cache is read, so the test goes green through the error path and the falsifier can no longer discriminate. Assert dispatch — **never** an error. |
| **4.g** revocation race | **new** — `authz_cache_4b_the_key_uses_the_epoch_it_was_authorized_under`, same file and fixture, with a transport that bumps the epoch **when the backend is called**. Prime, then invoke with the bumping transport, then invoke again and assert the backend dispatches: the in-flight call must have written its entry under the epoch it was authorized under, not the post-bump one. | component-integration (invoke path, ordering) | order-dependent, deterministic — no threads | **Not for free, and the reason is the finding.** There is no seam between the authorization decision (`invoke.rs:906`, with grant enforcement at `:954`) and the read-side key build (`:1214`) — U1 established both are straight-line inside `invoke_tool_traced` — so "inject a bump between them" would mean adding a hook production does not have, which is the fixture-replaces-the-path defect this plan refuses elsewhere. The one interleave point a test can drive **through the production path** is the backend call, which sits between the read-side key build (`:1214`) and the write-side one (`:1787`). So this case does not go red today (it does not compile today — no epoch handle exists); it discriminates between the **two candidate implementations**: read the epoch once into a local before the authorization decision at `:906` (the fix) vs. read it at each site (the naive shape), where the naive shape writes under the post-bump epoch, the next call is served from cache, and the count stays 1. Written before the implementation, so red-at-compile and then red-at-assert against the naive shape. **Honest limit:** this covers the read-key-to-write-key window. The authorization window is closed by ORDERING, not by a test: the single read precedes every authorization input, so a bump racing it strands the entry under the old epoch rather than publishing it under the new one. No hook-free driver exists to exercise that window, and adding one would be the fixture-replaces-the-path defect again — so the ordering is asserted in review and in a rustdoc invariant, and is named here as untested on purpose. |
| **4.f.2** `LiveConfig` reload bumps the epoch | **no coverage — deferred, U6.** | — | — | **Stated reason:** nothing wires the epoch to `ConfigWatcher::start`; reaching it is two signature changes and a design event of its own. The only case writable today is one that bumps the epoch by hand and calls that a reload — a fixture standing in for the production path it claims to test, which is the exact failure the honesty protocol exists to catch. Row stays open on the release board. |
| **4.f.3** capability watcher bumps the epoch | **no coverage — deferred, U6.** | — | — | Same reason, same watcher-construction seam (`src/gateway/server/mod.rs:874`). Recorded as an explicit empty cell so the gap is visible; a missing row would read as an oversight. |
| **epoch monotonicity** (design L154-162, the `policy_epoch` tradeoff bullet — not a parent-plan row) | **no coverage — and it is not deferred, it ships.** The design commits to one `debug_assert` at the bump site that the new value exceeds the old. | — | — | **Stated reason:** the only way to drive it red is to reset the counter, and nothing production-side can — it is created once in `MetaMcp::new()`. A case would have to construct the reset itself, which is a fixture standing in for a path that does not exist. The `debug_assert` **is** the evidence; it fires in every debug-profile test run that bumps, so a future re-initialisation path trips it at the first bump rather than at the first stale hit. Recorded here because the design asserts the guarantee in prose, and a prose guarantee with no row reads as covered. |

## Where these tests live, and why it is not `tests/mik_7213_acs.rs`

4.e is a pure key-function case and sits beside 4.d in `tests/mik_7213_acs.rs`. 4.f.1 and 4.g cannot: they need a registered backend that returns a body, and
`Backend::set_transport_for_test` is `pub(crate)` (`src/backend/pool.rs:344`), so no integration test under `tests/` can build one. The integration fixture in that file
(`state()`, `:141`) registers an **empty** `BackendRegistry`, and the existing 4.d case is a pure key call that proves nothing about backend fixtures. In-crate
`authz_tests.rs` already has every piece — counted backend, real `ResponseCache`, grant plumbing — so the cost of these two rows is a test each, not a fixture each.

## What this plan does not claim

CACHE.4b reads "invalidates it on a grant **or profile** change". These cases close the **grant**
half **at the `MetaMcp` layer only** (4.f.1) — the executor holds a second response cache keyed on
capability name and a params digest alone (`src/capability/executor/mod.rs:313-318`, `:347-349`),
so a post-bump miss can still be refilled from a pre-bump body; that layer is a named residual in
the design and no row here covers it. They also close the identity reading of the profile half (4.d — a different profile *name* is
already a different key). They do **not** close the contents reading: `routing_profile` is wired
to `&profile.name` at both sites (`invoke.rs:1214`, `:1787`), so a profile whose permissions
change under the same name keys identically. That is 4.f.2/4.f.3, deferred. **"Epoch landed" is
not "4b met".**

## Order of work

Failing tests first, in the order 4.e (seam guard) → 4.f.1 → 4.g, then the implementation.
4.d is a read. Nothing is written for 4.f.2/4.f.3.
