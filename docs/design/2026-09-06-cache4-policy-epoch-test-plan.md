# CACHE.4 policy epoch — test plan (§P2, before any test code)

Design receipt: `docs/design/2026-09-06-cache4-policy-epoch.md`.
Criteria: `docs/requirements/RELEASE-4.0.0-criteria-status.md:93` (CACHE.4a, PARTIAL) and
`:94` (CACHE.4b, ABSENT, release-blocking).
Plan rows in scope: 4.d, 4.e, 4.f.1, 4.f.2, 4.f.3, 4.g of
`docs/design/2026-08-31-cluster-f-response-cache-keying-test-plan.md`.

Every row below answers both plan-review questions: **does this criterion have a case, or a
stated reason it has none**, and **can that case actually fail**. An empty cell is the finding;
none are empty, and three rows say "none, because —" rather than inventing a case. The last of
those three is not a plan row at all but a property the design asserts in prose. Two further such
properties are carried **inside** the rows that come closest to them, in the same form: 4.g's
authorization window and 4.f.1's writer-side ordering. A claimed guarantee with no case is
visible here rather than absent — that is the whole reason these five appear at all.

## Rows

| row | case | V-model level | type | can it actually fail? |
|---|---|---|---|---|
| **4.d** routing profile in the key | **already exists** — `tests/mik_7213_acs.rs:506` `ac_cache_4a_two_routing_profiles_do_not_share_an_entry`. **Verify, do not build.** | component (pure key function) | equivalence, key-level | Not by a free failure — it is retrofitted, so it has none. What gives it a way to be wrong is the **determinism control** it already carries (`:535`): an `assert_ne!` over a key that is merely different every call passes vacuously, and the control is the assertion that catches that. Verified as read, not re-derived. |
| **4.e** protocol revision in the key | **new, and labelled** — `ac_cache_4e_seam_guard_only_this_does_not_close_the_criterion`. The label lives in the **function name** and in a comment, not only the comment. | component (pure key function) | seam guard | At the **seam**, yes: remove `protocol_revision` from the digest object (`src/cache.rs:119-125`) and it goes red. In **production**, no: both call sites pass `None` unconditionally, so nothing downstream can distinguish. That gap is the whole reason for the name — an unlabelled seam guard becomes evidence for 4.e within a week. **This case does not close 4.e** (U5, deferred). **It also carries 4.d's determinism control** (`tests/mik_7213_acs.rs:535`): 4.e's `assert_ne!` is over the same key function, so it passes vacuously for a key that is merely different every call, and the same-inputs-same-key assertion is what catches that. A seam guard without it guards nothing. |
| **4.f.1** grant change strands prior entries | **new** — `authz_cache_4b_a_grant_change_strands_the_prior_entry`, in `src/gateway/meta_mcp/authz_tests.rs`, modelled on `authz_12_refused_caller_is_not_served_a_cached_result` (`:648`): `counted_backend("alpha")` + `MetaMcp::with_features(registry, Some(cache.clone()), None, None, 300s)`. **The test holds the cache itself** — `let cache = Arc::new(ResponseCache::new())` before construction, passed as a clone, because `with_features` takes `Option<Arc<ResponseCache>>` (`src/gateway/meta_mcp/mod.rs:493-501`). `authz_12` constructs that `Arc` inline and keeps no handle (`:652`); copying it verbatim would put the size observable below out of reach and need a new accessor on `MetaMcp` to recover — a fixture specifying a path that does not exist, which is what this plan refuses in three other cells. Prime (count 1), check the hit lands (still 1 — the cache is real), mutate the grant store through `MetaMcp::set_identity_grants`, assert the primed entry is **still there** (`cache.stats().size` is still 1 — `src/cache.rs:238`, `:349`), invoke again, assert the backend **dispatched** (count 2). | component-integration (`MetaMcp` + `ResponseCache` + a registered backend) | behavioural, state-transition | Yes, and for free: no epoch writer exists today, so the third call is served from cache and the count stays 1. The observable is the **call counter**, not body text — the counter is what `authz_12` already uses and it cannot be satisfied by a body that merely looks different. The **size** assertion is the second observable and it discriminates what the counter cannot: a dispatch after a grant change is equally consistent with `ResponseCache::clear()`, the alternative the design rejected as racy and already-unwired (design L88). Stranding leaves the entry present under a key no live request can name; clearing removes it. Only `size` tells them apart, and without it 4.f.1 would go green for the mechanism this change exists to avoid. **Binding fixture constraint** (parent plan L113): the swapped-in grant store MUST leave the principal **authorized**. A revoking mutation fails authz *before* the cache is read, so the test goes green through the error path and the falsifier can no longer discriminate. Assert dispatch — **never** an error. **The writer ORDER has no case, because —** design L146 makes it part of the specification (grant store written under the write lock *first*, then the bump with `Ordering::Release`, against an `Acquire` capture-once load), and this case cannot observe it: a single-threaded sequential driver sees the same final state whichever of two writes lands first. Bump-then-write is the naive writer order and it reopens 4.g on the writer side — an invoke that snapshots the new epoch, authorizes against grants not yet published, and publishes a stale-authorization body under the fresh epoch. Carried here in the monotonicity row's "none, because —" form: the guarantee ships as a review assertion and a rustdoc invariant, and a prose guarantee with no row reads as covered. |
| **4.g** revocation race | **new** — `authz_cache_4b_read_and_write_keys_share_the_pre_dispatch_epoch` — named for what it discriminates, not for the guarantee. The authorization-window name it nearly carried (`..._the_epoch_it_was_authorized_under`) claims the property this same cell records as untested on purpose, and a coverage map reads a name. Same file and fixture, with a transport that bumps the epoch **once, on its first backend call**. **Wiring, named because the easy mistake here can never go green:** the counter is created inside `MetaMcp::new()` (design C9, choice A), so the transport must be handed a **clone of that same `Arc<AtomicU64>`** after construction — a fresh Arc bumps a counter no read side ever loads. Same reachability question as 4.f.1's, answered by module structure rather than by an accessor: `authz_tests` is a child module of the module declaring `MetaMcp` (`src/gateway/meta_mcp/mod.rs:1793`), so the test can name the field even if it stays private. **The field is not to be widened to `pub` for the test's benefit** — widening visibility is a design change, and this one is not needed, and the case then passes or fails for reasons unrelated to the race. **Three invokes, and no priming call** — a primed entry is hit by the next invoke while the epoch is still unbumped, the backend is never reached, and the bump this case turns on never fires. So: invoke once — the backend dispatches (count 1) and bumps the epoch mid-call; invoke again — now reading under the bumped epoch — and assert it dispatches (count 2), because the first call's entry belongs to the epoch it was authorized under, not the post-bump one; invoke a **third** time under that same still-bumped epoch and assert the count **stays 2**. The third invoke is not decoration, it is the premise the other two assume: with only the first two, an implementation that writes **nothing** dispatches twice and passes, so the case would prove the backend ran twice rather than that the entry landed under the pre-bump epoch. Bumping once rather than per call is what makes the third read hit — a per-call bump moves the epoch again and the count reaches 3 under the correct implementation too. | component-integration (invoke path, ordering) | order-dependent, deterministic — no threads | **Not for free, and the reason is the finding.** There is no seam between the authorization decision (`invoke.rs:906`, with grant enforcement at `:954`) and the read-side key build (`:1214`) — U1 established both are straight-line inside `invoke_tool_traced` — so "inject a bump between them" would mean adding a hook production does not have, which is the fixture-replaces-the-path defect this plan refuses elsewhere. The one interleave point a test can drive **through the production path** is the backend call, which sits between the read-side key build (`:1214`) and the write-side one (`:1787`). So this case does not go red today (it does not compile today — no epoch handle exists); it discriminates between the **two candidate implementations**: read the epoch once into a local before the authorization decision at `:906` (the fix) vs. read it at each site (the naive shape), where the naive shape writes under the post-bump epoch, the next call is served from cache, and the count stays 1. Written before the implementation, so red-at-compile and then red-at-assert against the naive shape. **Honest limit:** this covers the read-key-to-write-key window. The authorization window is closed by ORDERING, not by a test: the single read precedes every authorization input, so a bump racing it strands the entry under the old epoch rather than publishing it under the new one. No hook-free driver exists to exercise that window, and adding one would be the fixture-replaces-the-path defect again — so the ordering is asserted in review and in a rustdoc invariant, and is named here as untested on purpose. |
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

1. **4.e first, and it is green on HEAD.** The seam already exists — `protocol_revision` is hashed today and
   both call sites pass `None` — so this is a guard, not a failing test. It costs nothing and blocks nothing.
2. **4.f.1 next: the free red.** No epoch writer exists, so it fails on its own assertion against unchanged
   production code. This is the one genuine written-before-implementation failure in the set.
3. **Then the epoch field and its accessor — skeleton only, no bump wiring.** Out of order for a strict
   tests-first reading, and deliberately so: 4.g cannot compile without the handle, and a case that does not
   compile does not fail — it freezes the whole in-crate test target and takes 4.f.1's demonstrated red with it.
   A field that is only declared changes no behaviour, so 4.f.1 stays red across this step.
4. **Then 4.g**, whose first red is the named assertion against the naive shape rather than a compile error.
5. Then the implementation.

4.d is a read. Nothing is written for 4.f.2/4.f.3.

## §P2 plan review — verdicts

Dual-vendor, adversarial, on identical material: the plan above plus the review instructions.
Round 1 findings were repaired one commit per finding; each vendor then re-checked **its own**
findings (repair protocol step 6 — closure returns to the finder, never to the other vendor).

| leg | vendor | round 1 | closure | ledger row |
|---|---|---|---|---|
| 1 | Kimi | 3 findings | **SHIP** | payload digest `1625260010763a577be63f82fb21a4ff332bca687cb36ce7b3ab6e7d8905308d`, 39,525 B |
| 2 | Grok | 1 finding + 6 improvements | **SHIP** | `2026-09-06T07:58:40Z`, `head` = `head_live` = `829089d2`, `process_status: ok`, payload digest `b7b48ac4f63d4058ba9f6c8ba7a14580b7bd0326775c6c5c63dcf90f2d9f7d6b`, 18,259 B |

Both rows reconcile by the **payload digest**, exactly. An earlier draft of this section claimed
the grok leg could not — that its wrapper hashes the payload together with repository context it
adds itself. That inference came from a neighbouring row carrying 75,739 material bytes for a
smaller-looking payload; the row was another session's, on this shared branch, and the inference
was wrong. Corrected here rather than quietly, because the wrong version was committed.

**Kimi's SHIP is against the pre-repair text, and it holds.** It was issued at `84618a2e`,
before the 4.f.1 cell gained its cache-handle clause. Its three findings were 4.f.1's
writer-order sentence, 4.g's third invoke, and the five-step order of work. The later repair is
additive within a *different* clause of 4.f.1 and touches none of the three. Re-firing kimi
would buy a round and no information.

**What grok actually returned, stated as it stands.** `IMPROVEMENTS: NONE IDENTIFIED`, then a
single verdict line naming three things: the third invoke fails a skipped write, the held cache
`Arc` makes `stats().size` reachable, and neither repair stages a vacuous pass. That covers
round-1 finding 1 and the self-disclosed item 8 by name, and answers the "did a repair introduce
a new defect" question directly. It did **not** answer CLOSED/NOT CLOSED per finding as the
prompt asked. Findings 2-7 were improvements grok itself raised, and the verdict closes them
only by implication. Recorded as an implication, not as seven closures.

**The tree moved eleven commits under the review, and the citations survived it.**
`head` and `head_live` agreeing says the two samples agreed, not that nothing moved: this branch
is shared, and between the run's start (`02fcccb4`) and the row (`829089d2`) eleven commits
landed, two of them touching `invoke.rs` and `mod.rs` — files this plan cites by line. Checked
individually at the row's head: `invoke.rs:906`, `:954`, `:1214`, `:1787` and `mod.rs:493`,
`:890` all still name what the plan says they name. `mod.rs:1786` did not survive — the
`authz_tests` declaration moved to `:1793` inside that window, correct at both review heads and
stale by the time the row landed. Re-pointed in `89292be1`, immediately before this record. That is the whole
contamination check; the head-pair equality is not it.

**What of the canonical DoR actually travelled — a stated limit of both legs.** §P4 requires
every plan review to also check the canonical criteria, and both vendors are filesystem-isolated,
so a criterion that does not travel in the payload is a criterion nobody checked. What travelled
was one paraphrased sentence, identical in both payloads: judge it against the canonical DoR —
every open question scheduled (resolved = the question, the check run, what came back, what it
changed; or deferred = owner, what would resolve it, when, what if it resolves badly), an
explicit out-of-scope statement, dependencies mapped. That is the applicable subset for a plan,
and it is the subset both legs answered. What did **not** travel is
`rules-source/_reference/workflows/quality-gates-dor.md` itself — neither its text nor its path,
and neither vendor could have fetched it. So the honest claim is: the three plan-applicable
criteria were checked; the 84-gate file was not read by either reviewer. Recorded as a limit,
not repaired — re-firing both legs to transmit a file whose applicable content is those three
lines buys a round and no information.

**What the reviewers actually read.** Both payloads are the plan as of `6dd1c4fa`. This verdicts
section was appended afterwards and is not part of the reviewed material — recomputing either
digest from the current file will not reproduce it, and that is expected, not drift.
