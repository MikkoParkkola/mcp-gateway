# CACHE.4a / CACHE.4b — supplying and bumping the policy epoch the cache key already consumes

Design receipt. NO CODE. Companion to `docs/design/2026-08-31-cluster-f-response-cache-keying.md`
(new file rather than an edit: that document is the receipt of a landed change and its
eight-row verdict table is cited by others; this is a separate change with its own scope).

Release criteria owned here: `docs/requirements/RELEASE-4.0.0-criteria-status.md:93` (CACHE.4a,
PARTIAL) and `:94` (CACHE.4b, ABSENT, blocking). Test-plan rows in scope: 4.d, 4.e, 4.f.1,
4.f.2, 4.f.3, 4.g of `docs/design/2026-08-31-cluster-f-response-cache-keying-test-plan.md`.

## §P0 SCOPE

**FOR**: the response cache must not serve a body assembled under an authorization that has
since been superseded. One mechanism, not two — CACHE.4a (which dimensions key the entry) and
CACHE.4b (stale-authorization serving) are the same digest read at two moments.

**OUT**:
- 4.a, 4.b, 4.c, 4.k, 4.l.1, 4.l.2 — other owners / already closed.
- Per-principal or per-subject epoch granularity (see Accepted tradeoffs).
- Wiring the negotiated protocol revision down from the router (see U5 / 4.e, deferred).
- `src/capability/definition/mod.rs`, `src/capability/executor/`, `src/error.rs`,
  `RELEASE-4.0.0-criteria-status.md:344` and `:393` — owned by others; findings reported, not fixed.
  The executor's own unkeyed response cache is exactly such a reported finding: it bounds what the
  FOR sentence above can be true of, and it is the first row of the residual table below.
- Cache size, eviction, TTL. CACHE.4b is a security row, not a caching row.

## Problem, stated at source

The brief said "no policy epoch participates in `response_key`" and "routing profile and
protocol revision are still absent from the key". **Both are false as observations.**
`src/cache.rs:101` already defines `KeyContext { routing_profile, protocol_revision,
policy_epoch }`; `:112` hashes all three unconditionally into one digest; `:279`
`response_key` appends it as `|ctx:<digest>`. 4.d is already tested at
`tests/mik_7213_acs.rs:506`.

The brief's *conclusion* is nonetheless correct: a grant change leaves prior entries servable.
The reason is one line, twice:

```
src/gateway/meta_mcp/invoke.rs:1214   (cache read)
src/gateway/meta_mcp/invoke.rs:1787   (cache write)
    crate::cache::KeyContext { routing_profile: &profile.name,
                               protocol_revision: None,
                               policy_epoch: 0 }
```

The dimension is keyed. The **value** is hardcoded `0` and nothing in `src/` ever writes a
policy epoch — verified by searching `policy_epoch|PolicyEpoch|epoch|generation` across `src/`:
zero hits that are a policy generation (only certificate generation, protocol era, a
continuation unix-epoch, and k8s CR generation).

So the work is **not** "add a dimension to the key". It is "supply and bump a value the key
already consumes". Narrower, and a different shape, than briefed.

The test plan's own note that 4.d/4.e are "Blocked: `build_key` has no revision parameter and
the finished key has no callable form" is likewise stale — `response_key` + `KeyContext` lifted
that block.

## Measured constraints

| # | constraint | how established |
|---|---|---|
| C1 | Both key builds sit in **one function body**, `invoke_tool_traced` (invoke.rs:862–1896). | fn-boundary scan of invoke.rs; no `fn` declared between 862 and 1896. |
| C2 | The authorization decision precedes both: `authorizer.authorize(target)` at :906, `enforce_identity_grants(...)` at :954. | rg over 860–1230. |
| C3 | `set_identity_grants` (mod.rs:890) is the **sole** writer of the grant store (`*self.identity_grants.write() = grants;`). | `rg identity_grants src/ \| rg 'write()'` → one hit. |
| C4 | Its only production caller is `server/mod.rs:734`, at **startup**, through `Arc::get_mut`. There is no runtime grant-reload path today. | rg over src/ and tests/. |
| C5 | `MetaMcp` holds **no** `LiveConfig` and **no** `CapabilityWatcher` handle. | rg over `meta_mcp/mod.rs` → zero hits. |
| C6 | `KeyContext::digest()` hashes all three fields unconditionally, and `KeyContext::default()` is used by peers at `support.rs:546`, `:558` and `meta_mcp/tests.rs:4356`. | cache.rs:112; rg for `KeyContext::default`. |
| C7 | `ResponseCache::clear()` (cache.rs:302) has no production caller — tests only (`:442`). | rg for `.clear()` on the cache. |
| C8 | `set_identity_grants` takes **`&self`** (`*self.identity_grants.write() = grants;`). An `Arc<AtomicU64>` field bumps under `&self`, so 4.f.1 needs **no signature change** — production reaches it through `Arc::get_mut`, but the method itself does not require `&mut self`. | mod.rs:890-892. |
| C9 | Every one of the ~110 `MetaMcp::new` call sites across 25 files passes **exactly one** argument. An epoch initialised inside `new()` has zero blast radius; an injected handle would touch all 25 files. | `rg -c 'MetaMcp::new' src/ tests/` + arity scan. |

## Options considered

### Where the epoch lives

| option | rejected because |
|---|---|
| **A. `Arc<AtomicU64>` field on `MetaMcp`** | **CHOSEN.** The grant store it tracks is already a `MetaMcp` field (mod.rs:394); the sole writer is already a `MetaMcp` method (C3); the sole reader is already a `MetaMcp` method body (C1). Owner and both endpoints are the same object, so no new plumbing exists to get wrong. |
| B. counter on `ResponseCache` | The cache is `Option<Arc<ResponseCache>>` (mod.rs:219). An authorization epoch that vanishes when caching is disabled is an authorization fact stored in a performance component. Also puts the bump behind a null check that has nothing to do with grants. |
| C. counter in `config_reload` | Grants are not config. C5 says `MetaMcp` cannot reach it, so every read would need new plumbing to serve the one site that reads it. |

### Invalidation mechanism

| option | rejected because |
|---|---|
| **epoch bump** | **CHOSEN.** A post-bump reader computes a key that cannot *name* the superseded entry. The stale entry is stranded, not hunted. |
| `ResponseCache::clear()` (C7, already unwired) | It is the patch, not the elimination. It is global — every principal loses every entry on any grant change — and it is racy in exactly the way 4.g describes: an invocation authorized before the bump still writes *after* the clear, re-inserting a stale-authorization entry under a live key. Test: after the fix, can the finding still be stated? With `clear()`, yes. With the epoch, the entry is undescribable by any post-bump key. |

### The 4.g race — how the fix is shaped

The race is not "the epoch is missing from the key". It is that :1214 and :1787 read the epoch
**independently**. A bump landing between them makes the read miss and the write land under the
*post*-bump epoch — a body assembled under the superseded authorization, wearing the new
authorization's name, and therefore retrievable by every subsequent reader.

Fix, per C1+C2: read the epoch **once**, into a local, and thread that same local into both
`KeyContext` builds. One read means the two builds cannot disagree; there is no window for them
to disagree in. This is an ordering, not a lock — the repair protocol's "an order in which the
race cannot arise".

**Where the single read goes is load-bearing, and the first draft of this design put it on the
wrong side.** It read the epoch immediately *after* the authorization decision. A bump landing
between `authorize` at :906 and that read then yields the *post*-bump epoch for a body whose
authorization inputs were read *pre*-bump — the entry is written under the new epoch wearing the
old authorization, which is the 4.g failure this design exists to remove, merely narrowed to a
smaller window. Narrowing a race is patching it; the test is whether the finding can still be
stated afterwards, and there it still could.

The read therefore happens **before** the authorization decision at :906 — earlier than every
input the authorization consumes (`authorizer.authorize` at :906 and `enforce_identity_grants`
at :954). A bump landing after the read now strands the entry under the *old* epoch: no
post-bump reader can name it, and the request that raced simply writes a cache line nobody will
ever look up. The failure mode is a wasted insert, never a stale serve. Stale-closed beats
stale-open, and only this ordering gives it.

Two distinct properties live here and they have different evidence, so they are not merged:

| property | evidence |
|---|---|
| the two key builds use the *same* value (no re-read at the write site) | the 4.g falsifier below — re-reading at `:1787` turns the assertion red |
| the single read happens *before* `:906` | **nothing mechanical.** No hook-free driver reaches that window, and adding one would replace the production path with the fixture |

The second is recorded as UNTESTED, not as covered. A rustdoc invariant on the `policy_epoch`
accessor states it for the next reader, and a comment stating a property is not a test — it is
indistinguishable from coverage to a reviewer and to a coverage map alike, which is precisely
why it is written down here as an untested property rather than left to look like one.

**Falsifier (this is the row that proves the implementation, not merely the key):** read the
epoch fresh at the write site instead of threading the captured value. The entry then lands
under the post-bump epoch and the plan's assertion (ii) — "a post-bump reader cannot retrieve
it" — goes red. A test that only asserts the epoch is *in* the key stays green under that
mutation and therefore proves nothing about 4.g.

For 4.f.1 the falsifier is the **backend call counter**, the same observable the test plan uses,
and never body text: remove the bump (or pin the source to 0) → the post-change invoke is served
from cache → the counted backend's count stays at 1 → red. The counted backend returns a constant
body, so a response-inequality assertion cannot go red and is not the falsifier.

## Row-by-row disposition

| row | verdict | why |
|---|---|---|
| 4.d routing profile, key-level | **Already done — verify, do not build.** `KeyContext.routing_profile` is wired to `&profile.name` at both sites and tested at `tests/mik_7213_acs.rs:506` with a determinism control. Work here is confirming the test still binds after the epoch lands, and correcting the ledger. |
| 4.e protocol revision, key-level | **Seam guarded, row DEFERRED.** See U5. A key-level `assert_ne!` over `protocol_revision` is trivially green today and would be a passing test over an unwired dimension — production passes `None` unconditionally at both sites. The guard test is **to be written**, labelled as a seam guard in its **function name** and in a comment; it does **not** close 4.e. An unlabelled seam guard becomes evidence for the criterion within a week. |
| 4.f.1 grant-store mutation | **In scope.** Bump in `set_identity_grants` (C8: `&self`, no signature change). **Order is part of the specification, not an implementation detail:** write the grant store first **while still holding the write lock**, then bump with `Ordering::Release`; the capture-once load before `:906` is `Ordering::Acquire`. Bump-then-write reopens 4.g on the *writer* side — an invoke that snapshots the new epoch, then authorizes against grants not yet published, publishes a stale-authorization body under the fresh epoch, which is exactly the serve this design exists to remove. `Release`/`Acquire` is what makes "the store was written" visible to any reader that observed the new epoch; `Relaxed` would not. Honest limit recorded below. Test-shape constraint, recorded here so the plan inherits it: the mutation the test swaps in **must keep the same principal authorized**. A mutation that revokes the caller makes the second request fail authorization before it reaches the cache — the test then goes green for the wrong reason, and the 4.f.1 falsifier cannot tell the two apart. The observable is the **backend call counter**, never body text and never an error: the counted backend returns a constant body, so an `assert_ne!` over the response cannot go red — remove the bump and the count stays at 1, which is what discriminates a bump from a hit. |
| 4.f.2 `LiveConfig` reload | **DEFERRED** — C5. |
| 4.f.3 `CapabilityWatcher` reload | **DEFERRED** — C5. |
| 4.g revocation race | **In scope, and the load-bearing row.** Capture-once *before* the authorization decision at :906 (`Ordering::Acquire`, pairing with the `Release` bump above), threaded to :1214 and :1787. |

## Accepted tradeoffs, named so they are not re-derived

- **One global epoch, not per-subject.** Any grant change strands every principal's entries.
  That is a throughput property, not a correctness one, and it errs toward serving less. The
  dual review that shaped the parent design already took this direction (parent plan L268).
- **`policy_epoch` stays `u64` with `Default` = 0.** Not a newtype, not an `Option`. C6: the
  moment a non-zero epoch appears every production key changes — fine on a cold cache — but
  changing the *type* breaks peers' `..KeyContext::default()` call sites for no gain.
  The type carries no monotonicity guarantee, and nothing today can reset the counter because
  it is created once inside `MetaMcp::new()`. A future re-initialisation path could, and a reset
  epoch reuses keys minted under superseded grants — the exact collision the epoch removes. The
  guard is one `debug_assert` at the bump site that the new value exceeds the old, added with
  the bump rather than after the regression, so a reset becomes a test failure instead of a
  silent cross-epoch hit.
- **The bump is latent in production today.** C4: `set_identity_grants` runs once at startup,
  before any entry exists, so the 4.f.1 bump changes no production behaviour *yet*. It is not
  dead code — it is the correct behaviour at the only mutation point that exists. It is **not**
  "safe by construction" for a future runtime grant-reload: a second, lower cache sits under this
  one (see the residual table below), and until that one is keyed too, a runtime reload is safe
  only for responses the executor never cached. Stated here rather than discovered in review.

## Residual — what CACHE.4b still needs after this change

One table, so a later closer of the RED row cannot miss a half this change already knew was open.

| residual | why it is open | where it is tracked |
|---|---|---|
| **executor response cache is unkeyed** — `src/capability/executor/mod.rs:313-318` (read) and `:347-349` (write) hold a **second** cache, keyed `format!("{}:{}", capability.name, sha256(params)[..16])` (`executor/params.rs:243-258`). No identity, no profile, no epoch. A post-bump miss at the `MetaMcp` layer re-dispatches, the executor serves its **pre-bump** body, and `MetaMcp` then stores that body under the **new** epoch — a superseded-grant response laundered into the fresh epoch. | Out of scope here by size, not by importance: keying it needs one process-level epoch both constructors (`executor/mod.rs:208`, `:247`) snapshot, which is the parent design's B6 and a design event of its own. **Do not implement it in this change.** | this row + parent B6 |
| **4.e protocol revision has no production value** | both call sites pass `None` unconditionally; the seam guard proves the digest reads the field, not that anything varies it | U5 |
| **4.f.2 `LiveConfig` reload does not bump** | nothing wires the epoch to `ConfigWatcher::start` | U6 |
| **4.f.3 capability watcher does not bump** | same watcher-construction seam (`src/gateway/server/mod.rs:874`) | U6 |
| **profile *contents* under an unchanged name key identically** | `routing_profile` is `&profile.name`, not a digest of contents (`invoke.rs:1214`, `:1787`) | 4.f.2/4.f.3 above |

## §P1 Open questions — scheduled, not assumed

Format: `question — check run — what came back — what it changed`.

### Resolved

- **U1. Are the two key builds in one function body, or does capture-once need a signature
  change through the call chain?** — fn-boundary scan of `invoke.rs` for declarations between
  1000 and 1900 — only `record_error_budget` at :1896; both sites are inside
  `invoke_tool_traced` (862-1896) — **changed the shape of the fix**: 4.g is a local `let`, not
  a threaded parameter. This was the single largest open item and it collapsed the design.

- **U2. Is `set_identity_grants` the only runtime writer of the grant store, or does the plan
  under-count the bump sites?** — `rg -n "identity_grants" src/ | rg "write\(\)"` — exactly one
  hit, `mod.rs:891` — **changed nothing** in the mechanism; it confirmed the plan's claim rather
  than correcting it, so 4.f.1 has one bump site and not a hidden fourth.

- **U3. Can all three 4.f bump sites reach a `MetaMcp`-owned epoch, or does one of them set the
  shape?** — `rg -n "live_config|LiveConfig|CapabilityWatcher|capability_watcher"
  src/gateway/meta_mcp/mod.rs` — zero hits — **changed the scope**: only 4.f.1 is reachable
  without new plumbing, so 4.f.2/4.f.3 are deferred with the four fields below rather than
  implemented against invented wiring. Had all three converged on one construction point, an
  injected `Arc<AtomicU64>` owned by neither the cache nor `MetaMcp` would have been the cheaper
  answer; they do not, so option A stands.

- **U4. Is the epoch bump preferable to the already-unwired `ResponseCache::clear()`?** — read
  `cache.rs:302` and searched for callers — no production caller; `clear()` is global and
  cannot exclude an in-flight invocation authorized before it ran — **changed nothing**, it
  confirmed the direction the parent design's doc comment at `cache.rs:274` already states
  ("the policy epoch it was authorized under ... mixed in as one digest ... unconditionally").
  Recorded so the option is visibly rejected rather than silently unconsidered.

### Deferred

**U5 — 4.e: is the negotiated protocol revision reachable at the invoke layer?**

| field | |
|---|---|
| owner | this ticket (MIK-7213) |
| what would resolve it | thread `classify_and_observe` from `src/gateway/router/handlers.rs` into `meta_mcp`, so `protocol_revision` carries a real value at the key sites instead of `None` |
| when | before 4.0.0 ships — the modern revision is now default-on |
| what if it resolves badly | two clients negotiating different protocol revisions share one cache entry. That is a **correctness** bug, not a performance one, and it is why the row stays BLOCKING on the release board rather than being downgraded |

Nothing in this change depends on U5: the epoch mechanism keys, bumps and reads without it, and
the seam guard test asserts only that the seam discriminates.

**U6 — 4.f.2 / 4.f.3: what carries the epoch to the config and capability watchers?**

| field | |
|---|---|
| owner | this ticket (MIK-7213) |
| what would resolve it | whether `ConfigWatcher::start` (`src/gateway/server/mod.rs:1275`) and the capability watcher (`src/gateway/server/mod.rs:874`) can take a cloned `Arc<AtomicU64>` at construction — both are built in the same file that builds `MetaMcp`, so the handle exists at one point; the cost is two signature changes, which is a design event of its own |
| when | before 4.0.0 ships — CACHE.4b names a **profile** change and this is the half that carries it |
| what if it resolves badly | a reload that narrows a routing profile leaves entries assembled under the wider profile servable — stale-authorization serving, the exact defect CACHE.4b names. Fallback is NOT a hand-bumped epoch called a reload; it is 4.f.2/4.f.3 recorded as not covered |

**These two deferrals block nothing in this change and gate what they name**: no 4.e closure
claim, no 4.f.2/4.f.3 closure claim.

**They also bound what CACHE.4b may claim.** The criterion at `:94` reads "a policy epoch that
invalidates it on a grant **or profile** change". The epoch closes the *grant* half (4.f.1). The
*profile* half splits two ways: a different profile **identity** is already handled by 4.d keying
(different name, different key), but a profile whose **contents** change under the same name keys
identically — `routing_profile` is wired to `&profile.name` at both sites (invoke.rs:1214, 1787),
not to a digest of the profile's contents. That reading is exactly 4.f.2/4.f.3, deferred above.
So: **this change makes CACHE.4b's grant half true at the `MetaMcp` layer only, and leaves both
its profile half and the executor layer open.** "Epoch landed" must not be read as "4b met". Deferring the *work* is the lead's to approve; deferring
the *criterion* is a scope reduction needing the operator's recorded agreement, which we do not
have — so the row stays RED.

Note the criterion says nothing about *runtime*: with one startup-only writer (C4) the bump is a
latent limit, not a criterion miss.

## §P1 Asked-and-answered — what only the requester can settle

- **Is CACHE.4b's "size" dimension a caching concern or a security concern?** — asked of the
  lead — security: stale-authorization serving, not cache sizing — **changed the scope**: cache
  size, eviction and TTL are OUT, and the row is satisfied by the epoch mechanism alone.
- **One mechanism or two rows?** — asked of the lead — one mechanism — **changed the design**:
  CACHE.4a and CACHE.4b share the epoch and are not split into independent work.
- **Still open, asked in the accompanying report:** whether the ledger corrections below are
  mine to apply (the do-not-touch list named lines 344 and 393, not 93 and 94), and whether
  4.e's deferral is acceptable for a 4.0.0 release or whether the cross-layer wiring must land.

## §P4a Documentation delta — inside this change

- `docs/requirements/RELEASE-4.0.0-criteria-status.md` lines 93 and 94 — the six corrections below.
- `docs/design/2026-08-31-cluster-f-response-cache-keying-test-plan.md` — its 4.d/4.e "Blocked:
  `build_key` has no revision parameter and the finished key has no callable form" note is
  stale; `response_key` plus `KeyContext` lifted that block.
- This document is the design receipt; the parent design is cross-referenced, not edited.

## Ledger corrections — verified at source, all six

The brief and the criteria ledger are wrong in six places. Every correction below was checked
at the file, not inferred:

| claimed | actual |
|---|---|
| `src/gateway/cache.rs:229` | **`src/gateway/cache.rs` does not exist.** The file is `src/cache.rs`; `response_key` is at line 279. |
| call sites `invoke.rs:852` and `invoke.rs:1308` | `invoke.rs:1214` (read) and `invoke.rs:1787` (write) |
| `ac_cache_4_two_principals_do_not_share_an_entry` at `mik_7213_acs.rs:371` | `mik_7213_acs.rs:412` |
| `MetaMcp::set_identity_grants` at `mod.rs:814-816` | `mod.rs:890` |
| "Still absent from the key: routing profile (4.d) and protocol revision (4.e)" | **False.** All three fields are in `KeyContext`, committed, hashed unconditionally; 4.d is tested at `mik_7213_acs.rs:506`. |
| "No policy epoch participates in `response_key`" | **False as stated, true in effect.** The field exists and is hashed; the *value* is hardcoded `0` with no writer anywhere in `src/`. The conclusion drawn from it — "a grant or profile change leaves prior entries servable" — is correct. |

The last row is the inverse of the trap the brief warned about: a **true conclusion from a false
observation**. It matters because it changes the work's shape — not "add a dimension to the
key", but "supply and bump a value the key already consumes".
