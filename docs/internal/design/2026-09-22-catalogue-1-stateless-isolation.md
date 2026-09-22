# MIK-7334.CATALOGUE.1 — per-caller catalogues for `session_mode = stateless`

**Date** 2026-09-22 · **Status** design, not implemented · **Row**
`MIK-7334.CATALOGUE.1`, conjunct C2 for the `stateless` half · **Composes with**
`docs/internal/design/2026-09-21-catalogue-1-per-caller-view.md` (the `per_user`
half, shipped)

Every load-bearing claim about current behaviour carries `file:line` and a mark:
**V** verified at source in this worktree, **I** inferred from verified facts,
**A** assumption. Line numbers are from the `docs/catalogue-1-leak-closed`
worktree at `6d82206c`; `src/backend/metadata.rs`, `src/backend/tests.rs` and
`src/gateway/meta_mcp/search.rs` are under concurrent edit elsewhere, so those
three may drift by a few lines.

---

## 1. The obligation, and the two rulings that bound it

The criterion: *"Supported identity-dependent backend catalogues, cached
metadata and results are isolated by verified caller and authorization context,
including changes and revocation."*

For `session_mode = per_user` with a resolved binding this is built: the five
cache fields live on the per-caller pool slot (**V** `src/backend/pool.rs:90-103`)
and `pool_key_for` grants that slot to exactly `(Some(SessionMode::PerUser),
Some(binding))` (**V** `src/backend/pool.rs:213-220`).

For `session_mode = stateless` with identity propagation configured it is not
built. Every caller collapses to `PoolKey::Shared`, the catalogue is fetched
once under the gateway's static credential, and everyone is answered from it.
Omission, not disclosure — and not the mode.

**Ruling 1, 2026-09-21, operator.** The descope was DECLINED. Grading the row on
the word *supported* was rejected as a default-path descope: *"the 4.0.0 feature
set was decided deliberately, so everything scoped to the requirements is IN
SCOPE by default… CATALOGUE.1 is BUILD, not rescope."* Documenting the omission
is therefore not an available answer, and this design does not propose it.

**Ruling 2, the standing constraint.** Quoted from its source rather than from
the row's paraphrase (**V**
`docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md:293-307`):

> `tools_cache` is a single `CachedMetadata<Vec<Tool>>` per `Backend` … the
> identity key selects a connection `PoolKey` …, never a cache. So the tool
> catalogue is *already* shared across identities, and **the rejected set
> shadowing it** inherits exactly that scope. The proposed repair — key
> **rejection** by the identity pool key — would key a derived set finer than
> the data it is derived from, which cannot be built: there is no per-identity
> list to reject from. **The honest statement is that identity-scoped rejection
> becomes meaningful only if `tools_cache` itself becomes identity-partitioned,
> and that is a change to the cache, not to this gate.**

**I** What is forbidden is keying *storage* finer than the *fetch that fills
it*. Doing so stores N identical copies of one account's answer — isolation in
name only. Partitioning the source is not forbidden; the ruling names it as the
only repair that makes the property meaningful, and files it under MIK-7334.
The prior design already established this at
`docs/internal/design/2026-09-21-catalogue-1-per-caller-view.md:36-67`, and the
row's own note still carries the inverted paraphrase. See §12.

## 2. What `stateless` does today, traced

Every line below was read in this worktree.

1. **V** `src/gateway/meta_mcp/discovery_fetch.rs:67-79` — `catalogue_credential_for`
   resolves the caller's credential and evaluates the isolation verdict as one
   pair, returning `Some((headers, binding))` to fetch with.
2. **V** `src/identity_propagation/mod.rs:316-326` — `cache_binding` is composed
   from `subject_key` and `audience` and **never consults the session mode**.
   So a `stateless` backend's caller does resolve a `Some(binding)` and does get
   minted headers.
3. **V** `src/backend/metadata.rs:190-194` — `get_cached_list_for` derives
   `let key = self.pool_key_for(binding)` and then derives `identity_key` from
   that same `match`, so slot and headers cannot disagree.
4. **V** `src/backend/pool.rs:213-220` — `pool_key_for` returns
   `PoolKey::PerUser` only for `(Some(SessionMode::PerUser), Some(binding))`.
   A `stateless` backend lands on `Shared` however well its caller identifies.
5. **V** `src/backend/metadata.rs:206-209` — the header gate added by #727:
   `let fetch_headers = match identity_key { Some(_) => extra_headers, None => &[] }`.
   On `stateless` `identity_key` is `None`, so the minted headers are dropped
   and the fill runs as the gateway.
6. **V** `src/gateway/meta_mcp/catalogue_families_per_caller_tests.rs:622-659` —
   this is pinned by a test today: the fill transcript for a `stateless` backend
   is `vec![None]` with `vec![Vec::new()]` headers, and beta must not see
   alpha's item.

**I** Net: on `stateless`, the guard admits the caller on credential possession
and the answer they receive was fetched under the gateway's own account. That is
safe against caller-to-caller disclosure and is not the mode.

**And it is worse than "uncached".** **V** `src/gateway/meta_mcp/discovery_fetch.rs:113-123`:
`backend_tools_for_discovery` reads `get_cached_tools_snapshot_for(binding)`
first. On `stateless` that resolves through `pool_key_for` to the `Shared` slot,
which the background refresher keeps warm (**V** `:171-175`). Because
`binding.is_some()` the code takes the per-user branch and `has_cached_tools_for(binding)`
— also the `Shared` slot — reports fresh, so the caller is served the
static-credential list from cache without any fetch being attempted at all.

## 3. The invariant the leak taught us

Stated once, because both candidate mechanisms are graded against it.

| fetch granularity vs storage granularity | outcome |
|---|---|
| fetch **finer** than storage | cross-tenant disclosure — what #727 closed |
| storage **finer** than fetch | N identical copies, isolation in name only — what the 2026-08-31 ruling forbids |
| equal | correct |

**I** So the design rule is: *the cache key's granularity must equal the
granularity of the credential the fill ran under*, and the two must be derived
from one expression. `get_cached_list_for` already enforces exactly this
(**V** `src/backend/metadata.rs:190-194`), which is why any mechanism that keeps
that derivation intact inherits the property instead of re-arguing it.


## 4. What `stateless` declares, and whether per-identity caching contradicts it

The brief asks this plainly, so it is answered plainly: **orthogonal, not
contradictory.** The declaration grants permission to share; it does not oblige
sharing, and it says nothing about whether the catalogue varies by caller.

**V** `src/identity_propagation/mod.rs:194-201`:

> `Stateless` — *The backend keeps no per-session state; one transport is safe
> to share across users because identity is carried per-request in the
> credential.*
> `PerUser` — *The gateway must use a distinct transport/session per
> `(backend, user, audience)`.*

**V** `docs/adr/ADR-007-identity-propagation.md:84-93` gives the same contract
as a disjunction: an identity-propagating backend MUST satisfy *"(a) per-user
transport/session instances keyed by `(backend_id, stable_actor_id, audience)`;
(b) an explicit `stateless` (no session affinity) contract in config."*

**I** Three consequences.

1. The declaration is about **session affinity upstream**, not about catalogue
   content. A backend can keep no session state and still return a different
   `tools/list` per bearer identity — that is precisely what an identity-scoped
   REST-backed MCP server does. So "identity-dependent catalogue" and
   "stateless" are compatible claims, and the criterion's word *supported*
   ranges over this configuration.
2. `PerUser` is phrased as an obligation (*must use a distinct transport*);
   `Stateless` is phrased as a safety permission (*is safe to share*). Taking a
   distinct transport where one is merely permitted to be shared is wasteful,
   never unsafe. Nothing in the declaration is violated by giving a `stateless`
   backend per-identity slots.
3. The upstream MCP session is **already** per-caller on a shared transport when
   an `identity_key` is passed — **V** `src/transport/mod.rs:98-104` and
   **V** `src/transport/http/mod.rs:1472-1487, 1574-1581`, where `bucket_key`
   maps `Some(binding)` to that caller's own `MCP-Session-Id` bucket and `None`
   to the shared default. **I** So the thing `stateless` exists to permit —
   sharing one upstream session — is not actually what the shared path does for
   an identified caller today. The session split already exists; only the cache
   split is missing.

**Conclusion.** This mode *can* be supported as declared. The honest answer is
not "the mode is incoherent"; it is that the catalogue cache is the one part of
the per-caller path that was never keyed.

## 5. Mechanism: the candidates

Three were evaluated. Each is rejected or chosen against specific lines.

### 5.1 Candidate A — per-identity pool slot (one arm in `pool_key_for`)

Grant `PoolKey::PerUser { binding }` to `(Some(SessionMode::Stateless),
Some(binding))` as well, collapsing `pool_key_for`'s two identity-propagating
arms into one:

```rust
match (self.session_mode(), identity_key) {
    (Some(_), Some(binding)) => PoolKey::PerUser { binding: binding.to_string() },
    _ => PoolKey::Shared,
}
```

**What follows for free, because everything is already on the slot.** The four
metadata caches and `resend_permitted` (**V** `src/backend/pool.rs:90-103`); the
transport the fill runs over (**V** `src/backend/metadata.rs:210-215`, where
`select` is handed the `PooledEntry` and `ensure_entry_started(&key)` returns
that slot's transport); the header gate, which now yields `Some(binding)` and
therefore carries the minted headers (**V** `src/backend/metadata.rs:190-209`);
idle eviction (**V** `src/backend/pool.rs:419-447`); and revocation eviction
(**V** `src/backend/pool.rs:353-401`). No new type, no second keying function,
no new eviction policy.

**Does it violate the IDP.5 guarantee `pool_key_for` carries?** The comment at
**V** `src/backend/pool.rs:206-212` names three collapsing cases — *"no identity
propagation, `stateless`, or `per_user` without a resolved identity"* — and
attributes byte-for-byte single-tenancy to all three. The pinned promise is
narrower. **V** `docs/adr/ADR-007-identity-propagation.md:77-79` scopes IDP.5 to
*absent* propagation config: *"Absent → today's static-credential behavior is
unchanged (IDP.5)."* **V** The only executable pin is
`pool_key_collapses_to_shared_without_per_user_identity`
(`src/backend/pool_tests.rs:275-294`), which asserts exactly two things:
`backend.pool_key_for(None) == Shared`, and `plain.pool_key_for(Some("userA"))
== Shared` where `plain` is built from `BackendConfig::default()` — **no
identity-propagation config at all**. **I** Candidate A moves neither. IDP.5 as
written in the ADR and as pinned in the suite is untouched; what moves is an
un-pinned sentence in a doc comment. See §12.

### 5.2 Candidate B — uncached per-caller fetch on the shared transport

For `(stateless, Some(binding))`, fetch with the caller's headers over the
`Shared` slot's transport and return the list without writing any cache. This is
the option ADR-007's IDP.8 names: **V** `docs/adr/ADR-007-identity-propagation.md:94-97`
— *"cache keys MUST include `cache_binding` …; failing that, the cache MUST be
bypassed, so user A's cached backend result is never served to user B."* It also
matches the live-call path, which already runs a `stateless` `tools/call` on the
shared slot with the caller's headers and stores nothing (**V**
`src/backend/ops.rs:292-348`).

**Rejected, on three specific costs.**

1. **It needs a branch at every reader, not at the fill.** The cache is read
   before the fill is reached (§2, **V** `discovery_fetch.rs:113-123`), so
   "don't write" is not sufficient — each reader must also refuse to *read* the
   `Shared` slot for an identified caller on a `stateless` backend. That is the
   four caller-aware sites in `src/gateway/meta_mcp/search.rs:183, 279, 639, 713`,
   the three protocol list handlers reached through
   `catalogue_credential_for` (**V** `discovery_fetch.rs:67-79`), and the
   binding-taking accessor family `get_cached_tool_for`,
   `get_cached_tool_names_for`, `cached_tools_count_for`,
   `has_cached_tools_for`, `get_cached_tools_snapshot_for` (**V**
   `src/backend/metadata.rs:38-152`). Roughly a dozen sites, each one a place a
   future edit forgets the branch — and the row's own history is a record of
   exactly that failure (three of four `get_cached_list_on` call sites passed
   the constant; the fix was to make per-family drift a type error, **V**
   `src/backend/metadata.rs:157-165`). Candidate B reintroduces the convention
   that fix deleted.
2. **The tools parse closure writes to shared state on its own.** **V**
   `src/backend/metadata.rs:290-291`:
   `*self.tools_slot(binding).resend_permitted.write() = prepare_tool_metadata(...)`.
   For a `stateless` backend `tools_slot(binding)` is the `Shared` slot. An
   uncached per-caller fetch that reuses this closure writes one caller's
   catalogue-derived resend policy where every caller reads it (**V** the
   consumer is `resend_decision`, `src/backend/ops.rs:160-171`). "The uncached
   path never receives a `&CachedMetadata`" does not save it: this write reaches
   storage by itself. Candidate B therefore also requires splitting the parse
   closure — more diff, in the file the leak came from.
3. **Discovery is the hot path this product exists to make cheap.** **V**
   `src/gateway/meta_mcp/search.rs:264-284` and `:706-718` loop over every
   registered backend per `gateway_search_tools` / `gateway_list_tools` call.
   Uncached means one upstream `*/list` per backend **per discovery call**,
   where Candidate A means one per identity **per TTL**. **I** On a 33-backend
   gateway that is the difference between a warm discovery turn and 33 upstream
   round-trips on every keystroke-level search.

### 5.3 Candidate C — a binding-keyed map inside the shared slot

A `DashMap<binding, CachedMetadata<…>>` on `PooledEntry`, leaving
`pool_key_for` alone. **Rejected.** It is a second keying mechanism that must
agree with the first forever, which is the "two lookups that agree today" shape
the prior design's §3.1 exists to forbid (**V**
`src/backend/pool.rs:82-89`: *"Because the cache and the transport now live
behind the same `Arc<PooledEntry>`, the bytes in slot K's cache were fetched
over slot K's transport, and no expression pairs one slot's cache with another
slot's transport."*). It also puts caller-specific bytes inside the object
reachable from the shared key, which is the leak's exact shape.

### 5.4 Candidate D — refuse the configuration

Make `(stateless, identity_propagation)` a validation error at **V**
`src/identity_propagation/mod.rs:266-311`, on the reasoning that the mode cannot
be supported. **Rejected on §4**: the mode is coherent, and refusing it breaks
existing configs (**V** four such fixtures exist:
`src/backend/tests.rs:241`, `src/gateway/meta_mcp/account_raw_vault_tests.rs:38`,
`src/gateway/router/tests.rs:1359, 1427`). It is also the declined descope
wearing a compiler error.

## 6. Recommendation

**Candidate A. One arm in `pool_key_for`.**

The decisive reason is not cost and not elegance: it is **where the change
lives**. Candidate A is one expression in the one function that already derives
slot and credential together, so isolation, header carriage, eviction,
per-caller `resend_permitted` and per-caller failsafe all follow from an
invariant that is already proven and already tested. Candidate B is a dozen
coordinated branches plus a parse split, none of which the type system checks,
in the exact file and the exact shape that produced this row's two prior
defects.

Secondary, and independently sufficient: Candidate A leaves #727's header gate
(**V** `src/backend/metadata.rs:206-209`) **textually unchanged** and correct.
The gate says "carry the headers only where the derived key is private". Under
Candidate A the key becomes private, so the headers are carried — by the same
expression, with no new reasoning. Any design that instead argues its way past
that gate is arguing against the fix for a live disclosure.


## 7. Cost, and what bounds it

N identities on a `stateless` backend produce N pool slots. Per slot:

| resource | cost | what bounds it |
|---|---|---|
| metadata cache entries | 4 lists + 1 derived set (**V** `pool.rs:90-103`) | slot eviction — they are fields of the slot, so they die with it |
| upstream `*/list` fetches | 1 per family per identity per `cache_ttl` | per-slot single-flight (**V** `cached_metadata.rs:181` `get_or_fetch_shared`, one instance per slot) |
| local transport + `initialize` handshake | 1 per slot | slot eviction |
| upstream MCP session | **no change** | already per-caller via the session bucket (**V** `transport/http/mod.rs:1472-1487, 1574-1581`) |
| failsafe (breaker, rate limiter, health) | 1 per slot | slot eviction; and this is a *benefit* — **V** `pool.rs:50-60`, one identity's outage no longer trips the breaker for everyone |

**Does the idle-eviction path suffice?** **V** `Backend::evict_idle_per_user_entries`
(`src/backend/pool.rs:419-455`) sweeps every non-`Shared` slot, removes it under
`remove_if` when `in_flight == 0` and `last_used` is older than `idle_ttl`, and
closes its transport. Because the caches are fields of the removed
`PooledEntry`, they are freed with it and no separate cache-eviction policy
exists to get wrong.

**And it reaches `stateless` backends — checked, because a session-mode gate
here would turn the bound into nothing.** **V** the sweep has exactly one
production caller, `src/gateway/server/mod.rs:3651-3652`, and it iterates
`backends.all()` with a fixed `PER_USER_IDLE_TTL` of 300s on a 60s
`SWEEP_INTERVAL` (`:3634-3635`) — no `SessionMode` test, no per-backend opt-in.
**V** Same for the revocation path: `evict_identity_slots` has one production
caller, `src/config_reload/mod.rs:1851-1852`, looping `self.registry.all()`.
Searches, quoted:

```
awk '/evict_idle_per_user_entries/ {print FILENAME":"FNR}' $(find src -name '*.rs')
  → 1 production hit (gateway/server/mod.rs:3652); rest are pool.rs doc comments and *_tests.rs
awk '/evict_identity_slots/ {print FILENAME":"FNR}' $(find src -name '*.rs')
  → 1 production hit (config_reload/mod.rs:1852); rest are pool.rs:353 and slot_eviction_tests.rs
```

**I** So both bounds already apply to every backend the registry holds, and
Candidate A needs no widening of either gate. This is also what makes **T-S9**
implementable rather than aspirational.

**Answer: it bounds steady-state growth, and it does not bound peak.** Stated
plainly rather than waved at.

- **V** It already carries the whole `per_user` mode's growth today, with the
  same arithmetic. Candidate A adds no new unbounded dimension; it widens the
  set of backends that participate in a bound that already exists and already
  ships.
- **I** Peak is `active_identities × backends_with_propagation`, reached only if
  that many distinct identities are inside one `idle_ttl` window. Nothing in
  the pool refuses the N+1st slot — there is no cap. **V** Searched, and the
  absence is real: `awk '/max_slots|slot_limit|max_per_user|pool_cap|MAX_SLOTS|max_pool/'`
  over every `src/**/*.rs` returns three hits, all in
  `src/idempotency/task_service_capacity_tests.rs:51,111` and
  `src/idempotency/task_qualification_tests.rs:119` — the task service's slot
  limit, unrelated to the connection pool. **V** The only pressure
  signal is observability: `mcp_backend_pool_slots` is gauged on slot creation
  and after eviction (`src/backend/pool.rs:256-265, 456-466`).
- **I** A cap is deliberately **not** proposed here. An LRU bound on slots would
  mean evicting a live caller's slot to admit another's, and the eviction path
  closes transports — so a cap is a new failure mode on a path that currently
  has none, bought against a pressure nobody has measured. If `mcp_backend_pool_slots`
  shows real pressure, that is its own row with its own evidence.

**One honest cost that Candidate B would not pay:** a local transport per
identity for a backend whose operator declared one transport safe to share. **I**
This is real waste, and it is accepted because every design that avoids it
(share the transport, split only the cache) breaks the one-`Arc` pairing that
makes the isolation provable (§5.3). Paying a TCP connection to keep a proof
structural is the right trade at this scale; re-open it only with a measurement.

## 8. The guard and the fill (MIK-7544)

MIK-7544 is the disagreement between the admission predicate and the fetch. The
guard's own doc comment states the precondition it needs, and the `stateless`
path violates it today.

**V** `src/gateway/meta_mcp/mod.rs:1243-1250`:

> ONLY admissible where the operation AFTER the check runs on the same slot the
> credential selected. `has_per_user_credential = true` does not narrow
> `enforce_oauth_isolation_for` — it returns `Ok(())` before any isolation arm
> is evaluated — so calling this at a site that then fetches over
> `shared_transport()` would hand an arbitrary caller the gateway's own backend
> login.

**V** `meta_route_isolation_refused_for_caller` (`mod.rs:1257-1264`) admits on
`!propagated_headers.is_empty()`, and **V** `enforce_oauth_isolation_for`
(`mod.rs:1131-1133`) returns `Ok(())` immediately when that flag is set, before
the three isolation arms. **V** On `stateless` the fill then drops those very
headers (`metadata.rs:206-209`) and reads a slot the gateway's account filled.
**I** So for an isolated-OAuth `stateless` backend the guard admits and the
answer is the gateway account's catalogue — the leak class MIK-7544 names,
gateway-account-to-every-caller rather than caller-to-caller.

**How Candidate A keeps them consistent: they become one predicate evaluated
twice, and the design states the invariant so a future edit has something to
violate.**

> **INV-STATELESS-1.** `meta_route_isolation_refused_for_caller(backend, headers)`
> admits **iff** `pool_key_for(binding)` returns `PoolKey::PerUser` for the
> binding resolved in the same `catalogue_credential_for` call.

Under Candidate A both sides reduce to *the caller resolved a propagation
credential for this backend*: the guard reads it as non-empty headers, the key
reads it as `Some(binding)`, and **V** both come from the one
`resolve_propagation_credential` call that returns the pair
(`discovery_fetch.rs:72-78`, which exists precisely so "the isolation verdict
and the slot selection must not disagree about who the caller is", **V**
`mod.rs:1218-1221`). The remaining gap is the one `pool_key_for` arm; closing it
closes MIK-7544 by construction rather than by a second guard.

**The residual, named rather than hidden.** INV-STATELESS-1 still fails for
`(per_user, None)` — a caller with no resolved binding. There the guard refuses
(empty headers, so the isolation arms run) and the key is `Shared`, which agree;
and for a non-`required` backend the caller falls back to the shared catalogue,
which is the documented non-`required` fallback (**V**
`src/identity_propagation/mod.rs:480-481`, and the prior design's Q1 decision at
`2026-09-21-catalogue-1-per-caller-view.md:535-546`). That arm is unchanged by
this design and is not MIK-7544.

**T-GUARD in §10 is the executable form of INV-STATELESS-1.** Without it the
invariant is prose, and the row already has a lesson about prose invariants
discharged by reading their own letter.

## 9. Blast radius

`pool_key_for` has four production callers. Candidate A changes the answer for
`(stateless, Some(binding))` at all four, so all four are stated.

1. **V** `src/backend/metadata.rs:190` — the metadata fill. *This is the
   intended change.* The slot becomes private, the headers are carried, the
   cache is per-caller. Risk level: this is the row.
2. **V** `src/backend/metadata.rs:32-34` — `tools_slot`, feeding every
   binding-taking accessor (`metadata.rs:38-152`) and the `resend_permitted`
   write at `:290`. **I** These follow the fill automatically and are the reason
   Candidate A needs no reader-side branch: the accessors already take a
   binding and already route through `pool_key_for`.
3. **V** `src/backend/ops.rs:292` — the live request path. A `stateless`
   backend's `tools/call` moves from *shared slot + caller headers* to *private
   slot + caller headers*. **I** Strictly more isolated, and three behaviours
   move with it:
   - the failsafe becomes per-identity (**V** `ops.rs:298`, `pool.rs:50-60`) —
     an improvement, and the same one MIK-6735 fix 1 made for `per_user`;
   - `resend_decision` reads the private slot's `resend_permitted` (**V**
     `ops.rs:330`, `:160-171`). An empty set denies resends (**V**
     `pool.rs:96-99`: *"Absent means deny, so an unfilled slot denies every
     resend, which is the safe direction"*). **I** So a caller who invokes a
     tool on a `stateless` backend **without first listing it** loses resend
     permission it would previously have inherited from the shared fill. Safe
     direction, real behaviour change, must be named in the PR. ADR-012 A1 holds
     that discovery always precedes a `tools/call` (**V** cited at
     `metadata.rs:286-288`), so the window is narrow — but "narrow" is not
     "empty", and T-RESEND in §10 pins it.
   - the idle reaper may now stop a `stateless` backend's per-identity
     transport, where before only the never-evicted `Shared` slot existed for
     it (**V** `pool.rs:301-313`). **I** Handled by the existing restart path;
     no new code.
4. **V** `src/backend/ops.rs:528` — the notify path, same shape as (3), and
   already exercised for `per_user` by `pool_tests.rs:255-273`.

**What does NOT change.** **V** `pool_key_for(None)` for any backend, and
`pool_key_for(Some(_))` for a backend with no `identity_propagation` config —
the two arms IDP.5 is pinned on (`pool_tests.rs:275-294`). **V** The
`Shared` slot remains, is still inserted at construction and still never
idle-evicted (`pool.rs:301-313`, `:427`), so startup prefetch, the operator UI,
the provider adapter and `find_resource_owner` keep the identity-free view they
have today (**V** `metadata.rs:350-361`).

**One observability consequence, named because nobody would look for it.** **V**
`shared_entry()` (`pool.rs:301-313`) is what the status, metrics and health-loop
accessors read, *"intentionally report[ing] the backend-wide, single-tenant view
regardless of how many per-user slots exist"*. **I** On a `stateless` backend
whose traffic is now entirely identified, that slot sees only anonymous reads,
so health and last-used can read idle while the backend is busy. This is
pre-existing behaviour for `per_user` backends and is not made worse in kind,
only more common. Worth one line in the PR; not worth a mechanism.


## 10. Test plan

**Where it lives.** `src/gateway/meta_mcp/catalogue_families_per_caller_tests.rs`
carries the only `stateless` fixture wired to a per-identity catalogue harness —
**V** `stateless_config()` at `:567-579`, `stateless_gateway()` at `:586-600`.
(Four other `stateless` fixtures exist — **V** `src/backend/tests.rs:241`,
`src/gateway/meta_mcp/account_raw_vault_tests.rs:38`,
`src/gateway/router/tests.rs:1359, 1427` — but none serves a per-identity
catalogue, so none can express these assertions.) The harness records a full raw
transcript: `fills_for(method)` returns every fetch's slot key in order and
`headers_for(method)` returns every fetch's header list in order, both
deliberately unsorted and undeduplicated (**V** `:87-115`). That transcript is
what makes the two required discriminations mechanical rather than argued.

**Strategy is named in every cell, as the row's note requires.** All cells below
configure `PropagationStrategyKind::SignedAssertion` (**V** `:570`), the shipped
default (**V** `src/identity_propagation/mod.rs:206-209`). **I** The vault path
is grant-aware by key construction and the signed-assertion path is not, so a
cell that does not name its strategy is untestable as written; these cells cover
the signed-assertion path **only**, and say so.

**Families.** **V** `FAMILIES` at `:47` is `["resources/list",
"resources/templates/list", "prompts/list"]` — no `tools/list` arm, which is
MIK-7543. Every cell below runs over `FAMILIES` **and** over tools via
`catalogue_per_caller_tests::listed_for` (**V** `:252-269`), so the family that
actually leaked is covered by a test rather than by the shared-fill argument.

### 10.1 The two discriminations every cell must survive

The brief's requirement, made concrete against the transcript:

| mutant | what it does | what catches it |
|---|---|---|
| **never-cache** | the fill returns the list without storing it | **same caller reads twice → exactly ONE fill for that binding.** Under never-cache the transcript holds two identical keyed entries. |
| **overwrite-cache** | storage stays shared; each fill replaces the last | **alpha, then beta, then alpha again → alpha still sees alpha's item, and NO third fill.** Under overwrite-cache alpha's re-read either refetches or returns beta's item. |

**I** A cell asserting only "beta does not see alpha's item" passes under both
mutants and under a gateway that answers nobody. That is the shape this row
already shipped once.

### 10.2 The cells

| T | Cell | Conjunct | RED-before reason |
|---|---|---|---|
| **T-S1** | `stateless` fixture, signed-assertion. Alpha lists, then beta lists. Transcript must be `[Some(alpha_binding), Some(beta_binding)]` and each header list must carry that caller's minted credential. Alpha sees `ALPHA_ITEM`, beta sees `BETA_ITEM`, neither sees the other's. | C0, C1, C2 | **V** RED today at the transcript, not at the items: `a_stateless_backend_fills_its_shared_slot_unidentified` (`:622-659`) currently asserts the transcript **is** `vec![None]` with `vec![Vec::new()]` headers. T-S1 asserts the inverse. The existing cell's assertions are the RED-before, and it is rewritten, not deleted — §10.4. |
| **T-S2** | **never-cache discriminator.** Alpha lists the same family twice. Transcript must be exactly `[Some(alpha_binding)]` — one fill, two reads. | C2 | **V** RED today on the key, not the count: today's transcript is `[None]`, so the assertion fails on the first element before the arity matters. After Candidate A it is the cell that stays red against any implementation answering an identified `stateless` caller without storing — **I** the cell Candidate B could not satisfy (§12). |
| **T-S3** | **overwrite-cache discriminator.** Alpha lists, beta lists, alpha lists again. Transcript must stay `[Some(alpha), Some(beta)]` — no third fill — and alpha's third read must still contain `ALPHA_ITEM`. | C1, C2 | **V** RED today: `pool_key_for` returns `Shared` for both (`pool.rs:213-220`), so one entry exists and the second fill replaces it. Goes RED against any binding-keyed map that keys storage without moving the fetch (§5.3). |
| **T-S4** | **The guard/fill agreement, INV-STATELESS-1.** A `stateless` fixture that the guard can actually refuse: `oauth` present with `enabled = true` and `shared_account = false`, so `oauth_requires_per_user_isolation()` returns true (**V** `src/backend/ops.rs:93-98`), multi-user on. Assert: the caller admitted by `meta_route_isolation_refused_for_caller` is answered from a fill whose transcript key is `Some(binding)` — never `None` — and that the same caller without a credential is refused. | MIK-7544 | **V** RED today: the guard admits on non-empty headers (`mod.rs:1257-1264`) while `metadata.rs:206-209` drops them and the fill records `None`. **I** The `oauth` field is load-bearing: on the bare `stateless_config()` (`required: false`, no `oauth`, no `account`) `enforce_oauth_isolation_for` falls through all three arms to `Ok(())` (**V** `mod.rs:1144-1180`), so INV-STATELESS-1 would be asserted against a guard that never refuses anything. |
| **T-S5** | **Anonymous control on the same fixture.** A caller with no verified identity lists each family on the `stateless` backend. Transcript entry must be `None` with empty headers, and the answer must be `STATIC_ITEM`. | IDP.5, anti-vacuity | **V** Green today and must stay green (`:655-659` already carries this assertion). **I** Without it, T-S1 passes against a gateway that stopped answering unidentified callers — isolation bought by breaking the shared path, which is the failure T6 of the prior design exists to catch. |
| **T-S8** | **`resend_permitted` follows the slot.** `stateless`, signed-assertion. Alpha's `tools/list` declares a resend-safe tool; assert beta's `resend_decision` does not inherit it, and that alpha's does. | C2, ADR-012 A1 | **V** RED today: `metadata.rs:290` writes `tools_slot(binding).resend_permitted`, which is the `Shared` slot for a `stateless` backend, so alpha's fill sets beta's retry policy. **I** This is the fifth field the prior design's §12 added; it must move with the other four here too, or the leak class returns through the retry path. |
| **T-S9** | **Revocation reaches the new slots.** Revoke alpha's grant; assert `evict_identity_slots(prefix)` removes alpha's `stateless` slot and that alpha's next read refills with a fresh fetch, while beta's slot and transcript are untouched. | C4 | **V** `evict_identity_slots` (`pool.rs:353-401`) already skips `PoolKey::Shared` (`:363`), so today a `stateless` backend has nothing for it to evict — revocation is a silent no-op there. Goes RED against an implementation that creates per-identity slots without them being reachable by the revocation path. |
| **T-S10** | **#727's header gate keeps a test that can fail it.** Direct on the `stateless` backend, bypassing discovery: call `get_tools_for_binding(None, &minted_headers)` — and one family equivalent — and assert `headers_for` records an EMPTY list for that fill and the transcript key is `None`. | leak regression | **V** RED against a tree with `metadata.rs:206-209` deleted. **I** This cell exists because Candidate A removes the last *production* path that reaches the gate: `PropagatedCredential::cache_binding` is a `String`, not an `Option` (**V** `src/identity_propagation/mod.rs:105`), and the two places a `None` binding arises both return empty headers with it (**V** `src/gateway/meta_mcp/invoke.rs:2903-2904`, `src/gateway/meta_mcp/discovery_fetch.rs:46-51`). So after Candidate A the gate is defence-in-depth, and without T-S10 a mutant that deletes it passes every other cell here — the same fixture blind spot that let the original defect through. |

### 10.3 Regression controls, excluded from the discriminating set

These two do **not** use a `stateless` fixture and do **not** discriminate
against the two mutants. They are controls, and they are listed apart rather
than inside the table so that nobody counts them as coverage. See §12 item 6.

| T | Cell | RED-before reason |
|---|---|---|
| **T-S6** | **`per_user` regression.** The existing `FAMILIES` per-caller suite (**V** `:376-378`, `:454`, `:466-468`) and `catalogue_per_caller_tests::each_identity_sees_its_own_catalogue_and_no_one_elses` (**V** `:284-292`) pass unchanged. | Green today. **I** Candidate A collapses two `pool_key_for` arms into one; if that changed the `per_user` answer, the arm was written wrong. |
| **T-S7** | **IDP.5 pin, unchanged.** `pool_key_collapses_to_shared_without_per_user_identity` (**V** `src/backend/pool_tests.rs:275-294`) passes unchanged, and gains a third assertion: a `stateless` backend with a `None` binding is still `Shared`. | The two existing assertions are green today and must stay green — they are the actual pinned promise (§5.1). The added assertion goes RED against an over-broad arm that keys on session mode alone and forgets the binding. |

### 10.4 Two notes on the existing `stateless` cells

**V** `a_stateless_backend_fills_its_shared_slot_unidentified` (`:622-659`) and
its three `#[tokio::test]` wrappers (`:674`, `:684`, and the templates arm)
assert the current behaviour as correct, with a doc comment that says so: *"This
pins the documented gap, NOT a per-caller `stateless` catalogue."* Implementing
Candidate A **inverts** those assertions. They are the RED-before for T-S1 and
must be rewritten in the same commit, not deleted — **I** deleting them removes
the only cell that would catch a regression back to the shared fill.

**A** The harness's `PerIdentityMint` double must keep minting a binding that
does not consult `session_mode`, because that is what the real `cache_binding`
does (**V** `src/identity_propagation/mod.rs:316-326`). A double that started
returning `None` for `stateless` would make every cell above vacuous.


## 11. Risks

1. **The arm is written too wide.** `(Some(_), Some(binding))` keys on *any*
   session mode plus a binding. **I** That is intended and is the point — the
   two identity-propagating arms become one, so no third mode can be added later
   that silently collapses to `Shared`. The risk is the inverse mistake: keying
   on session mode alone and forgetting the binding, which would mint a slot
   named after nobody. **T-S7** pins it.
2. **A reader still routed to `Shared`.** **V** `get_resources_shared`,
   `get_tools_shared` and friends (`metadata.rs:253-255, 350-361`) pass `None`
   deliberately, for startup prefetch, the operator UI and `find_resource_owner`.
   **I** Those stay correct — they hold no caller. The risk is a *caller-holding*
   reader that calls the `_shared` wrapper anyway. **V** `discovery_fetch.rs:107-144`
   is the one such path and already threads the binding. Grep the tree for
   `_shared(` inside any function taking a `VerifiedIdentity` before shipping.
3. **Per-identity transport growth on a backend that declared sharing safe.**
   §7. **I** Accepted with the idle reaper as the bound, and explicitly not
   capped. The mitigation that looks obvious — let a `stateless` `PerUser` slot
   borrow the `Shared` transport — is rejected, not deferred: it pairs one
   slot's cache with another slot's transport, which is exactly what
   `pool.rs:82-89` says no expression may do.
4. **The resend window.** §9 item 3. **I** A `tools/call` that precedes any
   `tools/list` on a `stateless` backend now denies resends where it previously
   inherited the shared set. Safe direction, real change, **T-S8** pins the
   isolation half and the PR must name the behaviour change.
5. **`tools/list` covered by argument rather than by a cell.** MIK-7543.
   **V** `FAMILIES` (`:47`) has no `tools/list` arm, so every cell here runs the
   tools family through `catalogue_per_caller_tests::listed_for` as well. **I**
   The row's own history is that the family covered by the shared-fill argument
   is the family that leaked; do not accept "all four route through one fill" as
   coverage a second time.
6. **The `stateless` cells are inverted, not extended.** §10.4. **I** A reviewer
   seeing assertions flip in a security-sensitive test file should check that
   each flip is the mode being delivered and not a test being made to pass.

## 12. Things that contradict the brief

Reported rather than quietly worked around.

1. **The standing constraint is narrower than the brief states.** The brief says
   *"keying the shared cache by `cache_binding` is already ruled out, because it
   would key a derived set finer than its source"*, and asks for the ruling
   quoted. Quoted at §1: the source (**V**
   `docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md:293-307`)
   forbids keying **the rejection set** finer than `tools_cache` while
   `tools_cache` stays shared, and **names partitioning `tools_cache` as the
   only repair that makes the property meaningful**, filing it under MIK-7334.
   The prior design already recorded this correction (**V**
   `2026-09-21-catalogue-1-per-caller-view.md:36-67`) and the row's note still
   carries the inverted paraphrase. **I** The recommendation here executes the
   ruling rather than working around it, but a reviewer firing "cache_binding is
   ruled out" will be citing the paraphrase.
2. **`pool_key_for`'s IDP.5 guarantee does not bound the `stateless` arm.** The
   brief says `pool_key_for` *"carries a byte-for-byte single-tenant guarantee
   (IDP.5) — find where that is stated and what exactly it promises, because it
   bounds what you may change."* Found, and it promises less than the comment
   claims. **V** ADR-007 scopes IDP.5 to *absent* propagation config
   (`ADR-007-identity-propagation.md:77-79`). **V** The only executable pin
   asserts two things, neither of them about `stateless`:
   `pool_key_for(None) == Shared`, and `plain.pool_key_for(Some("userA")) ==
   Shared` where `plain` is `BackendConfig::default()`
   (`src/backend/pool_tests.rs:275-294`). Search quoted:
   `awk '/pool_key_for/ {print FILENAME":"FNR}' $(find src -name '*.rs')` returns
   four production sites (`backend/metadata.rs:33`, `:190`, `backend/ops.rs:292`,
   `backend/ops.rs:528`), `pool.rs:213` itself, and three assertions in
   `pool_tests.rs` (`:281`, `:282`, `:291`) — those three are the whole pinned
   surface. **V** The comment at `pool.rs:206-212`
   extends the IDP.5 label to `stateless` on its own authority. **I** So the
   guarantee bounds two arms and the recommendation moves neither. The
   `stateless` sentence in that comment must be corrected by whoever implements
   this, or it becomes the next false settled negative.
3. **"Every cell must discriminate against *never-cache*" is in tension with
   Candidate B, and that tension is evidence.** Under an uncached mechanism,
   never-cache on the identified `stateless` path **is** the design, so no cell
   could discriminate against it there. **I** The brief's own test requirement
   therefore encodes a preference for a caching mechanism. Recorded because it
   is an input to the decision, not a constraint discovered after it — and
   because if the operator's intent was to leave Candidate B open, the test
   requirement needs restating, not the mechanism.
4. **The `stateless` gap is not only a cache gap; the read path never reaches
   the fill.** The brief frames the omission as "the catalogue is fetched once
   with the gateway's static credential and answered to everyone", which is
   true. **V** The sharper fact is `discovery_fetch.rs:113-123`: an identified
   caller on a `stateless` backend is answered from the warm `Shared` snapshot
   **without any fetch being attempted**, because the binding selects that same
   slot. **I** This matters because it is why a write-side-only fix is
   insufficient, and it is the specific mechanism by which MIK-7544 is live
   rather than theoretical.
5. **One brief-named candidate is weaker than it looks for a reason the brief
   could not have known.** The brief offers "an uncached path for identified
   callers on `stateless` backends" as a co-equal candidate. **V**
   `metadata.rs:290-291` writes `resend_permitted` to `tools_slot(binding)` —
   the `Shared` slot on a `stateless` backend — from inside the tools parse
   closure. **I** So an uncached path that reuses that closure writes
   caller-derived data to shared storage even though it caches nothing, which is
   the leak class the brief warns against, arriving through the one door
   "don't write the cache" leaves open.
6. **Two of the planned cells are controls, not discriminators, and the brief
   requires every cell to be both.** The brief says every cell must discriminate
   against *never-cache* and *overwrite-cache* and must exercise a `stateless`
   fixture. **T-S6** (the `per_user` regression suite) and **T-S7** (the
   `pool_key_for` unit pin) do neither — T-S6 is a `per_user` fixture and T-S7
   is a pure key assertion with no fetch at all. **I** They are kept because
   dropping them is how this row previously shipped isolation bought by breaking
   the shared path, and they are moved out of the discriminating table (§10.3)
   so they cannot be counted as coverage. Deviation recorded rather than
   silently taken; the eight cells in §10.2 all meet the brief's rule.
7. **The brief's premise that the header gate stays a live guard does not
   survive the recommendation.** **I** After Candidate A no production path
   produces non-empty headers with a `None` binding (evidence in T-S10), so
   `metadata.rs:206-209` becomes defence-in-depth. That is an argument *for*
   T-S10, not against the mechanism — but a reviewer who assumes the existing
   `stateless` cells still cover the gate will be wrong, and the gate would then
   be deletable with every test green.

## 13. Decisions that would need an operator, if any

**None.** Stated explicitly because the standing instruction is to find the best
way forward rather than route decisions upward, and because this row has twice
had an agent recommendation mistaken for a ruling.

Checked, item by item:

- **The mechanism** is engineering. Operator ruling 1 already funded BUILD for
  this row and declined the descope; Candidate A builds it.
- **The standing constraint** is satisfied by construction, not waived: §3's
  invariant holds because fetch and storage move together (§1, §5.1). No
  exception is requested.
- **IDP.5** is not narrowed (§12 item 2). What changes is an unpinned doc
  comment, which is a correction, not a scope decision.
- **The `stateless` contract** is not overridden (§4). The declaration permits
  transport sharing; declining to share it is allowed by the declaration's own
  wording.
- **The resend behaviour change** (§9 item 3) moves in the fail-closed
  direction, which this module already treats as the default a caller may be
  given without asking (**V** `pool.rs:96-99`).
- **The transport cost** (§7) is a cost, not a policy: it is bounded by
  machinery that already ships and already carries the `per_user` mode.

**The one thing a reviewer might reasonably escalate, and why it should not be.**
Candidate A widens the population of backends that mint pool slots, and no cap
exists. **I** That is a pre-existing property of the shipped `per_user` mode,
not a new exposure created here, and capping it means evicting a live caller's
slot to admit another's — a new failure mode bought against unmeasured pressure.
If `mcp_backend_pool_slots` (**V** `pool.rs:256-265`) shows real growth, that is
its own row with its own evidence. Escalating it now would park this row behind
work nobody has justified, which is the shape the descope already took once.

---

## Verdict

**Candidate A — one arm in `pool_key_for`, collapsing the two
identity-propagating cases into `(Some(_), Some(binding)) => PerUser`.**

Ready to implement. The diff is one expression, one doc-comment correction
(`pool.rs:206-212`), the inversion of three existing `stateless` cells, and the
eight discriminating cells of §10.2 plus the two controls of §10.3. No new type,
no new keying function, no new eviction policy,
and #727's header gate is not touched.

The security property comes from the arm, not from a guard: once the key is
private the headers are carried by the expression that already decides both, and
the guard's stated precondition becomes true for `stateless` for the first time.


---

## 13. Independent review — both seats, and what survived

Two non-Claude seats read this design before any code existed. `gpt-review` is over
quota until 2026-09-26 and was not available; that is stated so the weight is not
overread.

| Seat | Verdict | Findings |
|---|---|---|
| grok | **SHIP** | none — five improvements |
| kimi | **SHIP-WITH-FIXES** | one HIGH gated BEFORE-PRODUCTION, one LOW |

grok's verdict line, verbatim: *"Candidate A keeps fetch, headers, and storage on one
`pool_key_for` expression, so the #727 leak cannot recur, and the pinned IDP.5 arms are
untouched."* It reached that by walking all four production callers of `pool_key_for`,
the header gate, the `resend_permitted` write, the isolation guard, ADR-007, both
eviction paths, the HTTP session buckets and the `stateless` harness.

### 13.1 T-S4 pins a configuration the gateway refuses to load — BLOCKING for the test plan

The sharpest finding, and it invalidates this design's headline cell as written.

T-S4 names an OAuth backend paired with identity propagation. That pairing is
**rejected at load** by `Config::validate` (`src/config/mod.rs:1005-1013`, the F3
refusal) and again at `create_oauth_client`. A cell built on it cannot run, and a test
plan whose central case is unloadable proves nothing about the invariant it claims to
pin.

**Correction:** target `identity_propagation.required = true` on the existing
`stateless` fixture. That is the production shape the isolation guard actually refuses,
and it loads.

This is the same class as the defect this whole row keeps producing — a fixture that
cannot reach the arm under test. It was caught here by a reviewer tracing the config
validator rather than reading the cell.

### 13.2 List and invoke will disagree after the arm widens

`invoke.rs:3507,3603` and `ops.rs:138` still read the Shared catalogue. Once `stateless`
lists per caller, a caller-only tool is listed from the caller's slot while its schema
is read from the shared one — so param mirroring, output-schema checks and "did you
mean" all consult the wrong catalogue.

Today the two agree because both are Shared. Widening the arm breaks that agreement
unless the binding is threaded through. MEDIUM cost, and it belongs in the
implementation plan rather than after it. Related to the list/read coherence gap
already tracked as MIK-7542, which is the same disagreement on the read path.

### 13.3 `resend_permitted` should be written through the lease

`metadata.rs:290-291` writes it via a second `tools_slot(binding)` lookup rather than
onto the `PooledEntry` the fill already leased. A revocation that removes the slot
mid-fetch can therefore resurrect the pre-revocation retry set on a freshly inserted
empty slot. Keeping C4 on one `Arc` closes it. SMALL.

### 13.4 Two cells do not yet discriminate

T-S5 cites `catalogue_families_per_caller_tests.rs:655-659`, which is an **identified**
alpha seeing `STATIC_ITEM` — the case T-S1 inverts. It needs its own unidentified
caller, or T-S1 can be bought by dropping the identity-free Shared path, which is the
failure the prior design's T6 exists to catch.

T-S9 drives eviction with `PerIdentityMint`'s `{subject}@{audience}` string rather than
the production `idp:{len}:{subject}:` prefix that `config_reload` passes to
`evict_identity_slots` (`identity_propagation/mod.rs:356-372`). C4 must be proven on
the prefix that actually ships.

### 13.5 The uncapped slot count is a production gate, not a design defect

kimi's HIGH: N identities times N propagation backends inside one 300-second idle
window is unbounded at peak, so a burst of distinct verified identities could exhaust
connections or memory and take the gateway down for every tenant.

Its recommended shape matters more than the finding: alert on the already-gauged
`mcp_backend_pool_slots`, and when a cap is eventually specified it must **refuse,
never fall back to Shared**. A Shared fallback under pressure would recreate exactly
the cross-tenant leak #727 closed — the mitigation that first suggests itself is the
one that reopens the defect.

Recorded here so that constraint is attached to the cap before anyone builds one.

### 13.6 The fixture blast radius, closed with evidence rather than a scratch run

kimi's LOW asked for the four other `stateless` fixtures to be run under a scratch
widened arm. Checked directly instead, and none can flip:

| Fixture | Why the widened arm cannot reach it |
|---|---|
| `create_oauth_client_refuses_identity_propagation_backends` | no identity passed; about client creation |
| `backend_handler_discovery_method_fails_closed_for_required_propagation` | no identity, so `(Some(_), Some(binding))` cannot match |
| `backend_handler_required_mint_without_route_audit_fails_closed_generically` | asserts an audit-failure path — HTTP 500, generic message, no leaked path — orthogonal to slot choice |
| `account_raw_vault_tests.rs` | zero assertions on `PoolKey`, `pool_key`, `fills_for`, `headers_for`, `cached` or `slot`; its own doc comment says it uses controls and negatives *"so a missing per-user pool slot can never be confused"* |

Showing why they cannot flip is stronger than observing that they did not.
