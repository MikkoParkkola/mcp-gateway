# MIK-7334.CATALOGUE.1 — identity-keyed tool cache, per-caller catalogue view

Design only. No implementation code exists at HEAD; its absence is the premise
of this document, not a defect in it.

Evidence tags: **V** = verified by reading source (file:line given), **I** =
inferred from verified facts, **A** = assumption needing confirmation.

---

## 0. Authority, and one correction to the pointer

**V** The criterion text is `docs/requirements/RELEASE-4.0.0-scope-update.md:32`:

> Supported identity-dependent backend catalogues, cached metadata and results
> are isolated by verified caller and authorization context, including changes
> and revocation.

**V** The row is `docs/requirements/RELEASE-4.0.0-scope-status.json`, id
`MIK-7334.CATALOGUE.1`: `status: pending`, `stage: graded`, `blocked_on: none`.

**V, CORRECTION** The briefing named `note` **and `decisions[]`** as the
authority. The row has no `decisions` key. Its fields are exactly
`id, status, stage, blocked_on, evidence, note`. All operator rulings live in
the `note` prose. Nothing is lost — the note carries them — but no reader should
go looking for a `decisions[]` array on this row.

**V** The note's closing block confirms the briefed ruling verbatim: *"OPERATOR
RULING 2026-09-21, STANDING SCOPE POLICY … The PR #604 rescope … is therefore
DECLINED as a default-path descope. CATALOGUE.1 is BUILD, not rescope.
Reclassified operator -> engineering."* And from the 2026-09-20 ruling: *"WORK
THIS FUNDS: an identity-keyed per-backend tool cache … This is a NEW MODE, not
defect repair — it needs a reviewed design before any code."* This document is
that design.

### 0.1 The standing constraint says the opposite of what the row says it says

This is the load-bearing finding of the whole design, so it is first.

**V** The row's note records a standing constraint: *"keying the cache by
`cache_binding` is already ruled out, because it would key a derived set finer
than its source."* It cites
`docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md`.

**V** That document, at :295-307, actually says:

> `tools_cache` is a single `CachedMetadata<Vec<Tool>>` per `Backend` … the
> identity key selects a connection `PoolKey` …, never a cache. So the tool
> catalogue is *already* shared across identities, and **the rejected set
> shadowing it** inherits exactly that scope. The proposed repair — key
> **rejection** by the identity pool key — would key a derived set finer than
> the data it is derived from, which cannot be built: there is no per-identity
> list to reject from. **The honest statement is that identity-scoped rejection
> becomes meaningful only if `tools_cache` itself becomes identity-partitioned,
> and that is a change to the cache, not to this gate.** Owner ruling: out of
> scope, and filed. … the decision itself is MIK-7334.

The ruling forbade keying **the rejection set** — a set *derived from*
`tools_cache` — finer than `tools_cache`, while `tools_cache` stayed shared. It
did not forbid partitioning `tools_cache`. It *names partitioning `tools_cache`
as the only repair that makes the property meaningful*, and files that decision
under MIK-7334 — this row.

**I** So the row's paraphrase inverts the ruling's scope. This design is not
working around the constraint; it is executing the repair the constraint
pointed at. Any reviewer who fires "cache_binding is ruled out" is citing the
paraphrase, not the ruling.

---

## 1. Conjuncts

Read as a conjunction over a quantified set. Conjunct 0 fixes the set.

| # | Conjunct | What satisfies it |
|---|---|---|
| **C0** | **"Supported" — which configurations the rest quantifies over** | The set is not empty and is not "all backends": it is backends with `identity_propagation` configured and `session_mode = per_user` (**V** `src/backend/pool.rs:173-181`, the only arm that mints a per-identity slot). This is the word #604 tried to turn — it argued the set is empty at 4.0.0, so the isolation clause ranges over nothing. The operator declined that. C0 is therefore a **build** obligation: make the set non-empty by making per-identity catalogues a real mode. |
| **C1** | Identity-dependent backend **catalogues** isolated by verified caller and authorization context | A `tools/list` fetched over the caller's own pool slot, cached in that slot, and never served to another binding. |
| **C2** | **Cached metadata** isolated by verified caller and authorization context | All four metadata lists (tools, resources, resource-templates, prompts) **and every raw accessor that reads their cache directly** are slot-scoped. §4.2. |
| **C3** | **Results** isolated by verified caller and authorization context | Capability side already keyed; MCP side has no result cache to leak. §4.3. |
| **C4** | Including **changes and revocation** | Generation-voided fills (exists) plus explicit revoke → evict-slot wiring (does not exist). §4.4. |

"Isolated by verified caller **and authorization context**" is two axes, and
they are satisfied on different mechanisms — see §4.5. Conflating them is how a
reviewer concludes the design misses half the criterion.

---

## 2. The catalogue path at HEAD

Traced end to end. Every line below was read.

1. **V** `src/gateway/meta_mcp/mod.rs:2163-2164` — meta dispatch:
   `"gateway_list_tools" => self.list_tools(&arguments, session_id).await`,
   `"gateway_search_tools" => self.search_tools(&arguments, session_id).await`.
   The `caller` binding is destructured at `:2133` and **is in scope at these
   two arms**, and it carries `verified_identity`
   (**V** `src/gateway/meta_mcp/mod.rs:163`). It is passed to
   `gateway_execute`, `gateway_invoke`, `gateway_cost_report` — and **dropped**
   for the two catalogue tools. *The identity is present and discarded at the
   catalogue boundary.*
2. **V** `src/gateway/meta_mcp/search.rs:703` —
   `async fn list_tools(&self, args: &Value, session_id: Option<&str>)`. No
   identity parameter. Same for `list_tools_single_server` (`:~640`).
3. **V** `src/gateway/meta_mcp/mod.rs:1182` — `meta_route_isolation_refused`
   omits an identity-bound backend fail-closed on a multi-user gateway, *before*
   any cold-cache fetch. **14** call sites across 6 files (mod, protocol, resources,
   search, spec_preview, surfaced). This is the shipped leak-stop.
4. **V** `src/backend/metadata.rs:156` `get_tools_shared` →
   **V** `:116` `get_cached_list_shared` → **V**
   `src/backend/cached_metadata.rs:162` `get_or_fetch_shared` — single-flight +
   TTL over **one** cache instance per backend.
5. **V** `src/backend/mod.rs:85,95,97,99` — `tools_cache`, `resources_cache`,
   `resource_templates_cache`, `prompts_cache`: four `CachedMetadata` fields
   **on `Backend`**, one slot each, no key.
6. **V** `src/backend/ops.rs:31-42` `request_internal` calls
   `self.shared_transport()` → **V** `src/backend/pool.rs:276`, which reads
   `PoolKey::Shared` unconditionally. No identity, no propagated headers.
7. **V** `src/backend/pool.rs:173-181` `pool_key_for` — `PerUser { binding }`
   only for `(Some(SessionMode::PerUser), Some(binding))`; everything else
   collapses to `Shared`.
8. **V** `src/gateway/router/backend_handlers.rs:675` — the direct route exempts
   `initialize | tools/list | ping` from the isolation gate, so `identity_key`
   stays `None` there for `tools/list` too.

**V, and this is the honest statement of the gap:** the per-identity *transport*
pool exists and works. The metadata path simply never asks it for a slot. What
is cached today is the gateway's own static-credential catalogue, handed
identically to everyone — documented in-tree at
`src/backend/metadata.rs:96-115`: *"this path is deliberately identity-free …
Per-identity catalogues remain unbuilt: delivering them needs a per-identity
fetch over the caller's own pool slot, which is a mode, not a guard."*

**I** So today's posture is *omission*, not isolation: a per-user backend is
made invisible rather than shown per-caller. That is a leak-stop, and the
operator ruled it is not the mode.

---

## 3. The design: move the caches into the pool slot

**Move the four `CachedMetadata` fields off `Backend` and into `PooledEntry` —
and `resend_permitted` with them. FIVE fields, not four (R1, §12).**

That is the whole idea. `Backend::tools_cache` (and its three siblings) ceases
to exist as a field. Every metadata read and fill goes through
`claim_pooled_entry(&key)` — the same lookup that already hands out the
transport, in the variant that holds the slot against the evictor (R3, §3.1).

**V** `src/backend/pool.rs:59-70` — `PooledEntry` already owns
`transport`, `start_lock`, `last_used`, **and its own `Failsafe`**. The doc
comment gives the precedent in the criterion's own language:

> The failsafe … is owned per-slot, not per-backend (MIK-6735 fix 1). Gating
> `request_with_headers` on a single backend-wide `Failsafe` meant one caller
> identity's transport failing enough tripped the breaker for every OTHER
> identity sharing the same backend too — the exact cross-tenant blast radius
> the per-user pool exists to eliminate.

**I** The metadata cache is the identical argument one rung further: a
backend-wide cache means one identity's *catalogue* is served to every other
identity sharing the backend. The repair is the one already performed on the
failsafe, applied to the field beside it.

### 3.1 Why this is provable and not merely plausible

The central risk in this row is that a security-adjacent cache keyed on identity
leaks when the key that selects the *cache entry* diverges from the key that
selected the *upstream connection*. Two key computations, one drifts, wrong
catalogue served.

The defence is not care. It is **the absence of a second path**:

- `pool_key_for` (**V** `src/backend/pool.rs:173`) becomes the *only* key
  computation in the system. It already is, for transports.
- `Backend` has no cache field left to read. A caller cannot reach a cache
  without first naming a `PoolKey`, because the cache is reachable only through
  **`claim_pooled_entry(&key)`** (**V** `src/backend/pool.rs:253`) — **CORRECTED
  2026-09-22 (R3)**. This document originally named `pooled_entry`
  (**V** `pool.rs:235`), whose own doc says it *"hands back an entry the evictor
  is still free to remove"* and sends callers who intend to USE the slot to
  `claim_pooled_entry` instead. A metadata fill routed through the unclaimed
  lookup races `evict_idle_per_user_entries`, which closes the transport under
  the fetch. The safe variant already exists beside it and claims an in-flight
  slot under the shard guard.
- The bytes in slot *K*'s cache were fetched over slot *K*'s transport, because
  the fill closure and the cache live behind the same `Arc<PooledEntry>`.

**What this proves, stated at its real width — NARROWED 2026-09-22 (R3).** What
co-location makes unrepresentable is **cache/transport divergence within a
slot**: no expression pairs one slot's cache with another slot's transport,
because a cache is obtainable only from a slot.

It does **not** make key *selection* correct. §4.2.1 instructs the identity-free
consumers to pass `PoolKey::Shared` explicitly, and once any call site may name a
key, a caller-scoped site can name `Shared` too — and the compiler sees a
well-typed call. The mitigation is to keep key construction out of call sites:
the slot-scoped accessors call `pool_key_for` on the caller's binding internally,
and `Shared` stays reachable only through the named `*_shared` helpers. That is a
convention plus a narrow API, not a proof, and this document should not claim
otherwise.

**Falsifier, pass/fail — WIDENED 2026-09-22 (R1, §12).** After the change,
`rg -n "tools_cache|resend_permitted" src/` returns hits only inside `pool.rs`
and `metadata.rs`'s slot-scoped accessors, and zero on `self.tools_cache` or
`self.resend_permitted` in `Backend` method bodies. If a single reader still
reaches a cache — or a set derived from one — without a `PoolKey` in hand, the
proof is void and the design has failed, not degraded.

**The `resend_permitted` term is not decoration: the original one-term grep
passed green while the bug was live** (§12). A falsifier that names only the
field you already thought of tests your memory, not the property. Widen it
again for any further field derived from a catalogue.

**I** This also satisfies the cluster-g ruling by construction (§0.1): the key
and the source are now the *same* granularity. Slot *K*'s cache holds bytes
fetched over slot *K*'s connection. Nothing is keyed finer than its source,
because the source was made per-identity first. The ordering matters and is the
entire reason the earlier repair "could not be built".

### 3.2 What this deliberately is not

- **Not** a new cache type, key type, trait, or dependency. Four struct fields
  move file. `CachedMetadata` is unchanged (**V** `src/backend/cached_metadata.rs`
  is already generic and already single-flight per instance).
- **Not** a signature change on the shared path. `get_tools_shared` keeps its
  name and its meaning — *the shared slot's tools* — and keeps serving the
  identity-free callers in §4.2.1 unchanged.
- **Not** a change to `meta_route_isolation_refused`'s *logic*. It stays as the
  fail-closed default for callers who resolve no identity (§4.6). **Its call
  sites do change** — see §9.2, a blocking correction from review: the helper
  hardcodes `has_per_user_credential = false`, which would omit the backend from
  exactly the callers this mode creates.

---

## 4. Conjunct by conjunct

### 4.1 C1 — catalogues

Thread the identity that already exists to the place that already needs it:

1. **V** `src/gateway/meta_mcp/mod.rs:2163-2164`: pass `caller` to `list_tools`
   and `search_tools`, exactly as `:2165` already does for `gateway_invoke`.
   Two arms, one argument each.
2. `list_tools` / `list_tools_single_server` / `search_tools` resolve the
   caller's binding the way the invoke path already does — **V**
   `resolve_propagation_credential(&name, verified_identity.as_ref())`
   (`src/gateway/router/backend_handlers.rs:720`) yields
   `PropagatedCredential::cache_binding` (**V** `src/identity_propagation/mod.rs:103`).
3. `pool_key_for(Some(&binding))` (**V** `src/backend/pool.rs:173`) selects the
   slot. Unchanged function, new caller.
4. The fill runs over **that slot's** transport, not `shared_transport()`. This
   is the one genuinely new line of behaviour in the backend: a metadata fetch
   that takes a `PoolKey` instead of hardcoding `PoolKey::Shared`.
5. The answer lands in that slot's cache, because that is the only cache
   reachable from the slot (§3.1). The fill runs **through the slot**, so it
   cannot reach `shared_transport()` — see §9.3, a review-driven amendment.
6. **BLOCKING, RESOLVED 2026-09-22 (§9.2, §11) — READ §11 BEFORE TOUCHING A CALL
   SITE.** The `meta_route_isolation_refused` call sites must carry the caller's
   real credential state instead of the hardcoded `false` at **V**
   `src/gateway/meta_mcp/mod.rs:1189`. **This is a per-site opt-in, NEVER a
   sweep**: `has_per_user_credential = true` does not narrow
   `enforce_oauth_isolation_for`, it returns `Ok(())` at **V** `:1116` before any
   isolation arm is evaluated, so loosening it at a site whose next operation
   still runs on the gateway's shared credential opens the leak ADR-008 INV-2
   exists to deny. Only the four catalogue-path sites change, each together with
   its own fetch becoming slot-scoped. §11 has the census and the signature.

**I** Per-identity `tools/list` bytes are now real, so C0's set is non-empty and
C1 has something to isolate. Today it does not.

### 4.2 C2 — cached metadata, including the accessors that bypass the fetch path

**This is the part a fetch-path-only change would ship broken.** Sixteen
production call sites read a metadata cache *directly*, never touching
`get_cached_list_shared`:

| Accessor | Production consumers (**V**) |
|---|---|
| `get_cached_tool` | `src/backend/ops.rs:151`; `src/gateway/meta_mcp/surfaced.rs:111,150`; `spec_preview.rs:179`; `task_confirmation.rs:204`; **`upstream.rs:421`** (output-schema resolution — found by GPT review, missed in my first sweep) |
| `get_cached_tools_snapshot` | `src/gateway/meta_mcp/search.rs:105`; `spec_preview.rs:96`; `src/gateway/ui/control_plane.rs:576` |
| `get_cached_tool_names` | `src/gateway/meta_mcp/spec_preview.rs:210`; **`invoke.rs:3498`** (stale-cache dispatch check — found by GPT review) |
| `cached_tools_count` | `src/backend/ops.rs:679`; `src/gateway/server/warmstart.rs:516` |
| **`has_cached_tools`** (fifth accessor — missed in my inventory *and* by the completed review; surfaced by `grok-review` before it stalled) | `src/gateway/meta_mcp/search.rs:155` (gates background refresh); `src/gateway/meta_mcp/spec_preview.rs:90` (gates backend inclusion) |

**I** If only the fetch path moves, every one of these keeps reading the Shared
slot while the caller sits on a PerUser slot. `spec_preview.rs:210` feeds
"did you mean?" name suggestions — one caller's *tool names* surfacing in
another caller's suggestions is precisely this criterion's leak class, arriving
through the back door while the front door is provably sealed.

So the accessors take a `&PoolKey` too, or they do not compile. That is the
point of deleting the `Backend` fields rather than merely adding a keyed path:
**V** removing `Backend::tools_cache` turns all twelve into compile errors. The
compiler enumerates the blast radius; no grep is trusted to have found it.

#### 4.2.1 The identity-free consumers stay identity-free

**V** Four production readers legitimately have no caller and must keep the
shared slot: `src/gateway/server/warmstart.rs:516,548` (startup prefetch),
`src/gateway/ui/mod.rs:606` and `ui/control_plane.rs:576` (operator UI),
`src/gateway/meta_mcp/search.rs:145` `refresh_stale_backend_tools` (detached
background task, spawned with only an `Arc<Backend>`).

They pass `PoolKey::Shared` explicitly. The name `get_tools_shared` becomes
literally true rather than incidentally true. **I** Single-tenant behaviour is
byte-for-byte unchanged, which is the same IDP.5 guarantee `pool_key_for`
already makes for transports (**V** `src/backend/pool.rs:169-171`).

**A** `refresh_stale_backend_tools` refreshing only the Shared slot is correct:
a per-identity slot's cache should be filled by that identity's own request, not
by a background task holding no credential. If the operator wants per-identity
prefetch, that is a separate decision — flag it, do not build it.

### 4.3 C3 — results

**CORRECTED 2026-09-21 after GPT review — my first draft was wrong here.**

I originally discharged C3 "by absence", on the grep `rg "CachedMetadata<"`
returning only the four metadata lists. That was the wrong grep: the result
cache is a different type, and it exists. GPT-review found it. The finding was
correct; its conclusion ("existing result-isolation obligations disappear") was
not, and the truth is better than either.

**V** The MCP dispatch path **does** cache `tools/call` results, at
`src/gateway/meta_mcp/invoke.rs:1842-1855` (`cache.get`) and `:2440`
(`cache.set`), plus a separate idempotency replay cache at `:1794`
(`GuardOutcome::CachedResult`).

**V** That cache is **already keyed by verified caller and authorization
context** — precisely what C3 demands. `response_cache_key_for`
(`src/gateway/meta_mcp/support.rs:168`) takes
`caller_principal.as_deref()` and a `crate::cache::KeyContext {
routing_profile, protocol_revision, policy_epoch }`
(`invoke.rs:1842-1853`). The principal comes from `caller_cache_principal`
(**V** `src/gateway/meta_mcp/support.rs:145-166`), which resolves, in order,
`cache_binding` → verified OIDC stable actor id → grant subject, and
**length-prefixes every component** (`format!("idp:{}:{binding}", binding.len())`)
so two distinct principals cannot collide by concatenation.

**I** So C3 is satisfied on both sides, and on the right mechanism:

- MCP results: keyed by caller principal (identity axis) **and** by
  `routing_profile` + `policy_epoch` (authorization-context axis). The
  `policy_epoch` component is what carries C4's "changes" into the result
  cache — **V** `set_identity_grants` bumps it under the write lock
  (`src/gateway/meta_mcp/mod.rs:~1207`), so a grant change invalidates every
  result key minted under the superseded grants without touching the cache.
- Capability results: `build_cache_key` prefixes authority and subject
  (**V** `src/capability/executor/params.rs:283`), asserted at
  `src/capability/executor_tests.rs:1559`.

**I** This design therefore **changes nothing for C3**. It cites the mechanism
rather than building one. That is the correct outcome and it strengthens the
row: C3 was the conjunct the withdrawn 2026-09-17 grade marked "NOT GRADED, NO
EVIDENCE", and the evidence exists.

**A** One residual worth an implementer's eye, not a blocker: the result key
uses `caller_cache_principal`, which prefers `cache_binding`, while this
design's catalogue key uses the `PoolKey` derived from that same
`cache_binding`. Same source value, two derivations. They need not be equal —
they key different things — but they must not *disagree about who the caller
is*. Confirm at implementation that both resolve from the one
`PropagatedCredential`, rather than each resolving the identity independently.

### 4.4 C4 — changes and revocation

**V** Half exists. `CachedMetadataState::generation`
(`src/backend/cached_metadata.rs:22-27`) is documented against this very
criterion — *"an invalidation that lands mid-fill voids that fill instead of
being overwritten by it (MIK-7334.CATALOGUE.1, 'changes and revocation')"* — and
`store_if_current` (**V** `src/backend/cached_metadata.rs:94`) drops a fill whose generation went stale. Covered by
`revocation_during_a_fill_is_not_served_afterwards`
(**V** `src/backend/tests.rs:1862`).

**V, and this is the trap:** `invalidate_tools_cache`
(`src/backend/metadata.rs:39-46`) discards an **empty** list only —
`self.tools_cache.invalidate_if(Vec::is_empty)` (**V** `cached_metadata.rs:121`) — deliberately, so a warm-start
re-confirming emptiness cannot erase a list another reader just populated.
**I** Routing revocation through it would therefore be a silent no-op on any
populated cache. Every revocation of a real catalogue would do nothing.

The wiring is instead **revoke → evict `PoolKey::PerUser { binding }`**, which
drops that identity's transport *and* its caches in one move, because they are
now the same object. **V** `src/personal_accounts/mod.rs:525` touches no backend
metadata today, so this is new work, not a re-route.

**I** Distinct from `evict_idle_per_user_entries`
(**V** `src/backend/pool.rs:286`): that is time-driven and best-effort;
revocation is event-driven and must be immediate. Same eviction primitive, two
triggers, different guarantees. Do not fold them.

### 4.5 "verified caller **and** authorization context" — two axes

**I** These are satisfied by different mechanisms, and saying so prevents a
false gap:

- **Verified caller** → the cache key. Different binding, different slot,
  different bytes. §3.1.
- **Authorization context** → post-cache filters, unchanged. **V**
  `src/gateway/meta_mcp/search.rs:691` (and `:663`) filters the cached list by
  `profile.tool_allowed(&t.name)` and `tool_matches_role(t, role_filter)`;
  **V** `current_search_state` (`search.rs:~161`) applies the FSM workflow state
  at every discovery entry point.

**I** This split is load-bearing for hit rate. The cache holds the *unfiltered
upstream answer*; authorization narrows it per request. If authz context were
folded into the key, every profile/role/state combination would fork a cache
entry — a derived set keyed finer than its source, the exact error the cluster-g
ruling names. Keeping authz in the post-filter is not laziness; it is the
ruling applied correctly a second time.

**A** This holds only while every authz filter is a pure function of the cached
list plus request context, with no upstream call. Verify at implementation; if
some future filter needs its own fetch, that fetch is slot-scoped too.

### 4.6 The unidentified caller gets a defined view

Enumerated, not left to fall through:

| Caller | Gateway mode | View | Source |
|---|---|---|---|
| No identity resolved | single-user | Shared slot: the static-credential catalogue | **V** `pool_key_for` → `Shared`, `pool.rs:178-180` |
| No identity resolved | multi-user, identity-bound backend | **Backend absent** — omitted fail-closed, indistinguishable from not configured | **V** `meta_route_isolation_refused`, `mod.rs:1182`; `search.rs:684` returns `BackendNotFound` |
| Identity resolved | multi-user, `session_mode = per_user` | Own slot, own catalogue | §4.1, new |
| Identity resolved | backend not identity-bound | Shared slot — genuinely shared service | **V** `pool_key_for` `_` arm |

**I** Every row is defined, and the fail-closed row is the *existing* behaviour,
unchanged. The design adds a view for the caller who has an identity; it does
not weaken the answer for the caller who has none. A reviewer claiming "the
unauthenticated case is undefined" should be pointed at row 2.

### 4.7 Hit rate, honestly

- **Shared / single-tenant:** unchanged. One slot, one fill per TTL. **I** The
  overwhelming majority of deployments never mint a second slot.
- **`session_mode = per_user`:** one fill per identity per TTL, where today
  there is one fill total — and, at HEAD, a backend that is *omitted entirely*
  from discovery. **I** The comparison is not "N fills vs 1 fill", it is "N
  fills vs the feature not existing". Cost is real; the alternative is not a
  cheaper catalogue, it is no catalogue.
- **Memory:** bounded by the pool's existing slot count, with no new bound to
  maintain — **V** `evict_idle_per_user_entries` already reaps idle per-user
  slots, and now reaps their caches with them, because they are one object.
  **I** This is the second structural dividend of co-location: no separate cache
  eviction policy is written, reviewed, or forgotten.

---

## 5. Test plan

**V** The row's own test plan is `docs/requirements/RELEASE-4.0.0-scope-tests.md:40`:

> One backend returns different tool names/schemas for two identities.
> Interleave cold/hot reads, rotate/revoke a grant during a fill and check both
> catalogue and call results. Invariant shared catalogue is a separate positive
> control.

Mapped, each test discriminating — it must go RED on the current tree for the
stated reason, not merely pass afterwards:

| T | Test | Conjunct | RED-before reason |
|---|---|---|---|
| **T1** | One backend, two identities, differing tool names. B's list must not contain A's tools, and upstream fetch count must be **2**, not 1. | C0, C1 | **V** Today `request_internal` fetches once over `shared_transport()` and both callers get identical bytes — the fetch count alone fails. |
| **T2** | Interleave cold/hot: A cold-fills, B reads hot. B must miss A's entry and fill its own. | C1, C2 | Today B hits A's cache entry. |
| **T3** | Accessor sweep: for each of `get_cached_tool`, `get_cached_tool_names`, `cached_tools_count`, `get_cached_tools_snapshot`, assert B's slot answers with B's tools. | C2 | **V** Today all four read the single `Backend` field (§4.2). Without T3 the fetch path is sealed and the accessors leak. |
| **T4** | Revoke A's grant mid-fill; then revoke after a populated fill. Neither serves A's catalogue afterwards. | C4 | The mid-fill half passes today (**V** `tests.rs:1862`); the **populated-cache** half fails, because `invalidate_tools_cache` discards empty lists only (§4.4). |
| **T5** | ~~Assert no MCP `tools/call` result cache exists.~~ **WITHDRAWN 2026-09-22 — the premise was refuted by §4.3/§9.1 of this document and the row was never updated. Replaced by T5-R: assert `response_cache_key_for` (`support.rs:168`) produces different keys for two principals that differ only in identity, with the same-caller-stable half beside it.** | C3 | T5 as drafted fails immediately for the wrong reason, or gets "fixed" by deleting a result cache that must stay. T5-R goes red for a future cache that derives a principal and then drops it while assembling the key. |
| **T6** | **Positive control** — invariant shared catalogue. Non-identity backend still single-flights to **one** fetch, `cached_tools_count() == 1`. | regression | **V** `get_tools_singleflight_coalesces_concurrent_requests` (`src/backend/tests.rs:683`) exists and passes; it must keep passing unchanged. |
| **T7** | **Structural, two required greps (amended §9.3)** — (a) `Backend` exposes no cache reachable without a `PoolKey`; (b) `shared_transport()` has no caller inside any metadata fill path. | §3.1 | Grep (a) alone proves only the cache end of the pairing; review showed a fill on a PerUser slot could still call `shared_transport()` and pass it. Both, or the proof is of the wrong property. |
| **T8** | **Provenance** — T1 asserts *which slot's transport* served each fetch, not merely that two fetches occurred. | C1, §3.1 | Field names prove naming; provenance proves isolation. Added on review. |

**I** T6 and T7 are the two that keep this honest. T6 catches the regression
where isolation is achieved by breaking the shared path. T7 catches the
regression where someone re-adds a convenience accessor on `Backend` and
quietly restores the second path.

**A** The standing limitation recorded against the withdrawn 2026-09-17 grade —
*"Both new tests would also pass if per-user catalogues were deleted outright"*
— is what T1's **fetch-count == 2** assertion exists to prevent. A withhold
scores zero fetches; only a real per-identity fetch scores two. State this in
the implementation PR, because it is the exact trap this row fell into once.

---

## 6. Risks

1. **Key divergence (central).** Mitigated structurally, not procedurally
   (§3.1). Accept the design only if `Backend` ends with no cache field; if
   implementation keeps one "for convenience", the central claim is void and the
   row should not be graded on it.
2. **Accessor bypass.** §4.2. Mitigated by deleting the fields so the compiler
   enumerates all twelve sites. **I** The risk is that an implementer adds a
   keyed path *alongside* the old field to keep the diff small — which is the
   one shortcut that reintroduces the whole bug class.
3. **Revocation no-op.** §4.4. `invalidate_tools_cache` looks like the right
   hook and is not. **I** High-likelihood implementer error; called out here
   precisely so it is not discovered in review.
4. **Fetch-count amplification on a cold multi-user start.** N identities, N
   fills, possibly concurrent. **I** Per-slot single-flight already prevents
   duplicate fills *per identity* (**V** `cached_metadata.rs:162` is per
   instance, and per-slot instances mean per-identity single-flight — a property
   co-location gives free). It does not prevent N distinct fills; nothing can,
   since they are N distinct upstream answers.
5. **Prompts/resources/resource-templates forgotten.** **V** The criterion says
   "cached metadata", not "tool catalogue", and there are four caches
   (`mod.rs:85,95,97,99`). **I** Moving only `tools_cache` would satisfy the
   peer's summary and fail the criterion. All four move together — **and so does
   `resend_permitted`, which is derived from the tool catalogue and is the fifth
   field (§12).**

---

## 7. Open questions for the release owner

**Q1 — Does the shared-slot fallback for a `required` per-user backend remain
correct?** **V** `pool_key_for` collapses `(PerUser, None)` to `Shared`
(`pool.rs:178-180`). For a backend whose propagation is `required`, serving the
static-credential catalogue to an unidentified caller is the downgrade ADR-007
IDP.2/IDP.3 forbids on the call path. **I** Today `meta_route_isolation_refused`
covers this on the meta route (§4.6 row 2), so it is not live. But once
catalogues are per-identity, the `(PerUser, None)` arm is the one place a
caller with no identity could receive *a* catalogue.

**This has a free answer and I am recording it as a decision, not a question.**
**V** `required` already carries fail-closed semantics in this module, three
times over: `identity_propagation/mod.rs:125` ("are fail-closed for a
propagation-required backend"), `:296` ("a required backend cannot fall back"),
and the guard at `:498` (`if required && !transport_carries_headers`). A
non-`required` backend is documented as taking the opposite path at `:480-481`
("matching the existing non-required fallback elsewhere in this module").

**DECISION:** for a `required` per-user backend, `(PerUser, None)` **omits** —
reusing `meta_route_isolation_refused` (`meta_mcp/mod.rs:1182`), which already
omits fail-closed before any cold-cache fetch. For a non-`required` backend it
falls back to `Shared`, matching `:480-481`. This needs confirmation, not a
ruling.

**This is not PR #604's descope returning in a new wrapper**, and the difference
is the whole point. #604 omitted per-user backends for *every* caller, which is
why the operator called it a leak-stop rather than the mode. This omits only for
a caller who presents **no credential at all** — for whom the mode has nothing
to range over. A caller who *does* present a credential gets their own pool slot
and their own catalogue, which is the mode being delivered.

**Q2 — Does the direct route's `tools/list` exemption stay?** **V**
`backend_handlers.rs:675` exempts `tools/list` from the identity gate, so route
1 serves the shared catalogue live while route 2 would serve per-identity. **I**
That is a deliberate parity break and the row's note already records route 1
serving "the same bytes". Per-identity catalogues make the two routes disagree
for the first time. Recommend keeping the exemption for this release and
recording the divergence, since closing it is a separate blast radius. Confirm.

**Q3 — Scope of C3.** §4.3 discharges the MCP side by absence and cites the
capability side as already keyed. **A** That reading matches the note's
correction of 2026-09-17. Confirm the row is gradeable on it rather than
requiring a new result-caching mechanism that does not exist and that nothing
asks for.

---

## 8. Verdict

**READY to implement, conditional on Q1.**

Q2 and Q3 are recordable decisions that do not block starting. Q1 is a security
policy choice on a fail-open path that this design creates the conditions for,
and it should be answered before the `(PerUser, None)` arm is written.

The design is small on purpose: four fields change file, one fetch takes a key
instead of a constant, two dispatch arms pass an argument they already hold, and
one revocation path gains an eviction. No new type, no new dependency, no new
eviction policy. The security property comes from deleting a path, not from
adding a guard.

---

## 9. Independent review and what survived verification

Reviewed by `gpt-review` (non-Claude). Every finding below was checked against
source before being accepted or rejected — a reviewer's claim is not evidence
until verified. Verdict returned: SHIP-WITH-FIXES. Three findings changed this
document; two are recorded as real-but-adjacent; the design's core survived.

### 9.1 CONFIRMED, and it corrected a real error of mine — C3

**Claim:** "C3 is incorrectly discharged by absence because the MCP invocation
path already reads and writes response caches and replays idempotency results."

**VERIFIED. The reviewer was right and I was wrong.** My absence claim rested on
`rg "CachedMetadata<"`, which only ever matches the metadata lists. The result
cache is a different type, so the grep could not have found it; I chose a test
that could not fail. **V** `src/gateway/meta_mcp/invoke.rs:1855` (`cache.get`),
`:2440` (`cache.set`), `:1794` (idempotency replay).

**The reviewer's *conclusion* was wrong, and the truth is better than either
position:** that cache is already keyed by caller principal *and* authorization
context — **V** `response_cache_key_for` + `caller_cache_principal`
(`src/gateway/meta_mcp/support.rs:145-168`), length-prefixed against collision.
§4.3 is rewritten to cite the real mechanism. C3 moves from "discharged by
absence" (brittle) to "satisfied by an existing keyed cache" (evidence), which
is a strictly stronger position for the row.

### 9.2 CONFIRMED and BLOCKING — the isolation guard locks out the new mode

**Claim:** "Keeping `meta_route_isolation_refused` unchanged still rejects
authenticated callers because the helper always reports that no per-user
credential exists."

**VERIFIED, and this is the most valuable finding of the review.**
**V** `src/gateway/meta_mcp/mod.rs:1183` calls
`self.enforce_oauth_isolation_for(backend, &backend.name, false)` — the third
argument, `has_per_user_credential`, is **hardcoded `false`**.
**V** `:1110`: `if !self.multi_user.load(…) || has_per_user_credential { return Ok(()); }`.

**I** So on a multi-user gateway the guard refuses an identity-bound backend
*unconditionally*, including for a caller who has just resolved a perfectly good
per-user credential. Ship §4.1 without touching this and the per-caller
catalogue is built, correct, and **unreachable** — every caller still sees the
backend omitted. My §3.2 claim that this helper is untouched was wrong.

**The fix is small and the shape is already there:** `enforce_oauth_isolation_for`
*takes* `has_per_user_credential` (**V** `:1104-1108`) — the parameter exists
and other callers pass it meaningfully. The discovery call sites must pass the
caller's real credential state instead of the constant.

**CORRECTED 2026-09-22 (R2, §11), in two ways.** The count is **14**, not 15 —
`mod.rs:1188` is the definition, not a call site, and `rg`'s 15 hits include it.
And the sentence that followed here — *"the 15 sites become credential-aware"* —
was wrong as a prescription and is withdrawn. `has_per_user_credential = true`
short-circuits `enforce_oauth_isolation_for` at **V** `mod.rs:1116` rather than
narrowing it, so applying it uniformly **disables** enforcement at the four sites
that go on to fetch over the shared credential. Only the four catalogue-path
sites change, each with its own fetch. §11.5 has the census; the fail-closed
answer is preserved exactly for the unresolved caller (§4.6 row 2).

**Design impact:** add to §4.1 as step 6. This is now the second blocking item
alongside Q1.

### 9.3 CONFIRMED, and it strengthens §3.1 — the proof proved the wrong property

**Claim:** "Co-location does not make mismatched fills unrepresentable because
the generic fetch closure can capture another entry or call the shared path
while still passing the proposed grep gate."

**VERIFIED and accepted.** **V** `get_or_fetch_shared`
(`src/backend/cached_metadata.rs:162`) takes an arbitrary
`F: Fn() -> Fut`. Nothing in the type prevents a closure invoked on a PerUser
slot's cache from calling `self.shared_transport()`
(**V** `src/backend/pool.rs:276`) and writing the *shared* catalogue into the
*per-user* slot. T7's grep for `self.tools_cache` would not catch it. The
reviewer correctly identified that my structural test checks the cache end of
the pairing and leaves the transport end open.

**Design change — the fill becomes slot-owned.** The closure must not be free to
choose a transport: `PooledEntry` exposes the fetch, so the transport is
`self.transport`, and `shared_transport()` is not in scope inside the fill at
all. Then *both* ends of the pairing come from the same `Arc<PooledEntry>` and
divergence is genuinely unrepresentable rather than merely uncaught.

**T7 is amended** to two greps, both required:
1. No cache reachable without a `PoolKey` (original).
2. `shared_transport()` has no caller inside a metadata fill path.

Plus a provenance assertion in T1: assert *which* slot's transport served each
fetch, not just that two fetches happened. **I** Checking field names proves
naming; checking provenance proves isolation. The reviewer is right that only
the second one is the property.

### 9.4 CONFIRMED — my accessor inventory was incomplete

**Claim:** the accessor table "omits production readers and miscounts".

**VERIFIED.** Two production readers were missing: **V**
`src/gateway/meta_mcp/upstream.rs:421` (`get_cached_tool` for output-schema
resolution) and **V** `src/gateway/meta_mcp/invoke.rs:3498`
(`get_cached_tool_names` for the stale-cache dispatch check). Twelve → fourteen;
§4.2 corrected.

**And then a third pass found more.** `grok-review` stalled before producing a
verdict, but its last emitted line was *"The table of cache readers looks
incomplete, so I'm tracing every production caller of those accessors plus
`has_cached_tools`"* — naming a **fifth accessor** neither I nor the completed
review had inventoried. **V** `Backend::has_cached_tools`
(`src/backend/metadata.rs:30`) has two production readers:
`src/gateway/meta_mcp/search.rs:155` and `src/gateway/meta_mcp/spec_preview.rs:90`.
Both are freshness predicates, and both would answer about the **Shared** slot
while the caller sits on a PerUser slot — `spec_preview.rs:90` gates whether the
backend appears at all. Twelve → fourteen → sixteen.

**I** This is the argument for §4.2's method, not against it, and it is now
demonstrated three times rather than asserted: my grep missed two, a completed
review missed a third accessor entirely, and a *stalled* review found it in
passing. No inventory in this document should be trusted as complete. That is
precisely why the design deletes the `Backend` fields and makes the compiler
enumerate the call sites — the only enumerator here with a perfect record.

### 9.5 CONFIRMED but PRE-EXISTING, not created here — suggestion filtering

**Claim (rated CRITICAL by the reviewer):** name suggestions and schema
resolution do not apply routing-profile filters, so restricted-profile callers
discover excluded tool names.

**VERIFIED as a fact.** **V** `collect_all_cached_tool_names`
(`src/gateway/meta_mcp/spec_preview.rs:199-212`) filters by
`meta_route_isolation_refused` — the identity axis — and does **not** call
`profile.tool_allowed`, which the discovery paths do apply (**V** `search.rs:691`).

**Labelled, not accepted as blocking.** This is a live gap on the
*authorization-context* axis that exists at HEAD today, on the shared catalogue,
independent of anything in this design. It is not introduced, worsened, or
fixed by moving caches into pool slots. Severity CRITICAL is defensible on its
own terms; **BLOCKING for this design is not**, because the design's premise is
unchanged either way.

**I** It does belong to this criterion's family (C2, authorization context), so
the honest handling is to file it as its own row rather than smuggle it into
this one — narrowing or widening a criterion mid-design is the exact move the
operator declined on 2026-09-21. Recommend: separate issue, cite
`spec_preview.rs:210` and `search.rs:691` as the asymmetric pair.

### 9.6 CONFIRMED as a limitation — per-user slots have no background refresh

**Claim:** background refresh stays Shared-only, so populated per-user
catalogues go stale past TTL on snapshot-based search paths.

**VERIFIED.** **V** `refresh_stale_backend_tools` (`src/gateway/meta_mcp/search.rs:145`)
is spawned with only an `Arc<Backend>` and holds no credential;
**V** `search.rs:105` reads `get_cached_tools_snapshot()` without forcing a
refresh. **I** A per-user slot past TTL would serve its stale snapshot while the
background task refreshes a slot the caller is not on.

**Accepted as a recorded limitation with a named fix**, consistent with §4.2.1's
**A**: a background task holding no credential *must not* fetch a per-identity
catalogue — that would re-introduce a static-credential fetch under a user's
slot, which is the original bug. The fix is on the read side: a per-user
discovery read whose slot is stale performs its own credentialed refresh
inline. Cheap, correct, and it keeps the no-credential task out of per-user
slots entirely.

### 9.7 REJECTED — none

No finding was dismissed as a reviewer error. The out-of-scope framing in the
review prompt did its job: the reviewer did not once argue that an unbuilt
mechanism is impossible because HEAD lacks it, which is the failure mode this
class of review usually produces.

`grok-review` was run twice and returned **no verdict**, but not nothing: its
second run named `has_cached_tools` as a missed accessor before dying, which
verified (§9.4) and moved the count to sixteen. The first run stalled
after emitting only a preamble (`~/.claude/data/reviews/runs/grok-20260921T110552Z-11919.md`,
241 bytes, no verdict), the second was re-issued with a narrowed three-question
prompt. **This design therefore rests on one independent reviewer, not two.**
Recorded rather than papered over: a second independent pass on §3.1 and §4.2 is
still owed before implementation.

---

## 10. Verdict, after review

**NOT READY — one blocker, down from two.**

| # | Blocker | Source |
|---|---|---|
| **B1** | `meta_route_isolation_refused` call sites must pass real credential state, or the mode ships unreachable | §9.2, review-confirmed |

B2 as first drafted ("does `(PerUser, None)` omit or fall back?") **is
withdrawn as a blocker.** It had a free answer I had not looked for: `required`
already means fail-closed at `identity_propagation/mod.rs:125`, `:296` and
`:498`, and non-`required` already means fall back at `:480-481`. The policy is
not a new choice this design forces; it is the module's existing one applied to
a new path. §7 Q1 now records it as a decision needing confirmation. Sending it
up as an open ruling would have read as PR #604's descope in a new wrapper and
would have cost B1 its credibility.

Q2 (direct-route `tools/list` parity) and Q3 (C3 scope — now answered with
evidence, §4.3) are recordable and do not block.

**One live gap, not caused by this design, that must not die in this document:**
`collect_all_cached_tool_names` (`meta_mcp/spec_preview.rs:199-212`) filters by
`meta_route_isolation_refused` (identity) but never by `profile.tool_allowed`
(authorization), which discovery *does* apply at `search.rs:691`. That
asymmetric pair — `spec_preview.rs:210` vs `search.rs:691` — is a live authz
gap at HEAD on the shared catalogue today. A reviewer rated it CRITICAL; I rate
it out of scope *for this row* because this design neither introduces, worsens
nor fixes it. It needs its own row.

The core survived review: co-locating the four metadata caches with the pool
slot is the right mechanism, the cluster-g ruling *requires* rather than forbids
it (§0.1), and the isolation proof holds **once amended** to cover the transport
end as well as the cache end (§9.3). Three of my own claims were wrong — C3 by
absence, the untouched isolation guard, and a twelve-of-fourteen accessor
inventory — and all three are corrected above rather than quietly restated.

Clear B1, confirm the §7 Q1 default, and this is ready to implement — subject
to the delivery process's own gate: §5's test plan is derived from the row's
plan (`RELEASE-4.0.0-scope-tests.md:40`) but has not itself been reviewed, and
that review sits between this document and code.

**Weight this verdict accordingly: it rests on one completed independent
review, not two.** `grok-review` produced no verdict in two runs (§9.7). Its
one useful emission — the fifth accessor — is credited at §9.4 and moved the
reader count up again. The count now stands at *at least* sixteen across five
accessors, revised upward twice by other people's eyes; §4.2's whole argument is
that no hand inventory here should be trusted, and that includes this one.

---

## 11. R2 — B1 resolved: a per-site opt-in, never a sweep

Landed 2026-09-22 from the round-2 review
(`2026-09-22-catalogue-1-design-review-round2.md`), which is where the full
evidence sits. Line citations here are against release-line HEAD.

### 11.1 The count is fourteen, not fifteen

**V** `rg -n "meta_route_isolation_refused" src/` returns 15 hits; `mod.rs:1188`
is the **definition**. §2 item 3 and §9.2 of this document both say 15. There are
**14 call sites**.

### 11.2 Why a sweep is a leak, not a smaller omission

**V** `mod.rs:1114-1116`:

```rust
if !self.multi_user.load(std::sync::atomic::Ordering::Relaxed) || has_per_user_credential {
    return Ok(());
}
```

`has_per_user_credential = true` **short-circuits the whole function**. Every
isolation arm below it is unreachable. §9.2's phrasing — *"the 15 sites become
credential-aware"* — read as a mechanical edit therefore does not narrow
enforcement, it disables it.

**V** Four sites guard and then fetch on the **shared** credential:

| Site | Enclosing fn | What runs after the guard |
|---|---|---|
| `protocol.rs:306` | `handle_logging_set_level` | `backend.request(...)` — the gateway's own credential |
| `protocol.rs:158` | `handle_prompts_list` | `get_prompts_shared()` |
| `resources.rs:293` | `handle_resources_list` | `get_resources_shared()` |
| `resources.rs:517` | `find_resource_owner` | shared ownership scan |

Loosening the guard there lets an authenticated caller drive the gateway's own
backend login on behalf of nobody in particular.

**This is the same defect class as the `VaultStrategy::principal` bug fixed in
#661**, approached from the other side, and the pairing is worth holding in mind
while implementing. There, a check existed and the decision never consulted it —
the enforcement point matched `CallerProof::Operator(_)` and discarded the
provenance. Here, a parameter *looks* like it refines a check and in fact turns
it off. **Both are "the guard is present and the decision does not use it."** An
implementer who internalises one will not reintroduce the other.

### 11.3 What the parameter actually means

Taken from the only caller that passes it meaningfully, not from prose. **V**
`src/gateway/router/backend_handlers.rs:834-836`:

```rust
// A per-user credential was resolved above iff
// `propagated_headers` is non-empty, so a per-user OAuth backend on a
// multi-user gateway is refused rather than served the shared token.
if isolation_guarded
    && let Err(e) = state.meta_mcp
        .enforce_oauth_isolation(&name, !propagated_headers.is_empty())
```

**"Identity propagation resolved non-empty per-user headers for THIS backend and
THIS caller."** Per-backend, per-request. **Not** "the caller authenticated".

**So `CallerProof` is the right identity input and is NOT this boolean.** **V**
`src/identity_propagation/caller_proof.rs` (landed in #661) distinguishes
`Verified`, `Operator(CallerProvenance)` and `Anonymous`. An
`Operator(Credential)` caller presented a validated bearer token and holds **no
per-backend binding**; wiring that into `has_per_user_credential` would serve
every authenticated caller the gateway's personal OAuth backend. Use
`CallerProof` to resolve *who* the caller is, then resolve the credential for the
backend; never substitute the first for the second.

### 11.4 Why the resolution cannot live inside the guard

Two independently fatal facts:

- **It is async.** **V** `src/gateway/meta_mcp/invoke.rs:2880`
  `pub async fn resolve_propagation_credential`. Seven of the fourteen sites
  cannot await — five sit in sync fns, two in sync `.filter()` closures inside
  async fns.
- **It mints and audits; it is not a predicate.** **V**
  `resolve_caller_credential` (`invoke.rs:2936`) calls
  `strategy.propagate(identity, &descriptor).await` (`:3043`) — a real token
  exchange — then `Self::audit_minted_credential(...)?` (`:3059`), whose contract
  is that a minted credential never reaches the caller without a durable audit
  record. The refuse path writes `idp_refuse` records too (`:2962`).

**I** `meta_route_isolation_refused` is evaluated per backend, in a loop over
every registered backend, on ordinary discovery calls. Resolving inside it would
mint N credentials and write N transparency-log entries per `tools/list`.

### 11.5 The census, and the disposition of each site

| # | Site | Enclosing fn | Ctx | Disposition |
|---|---|---|---|---|
| 1 | `mod.rs:1374` | `promoted_tools_for_session` | sync, closure | stays `false` |
| 2 | `protocol.rs:158` | `handle_prompts_list` | sync closure in async fn | **stays `false`** — shared fetch |
| 3 | `protocol.rs:306` | `handle_logging_set_level` | async | **stays `false`** — shared forward |
| 4 | `resources.rs:293` | `handle_resources_list` | sync closure in async fn | **stays `false`** — shared fetch |
| 5 | `resources.rs:395` | `handle_resources_templates_list` | async | stays `false` |
| 6 | `resources.rs:517` | `find_resource_owner` | async | **stays `false`** — shared scan |
| 7 | `search.rs:245` | `collect_code_mode_backend_matches` | async | **credential-aware** |
| 8 | `search.rs:334` | `collect_search_backend_matches` | async | **credential-aware** |
| 9 | `search.rs:683` | `list_tools_single_server` | async | **credential-aware** |
| 10 | `search.rs:749` | `list_tools` | async | **credential-aware** |
| 11 | `spec_preview.rs:92` | `collect_filtered_backend_tools` | sync | stays `false` |
| 12 | `spec_preview.rs:185` | `resolve_tool_by_name` | sync, closure | stays `false` |
| 13 | `spec_preview.rs:240` | `collect_all_cached_tool_names` | sync, closure | stays `false` (see §9.5) |
| 14 | `surfaced.rs:142` | `resolve_surfaced_tool` | sync | stays `false` |

**The decisive column is not awaitability — it is what the site does next.** Rows
7-10 are the catalogue path §4.1 converts to a slot-scoped fetch, and they are
the only rows that may change. The other ten keep `false` **by decision, not by
drift**.

### 11.6 The signature: an added sibling, not a changed one

```rust
// mod.rs:1188 — UNCHANGED, and now honestly named: the identity-free default.
pub(crate) fn meta_route_isolation_refused(&self, backend: &Backend) -> bool {
    self.enforce_oauth_isolation_for(backend, &backend.name, false).is_err()
}

// New. Used by rows 7-10 ONLY, each together with its slot-scoped fetch.
pub(crate) fn meta_route_isolation_refused_for_caller(
    &self,
    backend: &Backend,
    propagated_headers: &[(String, String)],
) -> bool {
    self.enforce_oauth_isolation_for(
        backend, &backend.name,
        !propagated_headers.is_empty(),
    ).is_err()
}
```

**I** A third `bool` parameter on the existing function would make all fourteen
sites editable and one wrong edit invisible in the diff. A separate entry point
means a site opts in **by name**, and the ten that must not are untouched. The
`!headers.is_empty()` test is copied verbatim from `backend_handlers.rs:836` so
the two routes cannot drift on what the parameter means.

**On the type.** **V** `resolve_propagation_credential` (`invoke.rs:2880-2884`)
returns the flattened `(Vec<(String, String)>, Option<String>)` — headers and
`cache_binding` — not the `PropagatedCredential` struct. That struct exists (**V**
`src/identity_propagation/mod.rs:86`, with a `headers` field) but is not the
value in hand at the dispatch arm, so the signature takes the headers slice and
needs no re-wrapping.

### 11.7 The precondition this design did not state

**Not one of the fourteen sites has a caller or a verified identity in scope
today.** **V** `mod.rs:169` carries `verified_identity` on `CallerContext`;
**V** `mod.rs:2139` destructures `caller` from `DispatchTarget`; **V** `:2171`
passes it to `gateway_invoke`, while **V** `:2169` (`gateway_list_tools`) and
**V** `:2170` (`gateway_search_tools`) drop it.

So §4.1 step 1 is a **precondition for B1**, not a parallel task: the credential
state is not merely unthreaded through the guard, it is absent at every call
site. Thread the caller first, resolve once per request, then make rows 7-10
credential-aware.

---

## 12. R1 — five fields, not four: `resend_permitted` moves with the caches

Landed 2026-09-22 from the round-2 review. Found by `gpt-review` and confirmed at
source; the release owner verified it independently before approving it.

### 12.1 The field

**V** `src/backend/mod.rs:93` —
`resend_permitted: parking_lot::RwLock<HashSet<String>>` sits **between** the
four caches this design moves: `:85` `tools_cache`, then `resend_permitted`, then
`:95` `resources_cache`, `:97` `resource_templates_cache`, `:99` `prompts_cache`.

**V** It is **derived from the tool catalogue on every fill**.
`src/backend/metadata.rs:176`, inside `get_tools_shared`'s fill closure:

```rust
*self.resend_permitted.write() = prepare_tool_metadata(&self.name, &mut tools);
```

**V** It decides retry policy at dispatch. `src/backend/ops.rs:178`:
`resend_permission(method, params, &self.resend_permitted.read())`. Its own doc
at **V** `mod.rs:87-92` states the stakes: membership is *"the only thing that
grants a `tools/call` permission to be resent"*.

### 12.2 Why leaving it behind defeats the design

**I** This is §0.1's error one level down. The cluster-g ruling forbids keying a
set finer than the source it derives from; leaving `resend_permitted`
backend-wide while `tools_cache` becomes per-identity does the mirror image —
it leaves a derived set **coarser** than its source, shared across every identity
that shares the backend.

Concretely: identity B's catalogue fill overwrites the resend set that identity
A's dispatch then reads. The failure is a **duplicate side effect on a
non-idempotent tool**, authorised by another caller's catalogue. That is a worse
outcome than a disclosure, and it arrives through a field nobody was looking at.

### 12.3 Why the design's own proof could not have caught it

This is the part worth remembering, because it bounds a claim this document
leans on.

§4.2's method — delete the fields, let the compiler enumerate the readers — is
the strongest idea here, and §9.4 earns it three times over. But it enumerates
**readers of the deleted fields**. `resend_permitted` is a **writer of derived
state** on a field that was *not* being deleted, so:

- the compiler reports nothing, because `Backend::resend_permitted` still exists
  and its readers still compile;
- §3.1's falsifier, `rg -n "tools_cache" src/`, returns clean, because the field
  has a different name.

**The proof and its falsifier both pass green while the bug is live.** §3.1's
falsifier is widened accordingly, and the general lesson is recorded there: a
falsifier naming only the fields you already thought of tests recall, not the
property.

### 12.4 What changes

`resend_permitted` moves into `PooledEntry` beside the four caches. The fill at
`metadata.rs:176` writes the slot's set; `ops.rs:178` reads the slot's set. The
identity-free callers reach the `Shared` slot's set exactly as they reach the
`Shared` slot's caches (§4.2.1), so single-tenant behaviour is unchanged.

**A** The direct-route path (`set_resend_permitted`, **V** `metadata.rs:199`,
currently `#[expect(dead_code)]` pending its caller) must write the same slot its
own `tools/list` was served from when that caller lands. Flag at implementation;
the `expect` marker already forces the conversation.
