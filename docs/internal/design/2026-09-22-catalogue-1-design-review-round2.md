# MIK-7334.CATALOGUE.1 — round-2 design review and B1 resolution

Reviews the landed design `2026-09-21-catalogue-1-per-caller-view.md` (`cc612afc`,
PR #648), which §9.7 records as resting on **one** completed independent review
and owing a second pass on §3.1 and §4.2. This is that pass.

Line citations are against release-line HEAD `9fb0674b`. Where the design's own
`file:line` differs it is because the design was written against `cc612afc`; the
drift is noted inline rather than silently re-cited.

Evidence tags: **V** = read at source (file:line given), **I** = inferred, **A** =
assumption.

---

## 1. Review seats

| Seat | Status | Verdict | Repo access |
|---|---|---|---|
| `kimi-review` | **LIVE** — 5.7K, verdict emitted | SHIP-WITH-FIXES | **No.** Stated plainly in its own evidence summary: *"I did NOT verify any file:line citation against the repository — it was not mounted."* Its findings are internal-consistency findings and are weighted as such. |
| `gpt-review` | **LIVE** — 3.9K, verdict emitted | SHIP-WITH-FIXES | **Yes.** *"Ran read-only source searches and Git inspection … against initial commit 9fb0674"* — the same commit this document cites. |
| `grok-review` | **DARK** — not run | none | The design's §9.7 already records two stalled runs. Not re-attempted. |

The briefing warned that `gpt-review` had been returning 0-byte output in this
session. It did not here: `gpt.out` is 3987 bytes and carries a verdict line.
Reported as live because it produced one, not because it was expected to.

Two live seats, one of which read the source. Neither is treated as evidence
until its claim is checked at source — §2 records what survived.

---

## 2. Findings verified at source

### 2.1 CONFIRMED, NEW BLOCKER — B1's naive fix opens a leak the guard exists to stop

`gpt-review`, rated CRITICAL, cited `src/gateway/meta_mcp/protocol.rs:306`.

**V** `handle_logging_set_level` (`protocol.rs:271`) runs the guard at `:306`,
then forwards at `:317` with `backend.request("logging/setLevel", …)` — the
**shared** transport. Its own comment states the obligation: *"never drive the
gateway-held OAuth token to an isolated backend on behalf of an arbitrary caller
on a multi-user gateway."*

**V** `enforce_oauth_isolation_for` (`mod.rs:1114-1116`) early-returns `Ok(())`
whenever `has_per_user_credential` is true. Passing `true` therefore does not
*narrow* the guard — it **disables all three of its arms**.

**I** So §9.2's prescription as written — *"the 15 `meta_route_isolation_refused`
sites become credential-aware"* — applied uniformly would let an authenticated
caller drive the gateway's shared credential into an isolated backend at every
site whose subsequent operation is still shared. That is not a smaller version of
the omission; it is the leak ADR-008 INV-2 exists to deny, newly opened.

**V** Four of the fourteen sites are exactly that shape — guard, then a shared
fetch:

| Site | Enclosing fn | Operation after the guard |
|---|---|---|
| `protocol.rs:306` | `handle_logging_set_level` (async) | `backend.request(…)` — shared |
| `protocol.rs:158` | `handle_prompts_list` (async) | `backend.get_prompts_shared()` |
| `resources.rs:293` | `handle_resources_list` (async) | `backend.get_resources_shared()` |
| `resources.rs:517` | `find_resource_owner` (async) | shared ownership scan |

**Resolution:** credential-awareness is **not** a mechanical sweep over the call
sites. It is admissible at a site only when that site's subsequent operation runs
over the **same slot** the credential selected. It lands site-by-site, paired
with that site's fetch becoming slot-scoped — never ahead of it.

### 2.2 CONFIRMED — derived catalogue state the design's own proof cannot catch

`gpt-review`, rated CRITICAL, cited `src/backend/metadata.rs:176`.

**V** `src/backend/mod.rs:93` — `resend_permitted: RwLock<HashSet<String>>` is a
`Backend` field sitting **between** the four caches the design moves (`:85`
`tools_cache`; `:95`, `:97`, `:99` the other three).

**V** `src/backend/metadata.rs:176`, inside `get_tools_shared`'s fill closure:
`*self.resend_permitted.write() = prepare_tool_metadata(&self.name, &mut tools);`
— it is **derived from the tool catalogue on every fill**.

**V** `src/backend/ops.rs:178` reads it to decide resend policy:
`resend_permission(method, params, &self.resend_permitted.read())`.

**I** This is the design's own §0.1 error one level down: a set derived from
`tools_cache` left backend-wide while its source becomes per-identity. Identity
B's fill overwrites the resend set identity A's dispatch then reads. Per **V**
`mod.rs:87-92`, membership is *"the only thing that grants a `tools/call`
permission to be resent"* — so the failure mode is a duplicate side effect on a
non-idempotent tool, decided by another caller's catalogue.

**And §3.1's proof structurally cannot catch it.** The falsifier is
`rg -n "tools_cache" src/`; `resend_permitted` is a different name on a field
that is *not* being deleted, so the compiler enumerates nothing and the grep
passes green. §4.2's inventory is of cache **readers**; this is a **writer of
derived state**. The design's strongest claim — *"the compiler enumerates the
blast radius"* — has a hole exactly the width of this field.

**Resolution:** `resend_permitted` moves into `PooledEntry` with the four caches,
or C3's isolation is defeated through dispatch. Five fields move, not four.

### 2.3 CONFIRMED — §3.1 cites the racy lookup

`gpt-review`, rated MEDIUM, cited `src/backend/pool.rs:235`.

**V** `pool.rs:235` `pooled_entry` — its own doc says: *"Callers that intend to
USE the slot's transport want [`Backend::claim_pooled_entry`] instead: this one
hands back an entry the evictor is still free to remove."*

**V** `pool.rs:253` `claim_pooled_entry` is the safe variant, claiming an
in-flight slot under the shard guard so `evict_idle_per_user_entries` cannot
remove it mid-use.

**I** §3.1 names `pooled_entry` as the sole path to a cache. A metadata fill
routed through it races the reaper, which closes the transport under the fetch.
The design cites the wrong function; the right one already exists next to it.

**Resolution:** one-word correction — §3.1 and §4.1 step 4 name
`claim_pooled_entry`. No new mechanism.

### 2.4 CONFIRMED — T5 encodes a premise §9.1 already refuted

Both seats found this independently; `kimi-review` stated it most exactly.

**V** §5's T5 row: *"Guard: assert no MCP `tools/call` result cache exists …
Passes today by absence."* **V** §4.3 and §9.1 of the same document establish the
opposite and cite it: `src/gateway/meta_mcp/invoke.rs:1842-1855` (`cache.get`),
`:2440` (`cache.set`), `:1794` (idempotency replay).

**I** The C3 rewrite landed in §4.3 and §9.1 but §5's row was never updated. As
written, T5 fails immediately for the wrong reason — or, worse, is "fixed" by
deleting a result cache that must stay. It is a stale row in a test plan, which
is the one place a refuted premise turns into shipped code.

**Resolution:** T5 asserts the cache **is** keyed — that `response_cache_key_for`
(**V** `src/gateway/meta_mcp/support.rs:168`) carries the caller principal and the
`KeyContext` — so a future *unkeyed* result cache fails it. Inverted from absence
to presence. This is T5-R in §4 below.

### 2.5 CONFIRMED — §3.1's "unrepresentable" is one step stronger than the code

`kimi-review`, rated MEDIUM. Verified against the design's own text rather than
source, which is all this claim needs.

§3.1 says key divergence is *"unrepresentable."* §4.2.1 then instructs the
identity-free consumers to *"pass `PoolKey::Shared` explicitly."* **I** Once any
call site may name a `PoolKey`, a caller-scoped site can name `Shared` too, and
the compiler sees a well-typed call. What co-location actually makes
unrepresentable is **cache/transport divergence within a slot** — a real and
valuable property, and not the same as key-selection correctness.

**Resolution:** narrow the claim to what it proves, and let the accessors call
`pool_key_for` on the caller's binding internally so no caller-scoped site
constructs a key by hand — `Shared` stays reachable only through the named
`*_shared` helpers. Kimi's proposed fix is the cheaper half and is adopted.

### 2.6 CONFIRMED — the arithmetic in §4.2 does not add up

`kimi-review`, LOW. Verified by counting the design's own table.

**V** §4.2's header says *"Sixteen production call sites"*; its table sums to
**15** (6 + 3 + 2 + 2 + 2). **V** Its closing paragraph still says *"turns all
twelve into compile errors."* **V** §4.2.1 says *"Four production readers"* and
lists five. **V** T3's sweep names four accessors and omits `has_cached_tools`,
which §9.4 had just elevated to a fifth.

**I** Cosmetic in isolation, and corrosive here: this is the section whose whole
thesis is that hand inventories cannot be trusted. Its numbers should be taken
from a compiler run, not a third hand count.

### 2.7 CONFIRMED as a limitation, not a blocker — revocation and in-flight Arcs

Both seats raised it; `gpt-review` rated it CRITICAL, `kimi-review` LOW.

**V** `pool.rs:253` `claim_pooled_entry` exists precisely so a live request holds
its slot against eviction. **I** Therefore a request in flight when revocation
evicts the slot completes against the pre-revocation cache it already holds.

**Rated with kimi, not gpt.** The retained `Arc` is that **same caller's** slot,
so what it serves is that caller's own pre-revocation catalogue. The criterion is
cross-caller isolation; a caller briefly seeing their own stale data is a freshness
bound, not a leak. gpt's CRITICAL rating over-weights it.

**Resolution:** one sentence in §4.4 stating the boundary — revocation is
immediate for slot resolutions *after* eviction; in-flight requests may finish on
pre-revocation data, same-caller only. Not a blocker.

### 2.8 NOT ACCEPTED — the other three caches need an inventory first

`kimi-review`, MEDIUM: no reader inventory exists for `resources_cache`,
`resource_templates_cache`, `prompts_cache`.

**Correct as an observation, and it is already the design's answer.** §6 risk 5
requires all four to move, and deleting all four fields gives the same compiler
enumeration §4.2 relies on for `tools_cache`. The design does not need a hand
inventory it has already argued nobody should trust. Recorded, not actioned.

### 2.9 REJECTED — gpt's "slot selection does not supply credentials"

`gpt-review`, CRITICAL: *"Selecting the correct transport slot does not supply
the caller's credentials, so the slot-only fetch can still cache a
static-credential response under a per-user key."*

**Already specified, and the reviewer missed it.** **V** §4.1 step 2 resolves the
credential via `resolve_propagation_credential`, and **V** §9.3 makes the fill
slot-owned so `shared_transport()` is out of scope inside it. **V** The existing
per-user transport (`pool.rs:173-181`) is opened *with* the caller's headers;
there is no path that selects a PerUser slot without them.

The *test* half of its fix is worth keeping — T8 asserting the received upstream
identity — and the prior-art suite already does exactly that. Finding rejected,
its test suggestion adopted.

---

## 3. B1 resolved

> **B1** (design §9.2, §10): *the `meta_route_isolation_refused` call sites must
> pass real credential state rather than a placeholder.*

### 3.1 First, the count: fourteen, not fifteen

**V** `rg -n "meta_route_isolation_refused" src/` returns 15 hits, of which
`mod.rs:1188` is the **definition**. There are **14** call sites. The design says
15 twice (§2 item 3, §9.2). Off by one, from counting the definition.

**V** The placeholder itself is `mod.rs:1189`:
`self.enforce_oauth_isolation_for(backend, &backend.name, false)`.

### 3.2 What `has_per_user_credential` actually means

Taken from the caller that passes it meaningfully, not from prose.

**V** `src/gateway/router/backend_handlers.rs:834-836`:

```rust
// A per-user credential was resolved above iff
// `propagated_headers` is non-empty, so a per-user OAuth backend on a
// multi-user gateway is refused rather than served the shared token.
if isolation_guarded
    && let Err(e) = state.meta_mcp
        .enforce_oauth_isolation(&name, !propagated_headers.is_empty())
```

So the parameter means **"identity propagation resolved a non-empty per-user
credential for *this* backend and *this* caller."** It is per-backend and
per-request. It does **not** mean "the caller authenticated".

**This rules out the obvious wiring.** The neighbouring `CallerProof` work
(`feat/single-user-principal`, `src/identity_propagation/caller_proof.rs`) offers
`proof.established()`, which is true for `Operator(Credential)` — a validated
bearer token. **V** That caller holds no per-backend binding, so
`has_per_user_credential = proof.established()` would hand every authenticated
caller the gateway's personal OAuth backend on a multi-user gateway. `CallerProof`
is the right *input* to the identity axis; it is not this parameter.

### 3.3 Why the resolution cannot live inside the guard

The natural shape — resolve inside `meta_route_isolation_refused` — is closed off
by two independently fatal facts.

**(a) It is `async`.** **V** `src/gateway/meta_mcp/invoke.rs:2880`
`pub async fn resolve_propagation_credential`. Seven of the fourteen sites cannot
await: five sit in sync fns, and two sit in sync `.filter()` closures inside async
fns (§3.4).

**(b) It mints and audits — it is not a predicate.** **V**
`resolve_caller_credential` (`invoke.rs:2936`) calls
`strategy.propagate(identity, &descriptor).await` (`:3043`) — a real token
exchange — and then `Self::audit_minted_credential(…)?` (`:3059`), whose contract
is *"a minted credential must never reach the caller without a durable audit
record."* **V** The refuse path likewise writes `idp_refuse` audit records
(`:2962`).

**I** `meta_route_isolation_refused` is evaluated **per backend, in a loop over
every registered backend**, on ordinary discovery calls (`protocol.rs:158`,
`resources.rs:293`, `spec_preview.rs:92`). Resolving inside it would mint N
credentials and write N transparency-log entries per `tools/list`. A side-effecting
predicate in a filter is not a smaller change than the alternative; it is a worse one.

### 3.4 Census: the fourteen sites and the state each has

**V** Enclosing function and awaitability read at source for every row.

| # | Site | Enclosing fn | Ctx | Caller state in scope | Disposition |
|---|---|---|---|---|---|
| 1 | `mod.rs:1374` | `promoted_tools_for_session` | sync, in `filter_map` | `session_id` only | **stays `false`** |
| 2 | `protocol.rs:158` | `handle_prompts_list` | sync closure in async fn | none | **stays `false`** (§2.1) |
| 3 | `protocol.rs:306` | `handle_logging_set_level` | async, direct | none | **stays `false`** (§2.1) |
| 4 | `resources.rs:293` | `handle_resources_list` | sync closure in async fn | none | **stays `false`** (§2.1) |
| 5 | `resources.rs:395` | `handle_resources_templates_list` | async, direct | none | **stays `false`** |
| 6 | `resources.rs:517` | `find_resource_owner` | async, direct | none | **stays `false`** (§2.1) |
| 7 | `search.rs:245` | `collect_code_mode_backend_matches` | async, direct | `session_id` | **threaded** |
| 8 | `search.rs:334` | `collect_search_backend_matches` | async, direct | `session_id` | **threaded** |
| 9 | `search.rs:683` | `list_tools_single_server` | async, direct | `session_id` | **threaded** |
| 10 | `search.rs:749` | `list_tools` | async, direct | `session_id` | **threaded** |
| 11 | `spec_preview.rs:92` | `collect_filtered_backend_tools` | sync | `session_id`, profile | deferred — §2.1 shape |
| 12 | `spec_preview.rs:185` | `resolve_tool_by_name` | sync, in closure | `name` only | deferred |
| 13 | `spec_preview.rs:240` | `collect_all_cached_tool_names` | sync, in closure | `session_id` | deferred (and see §5 gap) |
| 14 | `surfaced.rs:142` | `resolve_surfaced_tool` | sync | `session_id` | deferred |

**The decisive column is not awaitability — it is what the site does next.** Only
rows 7-10 are the catalogue path §4.1 converts to a slot-scoped fetch, and they
are exactly the rows that may become credential-aware. Rows 2-6 keep `false`
permanently and **by decision, not by drift**: their next operation is a shared
fetch, so loosening the guard there is §2.1's leak.

**Note the state column.** Not one of the fourteen sites has a `caller` or a
`VerifiedIdentity` in scope today. **V** `mod.rs:169` carries `verified_identity`
on `CallerContext`, and **V** `mod.rs:2139` destructures `caller` from
`DispatchTarget`, so it is in scope at the meta-dispatch arms: `:2171` passes it
to `gateway_invoke`, while `:2169` (`gateway_list_tools`) and `:2170`
(`gateway_search_tools`) drop it. The credential state B1 needs is not merely
unthreaded through the guard — it is **not present at any call site**, so the
threading §4.1 step 1 describes is a precondition for B1, not a parallel task.

### 3.5 The signature change

```rust
// mod.rs:1188 — unchanged, and now honestly named: the identity-free default.
pub(crate) fn meta_route_isolation_refused(&self, backend: &Backend) -> bool {
    self.enforce_oauth_isolation_for(backend, &backend.name, false).is_err()
}

// New, used only by rows 7-10, whose fetch is slot-scoped in the same change.
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

**I** An added sibling rather than a changed signature, and that is the point.
A third `bool` argument on the existing function makes all fourteen sites
editable and one wrong edit invisible; a separate entry point means a site opts
into credential-awareness by **name**, and the twelve that must not are untouched
by the diff. The `!headers.is_empty()` test is copied verbatim from
`backend_handlers.rs:836` so the two routes cannot drift on what the parameter means.

**On the type.** **V** `resolve_propagation_credential` (`invoke.rs:2880-2884`)
returns the *flattened* `(Vec<(String, String)>, Option<String>)` — headers and
`cache_binding` — not the `PropagatedCredential` struct itself. **V** That struct
does exist (`src/identity_propagation/mod.rs:86`) with a `headers:
Vec<(String, String)>` field, and is what the strategy returns one layer down
(`mod.rs:448`), but it is **not** the value in hand at the dispatch arm. The
signature above takes the headers slice, so it consumes exactly what the resolver
already hands back and needs no re-wrapping.

Those headers are resolved **once per request** by the dispatch arm (§4.1 steps
1-2), not per backend and not inside the predicate — which is also what §4.3's
own **A** asks for: one resolution, two derivations (the isolation verdict and
the `PoolKey`), never two independent resolutions of the caller's identity.

---

## 4. Test plan, revised — and what "failing test" honestly means here

### 4.1 The design's §5 rows, reclassified

§5 presents eight rows as one set. They are not one kind of thing, and calling
them all "failing tests" would be false. Classified by what each can actually do
against the current tree:

| Row | Class | Why |
|---|---|---|
| **T1, T2** | **blocked until the signature lands** | Both need an identity-carrying catalogue read. **V** `list_tools` (`search.rs:703`) and `search_tools` take `(args, session_id)` — no identity parameter exists, so "caller A reads as A" is not expressible. These are red-by-compile-error against an unwritten API, not red at runtime. |
| **T3, T8** | **blocked until the signature lands** | No per-slot accessor exists to call. |
| **T4** | half green, half blocked | **V** `revocation_during_a_fill_is_not_served_afterwards` (`src/backend/tests.rs:1862`) already covers the mid-fill half. The populated-cache half needs the eviction wiring. |
| **T5** | **stale, replaced** | §2.4 — asserts a premise §4.3 refuted. Replaced by T5-R below. |
| **T6** | **green-before control**, not a failing test | **V** `get_tools_singleflight_coalesces_concurrent_requests` (`src/backend/tests.rs:683`) passes today and must keep passing. |
| **T7** | **a grep**, not a test | Two required greps. A structural gate, run in CI, not a `#[test]`. |

**I** So the honest count against HEAD is: **zero** of §5's eight rows is a
runtime-red test today. Four are blocked on the signature change that B1 itself
is a precondition for, one is stale, one is a control, one is a grep, and one is
half-covered. A report claiming "the §5 suite is red" would be claiming a
property nobody could have observed.

### 4.2 What IS expressible today, and is now red

Two acceptance cases were written against the API that exists, in their own
module `src/gateway/meta_mcp/catalogue_isolation_tests.rs`. They test the **C0**
conjunct — *"Supported"*, the word PR #604 tried to turn — which is the only
conjunct reachable without the new signature, and is also the one the operator's
BUILD ruling turns on.

**Both are two-directional by construction.** Each case names a backend that must
appear beside one that must not:

| Case | Must be served | Must be withheld | Today |
|---|---|---|---|
| `per_user_catalogue_is_served_while_the_shared_oauth_one_is_withheld` | the `per_user` backend's catalogue; a genuinely shared backend's | a backend behind one gateway-held OAuth login | **RED** on the served half |
| `single_user_gateway_still_serves_every_catalogue` | all three | — | **GREEN** (control) |

**The asymmetry is the point, and it is why one-sided assertions were refused.**
Today the gateway answers a multi-user caller with *neither* the per-user
catalogue nor the OAuth one. A test asserting only *"B must not see A's tools"*
passes on that answer — vacuously, because the answer is empty. The `SHARED_TOOL`
assertion fires first in the case body so an empty gateway fails on the premise
rather than passing on the conclusion, and the fixture asserts
`has_cached_tools()` before any case runs, so a cold cache cannot supply the
absence either.

The second case is the control the first one needs. It fails if per-caller
catalogues are ever delivered by degrading the single-tenant path — the IDP.5
guarantee **V** `pool_key_for` already makes for transports
(`src/backend/pool.rs:169-171`).

### 4.3 T5-R — replacing the stale row

T5 asserted the absence of a result cache that **V** exists at
`invoke.rs:1842-1855`, `:2440`, `:1794`. Inverted to assert the property §4.3
actually relies on: that `response_cache_key_for` (**V** `support.rs:168`)
carries the caller principal **and** the `KeyContext` (`routing_profile`,
`protocol_revision`, `policy_epoch`). A future result cache added without a
principal in its key then fails this row instead of silently regressing C3.

### 4.4 T9 — new, locking §2.1's decision

Not in the design, and needed because of §2.1: a regression guard asserting that
an identity-bound backend stays refused at the sites whose subsequent operation
is shared — `handle_logging_set_level` (**V** `protocol.rs:306`) being the
sharpest. **Green today by construction.** Its job is to go red the day someone
implements B1 as the mechanical sweep §9.2's wording invites.

---

## 5. Does the design need revision before implementation?

**Yes — three changes, and the core stands.**

Said plainly because the briefing asked for it: a design that survives review
unchanged is a finding, and this one did not quite. But what changed is at the
edges. §3.1's mechanism — co-locate the metadata caches with the pool slot so a
cache is unreachable without a `PoolKey` — is right, and §0.1's reading of the
cluster-g ruling is right: that ruling forbids keying a *derived* set finer than
its source, and names partitioning `tools_cache` as the repair that makes the
property meaningful. This design executes it rather than working around it.

| # | Revision | Source | Size |
|---|---|---|---|
| **R1** | `resend_permitted` (`mod.rs:93`) moves into `PooledEntry` with the four caches. Five fields, not four. | §2.2 | one field |
| **R2** | §9.2's "the sites become credential-aware" becomes a named, per-site opt-in. Twelve sites keep `false` by decision; only the four catalogue-path sites change, and only together with their fetch becoming slot-scoped. | §2.1, §3 | wording + one new fn |
| **R3** | §3.1 and §4.1 step 4 name `claim_pooled_entry`, not `pooled_entry`; §3.1's "unrepresentable" narrows to cache/transport divergence *within* a slot. | §2.3, §2.5 | two words + one sentence |

Plus the bookkeeping: T5 replaced (§4.3), §4.2's four wrong counts recounted from
a compiler run rather than a fourth hand tally (§2.6), and one sentence bounding
revocation against in-flight slots (§2.7).

**B1 is resolved** (§3) and is no longer a blocker: the call sites are
enumerated, the state at each is recorded, and the signature is specified. It
does carry a precondition the design did not state — the caller must first be
threaded to `list_tools` / `search_tools`, because **no** call site has it today.

### 5.1 The dependency, stated plainly

B1's resolution consumes a `PropagatedCredential` resolved once per request. The
neighbouring `feat/single-user-principal` branch adds `CallerProof`
(`src/identity_propagation/caller_proof.rs`), which is the right **identity**
input and is **not** the value this parameter takes (§3.2). No second mechanism
is needed and none is proposed; the two compose, and the note here exists so a
later reader does not wire `proof.established()` into
`has_per_user_credential` because it was the nearest boolean.

---

## 6. Where I think the design is wrong

Three things, none fatal, recorded because the briefing asked for disagreement
rather than assent.

**6.1 The compiler-enumeration claim is narrower than stated.** §4.2's method —
delete the fields, let the compiler find the readers — is the best idea in the
document, and §9.4 earns it three times over. But it enumerates *readers of the
deleted fields* only. `resend_permitted` (§2.2) is derived from the same
catalogue, stays on `Backend`, and is invisible to both the compiler and the
§3.1 falsifier grep. The method is excellent; the claim that it finds the blast
radius is one step too strong, and the field it misses is the one that decides
whether a non-idempotent call may be retried.

**6.2 §9.2 prescribes a sweep where only a subset is safe.** "The 15 sites become
credential-aware" reads as mechanical, is off by one (§3.1), and applied
uniformly opens the leak at four sites (§2.1). The finding behind it is correct
and was the review's most valuable; its prescription is not, and an implementer
following the sentence rather than the reasoning ships a regression.

**6.3 §5 presents controls and greps as if they were tests.** T6 is green-before,
T7 is a grep, T5 is stale. Only a reclassification (§4.1) makes the row's test
plan reviewable as a test plan. This matters more than it looks: the design's own
§5 **A** warns that this row once accepted tests that *"would also pass if
per-user catalogues were deleted outright."* A test plan that miscounts what can
fail is how that happens twice.

**And one thing the design got right that is worth naming.** §4.5's split —
identity in the key, authorization in the post-filter — is the cluster-g ruling
applied correctly a second time. Folding authz context into the cache key would
fork an entry per profile/role/state combination: a derived set keyed finer than
its source, the exact error the ruling names. Both reviewers left it alone. So
do I.

---

## 7. The failing tests, verbatim

Module: `src/gateway/meta_mcp/catalogue_isolation_tests.rs`, built and run on
Spark (the Mac is under disk pressure with three agents on it).

```
running 4 tests
... 3/4
gateway::meta_mcp::catalogue_isolation_tests::per_user_catalogue_is_served_while_the_shared_oauth_one_is_withheld --- FAILED
failures:
---- gateway::meta_mcp::catalogue_isolation_tests::per_user_catalogue_is_served_while_the_shared_oauth_one_is_withheld stdout ----
thread 'gateway::meta_mcp::catalogue_isolation_tests::per_user_catalogue_is_served_while_the_shared_oauth_one_is_withheld' (534350) panicked at src/gateway/meta_mcp/catalogue_isolation_tests.rs:256:5:
a `session_mode = per_user` backend's catalogue never reached anyone: ["shared_status_read"]. Withholding it stops the leak and leaves the criterion's quantified set empty — which is the rescope the release owner declined (PR #604). CATALOGUE.1 is BUILD.
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
failures:
    gateway::meta_mcp::catalogue_isolation_tests::per_user_catalogue_is_served_while_the_shared_oauth_one_is_withheld
test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 5043 filtered out; finished in 0.09s
error: test failed, to rerun pass `--lib`
```

**Read the failure value, not just the failure.** `["shared_status_read"]` is the
whole answer a multi-user caller receives. One name in it, and it is the
genuinely shared backend's:

- the shared backend **is** present, so the gateway is not empty and the case is
  not passing its negative assertions vacuously;
- `gateway_oauth_secret_read` is **absent**, so the shipped leak-stop is working
  and stays working;
- `per_user_ledger_read` is **absent**, and that is the gap — a `per_user`
  backend's catalogue reaching nobody at all.

Three pass, one fails. The three that pass are controls and are supposed to pass:
the single-user path still serves all three catalogues, the guard still refuses
the identity-bound backends on the shared-credential routes (T9), and the result
cache still separates callers (T5-R). **The only red assertion is a positive
one** — which is what the two-directional rule buys. Had the case asserted only
that B cannot see A's tools, it would be green right now against a gateway that
serves nobody anything.

### 7.1 What is NOT red, stated so nobody infers it

The four conjunct-level cases from design §5 — T1, T2, T3, T8 — are **not**
written and **not** red. They cannot be: every one needs an identity-carrying
catalogue read, and **V** `list_tools` / `search_tools` take no identity
parameter (§4.1). Writing them now would produce compile errors against an
unwritten API, which is not a red test and must not be reported as one.

They land with the implementation, in the same change that threads `caller` to
those two dispatch arms. The prior-art suite on `origin/feat/v4-catalogue-identity`
(`a185dabe`, 221 lines) is the right starting point for them — it already
asserts fetch provenance, which is design §9.3's T8 — **but its API shape must
not be reused**: it adds `get_tools_for_identity` *alongside* `Backend`'s cache
fields (**V** `metadata.rs`, that commit) and lands it as a stub returning the
shared catalogue. That is design §6 risk 2 exactly — the keyed path added beside
the old field, which is the one shortcut that reintroduces the whole bug class.
Take its transport fixtures; leave its signature.
