# MIK-7530 — revocation reaches the caches: test plan

**Plan only. No implementation exists, and none should until this is reviewed.**

Owns the one conjunct `MIK-7334.CATALOGUE.1` left open: *"including changes and
revocation"* for the catalogue and metadata caches. `blocked_on: none` is
deliberate — `check_scope_acceptance.py:104` defines anything else as another
row's turn, and this is ours.

Evidence tags: **V** = read at source (`file:line`), **I** = inferred, **A** =
assumption needing confirmation.

---

## 0. THE ONE THING TO RATIFY BEFORE REVIEW RUNS

The fail-fast check is *"make the retirement path a no-op and confirm red on
**each** cell."* That check is only meaningful against an agreed enumeration —
**V** `RELEASE-4.0.0-scope-tests.md:40` decomposes several ways:

> One backend returns different tool names/schemas for two identities. Interleave
> cold/hot reads, rotate/revoke a grant during a fill and check both catalogue
> and call results. Invariant shared catalogue is a separate positive control.

"rotate/revoke" is one clause or two; "catalogue and call results" is one axis or
two. **If my five are not the five the check is run against, the check passes
vacuously and neither of us notices.** Proposed enumeration:

| # | Cell | Clause it comes from |
|---|---|---|
| **A1** | Two identities, differing tool names/schemas, isolated | "different tool names/schemas for two identities" |
| **A2** | Interleaved cold/hot reads across those identities | "interleave cold/hot reads" |
| **A3** | Revoke during a fill | "revoke a grant during a fill" |
| **A4** | After revocation, the **catalogue** is not served | "check both catalogue …" |
| **A5** | After revocation, **call results** are not served | "… and call results" |
| **A6** | **Rotate** during a fill: the pre-rotation catalogue is never served under the successor grant | "rotate … a grant during a fill" |
| **C0** | Invariant shared catalogue, unaffected throughout | "separate positive control" |

**RATIFIED 2026-09-22: six cells plus the control.** An earlier draft folded
rotation into A3 on the reading that both exercise the same retirement path. They
do — and **cells are enumerated by failure mode, not by code path**. Revocation's
only wrong behaviour is serving *anything*; rotation's is serving the
*pre*-rotation catalogue *under* the successor grant, which no revocation cell can
reach because it has nothing to mis-attribute to. §A6.

---

## 1. What exists, verified, so the plan builds on facts

**V** `src/backend/metadata.rs:57-59` already states the intended mechanism, and
it is not "invent a catalogue invalidation":

> *"discards an empty list only, so routing revocation through it would be a
> silent no-op on every populated cache. **Revocation evicts the identity's slot,
> which drops its transport and its caches together.**"*

**V** Since `MIK-7334.CATALOGUE.1`, that sentence is literally true: the four
metadata caches and `resend_permitted` are fields on `PooledEntry`, so evicting
the slot drops the caches with it. The construct is **identity-keyed eviction**.

**V** `set_identity_grants` (`meta_mcp/mod.rs:1286`) takes **`&self`**, so it is
callable at runtime through an `Arc<MetaMcp>`; its epoch bump is proven by
`policy_epoch_tests.rs:51`. **V** Its only production caller is
`gateway/server/mod.rs:1239`, at **startup**, and **V** grants are not on the
config-reload path (`rg identity_grants src/config_reload/` is empty).

**I** So construct (1) is **smaller than "build a revoke path"**: the method is
ready and nothing reaches it after boot.

**V** `policy_epoch` does not reach the metadata caches — `rg policy_epoch
src/backend/` returns nothing. It strands **result-cache keys only**. That is why
this is two constructs, not one.

---

## 2. The two constructs, and why one test cannot grade both

| # | Construct | Retires | Existing machinery |
|---|---|---|---|
| **K1** | A runtime revoke surface reaching `set_identity_grants` | result-cache keys, via the policy epoch | the method exists and takes `&self`; nothing calls it after boot |
| **K2** | **Identity-keyed** pool-slot eviction | the slot's transport **and** its five cache fields together | `evict_idle_per_user_entries` (`pool.rs:326`) evicts per-user slots but keys on an **idle TTL**, not an identity |

**A single end-to-end "revoke, then nothing is served" case passes if either
construct works and the other is dead.** So the fail-fast check runs
**per-construct**, not per-scenario: K1 made a no-op must redden A5, K2 made a
no-op must redden A4, and neither substitution may redden the other's cell. That
matrix is §4.

---

## 3. The trap that would ship a silent no-op

**This is the finding that should shape the implementation, and it gets its own
cell rather than a footnote.**

**V** `evict_idle_per_user_entries` (`pool.rs:340-355`) removes through
`remove_if`, whose predicate requires `entry.in_flight.load(SeqCst) == 0`. When a
request is in flight the removal **declines and returns `None`** — correct for an
idle reaper, which is best-effort and retries on the next sweep.

**I** For revocation it is wrong, and wrong in the session's recurring shape: a
revocation that returns `Ok(())` having evicted nothing is **an outcome that
exists and a decision that does not use it**. Worse, the moment it declines is
exactly the moment that matters — the revoked caller has a request in flight.

**V** `2026-09-21-catalogue-1-per-caller-view.md` §4.4 anticipated this:
*"time-driven and best-effort; revocation is event-driven and must be immediate.
Same eviction primitive, two triggers, different guarantees. **Do not fold
them.**"*

**The design question, and its answer is already ruled** so the reviewer does not
relitigate it: an in-flight request holds its own `Arc<PooledEntry>` and will
finish on the pre-revocation data it already has. **V** §2.7 of the round-2
review rated that acceptable — it is that **same caller's** own slot, so it is a
freshness bound, not a cross-caller leak. **Therefore K2 removes from the map
unconditionally and does not wait for `in_flight` to drain.** What must be true
is that the slot is unreachable for any *subsequent* resolution. That is cell A3.

**Do NOT weaken `invalidate_tools_cache` to achieve this.** **V**
`metadata.rs:61-66` — its `Vec::is_empty` predicate is a guard, not an oversight:
clearing unconditionally could erase a list another reader populated between one
caller observing emptiness and acting on it, turning a backend that had just
become discoverable invisible. Leave it; evict the slot.

### 3.1 The second in-flight case: a late fill re-creates the slot

**Verified at source, and it is the more dangerous direction of the two.**

Eviction removes the entry from the pool map. It does **not** cancel a fetch
already on the wire — **V** `cached_metadata.rs` says so outright: *"Deliberately
does NOT cancel an in-flight fetch: that fetch is already going to the backend."*

The chain that re-creates the slot, each link read:

1. **V** the fill closure in `get_cached_list_on` calls
   `self.ensure_entry_started(key).await?` **inside** the fetch;
2. **V** `ensure_entry_started` (`lifecycle.rs:206,210`) opens with
   `let entry = self.pooled_entry(key);`
3. **V** `pooled_entry` → `pooled_entry_with` (`pool.rs:241,248`) resolves through
   `self.pool.entry(key.clone()).or_insert_with(…)` — **it creates the entry when
   absent.**

**I** So a fill that was on the wire at revocation time re-inserts a pool entry
for the revoked binding, moments after it was evicted, and starts a transport on
it. The revocation returned `Ok(())`. The eviction genuinely happened. The slot
is back.

**This is the session's recurring shape at its sharpest: an operation that
succeeded and an outcome that did not hold.** Nothing in the revoke path is
wrong; the state simply does not survive the next few milliseconds.

**A** Whether the re-created slot ends up *populated* or merely *live* depends on
where the fill writes — the closure holds the `Arc<PooledEntry>` captured before
eviction, so its bytes may land on the orphan rather than the new entry. **The
plan deliberately does not assume which.** That is precisely why A3 asserts on
observable state after the fill lands rather than on an internal: a live
transport opened under a revoked credential fails `STORE.2`'s requirement that no
old connection outlive a grant, whether or not a catalogue came with it.

**I** The fix shape is a retirement marker the fill path consults, or a
resolution that refuses to create a slot for a retired binding — but that is an
implementation choice and this document is a test plan. What it fixes is pinned
by the cell.

### 3.2 The rotation variant of the same race, and why it is worse

**V** `cache_binding(subject_key, audience)` (`identity_propagation/mod.rs:316`)
is derived from **subject and audience only** — nothing about the grant enters
it. **I** So rotating a grant for the same user against the same backend yields
**the same binding, the same `PoolKey`, and therefore the same slot.**

That turns §3.1's late fill into a contamination rather than a resurrection:

1. G1's fill is on the wire when rotation to G2 lands;
2. the slot is retired and a successor established — **at the same key**;
3. the G1 fill completes and writes **into the successor's slot**.

**V** And it writes twice, through two independent paths in one closure:

- the catalogue, via `get_or_fetch_shared` into the `Arc<PooledEntry>` captured
  before retirement;
- **V** `metadata.rs:262-263` — `*self.pooled_entry(&key).resend_permitted.write()
  = prepare_tool_metadata(…)`, which resolves the key **fresh**, through
  `or_insert_with`, at completion time.

**I** The second is the sharper one and it was missed in r1. It does not write to
the captured orphan; it looks the key up again and writes to **whatever slot
holds that key now** — the successor's. So G1's retry permissions land on G2's
slot, and **V** membership of that set is the only thing granting a `tools/call`
permission to be resent (ADR-012 A1).

**I** The outcome is the A6 failure mode arriving through the A3 race: the
pre-rotation catalogue *and* its resend permissions served under the
post-rotation grant, with every operation having succeeded. **Sequence the test
explicitly** — pause `tools/list`, retire, establish the successor, *then*
release the old fill — and assert the completion neither recreates the retired
slot nor alters the successor's resend permissions.

---

## 4. The plan

**Format note:** the spec anchor is the row **above** its inputs and expectation,
so a reviewer checks the expectation against the **criterion** rather than
against current behaviour. Each row also names which construct it exercises, so
the per-construct no-op check reads as a matrix.

### A1 — two identities, differing catalogues, isolated

> **Spec:** *"One backend returns different tool names/schemas for two
> identities."*

| | |
|---|---|
| **Exercises** | neither K1 nor K2 — the precondition both retire |
| **Inputs** | one `per_user` backend; upstream answers by credential; alpha and beta each resolve a binding |
| **Expect** | alpha sees alpha's tools and not beta's; beta the converse |
| **Admitted case** | both callers are served **something** — absence-only assertions pass for a gateway serving nobody |
| **Status** | **already green**, `catalogue_per_caller_tests::each_identity_sees_its_own_catalogue_and_no_one_elses`. Cited, not rewritten. |

### A2 — interleaved cold/hot reads

> **Spec:** *"Interleave cold/hot reads."*

| | |
|---|---|
| **Exercises** | precondition |
| **Inputs** | alpha cold-fills; beta reads while alpha's slot is warm; alpha re-reads hot |
| **Expect** | beta misses alpha's entry and fills its own; each slot's fetch carries its own binding |
| **Admitted case** | a second read of a **warm** slot does **not** refetch — otherwise the isolation is bought by never caching |
| **Status** | **new.** Fetch-count and provenance assertions, not names alone. |

### A3 — revoke during a fill

> **Spec:** *"rotate/revoke a grant during a fill."*

| | |
|---|---|
| **Exercises** | **K2** |
| **Inputs** | alpha's fill is on the wire; revocation lands; and a second variant where alpha has a `tools/call` in flight |
| **Expect** | the fill's answer is never served afterwards, **and the revocation reports that it retired the slot** — a decline must not read as success |
| **ORDERING, LOAD-BEARING** | assert on state **after the in-flight fill has landed**, never merely after the revoke returns. An A3 that checks immediately post-revoke is **green against exactly the implementation that fails** (§3.1) |
| **Admitted case** | an **un-revoked** fill in the same shape **is** served afterwards |
| **Traps carried** | (i) **V** `invalidate_if` (`cached_metadata.rs:141-146`) returns early on a populated slot, so the generation bump never runs — routing through it covers a cold start only; (ii) the in-flight decline of §3 |
| **Status** | **new, and r1 overstated existing coverage.** **V** `tests.rs:1817` drives shared `get_tools()` and `invalidate_tools_cache()` — the identity-free path — despite its `per_user_backend` fixture. It is **not** coverage of a per-user binding on a runtime retirement path. **Cold per-user eviction is untested**, and r1 marked it covered. |
| **Sequencing** | pause `tools/list`; retire; establish the successor; **then** release the old fill; assert the completion neither recreates the retired slot nor alters the successor's `resend_permitted` (§3.2) |

### A4 — the catalogue is not served after revocation

> **Spec:** *"check both catalogue …"*

| | |
|---|---|
| **Exercises** | **K2** |
| **Inputs** | alpha's slot **populated and fresh**; revocation; alpha lists tools |
| **Expect** | alpha is served no catalogue from the retired slot — a refill requires a new credential |
| **Admitted case** | **beta's** catalogue is untouched, and alpha's own re-consented slot fills normally |
| **Status** | **new.** Must be a **fresh** populated slot: a TTL-expired one would pass for the wrong reason. |

### A5 — call results are not served after revocation

> **Spec:** *"… and call results."*

| | |
|---|---|
| **Exercises** | **K1** |
| **Inputs** | alpha's result cached under its principal; revocation; alpha re-invokes |
| **Expect** | the pre-revocation entry cannot be served — the epoch stranded its key |
| **Admitted case** | an identical call **without** an intervening revocation **does** hit cache (that scenario only); and beta remains **authorized**, receiving correct results after any necessary refill |
| **CORRECTED r2** | an earlier draft asserted "beta's entries survive" a revocation of alpha. **That is an inverted oracle** — see §4.5.1 |
| **Status** | **new** at this level. `policy_epoch_tests.rs:51` proves the epoch mechanism; this proves a revoke reaches it. |

#### 4.5.1 CORRECTED r2 — A5's positive control was an inverted oracle

**V** `meta_mcp/mod.rs:557-565`:

> *"Authorization-policy generation mixed into **every** response-cache key. **One
> counter for this handler.**"* — `policy_epoch: Arc<AtomicU64>`

**The epoch is global.** Any `set_identity_grants` bump strands *every* caller's
result-cache keys, bystanders included. There is no per-identity epoch and the
doc comment says so in as many words.

**I** So the r1 admitted case — *"beta's entries survive"* — demanded behaviour a
**correct implementation cannot produce**. An implementer driving it green would
have to break global invalidation to get there: the control would have actively
pushed the work toward a defect. That is worse than a vacuous assertion, because
a vacuous one merely fails to catch; this one steers.

**Restated:** beta remains **authorized** and receives **correct results after
any necessary refill**. The cache-**hit** assertion is kept, but moved to the
no-revocation scenario, which is the only place it is satisfiable.

**I** Worth naming the class, because it is not the one this session has been
hunting. Every other defect found today was *a value that exists and a decision
that does not use it*. This is its mirror: **a decision that demands a value the
system is designed never to produce.** A reviewer checking the assertion against
current behaviour would call it a bug report; only checking it against the
*mechanism* shows it is the test that is wrong.

### A6 — rotation: the pre-rotation catalogue is not served under the successor grant

> **Spec:** *"rotate/revoke a grant during a fill"* — the **rotate** half.
> **V** `scope-update.md:32` names **two nouns**: *"including changes and
> revocation"*. One row each.

| | |
|---|---|
| **Exercises** | **K2**, and the successor path K2 alone cannot reach |
| **Inputs** | alpha's slot populated under grant **G1**; a fill on the wire; rotation to **G2**; alpha reads |
| **Expect** | alpha is served the **G2** catalogue, or nothing — **never the G1 catalogue presented as G2's** |
| **Distinguishability** | G1 and G2 serve **different tool names AND different schemas** for a same-named tool, so a stale *schema* under a fresh *name* is caught too |
| **Successor access** | after the old fill completes, the successor must **succeed** and receive **only** new data — not merely be denied old data |
| **Mechanism** | **V** `cache_binding` is `(subject, audience)` only (`identity_propagation/mod.rs:316`), so a rotation reuses the **same `PoolKey`** — the successor inherits the retired slot's key, which is why contamination is representable at all (§3.2) |
| **Admitted case** | a read with **no** intervening rotation still hits cache, and beta is untouched |
| **Status** | **new**, and it may be green at HEAD — see below |

**RATIFIED 2026-09-22 as its own cell, not an A3 variant. Cells are enumerated
by failure mode, and rotation's is not revocation's:**

| | successor grant | the wrong behaviour |
|---|---|---|
| **revoke** (A3-A5) | none | serving **anything** |
| **rotate** (A6) | exists | serving the **pre**-rotation catalogue **under the post**-rotation grant |

**I** A construct that retires the slot correctly on revoke can still mis-serve
on rotate, and **no revocation cell can reach that**: with nothing to
mis-attribute *to*, the failure is unrepresentable in A3-A5. Folding rotation in
would have left the clause tested by no cell.

**The failure mode is worse than a leak, which is why it earns a row.** A refusal
announces itself. A mis-attribution is the **right shape of answer under the
wrong identity** — plausible, successful-looking, and detected only by someone
who already knows what G2's catalogue should contain.

#### A6 is a REGRESSION ROW if it is green at HEAD, not a falsifier

**A** It may well pass already. If it does, the cell states **which construct
makes it green** rather than being deleted as redundant:

- **V** `discovery_fetch.rs` (#672) — a per-user slot past its TTL refetches
  rather than serving stale, so a rotation that outlives the TTL self-corrects.
- **V** `policy_epoch` — strands result-cache keys minted under superseded
  grants (`policy_epoch_tests.rs:51`).

**I** Neither is *rotate during a fill*, which is what `scope-tests.md:40`
actually names: the TTL path self-corrects **eventually**, and the epoch never
touches the metadata caches at all. So a rotation landing inside the TTL window,
mid-fill, is covered by neither — and a cell that passes today while reddening if
someone removed the construct behind it is doing real work. **A clause tested by
no cell is the hole; a cell that is green for a named reason is not.**

### C0 — invariant shared catalogue

> **Spec:** *"Invariant shared catalogue is a separate positive control."*

| | |
|---|---|
| **Exercises** | both, negatively |
| **Inputs** | a non-identity backend, throughout every scenario above |
| **Expect** | unaffected by any revocation; still single-flights to one fetch |
| **Why** | catches the repair that retires more than it should — the shared slot is **V** never evicted (`pool.rs:302`, and `:310` panics if it ever is) and must stay so |

### 4.7 CORRECTED r2 — all four metadata caches, not just tools

r1 claimed metadata-cache coverage and specified observations only for **tools**
and **call results**. **V** The criterion says *"cached metadata"*, and **V**
`pool.rs` carries four caches on `PooledEntry` — `tools_cache`,
`resources_cache`, `resource_templates_cache`, `prompts_cache` — plus
`resend_permitted` derived from the first.

**I** Resources, resource templates and prompts escaped every r1 cell. A
retirement that drops only `tools_cache` would pass the whole suite while three
caches survive retirement fully populated, and **V** #666's own §6 risk 5 names
exactly this: *"Moving only `tools_cache` would satisfy the peer's summary and
fail the criterion."* r1 reproduced the risk the design it descends from records.

**Each of A3, A4 and A6 seeds and inspects all four**, each with its own admitted
control — the successor read must return the **new** list for that cache, not
merely fail to return the old one. `resend_permitted` is asserted separately
because §3.2 shows it is written through a different path from the other four.

### 4.8 CORRECTED r2 — observations that separate the mechanisms

r1's matrix assigned independent outcomes without naming observations that tell
the mechanisms apart, so a cell could pass through a mechanism other than the one
it grades — and the fail-fast substitution would still look sound.

Three ways a post-retirement read can return nothing, and they are **not**
interchangeable:

| Observation | Proves | Does **not** prove |
|---|---|---|
| authorization refusal | the guard fired | anything was retired |
| result-cache key **changed** | the epoch advanced (**K1**) | the slot was evicted |
| slot **identity** changed — a new `PooledEntry` | the slot was retired (**K2**) | the epoch moved |

**I** Refusal alone is the trap: a revoked caller resolves no credential, so **V**
`meta_route_isolation_refused` omits the backend and the read returns nothing
**whether or not anything was retired**. Every revocation cell is green against a
retirement path that does nothing at all — the strongest possible version of the
"operation succeeded, outcome did not hold" defect, because here the operation
need not even run.

**So each cell asserts its own mechanism directly**: A5 on the cache **key**
changing, A3 and A4 on slot **identity** changing, and both on top of — never
instead of — the behavioural assertion.

---

## 5. Fail-fast, per construct

| Substitution | Must redden | Must stay green |
|---|---|---|
| K1 revoke surface → no-op | **A5** | A1, A2, A3, A4, A6, C0 |
| K2 eviction → no-op | **A3, A4, A6** | A1, A2, A5, C0 |
| K2 evicts unconditionally, ignoring identity | **A4's bystander control** — beta retains its slot **and its warm-cache fetch count** | C0 (it cannot redden; see §5.1) |
| K2 keeps the `in_flight == 0` predicate | **A3** in-flight variant | — |
| **Retirement not consulted by the fill path** (§3.1) | **A3**, and only when its assertion runs **after** the fill lands | — |
| Rotation retires nothing, successor read falls through to cache | **A6** | A3, A4, A5 |

**I** Row 3 is the control on the control: a repair that retires every per-user
slot on any revocation would satisfy A3-A6 and is not isolation. **Its assignment
was wrong in r1 — see §5.1.**

**I** Row 5 is the one an ordinary reading of A3 misses entirely. The
substitution leaves the revoke path correct and the eviction real — only the
fill path stays unaware — so A3 reddens **only** if its assertion runs after the
in-flight fill has landed. Ordered the other way, this row is green and the
defect ships.

**I** Row 6 is why A6 is not folded into A3: the substitution leaves every
revocation cell green, because revocation has no successor to mis-attribute to.

---

### 5.1 CORRECTED r2 — the retire-everything mutant was assigned to a cell that cannot catch it

**V** `pool.rs:302-310` — the shared slot is *"Inserted at construction and **never
evicted** (`evict_idle_per_user_entries` explicitly skips it)"*, and `:310` is
literally `.expect("PoolKey::Shared is inserted at construction and never
evicted")`.

**I** So a mutant that retires **every per-user slot** on any revocation leaves
the shared slot untouched, **C0 stays green, and the mutant is undetected.** The
intent of r1's row 3 was right — retire-everything must be caught — and the
assignment could not do it.

**This document cited `pool.rs:302` and `:310` two sections earlier, as evidence
for C0.** The same fact that makes C0 a sound control makes it unable to catch
this mutant, and r1 used it for both. **A fact is not evidence until it is
checked against the specific claim it is offered for** — reading it once and
reusing the conclusion is how it went wrong.

**Reassigned:** the mutant goes to **A4's bystander control** — beta retains its
slot **and its warm-cache fetch count**. The second half is what does the work: a
retire-everything implementation leaves beta *authorized* and *able to refill*,
so an assertion that beta is merely "still served" is green against it. Only the
fetch count separates "beta's slot survived" from "beta's slot was destroyed and
silently rebuilt".

**I** That discriminator — *a bystander's warm slot must not refetch* — existed
in no r1 cell, which is a hole exactly where the plan claims its fail-fast
procedure matters most. **C0 is reserved for shared-slot eviction**, which is the
mutant it can actually catch.

## 6. Open, for the release owner

**RESOLVED 2026-09-22** — rotation is its own cell, A6. Enumerated by failure
mode rather than code path; the deciding argument is that `scope-update.md:32`
names two nouns, *"changes and revocation"*, and a construct checked against one
noun with the conclusion written against both is how an invalidation mechanism
covering results got reported as covering catalogues.

**A** What is K1's surface — admin route, CLI, or an internal call from the
account store? The plan grades behaviour and is deliberately silent on shape,
but **building** a surface is a different scope than **wiring** one, and
`set_identity_grants` being `&self` means wiring is available.

---

## 7. Citation provenance

**V** Every `file:line` above was read on this branch, whose base is
`origin/docs/ranking-1-release-line` and which `git log HEAD..origin/…` confirms
is **0 commits behind** tip `bd11e5dd`.

Stated because the local branch of that name in the main checkout sits at
`18f228ba`, **115 commits back** — it predates #666 and #672, so
`cached_metadata.rs`'s early return and `pool.rs`'s eviction machinery do not
look there the way this plan describes them. A reviewer resolving these
citations against that ref would find the plan wrong about code it is right
about. Resolve them against `origin/` by name.
