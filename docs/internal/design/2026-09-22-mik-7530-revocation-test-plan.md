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
| **C0** | Invariant shared catalogue, unaffected throughout | "separate positive control" |

**A** Rotation is folded into A3 as a variant rather than a sixth cell, on the
reading that rotate and revoke exercise the same retirement path with different
successor states. **Say if that should be its own cell.**

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
| **Admitted case** | an **un-revoked** fill in the same shape **is** served afterwards |
| **Traps carried** | (i) **V** `invalidate_if` (`cached_metadata.rs:141-146`) returns early on a populated slot, so the generation bump never runs — routing through it covers a cold start only; (ii) the in-flight decline of §3 |
| **Status** | **new.** The cold-start half exists (`tests.rs:1817`) with its control shipped in #672; the **populated-slot** half is what this row adds. |

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
| **Admitted case** | an identical call **without** an intervening revocation **does** hit cache; and beta's entries survive |
| **Status** | **new** at this level. `policy_epoch_tests.rs:51` proves the epoch mechanism; this proves a revoke reaches it. |

### C0 — invariant shared catalogue

> **Spec:** *"Invariant shared catalogue is a separate positive control."*

| | |
|---|---|
| **Exercises** | both, negatively |
| **Inputs** | a non-identity backend, throughout every scenario above |
| **Expect** | unaffected by any revocation; still single-flights to one fetch |
| **Why** | catches the repair that retires more than it should — the shared slot is **V** never evicted (`pool.rs:322`) and must stay so |

---

## 5. Fail-fast, per construct

| Substitution | Must redden | Must stay green |
|---|---|---|
| K1 revoke surface → no-op | **A5** | A1, A2, A3, A4, C0 |
| K2 eviction → no-op | **A3, A4** | A1, A2, A5, C0 |
| K2 evicts unconditionally, ignoring identity | **C0** | — |
| K2 keeps the `in_flight == 0` predicate | **A3** in-flight variant | — |

**I** Row 3 is the control on the control: a repair that retires every per-user
slot on any revocation would satisfy A3–A5 and is not isolation.

---

## 6. Open, for the release owner

**A** Does rotation need its own cell (§0)? Folded into A3 here.

**A** What is K1's surface — admin route, CLI, or an internal call from the
account store? The plan grades behaviour and is deliberately silent on shape,
but **building** a surface is a different scope than **wiring** one, and
`set_identity_grants` being `&self` means wiring is available.
