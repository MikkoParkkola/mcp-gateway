<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Identity-keyed eviction of a per-user pool slot — design

Design for the second of the two constructs `MIK-7334.CATALOGUE.1` needs on its revocation
half: dropping one caller's per-user pool slot, and with it that caller's catalogue cache,
when their grant is revoked or changed. Ticket MIK-7530.

**Read the scope claim before the design.** This closes the **catalogue** half and nothing
else. The live revoke **trigger** is the companion document's work
(`docs/internal/design/2026-09-22-live-identity-grant-reload.md`); this design is its
consumer and does not redesign it. Neither document closes `CATALOGUE.1` alone — the
criterion needs both, and a reviewer grading it on either in isolation is grading it wrong.

Evidence markers: **V** verified at the cited line, **I** inferred, **A** assumption.

**Branch caveat.** Every line number below was verified on `design/live-identity-grant-reload`
(worktree `/Users/mikko/github/.worktrees/relcheck`, HEAD `654d7b9d`). The reasoning is
branch-independent; the line numbers are not. Re-check them against the release line before
grading.

---

## 0. The brief, checked at source: what holds, and the two things it has backwards

The briefing for this work is unusually accurate — two prior attempts were burned on a wrong
premise and the corrections stuck. Each load-bearing claim was re-verified rather than
inherited:

| Brief's claim | Verdict |
|---|---|
| `policy_epoch` keys the response cache only; the epoch does not reach the catalogue | **V (absence), re-run with `-uu`.** `rg -uu -n "policy_epoch" src/backend/` → exit 1, zero matches. Hidden dirs and `.gitignore` cannot be hiding a hit. |
| The per-caller catalogue is `tools_cache` on `PooledEntry`, reached via `tools_slot(binding)` | **V** `pool.rs:90`; `metadata.rs:32-34`. |
| `invalidate_tools_cache` passes `Vec::is_empty`, so revocation through it is a no-op on a populated cache | **V** `metadata.rs:60-68`. The `is_empty` predicate is load-bearing and is not weakened here. |
| `invalidate_if` returns early on a populated keep, with the generation bump *below* that return | **V** `cached_metadata.rs:140-150`. The bump is at `:150`, the early `return` at `:145`. |
| `evict_idle_per_user_entries` is not reusable as-is | **V** `pool.rs:326-334,350-353`: filters `idle_ttl` **and** `in_flight`, skips `Shared`, takes no identity input. |
| Identity-keyed eviction is unimplemented, not merely un-triggered | **V (absence).** `rg -uu -n "pool\.remove" src/` returns exactly two hits: the idle reaper's `remove_if` (`pool.rs:343`) and one test (`pool_tests.rs:385`). Nothing removes a slot by identity. |

Two things the brief has backwards. Both change the design.

### 0.1 Resurrection is not the hazard. Declining to evict is.

The brief warns that `ensure_entry_started` → `pooled_entry` → `or_insert_with` **creates**
the entry when absent (**V** `pool.rs:248`), so "an eviction racing a fill can be immediately
resurrected", and asks for an ordering that makes eviction *stick*.

A resurrected slot is a **fresh** `PooledEntry` with `tools_cache: CachedMetadata::new()`
(**V** `pool.rs:184`) — an empty cache. The criterion is about **stale bytes**, not about
denying service. Denial lives on the authorization path (`is_active_at` → `covers` →
`evaluate`), which the companion design closes. So a slot that comes back empty is the
eviction *working*: the pre-revocation tool list is unreachable and the next read goes to
the backend.

**What "sticks" has to mean here:** no reader can reach the pre-revocation `Vec<Tool>` after
the eviction returns. Not "the key is absent from the map for some interval" — that is a
property nothing needs and nothing can hold, because any concurrent reader legitimately
recreates the key.

**The real hazard is the opposite one, and it is the `is_empty` trap one rung over.** If
eviction copies `evict_idle_per_user_entries`' shape and puts `in_flight == 0` inside the
`remove_if` predicate (**V** `pool.rs:351`), then a revocation against a slot that happens to
be **busy** silently declines. The idle reaper survives that because it re-sweeps every 60s
(**V** `server/mod.rs:3605`); a revocation **fires once**. Same failure class as routing
revocation through `Vec::is_empty`: a predicate that is correct for its original caller and
silently wrong for this one. §E3 rules on it.

### 0.2 "Which `cache_binding` can a revocation key on" has a third answer: neither, by prefix

MUST-ADDRESS #1 poses the two `cache_binding` functions as alternatives. The revoker calls
**neither**. It holds a `GrantSubject`, not a credential, and a credential is minted per
request from a `VerifiedIdentity` the revoker does not have.

What it can do is **reconstruct a prefix** of PATH A's binding and match on it. That is not a
softer version of exact keying — for token-exchange backends it is the **only** form that
works, because the pool key there is the *widened* string (§E1). PATH B (vault) is out of
scope and its namespace makes that automatic.

---

## 1. What exists today

**V** The pool is `pool: DashMap<PoolKey, Arc<PooledEntry>>` on `Backend`
(`src/backend/mod.rs:50`). `PoolKey` is `Shared` (`pool.rs:41`) or
`PerUser { binding: String }` (`pool.rs:44`).

**V** One `PooledEntry` owns the transport (`pool.rs:62`), the in-flight counter
(`pool.rs:78`), the failsafe, and **all four metadata caches plus `resend_permitted`**
(`pool.rs:90-103`). Its own comment states the invariant this design depends on: the caches
are *"CO-LOCATED WITH THE SLOT, NOT THE BACKEND (MIK-7334.CATALOGUE.1)"*, so *"the bytes in
slot K's cache were fetched over slot K's transport"* (`pool.rs:80-89`). Removing the entry
therefore drops every one of them in one move — which is exactly what
`metadata.rs:56-59` promises: *"Revocation evicts the identity's slot, which drops its
transport and its caches together."*

**V** The binding reaches the key through one funnel: `pool_key_for(identity_key)`
(`pool.rs:213-221`), and `tools_slot` resolves every cache read through that same function
(`metadata.rs:32-34`) — *"THE ONE PLACE A METADATA CACHE IS SELECTED"* (`metadata.rs:26`).

**V, and it matters for the tests.** `tools_slot` calls `pooled_entry`, which calls
`pooled_entry_with` → `self.pool.entry(key.clone()).or_insert_with(…)` (`pool.rs:248`). So
every non-blocking cache accessor — `has_cached_tools_for` (`metadata.rs:38`),
`cached_tools_count_for` (`:76`), `get_cached_tool_names_for` (`:111`) — **creates the slot
it then reports on**. An absence assertion written with any of them passes for a slot the
probe itself just built. §3 is built around this.

**V, and it raises the stakes on §E3.** Every catalogue fill holds an in-flight claim for the
duration of its fetch. `get_cached_list_on` takes its slot through
`begin_internal_activity_for(key)` (`metadata.rs:185`), which is
`ActivityGuard::adopt_claimed(self.claim_pooled_entry(key), false)` (`pool.rs:488-490`) — and
`claim_pooled_entry` does `in_flight.fetch_add(1, …)` (`pool.rs:296`). The doc comment says
why: the reaper is otherwise *"free to remove the slot and close the transport mid-fetch"*
(`metadata.rs:164-166`). So `in_flight > 0` is not a rare state on a slot being filled — it is
the **normal** state for the entire duration of a `tools/list`. An eviction gated on
`in_flight == 0` would therefore decline during exactly the window a revocation is most likely
to race. §E3 and C3 turn on this.

**V** The key round-trips back to the binding without an index: `get_cached_list_on`
destructures `PoolKey::PerUser { binding } => Some(binding.as_str())` (`metadata.rs:180-183`)
to hand the transport its `identity_key`. The binding **is** the key, which is what makes a
key-side prefix match (§E1) equivalent to an identity match rather than an approximation of one.

**V** Removal already has a supported "in use" path. `ensure_entry_started`
(`lifecycle.rs:206`) re-checks by `Arc::ptr_eq` that the pool still maps `key` to the entry
it started (`:245`, `reconcile_after_start` doc `:260-275`); if the evictor won, the losing
side closes the transport it built and retries against a fresh entry, bounded by
`MAX_RACE_RETRIES = 3` (`:207`). An orphaned `PooledEntry` is a state the codebase
handles deliberately, not a state this design invents.

**V** `PooledEntry` has **no async `Drop`** — stated at `lifecycle.rs:269-272`: *"there is no
async `Drop` for `PooledEntry`"*, which is why the losing side must close explicitly. §E3
owes an answer for the transport of a slot evicted while busy.

**V** The caller side exists. `BackendRegistry::all() -> Vec<Arc<Backend>>`
(`registry.rs:260`) is how the idle reaper reaches every backend (`server/mod.rs:3621`).

---

## 2. The design

### E1 — What identifies the slot: a **binding prefix**, reconstructed from the grant subject

**Decision: `Backend::evict_identity_slots(&self, binding_prefix: &str) -> usize`, matching
`PoolKey::PerUser { binding }` where `binding.starts_with(prefix)`. The prefix pins the
subject and leaves the audience free.**

This is the crux the brief names, so the reasoning is given in full.

**The two `cache_binding` functions produce keys in two disjoint namespaces.**

| Path | Function | Binding shape | Grant-revocable? |
|---|---|---|---|
| A | `identity_propagation::cache_binding` (**V** `mod.rs:316-325`) | `idp:{sl}:{subject_key}:{al}:{audience}` | **Yes — this design** |
| A′ | `token_exchange::exchange_cache_key` (**V** `token_exchange.rs:114-123`) | PATH A's string **plus** `:{el}:{endpoint}:{scl}:{scope}` | **Yes, via the prefix** |
| B | `personal_accounts::vault::cache_binding` (**V** `vault.rs:311-327`) | `acct:v1:{digest}:{lease.generation}:{authorization_epoch}:{token_revision}:{descriptor_revision}` | **No, and does not need to be — §E5** |

**A′ is why the prefix is load-bearing rather than tidy.** **V** `token_exchange.rs:376` binds
`let binding = exchange_cache_key(&subject_key, &backend.audience, endpoint, scope);` and
**V** `:421` publishes it as `cache_binding: binding`. So on a token-exchange backend the
*pool key itself* is the widened string. An eviction matching PATH A's binding **exactly**
would miss every token-exchange slot — a silent no-op on precisely the backends where a
revocation matters most. The widening is documented as appending length-prefixed segments on
top of PATH A's encoding (**V** `token_exchange.rs:109-112`), which is what makes
`starts_with` sound across both.

**What the prefix is, and why it pins what it claims to pin.**

```
prefix = format!("idp:{}:{}:", subject_key.len(), subject_key)
   where subject_key = format!("oidc:{}:{}:{}:{}", issuer.len(), issuer, subject.len(), subject)
```

(**V** `stable_actor_id` at `key_server/oidc.rs:132-140`; the outer shape at
`identity_propagation/mod.rs:316-325`.)

Any binding beginning with `idp:{n}:{S}:` has a subject component of length exactly `n` whose
bytes are exactly `S` — the length prefix makes the boundary unambiguous, which is the stated
reason it is there at all (**V** `mod.rs:317-318`: *"Length-prefixed so distinct (subject,
audience) pairs never collide even if a component contains the separator"*). So the prefix
cannot over-match into a different subject, and by leaving the audience open it matches every
backend that caller touched **and** every token-exchange widening of it.

**V (absence), and this is a gap the design must close rather than inherit.** The existing
collision test `cache_binding_isolates_users_and_audiences` (`mod.rs:722-725`) asserts three
bindings are pairwise **unequal**. `rg -uu -n "starts_with" src/identity_propagation/`
returns zero matches. Prefix *containment* is an unasserted property today; §3 C7 adds it.

**Why reconstruction is sound, and where it is not.**

The revoker holds `GrantSubject { authority, subject, label }` (**V** `identity_grants.rs:28-36`).
**V** `grant_subject_from_verified_identity` (`gateway/router/handlers.rs:71-78`) sets
`authority = identity.issuer` and `subject = identity.subject` — the same two fields
`stable_actor_id` length-prefixes. So for an OIDC caller the reconstruction is exact.

The other three constructors set a literal authority: `"trusted_header"`
(`handlers.rs:88`), `"mtls"` (`:104`), `"agent_oauth"` (`:111`). A grant carrying one of
those reconstructs to `oidc:14:trusted_header:…`, which no caller ever produces — so it
matches nothing.

**That is correct, not a hole, and the argument is stronger than "it fails safe".** **V**
`caller_grant_subject` (`handlers.rs:59-69`) tries `verified_identity` **first**, so a caller
with a `VerifiedIdentity` always yields the issuer-derived subject. And **V**
`SignedAssertionStrategy::propagate` takes `&VerifiedIdentity` (`mod.rs:442-446`), so a PATH A
slot only ever exists for a caller who had one. Authority ≠ issuer therefore implies no
`idp:` slot exists for that grant. Evicting nothing is the right answer. Further: `covers`
matches on `&self.subject == identity` (**V** `identity_grants.rs:231`) — the same
operator-supplied string the reconstruction consumes — so a grant whose authority is wrong
never authorized anyone in the first place.

#### E1.1 — The reconstruction breaks on a normalised subject, and this is the design's worst defect

**Raised in review, verified at source, and it makes the mechanism silently no-op for a whole
class of callers.** The design as first written walked straight into this codebase's signature
failure.

**V** Grant construction normalises the subject; the pool binding does not.
`grant_subject_from_verified_identity` routes the subject through `trimmed_non_empty`
(`handlers.rs:72`), which does `value.trim()` **and** `trimmed.chars().take(HEADER_IDENTITY_MAX_LEN)`
(`handlers.rs:121-127`), with **V** `HEADER_IDENTITY_MAX_LEN = 512` (`handlers.rs:51`).
`stable_actor_id` (`key_server/oidc.rs:132-140`) length-prefixes `self.subject` **raw**.

So for any verified subject with surrounding whitespace, or longer than 512 characters, the
grant stores one string and the binding carries another. The reconstructed prefix matches
nothing, `evict_identity_slots` returns `0`, and the reload reports success. **The criterion
goes unmet for exactly those callers, silently** — the same shape as routing revocation
through `Vec::is_empty`, one module over.

**V, and it is worse than a length cutoff.** `.chars().take(512)` truncates by **characters**
while `stable_actor_id` length-prefixes by `.len()`, which is **bytes**. For a multi-byte
subject the two disagree on the length prefix as well as on the content, so the mismatch is
not confined to subjects over the limit in the obvious sense.

**The fix is not in the eviction API, and cannot be.** An API keyed on a string the grant
never stored is unbuildable — this is the crux the brief named, arriving through the back
door. Three parts, all outside `Backend`:

1. **Preserve exact bytes at grant construction.** `grant_subject_from_verified_identity`
   should reject-or-store the verified issuer and subject **unmodified**. `trimmed_non_empty`
   is correct for *header*-sourced identity, which is untrusted operator input needing a
   bound; a `VerifiedIdentity` came from a validated token and its bytes are already
   constrained by the issuer. **I** Applying a header hygiene function to verified claims is
   the actual bug, and it predates this design.
2. **Reconcile grants already stored normalised.** A pure code fix leaves existing grant files
   holding normalised subjects that no binding will ever match. **A** The migration is a
   documented operator step (re-issue affected grants) rather than an automatic rewrite,
   because the gateway cannot recover bytes the file no longer contains — it can only detect
   that a stored subject differs from any live caller's. Piece 5's log is what surfaces it.
3. **Cells C10a/C10b** (§3) pin the whitespace and over-512 cases.

**The blank-issuer divergence is the same family and folds in here. V**
`grant_subject_from_verified_identity` falls back to `authority = "oidc"` when
`identity.issuer` is blank (`handlers.rs:73`) while `stable_actor_id` embeds the blank issuer
as `oidc:0::…`. Part 1 does not fix it; it needs the fallback to refuse rather than
substitute. **A** Lower priority — a blank `iss` in a verified token is implausible, where
whitespace and long subjects are not.


### E2 — Who calls it, and what they hold at the moment of revocation

**Decision: the grant-reload path calls it, and derives the subject set by diffing the
outgoing and incoming stores. No new plumbing between the CLI and the gateway.**

The companion design's `ReloadContext::reload_identity_grants()` reads the grants file,
compares it against the live store, and publishes (**V** the companion doc §D1 and MVP piece
2/4). At the instant it publishes it holds **both stores**, which is exactly the input this
API needs and the CLI cannot supply — the CLI edits a file in a different process.

**V** The diff is cheap and needs no new type. `LocalIdentityGrantStore` is a
`BTreeMap<String, IdentityGrant>` keyed by `grant_id` (`identity_grants.rs:503-504`) with
`values()` exposed (`:537-539`), and `IdentityGrant` derives `PartialEq, Eq`
(`:115`). So:

> the affected subjects are the `subject` field of every grant row that is present in one
> store and absent from the other, or present in both and unequal. **An unequal row
> contributes BOTH its outgoing and its incoming subject.**

**That last clause was missing in the first draft and both reviewers caught it.** A grant row
whose `subject` is edited A→B under an **unchanged `grant_id`** is one unequal row. Taking
only the incoming subject evicts B's slots and leaves **A's catalogue bytes live**, with no
log line naming A — a reassignment that silently preserves the previous holder's view. Cell
C11 pins it. The two-sided rule costs one extra `push` and closes it.

That single rule covers both nouns the criterion names — a **revocation** changes
`revoked_at`, a **rotation** changes `scope`/`tool`/`expires_at`/`agent`, and a removal or
addition is a presence difference. One mechanism, and §3 keeps them as separate cells anyway
because they fail differently.

**The loop, in full:**

```
for subject in changed_subjects(&outgoing, &incoming):
    prefix = identity_binding_prefix(&subject)        // None if authority is not an issuer-shaped subject
    // The None arm SKIPS the subject; it never falls through to a match.
    // §E1 shows no `idp:` slot can exist for such a grant, and C8 asserts it.
    let Some(prefix) = prefix else { continue };
    for backend in registry.all():                    // V registry.rs:260
        evicted += backend.evict_identity_slots(&prefix).await
```

**Ordering against the publish: evict AFTER the store is published and the epoch bumped.**
**I** The reverse order leaves a window in which a slot is evicted, a concurrent request
refills it against the *old* grants still in the store, and the refilled catalogue is once
again stale — an eviction that ran and achieved nothing. Publishing first means any refill
races forward into the new policy, never back into the old one. This costs nothing: the
publisher already holds the write-then-bump-under-lock discipline (**V**
`meta_mcp/mod.rs:1300-1307`), so by the time eviction starts the new store is visible to
every reader.

**V** One helper, not two copies. `cache_binding` is a private `fn` (`mod.rs:316`) and
`stable_actor_id` lives in another module (`key_server/oidc.rs:132`). Reconstructing the
prefix inside `config_reload` would duplicate **both** formulas into a module that has no
business knowing either — the exact duplication `invoke.rs:3409-3412` warns about when it
says a key built from a `GrantSubject` *"would bind a person the gateway never
authenticated"*. So: `pub(crate) fn identity_binding_prefix(subject: &GrantSubject) -> Option<String>`
lands **beside `cache_binding`**, returns `None` for a non-issuer authority, and is the only
place the two formulas meet.

### E3 — In-flight ordering: **remove unconditionally, close conditionally**

**Decision: the removal from `DashMap` is unconditional and is the atomic point. The
transport close is conditional on `in_flight == 0`. These are two different questions and
the idle reaper conflates them because for *its* caller they happen to have the same answer.**

**Why removal must not be conditional.** §0.1 has the argument; here is the shape it rules
out:

```rust
// WRONG — the is_empty trap one rung over.
self.pool.remove_if(&key, |_, entry| entry.in_flight.load(SeqCst) == 0)
```

**V** That is `evict_idle_per_user_entries`' predicate (`pool.rs:350-353`), and its comment
justifies it precisely: *"Evicting then closes the transport underneath a live request"*
(`pool.rs:349`). The hazard it names is the **close**. Removal alone harms nothing —
**V** `lifecycle.rs:260-275` documents an orphaned `PooledEntry` as a handled state, and
`ensure_entry_started` detects it by `Arc::ptr_eq` and recovers (`:245`). Copying the
predicate would mean a revocation against a busy slot silently declines, with no re-sweep
behind it (the reaper has one, **V** `server/mod.rs:3605`; a revocation does not).

**The ordering that makes eviction stick.**

1. `self.pool.remove(&key)` — unconditional. The moment this returns, no future
   `pooled_entry(key)` can reach the old `PooledEntry`; it returns a fresh, empty one.
   **This single step is the whole criterion.** The stale `Vec<Tool>` is now reachable only
   through `Arc`s already handed out.
2. Take the transport under the write guard **only if** `in_flight == 0`, and `close()` it.
3. If `in_flight > 0`, leave the transport in the orphan and return. §E4 rules on what
   happens to it.

**What happens to a request already using the transport: it finishes.** It holds
`Arc<PooledEntry>` — handed out by `claim_pooled_entry` under the shard guard **and** the
transport read guard (**V** `pool.rs:293-299`), or reached through `ActivityGuard::entry()`
(**V** `pool.rs:158-160`). Removing the map entry does not invalidate an `Arc`. The request
completes against the transport it was already using, and its result is returned to its
caller. **This is correct, not a leak of authority:** that request was authorized before the
revocation landed, on a connection opened before it. Revoking a grant is not a mandate to
sever a TCP connection mid-response.

**A fill already on the wire writes into a grave.** A fetch that started before the eviction
completes and calls `store_if_current` (**V** `cached_metadata.rs:97-105`) on the **orphan's**
cache. Nobody can read it. Note the generation guard at `:99` is not what saves us here and
must not be credited for it — the orphan's generation is untouched by this design, so the
store **succeeds**; it is the unreachability of the orphan that makes it harmless. Saying
which mechanism does the work matters, because the generation guard is the one the
`invalidate_if` path relies on, and the two are easy to confuse.

**A resurrection racing the eviction is the eviction working.** `ensure_entry_started` retries
up to three times (**V** `lifecycle.rs:207,209`) and re-derives `pooled_entry(key)` each
time, so a request in flight when the slot is removed may recreate the key. The recreated
entry has an empty `tools_cache` (**V** `pool.rs:184`) and will refill from the backend,
under the already-published new grants (§E2 ordering). §3 C3 asserts the property that
survives this — the post-eviction read reaches the backend — rather than asserting the key is
absent, which is the assertion that would fail for the wrong reason.

#### E3.1 — The claim must travel with the entry, and today it does not

**Raised in review, verified at source, and it is the one place "remove unconditionally"
genuinely costs something.** It does not refute the ruling; it adds a precondition.

**V** `get_cached_list_on` claims one entry and then independently re-resolves another. The
lease is taken at `metadata.rs:185` (`begin_internal_activity_for(key)` → `claim_pooled_entry`,
incrementing `in_flight` on entry **E**), the cache written is `select(&entry)` on **E**
(`:186-187`) — but the transport comes from `self.ensure_entry_started(key).await` at
`:189`, which re-resolves the key through the **unclaimed** `pooled_entry` (**V**
`lifecycle.rs:210`).

**The code contradicts its own comment.** `metadata.rs:184` reads *"Resolve the slot ONCE and
keep it for both the cache and the fetch"*, and `:157-162` insists *"the cache written and the
transport written from are the same `Arc<PooledEntry>` — not two lookups that agree today."*
Line `:189` is a second lookup. Today the gap is unreachable in practice: the only remover is
the idle reaper, which also requires `last_used` past the TTL (**V** `pool.rs:352-353`), so a
slot being actively fetched does not qualify. **An unconditional remove makes it reachable.**

Two consequences, both real:

- The fetch fills **E**'s cache over **E′**'s transport, breaking the co-location invariant
  `pool.rs:80-89` exists to guarantee. The bytes land in a grave, so this wastes a fetch
  rather than leaking across identities — but the invariant is the criterion's own.
- **E′ carries `in_flight == 0` while its transport is actively in use.** A second eviction,
  or the reaper, may then close it mid-fetch — precisely the harm `claim_pooled_entry` exists
  to prevent (**V** `metadata.rs:164-166`).

**Required with this design: `ensure_entry_started` returns the transport together with a
claim on the entry it actually resolved, and the claim transfers across its retry loop
(`lifecycle.rs:209`).** The caller then holds a lease on the entry it is really using.
**A** This touches a shared function with callers beyond the metadata path
(`lifecycle.rs:176`), so it wants upstream impact analysis before the edit — flagged here
rather than assumed cheap. Cell C12 is the barrier: evict between the claim and the transport
acquisition, and assert the fetch's transport is not closed under it.

**And one ordering rule that must be written down, because the naive implementation is
writable.** `in_flight` is incremented under the transport **read** guard
(**V** `pool.rs:294-296`), so eviction must re-check it **after** taking the transport
**write** guard, not before. A read-then-lock implementation reintroduces a TOCTOU the
reaper's atomic `remove_if` never had — the removal is now unconditional, so the write guard
is the only remaining mutual exclusion against a claim landing mid-eviction. `ActivityGuard`'s
own comment states the discipline: *"the `RwLock` — not the atomic — is what makes the two
mutually exclusive"* (**V** `pool.rs:113-121`).


### E4 — What eviction drops: the caches immediately, the transport by ownership

**Decision: caches go with the slot, unconditionally. A live transport is not severed, and it
is not chased with a waiter either — dropping the last handle reaps it.**

**The caches are free.** All four `CachedMetadata` fields plus `resend_permitted` live on
`PooledEntry` (**V** `pool.rs:90-103`). Removing the entry drops them together — no per-cache
call, no predicate, no `invalidate_if`, and therefore no contact with the `Vec::is_empty`
hazard at all. The design never calls `invalidate_tools_cache` and never weakens it.

**The failsafe goes too, and that is a small deliberate cost.** **V** `Failsafe` is per-slot
(`pool.rs:79`, justified at `pool.rs:51-60`). A revoked-then-re-granted identity gets a fresh
circuit breaker. **I**
Acceptable: the alternative is carrying breaker state across an authorization change, and the
slot is rare and operator-triggered.

**Draining, ruled on — and the first draft's justification for a waiter was wrong.** The brief
asks whether dropping a live transport is correct. It is not, and the design does not do it —
§E3 step 2 only closes an idle one. The first draft then argued that a transport left in an
orphan leaks, citing the absent async `Drop` (**V** `lifecycle.rs:269-272`), and spent ~15
lines on a bounded polling waiter to close it. **Review pushed back and the source agrees with
review.**

**V** Ownership already does this cleanup. `StdioTransport` spawns its reader task holding a
**`Weak`** (`transport/stdio.rs:274`), and the comment above it states the consequence in its
own voice (`stdio.rs:270-273`):

> With a `Weak`, dropping the last real handle drops the transport, which drops the `Child`,
> which kills the process, which closes stdout, which ends this task. **Ownership does the
> cleanup; nothing has to decide when it is safe.**

`kill_on_drop(true)` is set at **V** `stdio.rs:219`. So when the last in-flight request
finishes and drops its `Arc<PooledEntry>`, the transport drops, and the child is reaped. The
"leaked child process" the waiter existed to prevent **does not occur**. The leak the comment
at `stdio.rs:266-268` warns about is the *strong*-`Arc` design that was rejected.

**Decision: no waiter. Cut from the MVP.** What an explicit `close()` still buys is **graceful
session termination** — a clean MCP shutdown, an HTTP session teardown — which is a courtesy
to the upstream, not resource hygiene for us. Those are different goals and the first draft
conflated them. A revoked identity's orphaned transport terminating ungracefully when its last
request finishes is acceptable; it is also, on the stdio path, indistinguishable from what
happens when the process exits.

**A** One line of follow-up instead: confirm the HTTP transport's refresh tasks abort on drop
rather than assuming it, since the stdio argument does not transfer automatically. If that
turns out false for HTTP, the waiter returns as HTTP-only — which is a smaller thing than the
general waiter and a better-targeted one. **This is the ladder working: the platform already
owned the problem, and ~15 lines came out.**


### E5 — PATH B (vault) is out of scope, and a test there proves nothing

**V** The vault binding embeds `lease.generation`, `authorization_epoch`, `token_revision`
and `descriptor_revision` (`vault.rs:311-327`), and its own comment states the consequence:
*"a re-authorized or rotated account produces a different binding, so a result cached for the
previous grant is never served for the new one"* (`vault.rs:307-308`).

**This design must be distinguishable from that, and here is the distinction.** On PATH B,
isolation after a rotation is **structural**: the new credential yields a new `PoolKey`, the
old slot is simply unreachable by key, and no eviction runs or is needed. A test phrased as
*"the revoked caller is not served stale tools"* passes on PATH B **whether or not this design
exists** — it is measuring the key derivation, not the eviction. That is the trap the brief
names, and every cell in §3 is written to avoid it:

- every cell runs on a **PATH A** binding, where the binding does **not** move on a grant
  change, so a pass can only come from eviction;
- C5 makes rotation-without-binding-movement its own cell precisely because it is the case
  PATH B gets for free and PATH A does not;
- no cell asserts "a different key yields different bytes", which is the vacuous form.

**I** A local identity-grant revocation does not touch a vault account's lease, and the
`idp:` prefix cannot match an `acct:v1:` binding, so PATH B slots are untouched by
construction rather than by a check. If managed-account revocation ever needs slot eviction it
is a different trigger and a different prefix, and it should be its own ticket.

---

## 3. Test plan — cells by failure mode

Each row names the **failure it goes red on**. "Unimplemented, so it does not compile" is not
a failure mode and is not counted: every cell below is written so it also goes red against a
**plausible wrong implementation**, named in its own column. That column is the point of the
table.

### 3.1 Two rules the harness must obey before any cell runs

**Rule 1 — no absence assertion may use a cache accessor.** **V** `has_cached_tools_for`,
`cached_tools_count_for` and `get_cached_tool_names_for` all route through `tools_slot` →
`pooled_entry` → `or_insert_with` (`metadata.rs:32-34`, `pool.rs:248`), so each one **creates**
the slot it reports on and then truthfully reports it empty. A cell asserting
`cached_tools_count_for(Some(b)) == 0` after eviction passes for a slot the assertion itself
built — the absence is manufactured by the probe.

**V** The only non-creating probe today is `pooled_transport_for_test`
(`pool.rs:404-408`), which uses `self.pool.get(key)`. It answers `None` both for "slot
absent" and "slot present, transport unstarted", so it cannot distinguish the two. **A** The
fixture wants one more test-only one-liner beside it — `self.pool.get(key).is_some()` — and
that is the whole addition. Where a cell can assert a positive property instead, it does.

**Rule 2 — every cell asserts its premise before its conclusion, in its own body.** Lifted from
this house's own convention: **V** `docs/internal/design/2026-09-22-catalogue-1-design-review-round2.md:400-407`
— *"The asymmetry is the point, and it is why one-sided assertions were refused"* — the
served-half assertion fires **first in the case body** so an empty gateway fails on the
premise rather than passing on the conclusion. **V** The failure this prevents is recorded, not
hypothetical: `2026-09-21-catalogue-1-per-caller-view.md:1157` — *"That case was also
one-sided — both assertions were absences, so it held against a gateway caching nothing."*

**In its own body is the operative phrase**, and the first draft got this wrong by leaning on
a fixture-level check plus "C6 runs first". Rust guarantees no in-module test ordering and
runs cases in parallel threads, so a control case cannot gate its siblings. Every cell carries
its own premise assertion as explicit setup; C6 states the property standalone rather than
guarding anything.

Concretely, each eviction cell asserts **the target slot is populated** (non-zero tool count,
read before the revocation) before it revokes anything.

### 3.2 The cells

| # | Goes red when | The wrong implementation it kills | Setup → observable |
|---|---|---|---|
| **C1** | **A POPULATED per-user slot survives revocation** — the criterion's own case, and the one `is_empty` cannot reach. | Routing revocation through `invalidate_tools_cache` (`Vec::is_empty`, **V** `metadata.rs:60-68`). That passes its own predicate check and voids nothing on a warm cache. | PATH A binding for subject A on a `per_user` backend. Fill A's slot; **assert `cached_tools_count_for(Some(a)) > 0` first**. Revoke A's grant; reload. → the next `get_or_fetch` for A reaches the backend (fetch counter increments) and returns the post-revocation list, not the seeded one. |
| **C2** | **An unaffected caller's slot is evicted too.** | "Evict all per-user slots on any grant reload" — the blunt hammer (§4 names it as the reviewer's cut). It passes C1 and fails only here. | Fill slots for A **and** B. Revoke A only; reload. → **positive assertion**: B's cached tool list is byte-identical afterwards and B's fetch counter did **not** increment. Not an absence. |
| **C3** | **Eviction silently declines against a BUSY slot.** | Copying `evict_idle_per_user_entries`' predicate, `in_flight == 0` inside `remove_if` (**V** `pool.rs:351`). Green on C1 and C2, red only here — and there is no re-sweep behind a revocation to hide it. **This is not an edge case:** every catalogue fill holds an in-flight claim for its whole duration (**V** `metadata.rs:185` → `pool.rs:488-490` → `:296`, §1), so the wrong predicate declines during exactly the window a revocation races. | Fill A's slot. Hold an `ActivityGuard` on it (`in_flight > 0`). Revoke A; reload. → the post-eviction read for A reaches the backend. Deliberately **not** "the key is absent": a concurrent reader may legitimately recreate it (§E3), so key-absence would go red for the wrong reason. |
| **C4** | **Token-exchange slots are missed.** | Exact subject+audience matching instead of a prefix. **V** the pool key on that path is the *widened* `exchange_cache_key` string (`token_exchange.rs:376,421`), so exact matching no-ops on exactly the backends where revocation matters most. | Seed a slot by driving the **actual credential producer** — run `TokenExchangeStrategy::propagate` against a stubbed exchange endpoint and take `credential.cache_binding` as the `PoolKey` (**V** it is published there, `token_exchange.rs:421`). **Not a handwritten string**: the first draft built the widened binding literally in the test body, which cannot detect a production key-format change that leaves the fixture untouched — the cell would stay green while the thing it guards moved. Revoke A; reload. → that slot is evicted. Red today **and** red against exact subject+audience matching. |
| **C5** | **A grant ROTATION does not evict** — the criterion names two nouns and this is the second. | Keying eviction on `revoked_at.is_some()` rather than on inequality. Passes C1 (revocation) and fails here. | Fill A's slot. **Narrow** A's grant scope — no `revoked_at`, binding unchanged (PATH A takes no grant input, **V** `mod.rs:316`). Reload. → A's slot is evicted. **This is the cell PATH B gets for free** (§E5): on the vault path the binding would have moved and the old slot would be unreachable without any eviction. Here it does not move, so a pass can only come from the mechanism. |
| **C6** | **The gateway serves nobody** — the positive control, and the reason C1–C5 cannot pass vacuously. | Any change that degrades the single-tenant or unaffected-caller path to deliver "isolation". | No revocation at all. A populated PATH A slot and the `Shared` slot both serve their catalogues; `has_cached_tools()` is true. **Not "runs first in the module"** — the first draft said that and it is unenforceable: Rust guarantees no in-module test order and runs cases in parallel threads. The vacuity guard is Rule 2's per-cell premise assertion, which every cell carries in its own body; C6 is the standalone statement of the same property, not a gate on the others. |
| **C7** | **The prefix over-matches or under-matches.** | `contains` instead of `starts_with`; or dropping the trailing separator; or forgetting the length prefix. | **The first draft of this cell was vacuous and review caught it.** On ordinary fixtures a full `idp:{n}:{S}:` prefix occurs only at offset 0, where `contains` and `starts_with` agree — so the cell could not go red against the matcher its own row claims to kill. **The fixture must plant the collision:** give identity Y an audience whose bytes contain identity X's *complete* prefix at a nonzero offset (e.g. audience `https://h/idp:3:xyz:junk`). Then X's revocation evicts Y under `contains` and does not under `starts_with`. Reachable by configuration, not contrived — the audience is an operator-set string (**V** `mod.rs:459`). Plus the plain direction: X's prefix matches `cache_binding(X, aud)` for every audience and every widening of it. |
| **C8** | **A non-issuer authority silently evicts something.** | Reconstructing a prefix for an `mtls` / `agent_oauth` / `trusted_header` grant and matching by accident. | Grant with authority `"mtls"`. → `identity_binding_prefix` returns `None`, the eviction loop skips it, and **no** slot is touched. Guards §E1's soundness argument rather than adding coverage; labelled as a guard. |
| **C9** | **Only the first matching backend is evicted.** | A loop that `break`s on the first hit, or one that evicts per-subject rather than per-(subject, backend). **Passes C1–C8 undetected** — every other cell uses one backend, so this is the cheapest wrong implementation of §E2's nested loop and is currently invisible. | One subject with populated slots on **two** `per_user` backends. Revoke; reload. → **both** are evicted, asserted separately. |
| **C10a** | **A subject with surrounding whitespace is never evicted** (§E1.1). | The shipped normalisation: `trimmed_non_empty` trims at grant construction (**V** `handlers.rs:72,121-127`) while `stable_actor_id` keeps raw bytes. | Verified subject `" alice "`. Fill its slot; revoke; reload. → evicted. **Red today** and red against any fix that changes only the eviction side. |
| **C10b** | **A subject longer than 512 characters is never evicted** (§E1.1). | `.chars().take(HEADER_IDENTITY_MAX_LEN)` (**V** `handlers.rs:126`, `:51`). Distinct cell from C10a: a length cutoff and a trim fail on different inputs, and the char-vs-byte mismatch means a multi-byte subject diverges on the length prefix too. | Verified subject of 600 characters, and a second of 600 multi-byte characters. → both evicted. |
| **C11** | **A subject reassigned under a stable `grant_id` leaves the previous holder served** (§E2). | Taking only the incoming subject from an unequal row. Passes C1 and C5. | Populated slots for A and B. Edit one grant row's `subject` A→B, `grant_id` unchanged. Reload. → **A's** slot is evicted (and B's), and the log names A. |
| **C12** | **An eviction between the claim and the transport acquisition closes a live fetch's transport** (§E3.1). | Any implementation that leaves `ensure_entry_started` re-resolving the key unclaimed (**V** `metadata.rs:185` vs `:189`). | Barrier between `begin_internal_activity_for` and `ensure_entry_started`. Evict at the barrier, release. → the fetch completes and its transport was not closed under it. Unreachable today only because the reaper also gates on `last_used` (**V** `pool.rs:352-353`); the unconditional remove makes it reachable, so this cell is created by this design and must land with it. |

**Not a test, and not counted as one.** That eviction reaches the caches at all is structural
— they are fields on the removed `PooledEntry` (**V** `pool.rs:90-103`) — not a behaviour with
a reachable red state. Asserting it would pass by construction.

**A** Harness: `src/backend/` already drives per-user slots directly with a fake transport
(**V** `resend_isolation_tests.rs:134,145`, `catalogue_per_caller_tests.rs:198,530` construct
`PoolKey::PerUser` and call `pooled_entry` / `set_pooled_transport_for_test`), so C1–C6 need
no live MCP backend. C7 and C8 are plain unit tests. Proposed module:
`src/backend/slot_eviction_tests.rs`.

---

## 4. Scope: minimum viable versus gold-plating

**This is a new removal primitive on the request path of a release candidate**, so the MVP is
sized to be cut rather than to be complete.

### MVP — six pieces

| Piece | Size | Why it is not cuttable |
|---|---|---|
| 1. `pub(crate) fn identity_binding_prefix(&GrantSubject) -> Option<String>`, beside `cache_binding` (`identity_propagation/mod.rs:316`). | One function. Reuses `stable_actor_id` (**V** `key_server/oidc.rs:132`) rather than restating it. | It is the single place the two formulas meet. Duplicating them into `config_reload` is the failure `invoke.rs:3409-3412` warns about. |
| 2. `Backend::evict_identity_slots(&self, prefix: &str) -> usize`, **`async`** — step 2 of §E3 calls `transport.close().await`, exactly as the reaper does at `pool.rs:358`. Collect matching `PerUser` keys, `pool.remove` each unconditionally, close the transport where `in_flight == 0`. | Mirrors `evict_idle_per_user_entries`' two-pass shape (**V** `pool.rs:326-381`) minus the idle predicate; the close is the same three lines (`pool.rs:356-359`). | The criterion. |
| 3. The reload path's diff + loop (§E2), called **after** publish-and-bump. | One iterator over two `BTreeMap`s (**V** `IdentityGrant: PartialEq`, `identity_grants.rs:115`), one nested loop over `registry.all()` (**V** `registry.rs:260`). | Without a caller this is piece 2 sitting unreachable — the exact state `CATALOGUE.1` is already in. |
| 4. **Preserve exact verified subject/issuer bytes at grant construction** (§E1.1), plus the operator migration note for grants already stored normalised. | Stop routing a `VerifiedIdentity`'s claims through `trimmed_non_empty` (**V** `handlers.rs:72`); keep it for header-sourced identity. One call site, one docs paragraph. | **Without this the whole mechanism silently no-ops** for any subject with whitespace or over 512 chars. It is outside `Backend` and outside the eviction API, and it is the single highest-value piece in the table. |
| 5. One log line per reload, with **three distinct outcomes**: subjects skipped because `identity_binding_prefix` returned `None` (**named individually**), subjects considered whose eviction count was zero, and subjects evicted. | One `info!`. | The first draft conflated the first two, which defeats the tripwire: "skipped by construction" is expected, "matched nothing" is §E1.1 biting. They must not share a counter. |
| 6. `ensure_entry_started` returns its transport with a claim on the entry it resolved (§E3.1), claim transferred across its retry loop. | One signature change, one `Arc` threaded. **A** Shared function — wants upstream impact analysis first (`lifecycle.rs:176` is another caller). | The unconditional remove creates the race; the design must not ship the race without the fix. |
| C1–C12 (§3), plus the non-creating test probe. | — | — |

### The cut a reviewer can make, stated so they do not have to find it

**Replace pieces 1 and 3 with "evict every `PerUser` slot on any applied grant reload."** It
needs no binding derivation at all, is correct for **every** authority kind including the ones
§E1 reasons away, and — **the argument got stronger during review** — it sidesteps §E1.1
entirely. With no reconstruction there is no subject to normalise, so the whitespace and
over-512 classes cannot arise, and piece 4 (the grant-construction fix and its migration)
becomes optional rather than load-bearing. It passes C1, C3, C5, C6, C9, C10a, C10b, C11, C12,
and trivially C4/C7/C8 (which become moot). It fails exactly one cell: **C2**.

The price is the blast radius. Every per-user caller on every backend loses their transport
and their catalogue because one unrelated grant changed, and re-establishing a transport is
not free — on a stdio backend it is a process spawn. **I** That is a self-inflicted
thundering herd on an operator action, and it discards the isolation property the per-user
pool exists to provide (**V** `pool.rs:30-35`). Given that the ticket is named *identity-keyed*
eviction, the keyed version is the recommendation; but the blunt one is a legitimate first
increment and this design does not hide it.

### Gold-plating — explicitly out

- **Evicting on a schedule, or on grant *expiry*.** Expiry already works live against
  in-memory data (**V** the companion doc §1: `is_active_at`, `identity_grants.rs:217-218`),
  and the idle reaper already collects unused slots (**V** `pool.rs:326`). A third sweep
  would be a third thing to reason about for no reachable defect.
- **Cancelling an in-flight request on revocation.** §E3 rules the other way: a request
  authorized before the revocation finishes. Severing it is a different product decision and
  needs its own ticket.
- **An index from subject to live bindings.** The prefix scan is `O(slots)` over a `DashMap`
  on an operator-triggered event. An index would be a second source of truth for a mapping
  the key already encodes. **ponytail:** linear scan; add an index only if slot counts reach
  a scale where an operator action visibly stalls.
- **Evicting the `Shared` slot.** It backs init, metadata and single-tenant traffic and is
  documented as never evicted (**V** `pool.rs:301-305`). A grant revocation is per-identity;
  touching `Shared` would break IDP.5 byte-for-byte equivalence.
- **Extending this to PATH B (vault).** §E5. Different trigger, different prefix, different
  ticket.

---

## 5. Where I think this design is weak

Recorded so a reviewer does not have to find these.

**1. The prefix reconstructs a private formula from a different module's data.** §E1 argues
it is sound and C7/C8 pin it, but the honest shape of the objection stands: eviction keys on
a string the *request path* builds, rebuilt by the *control path* from different inputs. The
single-helper rule (piece 1) reduces this to one function that can drift only if someone
edits `cache_binding` without editing its neighbour. A stronger design would have the request
path **record** the binding against the subject so eviction looks it up rather than derives
it — that is a new index, rejected above as gold-plating, and it is the first thing to build
if C7 ever goes red for a reason nobody predicted.

**2. Eviction is only as live as its trigger.** This design fires when the companion design's
reload fires, which is an operator action, not a file watch (**V** companion §D1, recorded
there as its own weakness). An operator who revokes and walks away has evicted nothing. Both
documents inherit the same limitation and neither should be read as closing it.

**3. `evicted = 0` is still ambiguous, even with the three-way log.** Piece 5 now separates
"skipped because the authority is not issuer-shaped" from "considered, matched nothing", which
closes the conflation review flagged. What it still cannot separate is **"considered, matched
nothing because that caller had no live slot"** — the common, benign case — from
**"considered, matched nothing because the stored subject diverges from the binding"** — §E1.1
biting after the fix, on a grant file not yet reconciled. Both print `evicted = 0` on a
subject that was considered. **A** Distinguishing them needs the index from weakness 1, or a
one-off audit command that compares stored subjects against live bindings. The log is a
tripwire, not a diagnostic, and after §E1.1 it is a tripwire that will fire benignly.

**4. C2 rests on a fetch counter the fixture supplies.** "B did not refetch" is only as good
as the fake transport's counting. **V** The existing per-caller fixtures already count fetches
(`catalogue_per_caller_tests.rs`), so this reuses rather than invents — but if that counter is
ever loosened, C2 degrades quietly toward the vacuous form §3.1 exists to forbid.

**5. §E2's publish-then-evict ordering is inferred, and nothing verifies it.** Raised in
review as MEDIUM and accepted. The claim *"any refill races forward into the new policy"*
assumes a catalogue fill consults the published grant store **at fetch time**. §E3 covers
fills that claimed the **old** entry — those write into a grave. It does **not** cover a fill
authorized before the publish that completes into a **fresh post-eviction slot**: that slot is
live and reachable, and it would carry pre-reload bytes.

**At implementation, verify where a fill reads grant scope.** If scope is read at fetch time,
the ordering holds as written. If it is captured at authorization, the fix is to fold a
grant-store version into the store condition beside `store_if_current`
(**V** `cached_metadata.rs:97-105`) — the same generation discipline, one input wider. **I**
The exposure is a **stale catalogue**, not privilege escalation: invocation stays
authorization-gated on the live store (`invoke.rs:2663`), so a stale listing cannot be acted
on. That bounds the severity but does not excuse leaving it unverified, which is why it is
here and not in §E2's prose.

**6. Two reviews ran static-only.** Their **V** markers are claims, not executions. The three
findings that changed this design — subject normalisation (§E1.1), the claim/transport split
(§E3.1), and the `Weak`-drop refutation of the drain waiter (§E4) — were re-verified at source
before amendment and are marked **V** on that basis. The rest of their input is folded in as
reasoning, not as evidence.

**7. The criterion still needs both documents.** Stated again because it is the failure mode
that burned two prior attempts: this design supplies eviction and assumes a trigger; the
companion supplies a trigger and explicitly disclaims eviction (**V** its §4: *"`MIK-7334.CATALOGUE.1`
does not close on this document"*). **`MIK-7334.CATALOGUE.1` does not close on this document
either.** It closes when both land and C1–C12 are green.
