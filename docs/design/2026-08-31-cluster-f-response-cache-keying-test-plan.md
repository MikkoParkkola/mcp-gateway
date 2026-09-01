# Cluster F — response-cache keying: TEST PLAN

Sibling of [the design](2026-08-31-cluster-f-response-cache-keying.md). Written
under `rules-source/workflows/development-process.md` §P2 and the
`test-plan-honesty` skill (A1-A9). Criteria text:
`docs/requirements/RELEASE-4.0.0-requirements.md:123-126`.

The design is 896 lines and both vendors have reviewed it. This is a separate,
bounded artifact so the plan can be reviewed as a plan without re-opening it.

## Coverage tier

Cross-principal data handling on the invoke path → **Critical**. DoD §4 asks
≥95% line and ≥85% mutation on new code. That is the bar this plan promises,
with one declared exception (row 3.b, a mutant expected to survive).

## Scope (§P0)

**FOR**: the response cache on the meta-MCP `tools/call` path
(`ResponseCache`, `invoke.rs`), the capability executor's cache
(`capability/executor/params.rs`), and the `cacheScope`/`ttlMs` fields on the
five `CACHEABLE_METHODS` list surfaces.

**OUT**: the idempotency store's own semantics (it appears here only as the
half-move control in case 3.d); `server/discover`'s scope, deliberately excluded
from `CACHEABLE_METHODS` and out of the criteria; TTL and eviction policy;
performance of the cache.

**Scope receipt — the direct route moves from OUT to IN-as-guarded.** The design
settles `POST /mcp/{name}` as OUT on the ground that it "neither reaches
`invoke_tool_traced` nor keeps a cache, so there is nothing on it to key". The
team lead reads CACHE.4 as binding on *any shared cache the gateway keeps*,
which makes "no cache here today" a claim that needs a **guard**, not an
exemption. This plan carries that guard (row 5.g). No second key shape is
designed and none is implied: what exists is a case that goes red if a shared
cache ever appears on that door.

## Fixture doctrine — read before any row below

A cache that never populates passes every isolation assertion ever written
(A3, A5). Therefore **every cross-principal row is a pair, not a case**:

| half | what it does | why it exists |
|---|---|---|
| **hit control** | same principal, identical inputs, twice → backend called **once** | proves the cache is live and the key is reachable. Without it the miss half is vacuous |
| **miss under variation** | vary **exactly one** input (A9) → backend called **twice**, and the second caller's body is asserted to be **its own** by identity (A4), never merely "not the other's" (A3) |

Where a row says "pair", both halves are required and the row is not evidenced
until both are green.

**A8 — never assert a key against the expression that builds it.** No case may
compare a composed key to `build_key(...)`-shaped code. Pin literals separately;
let the behavioural hit/miss pair carry the "this input is in the key" claim.
The exception is a *class*, not a list: an `assert_ne!` between two keys built
from two different component tuples is a **difference** assertion, not a
self-comparison, because no side restates the composition under test. Every
key-level row here (1.a, 2.a, 4.d, 4.e, 4.l.1, 4.l.2) is of that class, and each
carries a determinism control so a per-call salt cannot satisfy the difference
vacuously. Stated as a class because an enumerated list is falsified by the next
row added — as this one was.

## Coverage table

Columns follow the house format used by `authorize-at-dispatch-test-plan.md`.
Level: **U** unit · **I** integration · **S** system. Status: **evidenced** (a
case can fail and proves the rule) · **guard** (green on `HEAD`; exists to go
red on regression) · **designed (blocked)** (specified, never run, waiting on a
named seam that does not exist on `HEAD`) · **carried-by-review** (declared
surviving mutant) · **deferred** (four fields below the table).

### MIK-7213.CACHE.1 — `ttlMs` and `cacheScope` on five surfaces

| AC | Case | Level | Type | Can it fail? | Status |
|---|---|---|---|---|---|
| CACHE.1 | **1.a** For each of the five methods in `CACHEABLE_METHODS` (`handlers.rs:1386-1392`) individually — `tools/list`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list` — the result object carries **both** `ttlMs` and `cacheScope`. Asserted as an **exact key-presence pair per method name**, five named assertions, never a count over the array (A2) | I | contract | Yes — deleting any one entry from `CACHEABLE_METHODS`, or renaming either field, turns exactly one assertion red and names which method lost it. It does **not** fail on `HEAD`: all five are present today, so this is a regression guard and is marked as one | guard |
| CACHE.1 | **1.b** A method deliberately outside the list — `initialize` — carries **neither** field. This is the permitted side of the same pinned set (A1): 1.a alone is satisfied by an implementation that staples the fields onto every response | I | contract | Yes — widening the emission predicate to all methods turns 1.b red while leaving 1.a green, which is the only way to catch that mutation | guard |
| CACHE.1 | **1.c** `ttlMs` equals the literal `60000`, asserted as a literal; separately, `LIST_TTL_MS == 60_000` (A7/A8 — the wire value is never asserted against the constant that produces it) | U | contract | Yes — changing `LIST_TTL_MS` alone turns the wire assertion red; changing both turns the constant assertion red. A single self-comparison would survive both | guard |

### MIK-7213.CACHE.2 — authorization-derived list responses are `private`

| AC | Case | Level | Type | Can it fail? | Status |
|---|---|---|---|---|---|
| CACHE.2 | **2.a** `tools/list` emits `cacheScope` equal to the **literal string** `"private"`. Never `scope_for_method("tools/list").as_str()` — that expression matches after every row of the table is deleted (A8) | I | security | Yes — flipping the `tools/list` row to `for_list(false)` turns it red. Green on `HEAD` | guard |
| CACHE.2 | **2.b** `CacheScope::for_list(true) == Private` **and** `for_list(false) == Public`, both sides pinned to literals | U | functional | Yes — collapsing the branch to a constant turns exactly one of the two red. A one-sided assertion survives the collapse | guard |
| CACHE.2 | **2.c** **Pair.** Two callers whose credentials resolve to *different* visible backend sets each call `tools/list`. Hit control: the same caller lists twice and receives the same content. Miss half: caller B's list is asserted to contain **exactly B's backend names** (A4 — identity-pinned, an exact set, not `⊆ allowed` and not a length, which are both true of an empty list, A2/A3) | I | security | Yes — introducing any shared, unkeyed list cache serves A's set to B and the exact-set assertion names which backend leaked. Green on `HEAD` (no shared list cache exists), so it is a guard against the cache CACHE.2 anticipates | guard |

### MIK-7213.CACHE.3 — `public` only where provably invariant

| AC | Case | Level | Type | Can it fail? | Status |
|---|---|---|---|---|---|
| CACHE.3 | **3.a** No response from any of the five methods ever carries `cacheScope: "public"` while the assembly consulted the caller. Asserted over a fixture where the caller **is** consulted, pinning the literal `"private"` on all five | I | security | Yes — any future `for_list(false)` on a caller-dependent surface turns it red, naming the method | guard |
| CACHE.3 | **3.b** *"A decision table … MUST exist and be referenced from the code that emits the field."* Mechanical check only: `src/protocol/cacheable.rs` contains a reference to the decision table, and `scope_for_method` is the sole path from `handlers.rs` to the table | U | lint | **Partly.** The lint fails if the reference is deleted or a second unaudited `for_list` call site appears. It cannot fail for a table that *exists and is wrong*. **Declared mutant, expected to SURVIVE:** replace the doc-comment's reasoning with any other prose of the same shape — every test stays green. The rule is carried by human review, and the closing gate is the §P4 dual review reading `cacheable.rs:20-66` against the criterion | carried-by-review |

### MIK-7213.CACHE.4 — one row per response-varying input

Decomposed against the design's eight-row verdict table
(`2026-08-31-cluster-f-response-cache-keying.md` §L256-265). A single CACHE.4
row is the trap the fixture doctrine above exists to refuse. The mapping is not
1:1 and does not claim to be: each of the eight inputs has at least one row, the
policy epoch has three (one per bump site), and two rows correspond to no input
at all — **4.k** asserts a *bypass* rather than a key component, and **4.l.1 /
4.l.2** test the framing that makes any component separable in the first place.

| AC | Case | Level | Type | Can it fail? | Status |
|---|---|---|---|---|---|
| CACHE.4 · backend | **4.a** **Pair.** Same `{tool, arguments}`, two different `server` values. Hit control: same server twice → backend invoked once. Miss half: the second server's body is asserted to be **that server's own** by a value only it returns (A4) | I | functional | Yes — dropping `server` from `build_key` (`cache.rs:223-225`) serves server A's body for server B, and the identity assertion names it. Green on `HEAD` | guard |
| CACHE.4 · auth binding | **4.b** Two callers with **different authorization identities** and **no** `cache_binding` — identity propagation off, the shipped default — build a key for the same `{server, tool, arguments}`. `assert_ne!(key(alice), key(bob))`, through a named seam taking both principals as arguments, never an inlined copy of the key expression | U | security | **Yes, on `HEAD`.** `unwrap_or_default()` (`invoke.rs:773-777`) empties the suffix for **both**, every other input is equal by construction, and the keys are byte-identical. Fails on the `assert_ne!` itself — read the assertion, not the exit code (ERROR ≠ FAILURE) | **done** 2026-09-01: `tests/mik_7213_acs.rs:371`, against the seam `ResponseCache::response_key` (`cache.rs:229`). Falsified by dropping the principal from the key: red at `:380`, green on restore |
| CACHE.4 · auth binding | **4.c** **Pair, behavioural.** The same two principals invoke through the live cache. Hit control: one principal twice → backend called once. Miss half: backend called **twice**, and each caller's body carries **its own** principal marker (A4). Both principals must POPULATE, never one populate and one read — a fixture filling one entry proves nothing (A3/A5) | I | security | Yes — 4.b proves the keys differ; 4.c proves the differing key is the one the cache actually consults. Red on `HEAD` for the same reason as 4.b | evidenced |
| CACHE.4 · routing profile | **4.d** **Key-level, on a seam that does not yet exist.** `assert_ne!(finished_key(profile_a), finished_key(profile_b))` for the same principal and the same `{server, tool, arguments}`, plus a determinism control asserting the same inputs yield the same key twice (so a per-call salt cannot pass the difference vacuously). **Blocked, and the block is a source fact:** `ResponseCache::build_key` (`cache.rs:223`) takes only `(server, tool, arguments)`, and the finished key is assembled by an inline `format!` duplicated at `invoke.rs:843` (read) and `invoke.rs:1296` (write). There is no function this case can call, so writing it today yields a compile `ERROR`, not the `FAILURE` this plan requires. **Seam needed:** one shared `finished_key(...)` taking the components, replacing both inline sites — which the implementation must build anyway to mix the profile in. **A behavioural pair is also impossible here:** `profile.check` denies at `invoke.rs:711`, before any cache interaction, so a wrongly-shared entry is never observable through a response body. Verified at source 2026-08-31 | U | security | Not yet — the seam exists as of 2026-09-01 (`ResponseCache::response_key`, `cache.rs:229`) but takes no profile argument, so there is still nothing to vary. Red on the profile-less key once it does | designed (blocked) |
| CACHE.4 · protocol revision | **4.e** **Key-level, on the same missing seam as 4.d.** `assert_ne!(finished_key(rev_a), finished_key(rev_b))` for the same principal and arguments, differing only in the negotiated `declared_version`, plus the same determinism control. Blocked for the identical reason: `build_key` has no revision parameter and the finished key has no callable form. **A behavioural pair is also impossible here:** revision shaping happens in `build_modern_response` (`router/handlers.rs:1400`, called at `:1371`), downstream of the meta-MCP cache, so both eras cache and read the same inner body. Verified at source 2026-08-31 | U | security | Not yet — same seam as 4.d: it now exists and takes no revision argument. Red on the revision-less key once it does | designed (blocked) |
| CACHE.4 · policy epoch | **4.f.1** **Grant store.** Same principal, same arguments. Warm the cache, bump the epoch through `MetaMcp::set_identity_grants` (`meta_mcp/mod.rs:814-816`) — the only writer of the grant store — invoke again; the post-bump response MUST NOT be the pre-bump body, asserted by a value the new grant set changes (identity-pinned, A4) | I | security | Yes — an epoch absent from the key serves the pre-bump body | designed (blocked) |
| CACHE.4 · policy epoch | **4.f.2** **`LiveConfig` reload.** The same pair, driven through the `LiveConfig` reload seam instead of the grant store. A distinct site with a distinct trigger: an epoch bumped on grants alone leaves this one unbumped | I | security | Yes — a reload that does not bump the epoch serves the pre-reload body | designed (blocked) |
| CACHE.4 · policy epoch | **4.f.3** **`CapabilityWatcher` reload.** The same pair, driven through a capability-registry reload. Named separately because a capability set change alters what a caller may reach without touching either grants or `LiveConfig` | I | security | Yes — a capability reload that does not bump the epoch serves a body from the superseded registry | designed (blocked) |
| CACHE.4 · policy epoch | **4.g** **The revocation race, not an equality check.** Drive one invocation and bump the epoch through `MetaMcp::set_identity_grants` **between authorization and the cache read**. Assert (i) the entry that lands carries the *pre-bump* epoch it was authorized under, and (ii) a post-bump reader cannot retrieve it. An assertion that only compares the epoch read at key construction against the epoch stamped at write is satisfied by sampling the epoch *after* authorization — the exact defect — and is therefore not the case | U | security | Yes — sampling the epoch after authorization, or recomputing it at write time, turns it red. Cannot run before the epoch exists | designed (blocked) |
| CACHE.4 · Code Mode | **4.h** **No keying case, and the reason.** `code_mode_execute` re-enters `invoke_tool` with the same `{server, tool, arguments}` and returns the result unmodified (`meta_mcp/search.rs:466-479`). Same inputs, same path, same response: it is **not response-varying**, so a key component would partition the cache without protecting anything. The premise guard pins **both** invocations to the same known **non-empty** backend-produced body (identity-pinned per A4) and asserts the backend path was exercised, so two equal empty or error bodies cannot satisfy it | I | functional | Yes — a Code Mode wrapper that reshapes the payload turns it red. Green on `HEAD`: it keeps the premise, it does not prove a rule | guard |
| CACHE.4 · preview query | **4.i** **No keying case at the cache, and the reason.** spec-preview is a list surface (`meta_mcp/spec_preview.rs:3-6`); `ResponseCache` sits only on the `tools/call` invoke path, so a preview query is structurally unreachable from this key. Kept as a **structural guard**: assert no `ResponseCache` read or write is reachable from the spec-preview handler | U | lint | Yes — wiring the cache onto a list surface turns the guard red, which is the fail-closed rule the design substituted for the key component | guard |
| CACHE.4 · cursor | **4.j** Same disposition, same guard, separate row: every `next_cursor` site is a list or read surface (`spec_preview.rs:57`, `protocol.rs:176`, `resources.rs:268,348`). Assert no cursor-bearing surface reaches `ResponseCache` | U | lint | Yes — same trigger as 4.i, asserted separately so one wiring change cannot be masked by the other passing (A9) | guard |
| CACHE.4 · projection | **4.k** **The bypass, not a key component.** A `_full` request is **never cached** — `invoke.rs:717-723` refuses both the response cache and the idempotency store for it, precisely so a projected and an unprojected shape can never share an entry. The honest guard is therefore that bypass, not a suffix: drive `_full` twice with identical arguments and assert the backend is invoked **twice** and that **no entry appears in either store**. The projection-mode suffix is empty for both modes today because the two modes never contend for a key; a difference assertion on it would be vacuous | I | security | Yes — making `_full` cacheable turns it red on the store assertion. Green on `HEAD`: it keeps the bypass, it does not prove a keying rule | guard |

### MIK-7213.CACHE.4 — the mirrored cache, the ordering claim, and the stored body

| AC | Case | Level | Type | Can it fail? | Status |
|---|---|---|---|---|---|
| CACHE.4 · executor | **5.a** Capability executor, mirrored. Two **different principals** execute the same capability with the same params: `assert_ne!(key(alice), key(bob))` against `build_cache_key` (`capability/executor/params.rs:245-258`) | U | security | **Yes, on `HEAD`.** The tuple is `{capability.name}:{params_hash}` with no principal term at all, so the keys are byte-identical for *any* two principals — this one does not even need the static-credential premise | evidenced |
| CACHE.4 · executor | **5.b** **Pair, behavioural.** The same two principals execute through the live executor cache. Hit control: one principal twice → upstream called once. Miss half: upstream called twice, each body identity-pinned to its own principal (A4). Both principals populate | I | security | Yes — 5.a proves the keys differ, 5.b proves the executor consults them. Red on `HEAD` | evidenced |
| CACHE.4 · ordering | **5.c** A caller denied by `GrantAgent::Exact` invokes a capability for which a **warm** entry exists, written by a caller the grant allows. **Every finished-key component is held constant** — principal binding, routing profile, protocol revision, projection shape, backend, cursor, epoch — and the **only** variation is the `GrantAgent::Exact` input that changes the authorization result, so the two callers provably contend for the same key rather than merely for the same `{server, tool, args_hash}`. Assert the denial is returned and **no body** is returned. Hit control: the allowed caller re-invokes and hits (backend invoked once) | I | security | **Yes, on `HEAD`.** The cache read is at `invoke.rs:838`; `enforce_identity_grants` is reached later, so the denied caller is served the warm body | evidenced |
| CACHE.4 · ordering | **5.d** **The half-move control, and the point of 5.c.** The same denied caller is run **twice** — once with the idempotency store warm, once cold — and both must return the denial. **Reachability control first:** the seeded entry is retrieved through the *same* idempotency key by the allowed caller, proving the store is populated and reachable; without it a cold, disabled, or miskeyed store makes both halves pass vacuously. Constructed to go red against a chokepoint placed above the response-cache read *alone* | I | security | Yes — a chokepoint that guards the response cache but not the idempotency short-circuit leaves the warm half serving a body. Cannot run before the chokepoint seam lands | designed (blocked) |
| CACHE.4 · stored body | **5.e** Populate the cache as caller A, then read the **stored** value directly — not the returned one — and assert its `_context_integrity` carries neither a `subject` nor A's `trace_id`. Then invoke as caller B on a key that hits, and assert the **returned** body carries B's subject and B's trace id | I | security | **Yes, on `HEAD`,** on the **first** assertion: `apply_context_integrity` runs at `invoke.rs:1246` and the cache write is downstream at `:1286-1291`, so the stored value cannot be unstamped. A case checking only the second half passes on `HEAD` whenever A and B happen to share an api-key name — that is the A5 trap in this row and it is why the first assertion is the one that must go red | evidenced |
| CACHE.4 · fail-closed | **5.f** *"A response varying on an unkeyed input MUST NOT be cached."* Fixture pins **no principal at all** — not an anonymous principal, not an empty binding, but an unresolvable one, distinguishing this row from 4.b (which varies *between* two resolvable principals). Invoke twice and assert the backend is called **both** times, and that **no entry appears in the store** | I | security | **Yes, on `HEAD`.** Today `unwrap_or_default()` supplies an empty suffix and the response is cached under it, so the second invocation hits | evidenced |
| CACHE.4 · direct route | **5.g** **Regression guard on the second door.** `POST /mcp/{name}` is driven twice with identical arguments under **two different principals**; assert the backend is invoked **twice** and each response is identity-pinned to its own caller (A4). **Inverted control:** assert directly that the direct route wrote **no entry** to any shared store — without it the row stays green under a *correctly keyed* cache and so cannot distinguish "no cache" from "a cache that happens to be keyed", which is the property CACHE.4 asks about for this door | I | security | Yes — adding an unkeyed cache to the direct route turns it red on the store assertion. Green on `HEAD` (`backend_handlers.rs:594`) | guard |
| CACHE.4 · fail-closed | **5.h** **`TrustLab` local-sandbox context.** The design gives `allow_loopback_egress` **no key segment** and instead requires that a context carrying it **must not cache — neither read nor write** (`2026-08-31-cluster-f-response-cache-keying.md:243-247`, `execution_context.rs:35,41-48`). Drive the same `{server, tool, arguments}` twice under such a context: assert the backend is invoked **twice** and **no entry appears in the store**; then, as the inverted control, seed an entry from a production context and assert the sandbox context does **not** read it | I | security | Yes — a sandbox context that caches, or reads a production entry, turns it red on the store assertion. Cannot run before the split lands | designed (blocked) |
| CACHE.4 · key framing | **4.l.1** **Delimiter injectivity, writable today.** Property test over `ResponseCache::build_key` as it stands: for distinct `(server, tool)` pairs — including members containing the `:` delimiter, and Unicode members that normalize alike — the keys are distinct. Concrete red case verified at source: `build_key("a:b", "c", &args)` and `build_key("a", "b:c", &args)` both render `a:b:c:<hash>` (`cache.rs:225`, `format!("{server}:{tool}:{args_hash}")`) | U | security | **Yes, on `HEAD`.** The two calls above return equal keys and the property fails | evidenced |
| CACHE.4 · key framing | **4.l.2** **The schema-version segment.** One assertion pinning a version segment in the finished key, so a key-shape change without a version bump cannot silently reuse entries written under the old shape. Blocked on the same `finished_key(...)` seam as 4.d and 4.e — there is nothing to assert a segment of | U | security | Not yet — same seam as 4.d, which now exists and carries no version segment. Note the shape has already changed once unversioned: adding the principal (2026-09-01) invalidates every entry written under the old shape, which this cache survives only because it is in-memory | designed (blocked) |

### Deferred — one row, with its four fields

**This section supersedes the sibling design's "Deferred: none. Nothing in this design waits on an unanswered question." (`2026-08-31-cluster-f-response-cache-keying.md:662`)** — that line was true when the design froze and is not true of the plan built on it. The plan governs; the design line is corrected in the same change.

The design leaves the stdio `proto` segment as a disjunction: it is "either
threaded from the negotiated value or the transport does not cache"
(`…cache-keying.md:48-53`). **A plan cannot test a disjunction** — an
unresolved OR silently becomes an untested branch, so 4.e above is scoped to
HTTP, where `declared_version` (`handlers.rs:572`) exists, and the stdio branch
is deferred rather than assumed.

| field | value |
|---|---|
| **owner** | the Cluster F implementer, under MIK-7213 |
| **what would resolve it** | an operator answer to a question only the operator can settle: are CACHE.1-4 read at full transport scope (HTTP + stdio) or HTTP-only? The design flags this as the team lead's reading of the release plan, not an operator confirmation (`…cache-keying.md:57-60`). If stdio is in scope, the second question is a checkable one: does the negotiated revision at `meta_mcp/mod.rs:1053` reach the key site, or does the stdio transport refuse to cache? |
| **when** | before the first line of the key constructor is written — the answer decides whether the constructor takes a `proto` that stdio can supply |
| **what if it resolves badly** | if stdio cannot supply a revision, the fail-closed exit is taken: the stdio transport does not cache. That exit needs its own case — invoke twice over stdio, assert the backend is called twice — which is written only once the branch is chosen. Nothing depending on this is implemented meanwhile |

**Blocked rows.** 4.g and 5.d cannot go honestly red before the change that owns
`invoke.rs` lands (§P2's ERROR ≠ FAILURE class: run early they fail on a missing
seam, and a red suite is where that hides). They are held, and the reason each
would fail early is stated in its row so a runner can tell the two reds apart.

## A1-A9 sweep — run before review, violations recorded

Findings the author generates cost an edit; the same findings from a vendor cost
a round. Every row above was swept. What the sweep changed:

| rule | violation found in the draft | fix |
|---|---|---|
| **A1** | CACHE.1 asserted only that the five methods **carry** the fields — an implementation stapling them onto every response passed | added 1.b, the permitted side: `initialize` carries neither |
| **A2** | 1.a was drafted as "the result carries the cacheable fields", satisfiable by a count over `CACHEABLE_METHODS` | rewritten as five named per-method assertions on an exact key pair |
| **A3** | 2.c asserted caller B's list "contains none of A's backends" — true of an empty list | rewritten to pin B's **exact** backend set. Same fix applied to 5.f, where a call count alone is satisfied by a cold cache: the store is now asserted too |
| **A4** | every "backend called twice" miss half originally stopped at the count | each now names **which** body each caller received, pinned to a value only that principal's path produces |
| **A5** | the cross-principal rows had no hit control, so a cache that never populates would have passed all of them; and 5.e originally asserted only the returned body, which passes on `HEAD` whenever A and B share an api-key name | the fixture doctrine (hit control + miss half, both principals populate) was made a precondition of every pair row; 5.e's **first** assertion — the stored value is unstamped — is now the one that must go red |
| **A7** | `ttlMs` was asserted against `LIST_TTL_MS` | 1.c pins the literal `60000` on the wire and asserts the constant separately |
| **A8** | 2.a was drafted as `scope == CacheScope::current_for_tools_list().as_str()` (a helper since deleted; the surviving shape of the same mistake is `scope_for_method("tools/list").as_str()`), which matches after every row of the table is deleted | pins the literal `"private"`. The `assert_ne!` rows (4.b, 5.a) are the named exception: a difference between two principals' keys is not a self-comparison |
| **A9** | 4.f bundled all three epoch bump sites into one case, so a fix wiring only config reload would have passed; 4.i and 4.j were one row | split into one row per site and one row per surface |
| **A6** | no relative rule in this plan (no freshness or TTL-expiry case is claimed) | nothing to fix — stated so the sweep is complete rather than silently short |

## DoR check — applicable gates only

| gate | verdict |
|---|---|
| **B4** acceptance criteria | **PASS.** Four stable IDs, `MIK-7213.CACHE.1-4`, already in the requirements at `:123-126`; every row above cites one |
| **C6** security pre-analysis | **PASS.** STRIDE class is **Information Disclosure** across authorization contexts, and it is the whole subject: an authorized caller receiving another authorized caller's response body. Mitigation is the principal in the key (4.b, 4.c, 5.a, 5.b) plus authorization above the read (5.c, 5.d). No new crypto |
| **C11/C12** contract tests | **PASS.** 1.a-1.c and 2.a are wire-contract cases on the five `CACHEABLE_METHODS` surfaces |
| **C14** protocol-first | **PASS with a note.** The key shape is a cross-boundary schema and it is versioned — the policy epoch **is** its version, and 4.g pins the build-once-carry rule that makes the version meaningful |
| **C15** trust boundary | **PASS.** `auth-user`, data-locality local, consistency strong: the cache must never cross an authorization context |
| **G6** alternatives, **G10-G12** fail-fast | **PASS by citation.** The design carries the alternatives and the disproof artifact; not restated here |
| **T1c** PQC | **N/A** — hashing a cache key is neither key agreement nor a signature |
| **T6** numerical discipline | **N/A** — no quantization, no parallelism, no collective |
| **G20** profiling-first | **N/A** — a correctness change, not a performance one |
| **G13/G14, T1b** moat | **N/A** — compliance-shaped work against a shipped criterion, not a technology bet |

## Honest declarations

Two things this plan does **not** evidence, stated rather than smoothed over:

1. **CACHE.3's second half is carried by review, not by the suite** (row 3.b).
   A mutant is declared expected to SURVIVE: any prose of the same shape in
   `cacheable.rs` keeps every test green. The closing gate is the §P4 dual
   review reading that file against the criterion.
2. **Therefore this plan claims no total coverage figure.** A table claiming
   100% beside a declared surviving mutant contradicts itself in one document.
   The per-row `Status` column is the coverage statement: **evidenced** rows
   prove a rule, **guard** rows only keep one.

Thirty-one rows: **13 guards** (green on `HEAD` by design), **8 evidenced**, **9 designed (blocked)** and **1 carried by review**. A blocked row is *designed*, never *evidenced* — it has never been run and cannot yet fail honestly, so it is not evidence of anything. The guards are not padding and not evidence either: each names the mutation that turns it red.

## What passing means

Every **evidenced** row must fail against `HEAD` before the implementation
lands, and must fail **on the assertion it names** — not on a missing import, a
panic, or a setup error. Run the red suite and read the failure *reason* of
every case, never the count: `ERROR` and `FAILURE` are different facts. The nine
**designed (blocked)** rows are exempt from that run and are held until the seam
each names exists. Three of them — 4.d, 4.e and 4.l.2 — wait on the same one:
a `finished_key(...)` function replacing the inline composition duplicated at
`invoke.rs:843` and `:1296`. **Updated 2026-09-01:** that seam now exists as
`ResponseCache::response_key` (`cache.rs:229`), and both sites call it
(`invoke.rs:852` read, `:1308` write). The three rows stay blocked, on a
narrower fact than before: the seam takes no routing-profile and no
protocol-revision argument, so their `assert_ne!` still has nothing to vary.

Every failure reason read during the red run is appended to `docs/design/evidence/2026-08-31-cluster-f-red-run.md` — one line per case: case ID, `ERROR` or `FAILURE`, and the assertion text. A reason that was read but not written down is an unrecorded act, not evidence.

## Coverage measurement

This change targets the DoD §4 **Critical** bar (≥95% line, ≥85% mutation) on the new key-construction and cache-gating code. Line coverage: `cargo llvm-cov --lib --fail-under-lines 95 -- cache`. Mutation: `cargo mutants --in-place --file src/cache.rs --file src/gateway/meta_mcp/invoke.rs`. Both numbers are recorded in the same evidence file as the red run, and in the DoD comment on the tracking issue. This does **not** contradict the "no total coverage figure" declaration above: that declaration is about *this plan* claiming completeness against the criteria, which it cannot while row 3.b carries a declared surviving mutant. The tool numbers are a separate, measurable DoD gate on the implementation.

Order of work: coverage table → levels and types → cases → A1-A9 sweep → run the
red suite and read every reason → review.


## §P4 review round 1 — dispositions

Three vendors, identical material, all three **SHIP-WITH-FIXES**. Every finding
below was verified at source before repair; a finding is a lead, not evidence.
Elimination was the default (§P2 test-plan findings); where a patch was taken
the reason is on the row.

| finding | vendor | disposition |
|---|---|---|
| 4.d behavioural pair cannot fail — `profile.check` denies before the cache read | grok | **Eliminated.** Verified: `invoke.rs:711` precedes every cache interaction. Row rebuilt as a key-level `assert_ne!` with a determinism control |
| 4.e behavioural pair cannot fail — era shaping is downstream of the cache | grok | **Eliminated.** Verified: `build_modern_response` (`handlers.rs:1400`, called `:1371`) is below the meta-MCP cache. Row rebuilt key-level |
| 4.f is one row for two (in fact three) epoch-bump sites | grok, gpt | **Split** into 4.f.1 grant store, 4.f.2 `LiveConfig`, 4.f.3 `CapabilityWatcher`, each with its own identity-pinned post-change body |
| 4.g passes if the epoch is sampled *after* authorization — the revocation race is uncovered | gpt | **Repaired** (the mechanism is sound, the assertion was too weak): bump between authorization and read; assert the entry keeps its pre-bump epoch and is unreachable to post-bump readers |
| 4.h is satisfied by two equal empty or error bodies | grok, gpt | **Repaired**: both invocations pinned to the same known non-empty backend body, plus an assertion the backend path was exercised |
| 4.k's varying input is not real — both projection modes share an empty suffix | grok | **Re-named.** Verified: `_full` bypasses the cache entirely (`invoke.rs:717-723`), so the modes never contend for a key. The honest guard is the bypass, and the row now asserts it |
| 5.c pins only the legacy key fields, so the two callers may never contend for the same finished key | gpt | **Repaired**: every finished-key component held constant, only the `GrantAgent::Exact` input varies |
| 5.d never proves its warmed entry is reachable | gpt (and grok's hit-control doctrine) | **Repaired**: reachability control retrieves the seeded entry through the same idempotency key first |
| 5.f fixture does not distinguish itself from 4.b | grok | **Repaired**: fixture pinned to *no principal at all*, not an anonymous or empty one |
| 5.g stays green under a correctly keyed cache, so it cannot answer CACHE.4 for that door | grok | **Repaired** with an inverted control: assert the direct route wrote no entry to any shared store |
| C14 passes by calling the policy epoch a schema version; no case for framing injectivity | gpt | **New rows 4.l.1 / 4.l.2**: property test over delimiter-containing and Unicode tuples, plus a pinned schema-version segment |
| CACHE.4 omits the declared fail-closed `TrustLab` / `allow_loopback_egress` context | gpt | **New row 5.h.** Verified in the design at `…cache-keying.md:243-247` |
| CACHE.4 omits fail-closed cases for *retry continuations* and *input capabilities* | gpt | **Dropped, unverified.** Neither term appears in the design or the criteria; `rg` over both returns nothing. Per the repair protocol a speculative finding is dropped until source-verified, rather than spending a round on it. Recorded here so it is not silently ignored |
| Blocked and premise-guard rows labelled *evidenced*; guard count wrong | gpt, grok, kimi | **Repaired**: blocked rows are now *designed (blocked)*, 4.h is a *guard*, and the totals are recounted mechanically (30 rows: 13 guard, 9 evidenced, 7 designed (blocked), 1 carried by review) |
| The Critical coverage tier is promised with no measurement mechanism | kimi | **Repaired**: a Coverage measurement section names both commands and where the numbers are recorded |
| The design still says "Deferred: none" while the plan defers the stdio question | kimi | **Repaired in both documents**: the plan states it supersedes, and the design's line is corrected |
| `assert_ne!` rows could pass vacuously against a per-call salt | kimi (improvement) | **Adopted**: determinism control added to 4.d and 4.e |
| Red-run failure reasons are read but never archived | kimi (improvement) | **Adopted**: reasons are appended to a named evidence file |
| The commit carries four unrelated source hunks (`messages.rs`, `http/mod.rs`, `http/tests.rs`, `stdio.rs`) whose tests are red without an implementation this change does not contain | kimi, gpt | **Eliminated — and both halves were true.** The hunks were swept into `b55116d1` from a dirty shared checkout; my first reading of them as "another session's uncommitted work, not mine to touch" was wrong, and `git show --stat b55116d1` settled it. The red claim is also correct: `JsonRpcResponse` is a plain `#[derive(Deserialize)]` (`messages.rs:44`) with no `deny_unknown_fields`, so a frame carrying `method` parses cleanly and `assert!(outcome.is_err())` fails — a CI-breaking commit. All four files are reverted to `b55116d1^`; the sampling-frame work keeps them in history and can land in the change that owns it |

**Round 1, mechanically tallied over the nineteen rows above: 9 repaired, 3
eliminated, 1 re-named, 1 split into three, 2 answered by new rows, 2
improvements adopted, 1 dropped unverified.** Re-check per the repair protocol
returns to the vendor that raised each finding.

### Corrections found on the whole-document re-read

The repair protocol requires re-reading the entire document after any response,
not the edited paragraph. That pass caught four defects the row edits had
introduced — three of them the same class the vendors had just flagged.

| Correction | Disposition |
|---|---|
| 4.d and 4.e were marked *evidenced* with "**Yes, on `HEAD`**", but `ResponseCache::build_key` (`cache.rs:223`) takes only `(server, tool, arguments)` and the finished key is an inline `format!` duplicated at `invoke.rs:843` and `:1296`. The named assertion would not compile — an `ERROR`, which this plan's own "What passing means" section forbids as evidence | **Repaired**: both are *designed (blocked)* on one named seam, a shared `finished_key(...)`. This was the vendors' own finding — status claiming evidence for something unrunnable — reappearing inside its repair |
| 4.l was blocked whole, but half of it is writable today: `build_key("a:b", "c", &args)` and `build_key("a", "b:c", &args)` both render `a:b:c:<hash>`, a genuine collision on `HEAD` | **Split**: 4.l.1 *evidenced* (red today), 4.l.2 *designed (blocked)* on the same seam |
| "The two blocked rows are exempt from that run" — blocked rows had gone from 2 to 9 while the sentences above and below it were edited and this one was not | **Repaired**: the count is stated, and the three rows sharing one seam are named |
| Rule **A8** named 1.a and 2.a as the only permitted key-level cases; the repairs added four more, falsifying the rule inside the document that states it | **Eliminated, not patched**: A8 now states the permitted *class* (a difference assertion between two component tuples, with a determinism control). An enumerated exception list is falsified by the next row added |

The status legend gained a fourth term, **designed (blocked)**, which the row
edits had been using without defining. Totals recounted mechanically:
**31 rows — 13 guards, 8 evidenced, 9 designed (blocked), 1 carried by review.**
