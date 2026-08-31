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
exemption. This plan carries that guard (row 4.a). No second key shape is
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
The two key-level cases (1.a, 2.a) are `assert_ne!` between two *keys produced
for two principals*, which is a difference assertion, not a self-comparison —
they are the named exception and they are the only one.

## Coverage table

Columns follow the house format used by `authorize-at-dispatch-test-plan.md`.
Level: **U** unit · **I** integration · **S** system. Status: **evidenced** (a
case can fail and proves the rule) · **guard** (green on `HEAD`; exists to go
red on regression) · **carried-by-review** (declared surviving mutant) ·
**deferred** (four fields below the table).

### MIK-7213.CACHE.1 — `ttlMs` and `cacheScope` on five surfaces

| AC | Case | Level | Type | Can it fail? | Status |
|---|---|---|---|---|---|
| CACHE.1 | **1.a** For each of the five methods in `CACHEABLE_METHODS` (`handlers.rs:1386-1392`) individually — `tools/list`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list` — the result object carries **both** `ttlMs` and `cacheScope`. Asserted as an **exact key-presence pair per method name**, five named assertions, never a count over the array (A2) | I | contract | Yes — deleting any one entry from `CACHEABLE_METHODS`, or renaming either field, turns exactly one assertion red and names which method lost it. It does **not** fail on `HEAD`: all five are present today, so this is a regression guard and is marked as one | guard |
| CACHE.1 | **1.b** A method deliberately outside the list — `initialize` — carries **neither** field. This is the permitted side of the same pinned set (A1): 1.a alone is satisfied by an implementation that staples the fields onto every response | I | contract | Yes — widening the emission predicate to all methods turns 1.b red while leaving 1.a green, which is the only way to catch that mutation | guard |
| CACHE.1 | **1.c** `ttlMs` equals the literal `60000`, asserted as a literal; separately, `LIST_TTL_MS == 60_000` (A7/A8 — the wire value is never asserted against the constant that produces it) | U | contract | Yes — changing `LIST_TTL_MS` alone turns the wire assertion red; changing both turns the constant assertion red. A single self-comparison would survive both | guard |

### MIK-7213.CACHE.2 — authorization-derived list responses are `private`

| AC | Case | Level | Type | Can it fail? | Status |
|---|---|---|---|---|---|
| CACHE.2 | **2.a** `tools/list` emits `cacheScope` equal to the **literal string** `"private"`. Never `CacheScope::current_for_tools_list().as_str()` — that expression matches after every branch in `for_list` is deleted (A8) | I | security | Yes — flipping `current_for_tools_list` to `for_list(false)` turns it red. Green on `HEAD` | guard |
| CACHE.2 | **2.b** `CacheScope::for_list(true) == Private` **and** `for_list(false) == Public`, both sides pinned to literals | U | functional | Yes — collapsing the branch to a constant turns exactly one of the two red. A one-sided assertion survives the collapse | guard |
| CACHE.2 | **2.c** **Pair.** Two callers whose credentials resolve to *different* visible backend sets each call `tools/list`. Hit control: the same caller lists twice and receives the same content. Miss half: caller B's list is asserted to contain **exactly B's backend names** (A4 — identity-pinned, an exact set, not `⊆ allowed` and not a length, which are both true of an empty list, A2/A3) | I | security | Yes — introducing any shared, unkeyed list cache serves A's set to B and the exact-set assertion names which backend leaked. Green on `HEAD` (no shared list cache exists), so it is a guard against the cache CACHE.2 anticipates | guard |

### MIK-7213.CACHE.3 — `public` only where provably invariant

| AC | Case | Level | Type | Can it fail? | Status |
|---|---|---|---|---|---|
| CACHE.3 | **3.a** No response from any of the five methods ever carries `cacheScope: "public"` while the assembly consulted the caller. Asserted over a fixture where the caller **is** consulted, pinning the literal `"private"` on all five | I | security | Yes — any future `for_list(false)` on a caller-dependent surface turns it red, naming the method | guard |
| CACHE.3 | **3.b** *"A decision table … MUST exist and be referenced from the code that emits the field."* Mechanical check only: `src/protocol/cacheable.rs` contains a reference to the decision table, and `current_for_tools_list` is the sole `for_list` call site reachable from `handlers.rs` | U | lint | **Partly.** The lint fails if the reference is deleted or a second unaudited `for_list` call site appears. It cannot fail for a table that *exists and is wrong*. **Declared mutant, expected to SURVIVE:** replace the doc-comment's reasoning with any other prose of the same shape — every test stays green. The rule is carried by human review, and the closing gate is the §P4 dual review reading `cacheable.rs:20-66` against the criterion | carried-by-review |

### MIK-7213.CACHE.4 — one row per response-varying input

Decomposed against the design's eight-row verdict table
(`2026-08-31-cluster-f-response-cache-keying.md` §L256-265). A single CACHE.4
row is the trap the fixture doctrine above exists to refuse.

| AC | Case | Level | Type | Can it fail? | Status |
|---|---|---|---|---|---|
| CACHE.4 · backend | **4.a** **Pair.** Same `{tool, arguments}`, two different `server` values. Hit control: same server twice → backend invoked once. Miss half: the second server's body is asserted to be **that server's own** by a value only it returns (A4) | I | functional | Yes — dropping `server` from `build_key` (`cache.rs:225`) serves server A's body for server B, and the identity assertion names it. Green on `HEAD` | guard |
| CACHE.4 · auth binding | **4.b** Two callers with **different authorization identities** and **no** `cache_binding` — identity propagation off, the shipped default — build a key for the same `{server, tool, arguments}`. `assert_ne!(key(alice), key(bob))`, through a named seam taking both principals as arguments, never an inlined copy of the key expression | U | security | **Yes, on `HEAD`.** `unwrap_or_default()` (`invoke.rs:773-777`) empties the suffix for **both**, every other input is equal by construction, and the keys are byte-identical. Fails on the `assert_ne!` itself — read the assertion, not the exit code (ERROR ≠ FAILURE) | evidenced |
| CACHE.4 · auth binding | **4.c** **Pair, behavioural.** The same two principals invoke through the live cache. Hit control: one principal twice → backend called once. Miss half: backend called **twice**, and each caller's body carries **its own** principal marker (A4). Both principals must POPULATE, never one populate and one read — a fixture filling one entry proves nothing (A3/A5) | I | security | Yes — 4.b proves the keys differ; 4.c proves the differing key is the one the cache actually consults. Red on `HEAD` for the same reason as 4.b | evidenced |
| CACHE.4 · routing profile | **4.d** **Pair.** Two sessions on different `RoutingProfile`s (`routing_profile/mod.rs:82-84`, resolved at `invoke.rs:710`) invoke the same `{server, tool, arguments}` as the **same principal**, so the profile is the only varying input (A9). Miss half asserts each response matches **its own** profile's routing | I | security | **Yes, on `HEAD`.** The profile name appears in no cache key, so session B is served A's body. Fails on the body-identity assertion | evidenced |
| CACHE.4 · protocol revision | **4.e** **Pair.** Same principal, same arguments, two negotiated protocol revisions (`protocol/era.rs`). Miss half asserts each body carries its own revision's shape | I | security | **Yes, on `HEAD`.** No cache-key occurrence of the revision; the second era is served the first era's shaped body | evidenced |
| CACHE.4 · policy epoch | **4.f** Same principal, same arguments. Warm the cache, bump the epoch through a **named** site, invoke again; the post-bump response MUST NOT be the pre-bump body, asserted by a value the new grant set changes. Two sites, **one row each**: `MetaMcp::set_identity_grants` (`meta_mcp/mod.rs:814-816`), the only writer of the grant store, and the `LiveConfig` reload seam (`config_reload/mod.rs:243-268`) | I | security | **Yes, on `HEAD`.** Nothing bumps a generation, so the stale body is served, and each row fails on its own body assertion. Split per site (A9) so a fix wiring only config reload cannot pass the grant row | evidenced |
| CACHE.4 · policy epoch | **4.g** The key is **built once and carried**: a bump landing between the read and the write must not make the insert land under the old epoch and be unreachable. Assert the epoch read at key construction equals the epoch stamped on the stored entry | U | functional | Yes — recomputing the epoch at write time turns it red. It cannot fail before the epoch exists, so it is **blocked-on 4.f** and stated as such rather than run early | evidenced (blocked) |
| CACHE.4 · Code Mode | **4.h** **No keying case, and the reason.** `code_mode_execute` re-enters `invoke_tool` with the same `{server, tool, arguments}` and returns the result unmodified (`meta_mcp/search.rs:466-479`). Same inputs, same path, same response: it is **not response-varying**, so a key component would partition the cache without protecting anything. One assertion is kept as the premise's guard — a Code-Mode invocation and a direct invocation of the same tool produce **equal** bodies | I | functional | Yes — if Code Mode ever post-processes the result, the equality assertion goes red, and that is exactly the moment a key component becomes required | evidenced (premise guard) |
| CACHE.4 · preview query | **4.i** **No keying case at the cache, and the reason.** spec-preview is a list surface (`meta_mcp/spec_preview.rs:3-6`); `ResponseCache` sits only on the `tools/call` invoke path, so a preview query is structurally unreachable from this key. Kept as a **structural guard**: assert no `ResponseCache` read or write is reachable from the spec-preview handler | U | lint | Yes — wiring the cache onto a list surface turns the guard red, which is the fail-closed rule the design substituted for the key component | guard |
| CACHE.4 · cursor | **4.j** Same disposition, same guard, separate row: every `next_cursor` site is a list or read surface (`spec_preview.rs:57`, `protocol.rs:176`, `resources.rs:268,348`). Assert no cursor-bearing surface reaches `ResponseCache` | U | lint | Yes — same trigger as 4.i, asserted separately so one wiring change cannot be masked by the other passing (A9) | guard |
| CACHE.4 · projection | **4.k** **Pair.** Two callers differing **only** in projection mode (`projection/mode.rs:115-122`, response shape A/B). Miss half asserts each body carries its own shape | I | functional | Yes — dropping `projection_key_suffix` serves shape A to a shape-B caller. Green on `HEAD` — this component is correctly present today and the row exists to keep it | guard |

### MIK-7213.CACHE.4 — the mirrored cache, the ordering claim, and the stored body

| AC | Case | Level | Type | Can it fail? | Status |
|---|---|---|---|---|---|
| CACHE.4 · executor | **5.a** Capability executor, mirrored. Two **different principals** execute the same capability with the same params: `assert_ne!(key(alice), key(bob))` against `build_cache_key` (`capability/executor/params.rs:245-258`) | U | security | **Yes, on `HEAD`.** The tuple is `{capability.name}:{params_hash}` with no principal term at all, so the keys are byte-identical for *any* two principals — this one does not even need the static-credential premise | evidenced |
| CACHE.4 · executor | **5.b** **Pair, behavioural.** The same two principals execute through the live executor cache. Hit control: one principal twice → upstream called once. Miss half: upstream called twice, each body identity-pinned to its own principal (A4). Both principals populate | I | security | Yes — 5.a proves the keys differ, 5.b proves the executor consults them. Red on `HEAD` | evidenced |
| CACHE.4 · ordering | **5.c** A caller denied by `GrantAgent::Exact` invokes a capability for which a **warm** entry exists under the same `{server, tool, args_hash}`, written by a caller the grant allows. Assert the denial is returned and **no body** is returned | I | security | **Yes, on `HEAD`.** The cache read is at `invoke.rs:838`; `enforce_identity_grants` is reached at `:1842` inside `dispatch_to_backend`, so a hit short-circuits before the grant is evaluated and the denied caller receives the body. Fails on the returned body, never on a setup error | evidenced |
| CACHE.4 · ordering | **5.d** **The half-move control, and the point of 5.c.** The same denied caller is run **twice** — once with the idempotency store warm, once cold — and both must return the denial. Constructed to go red against a chokepoint placed above the response-cache read *alone*: with `enforce_identity_grants` inserted at `:838` and the idempotency short-circuit at `:796-810` untouched, the warm run still returns `GuardedValue::from_cache` before line 840 | I | security | Yes — this is the assertion that separates a correct chokepoint from one placed hundreds of lines too low. "Above the cache read" is precisely the phrasing an implementer satisfies at `:837`, and 5.c alone cannot tell the two apart. **Blocked-on** the sibling change that owns `invoke.rs`; run early it fails on a missing seam, not on the ordering, so it is held rather than run red for an unread reason | evidenced (blocked) |
| CACHE.4 · stored body | **5.e** Populate the cache as caller A, then read the **stored** value directly — not the returned one — and assert its `_context_integrity` carries neither a `subject` nor A's `trace_id`. Then invoke as caller B on a key that hits, and assert the **returned** body carries B's subject and B's trace id | I | security | **Yes, on `HEAD`,** on the **first** assertion: `apply_context_integrity` runs at `invoke.rs:1246` and the cache write is downstream at `:1286-1291`, so the stored value cannot be unstamped. A case checking only the second half passes on `HEAD` whenever A and B happen to share an api-key name — that is the A5 trap in this row and it is why the first assertion is the one that must go red | evidenced |
| CACHE.4 · fail-closed | **5.f** *"A response varying on an unkeyed input MUST NOT be cached."* With no resolvable principal, an invocation is **not cached**: invoke twice with an unresolvable principal and assert the backend is called **both** times, and that no entry appears in the store | I | security | **Yes, on `HEAD`.** Today `unwrap_or_default()` supplies an empty suffix and the response is cached anyway, so the second call is served from cache. Asserted on the store as well as the call count, because a call count alone is also satisfied by a cache that is simply cold (A3) | evidenced |
| CACHE.4 · direct route | **5.g** **Regression guard on the second door.** `POST /mcp/{name}` is driven twice with identical arguments under **two different principals**; assert the backend is invoked **twice** and each response is identity-pinned to its own caller (A4) | I | security | Yes — it is green today because the direct route keeps no per-user cache (`backend_handlers.rs:594`), and it goes red the moment a shared cache appears on that door. Stated as a guard, not as evidence of a defect: the design's scope receipt above explains why this row exists at all | guard |

### Deferred — one row, with its four fields

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
| **A8** | 2.a was drafted as `scope == CacheScope::current_for_tools_list().as_str()`, which matches after every branch in `for_list` is deleted | pins the literal `"private"`. The `assert_ne!` rows (4.b, 5.a) are the named exception: a difference between two principals' keys is not a self-comparison |
| **A9** | 4.f bundled both epoch bump sites into one case, so a fix wiring only config reload would have passed; 4.i and 4.j were one row | split into one row per site and one row per surface |
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

Eleven rows are guards, green on `HEAD` by design. They are not padding and
they are not evidence — each names the mutation that turns it red.

## What passing means

Every **evidenced** row must fail against `HEAD` before the implementation
lands, and must fail **on the assertion it names** — not on a missing import, a
panic, or a setup error. Run the red suite and read the failure *reason* of
every case, never the count: `ERROR` and `FAILURE` are different facts. The two
blocked rows are exempt from that run and are held until the seam they need
exists.

Order of work: coverage table → levels and types → cases → A1-A9 sweep → run the
red suite and read every reason → review.
