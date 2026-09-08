# TASK.1 — tasks extension: §P2 test plan

**Status:** §P2 test plan, awaiting dual-vendor review of the whole plan and the
full-lifecycle amendment in §10. Existing tests are present but have not been
reconciled to this amendment; their existence does not pass plan review or runtime
acceptance. Historical red-on-HEAD cells below refer to their named old revision.

**Design:** `docs/design/2026-08-31-task-1-tasks-extension.md` (§13 is the current
full-lifecycle amendment, review pending; prior receipts do not review the delta).
That note is the survivor; the 2026-09-05 duplicate was deleted in `cb00805a` and must not be
resurrected.

**Dependency:** commit `8ab52da8` gates the *code* this plan describes, not the plan. The plan is
reviewable and mergeable ahead of it; no row here waits on it to be written.

**Ledger position:** `MIK-7272.TASK.1` is one row. `.12` and `.13` are design-note criteria under
that parent row, not ledger rows of their own — settled by the team lead on 2026-09-06, not
reopened here.

## 0. Scope

**FOR:** one test case per acceptance-criterion clause of `MIK-7272.TASK.1` and the
approved `MIK-7311.LIFECYCLE.1`–`.5` expansion, each with its V-model
level, its type, and an honest statement of whether it can fail against HEAD — **plus** the
design-decision rows `.14`–`.17`, which descend from no criterion clause and are named here so a
reader does not have to decide whether they are extras that escaped the one-case-per-clause rule
(grok, 2026-09-06). They are in scope on purpose: each pins a choice this design made that the
pinned specification leaves open or does not speak to at all, and §4's counting note says which is
which.

**OUT:**
- test code (that is §P2's second half, not this document)
- the criterion *text* — the design owns it. Where this plan disagrees with the design's wording,
  the design wins and this plan is wrong.
- SUB.2's own criteria. `.9` and `.12` name SUB.2 as a trigger; they do not specify it.
- duplicating the four deferred §P1 fields owned by the design's §13.8.

**Authority split:** the design owns *what must be true*. This plan owns *which case proves it and
whether that case can fail*. A row here that invents a requirement the design does not carry is a
defect in this plan, and the repair is to delete the row, not to widen the design.

## 1. Row order is deliberate

The table runs `.1 .. .9`, then `.11`, then `.10`, then `.12`, `.13`, and finally the
design-decision rows `.14`–`.17` — appended, in the order they were written, never interleaved with
the clause rows they sit beside in subject matter. `.11` precedes `.10` because
`.10` is the split-criterion row and reads as a footnote to the authorisation pair around it. **Do
not renumber.** The identifiers are cited from the design, the criteria status doc, and the release
ledger; renumbering silently invalidates three documents to tidy one table.

## 2. Assertion rules

Rules A1–A9 are NOT restated here. They live in
`docs/design/2026-08-31-cluster-b-capability-and-trace-metadata-test-plan.md` §2, and this plan is
written against them by pointer (H3 — a second copy drifts, and then two plans disagree about what
a strong assertion is). Full path, never the bare name: both copies of several plans exist on disk
and the bare name resolves to whichever is stale.

The two that do most of the work here, in that document's own words: **A3** — a set assertion says
what DID arrive; **A5** — the fixture lets the rule under test be the thing that decides.

One rule this plan needs is **not** among the nine, so it is declared here rather than borrowed:

> **PC (positive control).** An absence assertion over a channel that carries nothing is not an
> assertion. Every negative row over a stream or a store carries a positive control as its own
> row, and the negative may not be read as evidence while the control is unsatisfied.

PC is this plan's, not cluster-b's. Do not renumber it into the A-series — the series belongs to
another document and a tenth entry appearing only here is exactly the drift §2 exists to avoid.

## 3. Why some criteria decompose into several cases

Four criteria are compound MUSTs. A single case per criterion would let half the requirement pass
unobserved, and the coverage map would show a filled cell.

| criterion | clauses it actually carries |
|---|---|
| `.2` | five status shapes, each with its own required payload field |
| `.3` | timestamp advance on accepted changes; ignore unmatched/already-satisfied input keys; the empty complete ack shape; cooperative cancellation. Corrected by design §13.2. |
| `.8` | same `taskId` on retry; backend runs once; never in the response cache; never marked idempotency-completed; keyed repeats vs keyless repeats |
| `.10` | the declaring half (green today) and the honouring half (red today) |

Six further criteria carry suffixed rows in §4 (`.4`, `.6`, `.9`, `.11`, `.12`, `.13`) for a
different reason: they split to pair a negative with its positive control (PC), or to separate a
clause that is red today from one that is not. Compound-MUST decomposition and control-pairing are
two causes with one visible effect, and a reviewer reading the table above as the whole
justification would find it covers a third of the suffixes.

Rows below carry a letter suffix per clause. The suffix is part of the case name, not decoration:
a coverage tool that collapses `.8a`–`.8f` back to `.8` has re-created the problem.

## 4. Coverage map

One row per clause. The last column records the original inspection at HEAD `22084cfb`,
and why. A row that cannot fail for a *behavioural* reason names its trigger — which assertion goes
live, in which increment, owned by whom — inline. A vacuous row without that triple is not a plan
row, it is a wish.

The 2026-09-06 takeover amendment does not rerun those old measurements. In the
delivery base `0d4df3c0`, SUB.2 has a live registry/stream, but task-specific admission
and delivery are missing. References to an entirely absent stream below are
historical; task cases must now drive the existing production stream as §10 specifies.

| clause | case | level | type | red on HEAD `22084cfb`? |
|---|---|---|---|---|
| `.1` | task-augmented `tools/call` from a declaring client returns `CreateTaskResult` with `resultType: "task"`, and `tasks/get` resolves the returned id **in the same test** | integration | functional | **No — vacuous.** No arm in `handlers.rs`; red for absence. Any stub passes. **Trigger:** the `tools/call` task arm; increment TASK.1 piece 4; owner TASK.1. |
| `.2a` | `working` serialises with no `result` and no `error` | unit | contract | **Yes.** `TaskStatus` exists with three variants; this one is assertable now. |
| `.2b` | `completed` carries `result` | unit | contract | **Yes.** |
| `.2c` | `failed` carries `error` | unit | contract | **Yes** — and see `.6a`: it fails to *compile* against the current `Option<String>`, which is the intended red. |
| `.2d` | `input_required` carries all outstanding `inputRequests` | unit | contract | **Required by approved scope.** The variant was absent at the measured base; the production input round trip is additionally required by §10, not satisfied by this wire-shape case. |
| `.2e` | `cancelled` serialises with neither `result` nor `error` | unit | contract | **No — the variant does not exist.** **Trigger:** the enum gains the variant; increment TASK.1 piece 2; owner TASK.1. |
| `.3a` | `tasks/update` accepting a new outstanding answer advances `lastUpdatedAt`; an ignored duplicate leaves the stored state unchanged | unit | functional | **Originally absent at the measured base.** Paired with a real outstanding question by INPUT-01/02. The timestamp is not a substitute for backend continuation evidence. |
| `.3b` | `tasks/update` accepts valid outstanding keys and ignores unknown/already-satisfied keys; malformed maps are invalid-params and cause no partial mutation | unit + integration | contract / negative | **Corrected by design §13.2.** Pinned server prose recommends ignoring those keys. Pair the no-op duplicate with a real accepted answer and backend resume count; §10 cases INPUT-02/03 make it falsifiable. |
| `.3c` | the acknowledgement is the empty `resultType: "complete"` shape | unit | contract | **No — vacuous.** Same trigger as `.3b`. |
| `.3d` | `tasks/cancel` promptly acknowledges and preserves cancellation while a fixture deliberately ignores the cancellation signal; a cooperative backend may stop promptly too | integration | functional | **No — vacuous.** Depends on `.2e`'s variant *and* the dispatch arm. Written now so the licence is asserted rather than discovered by a reviewer as a bug. |
| `.4a` | a client declaring on request 1 and omitting on request 2 gets `MISSING_REQUIRED_CLIENT_CAPABILITY` on request 2 — not a task | integration | negative | **Yes — the row that catches a stub.** A dispatcher returning tasks unconditionally passes `.1` and fails this. |
| `.4b` | the error carries `data.requiredCapabilities.extensions["io.modelcontextprotocol/tasks"]` | integration | contract | **Yes, and for a shape reason, not only a routing one.** The number is settled: `MISSING_REQUIRED_CLIENT_CAPABILITY = -32021` (`src/protocol/era.rs:58`), confirmed by the pinned 2026-07-28 text — nothing deferred. What is red is the **payload**: today's guard (`src/gateway/router/handlers.rs:804`) emits `data.requiredCapabilities` as a **list of capability strings**, not the `extensions["io.modelcontextprotocol/tasks"]` map this clause asserts. Assert the serialised `data`, never the code alone. Note also that the handler emits `-32021` as a **bare literal** rather than the constant (as does `meta_mcp/invoke.rs:690`), so a unit case asserting the constant cannot observe a handler that drifts from it — assert the wire value. Measured on both emitters (HEAD `22084cfb`): `invoke.rs`'s `undeclared_input_request` builds `REQUIRED_CAPABILITIES_DATA_KEY: [capability]` — the same list of strings — so the `tools/call` path this clause actually runs on is red for the same shape reason the router is, not merely by inheritance from it. |
| `.5` | a 2025-era peer calling `tasks/cancel` is refused `-32601` by the era gate | unit + integration | negative | **Yes, red now, for a real reason.** `ADDED_IN_2026_07_28` does not list `tasks/cancel`, so the gate lets it through today. Independent of the dispatcher — a list-membership assertion plus one router case. |
| `.6a` | a `failed` task carries the JSON-RPC `error` **object** | unit | contract | **Yes, red now.** The field is `Option<String>`; an object cannot be represented, so this fails to compile. |
| `.6b` | a tool result with `isError: true` is `completed` with `result`, **never** `failed` | unit | classification | **No — vacuous.** Nothing classifies backend results yet. **Trigger:** the result-to-status mapping; piece 4; owner TASK.1. |
| `.7` | `Mcp-Name` on `tasks/get`, `tasks/update`, `tasks/cancel` mirrors `params.taskId` | unit | contract | **Yes, red now.** `mcp_name_body_field` returns `None` for all three ("exactly these three" methods); no dispatcher involved. |
| `.8a` | a retried call carrying the **same client idempotency key** returns the **same** `taskId` and runs the backend **once** — mutation counter on the mock tool asserts 1 | integration | functional | **No for the dedupe half.** Needs the store. **Fixture is binding:** `config.cache.enabled = false`, because the response cache is written after the backend result and before the client stream, so an enabled cache passes this vacuously. Assert the counter, never the body. **Trigger:** the idempotency store; piece 3; owner TASK.1. |
| `.8b` | the dedupe key is `(authenticated principal, client idempotency key)`, and a same-key/different-body call is **rejected** against the stored fingerprint | integration | negative | **No — vacuous.** No store, no fingerprint. **Trigger:** same as `.8a`. Written separately because a key on the idempotency string alone passes `.8a` and lets one principal claim another's task. |
| `.8c` | two identical calls carrying **different** keys produce **two** `taskId`s and a mutation counter of **2** | integration | functional | **No — vacuous**, and it is the row that stops `.8a` being satisfied by a global "one task per body" cache. |
| `.8d` | a positively classified **read-only keyless** repeat stays synchronous, returns no task handle, and executes both calls; a modern keyless external write/unknown mutability refuses before dispatch | integration | regression / eligibility | The synchronous repeat is an existing control; the no-task assertion becomes discriminating when task admission is implemented. It prevents body-identity dedupe and automatic task promotion, per current design §13.4. |
| `.8e` | the `CreateTaskResult` is **never written to the response cache** | integration | negative | **Yes for the guard.** Falsifiable against the existing `is_final` gates. **Fixture is the opposite of `.8a`'s: the cache must be ENABLED**, or the assertion observes a cache that was never going to be written to. Two rows of one criterion needing contradictory fixtures is a finding this plan's decomposition surfaces and a single `.8` row would have hidden. |
| `.8f` | the `CreateTaskResult` is **never marked idempotency-completed** | unit | negative | **Yes for the guard.** Asserted against `is_final` (`src/protocol/cacheable.rs:130`); no dispatcher involved. |
| `.9a` | a task that would emit progress produces `notifications/tasks` on a `subscriptions/listen` stream carrying `taskIds` | integration | functional | **No — vacuous until TASK.1 and SUB.2 both land.** Nothing emits task notifications, so an empty stream passes. **Trigger:** SUB.2's emit path; owner SUB.2, constrained here so it is not discovered late. Method name is `notifications/tasks` per the design's §10.2 correction — do not "fix" it to `notifications/task`. |
| `.9b` | the stream carries **no** `notifications/progress` and **no** `notifications/message` | integration | negative | **No — vacuous** for the same reason, and vacuous in the dangerous direction: an empty stream satisfies every absence. Per A3 the assertion is on the **observed method set** — say what did arrive — never on the absence of two names. |
| `.11a` | a retrieval naming a task created by a different principal is answered not-found, **byte-identical** to that principal retrieving an id that never existed | integration | negative | **No — vacuous until the dispatcher exists**, and it is the row most likely to be dropped as a nicety. Byte-identical is what makes it a test rather than a sentiment: a distinct "not yours" code is itself the disclosure. **Never** widen this row to cover subscription admission — that fold is what produced RL.5's "MET (narrowed)"; admission is `.12`. |
| `.11b` | **positive control in the same test:** principal A retrieves its own id successfully | integration | control | **No — vacuous**, and that is the point of writing it down: without it, both sides of `.11a` are "not found because nothing works". PC. |
| `.10a` | `gateway_declares()` returns `extensions["io.modelcontextprotocol/tasks"] = {}` | unit | contract | **No — green today.** `extensions.rs` already returns the entry. Proves nothing on its own; recorded so the split is visible rather than credited. |
| `.10b` | the **served** `initialize` **and** `server/discover` capabilities carry the identifier | unit + integration | contract | **Yes — red today.** `implemented_extensions()` returns an empty map. That insert is TASK.1's, and this is the only half of `.10` that is. |
| `.12a` | **positive control:** principal A opens a listen stream on its own task and receives at least one `notifications/tasks` | integration | control | **No — vacuous until SUB.2 lands.** Listed first because `.12b` is unreadable without it. |
| `.12b` | principal B listening on A's `taskId` gets a stream **byte-identical** to B listening on a fabricated id, and nothing is ever pushed to it | integration | negative | **No — vacuous.** Nothing admits a subscription today, so an empty stream passes for the wrong reason. It goes red the moment a stream is admitted without an ownership check — which is the state the code ships in unless this row exists, because the design states the principal check for the three *retrieval* methods and admission is a fourth surface reaching the same records. |
| `.12c` | **the bar, recorded in-row:** `.12` MAY NOT be marked MET while `.12a` is unsatisfied | — | gate | Not a test. A verdict rule, recorded where the verdict is read. See §5. |
| `.13a` | a client declaring on request 1 that opens a listen stream carrying `taskIds` **without declaring on that request** is refused `-32021`, with the same `data.requiredCapabilities` payload `.4b` asserts | integration | negative | **Partially, for a real reason.** The per-request capability read exists (`.4` asserts it on the `tools/call` path and is red for behaviour, not absence), so this waits on the subscription path, not on the dispatcher. |
| `.13b` | the gate is per **request**, not per **method family** | integration | negative | **Partially.** Written separately because a gate keyed on `tasks/*` passes `.4` and fails this: `subscriptions/listen` is not in that family and reaches the extension anyway. |
| `.14` | an expired task's record is **deleted**, not marked `failed` and retained: polling `tasks/get` for the owner's own task across the expiry boundary, every response is either the task's live non-`failed` status or not-found — `failed` is never observed — and once not-found is reached it is byte-identical to `tasks/get` for an id that never existed | integration | negative | **No — vacuous until a store and a reaper exist**; the not-found is not-found for the wrong reason. Written now because the pinned text permits the other branch — `tasks.md:340`, servers **MAY** mark a task `failed` after the TTL elapses and delete it later — so an implementer taking it would be conformant and would silently split `.11a`'s byte-identical assertion into two distinguishable answers. Two staging rules carry the row, both from the 2026-09-06 dual review. **Poll across the boundary, do not sample after it** (grok, MEDIUM): a single retrieval taken once expiry is complete passes against a conformant mark-`failed`-then-delete reaper, because the `failed` window has already closed — and the case must not wait on a reaper-completed signal, since that signal is exactly what hides the window. **Assert the sequence, not one answer** (kimi): the row does not decide whether expiry is a periodic sweep or a lazy check at access, so a live status at TTL+ε is a pass and a `failed` at any point is the failure. And it needs a successful retrieval of the same id before the TTL as its own positive control, or expiry is indistinguishable from nothing having been created. **The poll cadence is part of the assertion, not an implementation detail** (kimi, confirmation pass): the case detects a `failed` window only if it samples faster than that window is held, so the fixture drives an explicitly controlled clock and polls at least once per shortest interval the implementation could retain a `failed` record — with a real reaper's sweep interval as that bound, stated in the test, not inferred from wall-clock luck. **Trigger:** the reaper; owner TASK.1 piece 2. |
| `.15` | capacity is released when the record is **deleted or expires**, never when the task reaches a terminal state: with the per-principal cap at N, N `completed`-but-unreaped tasks refuse the N+1th admission, and the slot frees once the record is gone | integration | negative | **No — vacuous until the caps and expiry semantics both exist**, and vacuous in the dangerous direction: the default an implementer reaches for is an active-only counter, which reads zero and admits forever, so a case asserting only that admission succeeds after expiry passes on the broken code. The assertion that carries the row is the **refusal at N with terminal-state records**; advance the clock past the TTL and assert admission second. The row does not require a distinct reaper process (kimi and grok both, 2026-09-06): a lazy expiry check at admission time satisfies the design's "deleted or expires" exactly as a sweeper does, and naming the sweeper in the trigger would have made a conformant implementation look like a miss. **Trigger:** §11.2's caps and whatever releases an expired record; owner TASK.1. |
| `.16` | a client polling `tasks/get` more frequently than the recorded `pollIntervalMs` is served normally — no throttle, no error | integration | negative | **No — vacuous until `tasks/get` exists**, and the weakest of the three: it asserts the absence of a behaviour nobody has written. Per A3 the case asserts the **observed responses** — N successes carrying the same shape — never "no rate-limit error occurred". Kept because `tasks.md:308` says servers **MAY** rate-limit below the recorded interval: declining that permission is a design decision, and this row is where a later implementer learns that adding a limiter changes our design rather than improving our conformance. |

| `.17` | an in-flight task follows the `ttlMs` recorded **at creation**, not a default a later configuration reload changed: create a task under a default TTL of T1, reload a configuration whose default is T2 **< T1**, and both `tasks/get` and expiry still use T1 — the task is retrievable after T2 has elapsed, and the T1 half is asserted in `.14`'s terms rather than as a disappearance at an instant: poll across the T1 boundary and require every response to be the live status or not-found, reaching not-found. Written that way on grok's confirmation pass (SMALL, 2026-09-06) because a periodic sweep that re-reads the record — the ownership rule implemented correctly — deletes at the first tick after T1, not at T1, so an instant-check at T1+ε reads a correct implementation as a miss | integration | negative | **No — vacuous until piece 2's task default-TTL key and a store exist.** Added 2026-09-06 (grok, HIGH): it is the ownership rule's **only** failure observable inside 4.0.0's own behaviour, and it had no row. `.14`–`.16` each run under one static configuration, so a reaper that reads live config rather than the record passes all three — the rule would have shipped with nothing able to contradict it. The direction is pinned deliberately: a reload **downward** makes live handles vanish while the backend call is still running, which is the failure the ownership rule exists to prevent; a reload upward merely extends a task and is barely observable, so a case run in that direction would be vacuous in the safe direction. **Trigger:** piece 2's task default-TTL configuration key; owner TASK.1 piece 2. |
**Tally.** Of 33 clause rows — 32 cases plus `.12c`, which is a verdict rule and not a test — 11
can fail against HEAD for a behavioural or compile reason: `.2a`,
`.2b`, `.2c`, `.4a`, `.4b`, `.5`, `.6a`, `.7`, `.8e`, `.8f`, `.10b` — with `.13a`/`.13b` partial.
The rest wait on the dispatcher or on SUB.2 and must be written **against the spec text**, not
against whatever the dispatcher turns out to do. That asymmetry is the plan's headline finding:
TASK.1 is mostly new surface, and the tests that constrain it on day one are the ones asserting
against code that already exists.

**Four design-decision rows, counted apart from the clause rows.** `.14`, `.15`, `.16` and `.17`
do not descend from a criterion clause. Three of them — `.14`, `.15`, `.16` — pin the point this
design picked inside a range the pinned spec leaves open (`tasks.md:308`, `tasks.md:340` — every server-side clause on expiry, retention
and poll-interval handling is a **MAY**, checked against the pinned blob before these rows were
written — the check, since asserting a sweep is not running one (kimi, 2026-09-06):
`rg -n 'MUST' <tasks.md> | rg -i 'ttl|poll|expir|delet|discard|retain|terminal|capacity'`, run against
the blob §1 pins (`modelcontextprotocol/ext-tasks`, tree `0d0a6bd4c258b35caa3c810a1dd506cf105b1501`,
blob `5d6a202eacbaab3444f9d0727ce6587598e7e077`, 34,148 bytes) and not against a local scratch copy,
so the line numbers below are reproducible by anyone who fetches that blob,
returns four lines and only four — `:300` (a `CreateTaskResult` MUST NOT be returned before the
task is durably created), `:348`, `:350` and `:404`, none of which governs whether an expired
record is deleted or retained, how capacity is released, or how a server answers a client polling
too fast). `.17` is there for a different reason and the sentence above does not cover it: it pins
no spec range at all, it pins this design's own internal invariant — the record, not live
configuration, owns the value — which the specification neither requires nor forbids. That still
makes it ours to test rather than the ledger's to judge, by the same rule and not by the same
argument. All four are the plan's to test and not the ledger's to judge, all four are appended
rather than slotted next to related rows, and none of them can fail against HEAD — the red tally
stays at 11.

## 5. `.12` cannot close on a vacuous pass — read this section first

Reviewed before the rest of the plan, because it is the one row where a green result means nothing
and a reviewer skimming §4 will read `.12b` as covered.

`.12b` asserts that principal B's listen stream on A's `taskId` is byte-identical to B's stream on
a fabricated id, and that nothing is ever pushed. **Today no subscription is admitted at all**, so
both streams are empty, both are byte-identical, and the case passes. It passes for the reason the
system is broken, not the reason it is right.

The bar, stated so it can be checked rather than remembered:

> `MIK-7272.TASK.1.12` MAY NOT be marked MET while `.12a` is unsatisfied. `.12a` is the positive
> control: principal A opens a listen stream on its own task and receives at least one
> `notifications/tasks`. Until that control is green, `.12b` is not evidence — it is silence.

This is the general shape of PC (§2) applied to the one row where the ownership check is the whole
point: **a negative assertion over a channel that carries nothing is not an assertion.** The same
reasoning binds `.9b` and `.11a`, and each carries its own control (`.9a`, `.11b`). `.12` gets its
own section because it is the row a release-ledger reader will meet as a single cell.

Practical consequence for sequencing: `.12` cannot close until a live dispatcher exists **and**
SUB.2 admits a subscription. Marking it MET earlier is not optimism, it is a false ledger entry.

## 6. Fixture hazards specific to TASK.1

Three, all of them the kind that make a case pass while the thing it names is broken.

**The `.8a`/`.8e` opposite-fixture split.** `.8a` requires `config.cache.enabled = false`, because
the response cache is written after the backend result and before the client stream — leave it on
and the second call is served from cache, the mutation counter reads 1, and the case passes without
a task store existing. `.8e` requires the cache **enabled**, because "never written to the response
cache" observes nothing when the cache was never going to be written. Two clauses of one criterion,
two contradictory fixtures. A single `.8` row forces one of them, and whichever is chosen the other
clause goes unobserved. This is a plan finding, not a test-writing detail.

**Serialise, do not compile.** `.2` and `.6` are about wire shapes. A case that constructs a
`TaskStatus` and reads its fields asserts the Rust enum, not the JSON the client sees; a `#[serde]`
rename or a `skip_serializing_if` change slips straight past it. Assert against the serialised
value. The corollary is that `.2d` and `.2e` fail to *compile* today rather than fail an assertion,
and a compile failure is a legitimate red — but it is red for absence, so it goes back to green the
moment the variant exists, whatever it serialises to. The serialisation assertion is what survives.

**Empty-stream vacuity.** `.9`, `.11` and `.12` all read a channel. An empty channel satisfies every
absence assertion ever written. Every one of those rows carries a positive control in the same
test, and per A3 the negative half asserts the **observed** set rather than the absence of named
members — "the methods that arrived were exactly {`notifications/tasks`}" fails loudly when a
fourth notification type appears; "no `notifications/progress`" does not.

## 7. Assertion-rule sweep

Run against A1–A9 (`docs/design/2026-08-31-cluster-b-capability-and-trace-metadata-test-plan.md` §2)
and against PC (§2 above). Violations are recorded, not silently repaired — a plan that
quietly fixes its own drafts teaches nothing to the next plan.

| finding | rule | disposition |
|---|---|---|
| `.9b` was first drafted as "no `notifications/progress` and no `notifications/message`" — two named absences | A3 | **Kept in the row's prose** (it is the criterion's own wording) but the case asserts the observed method set. The row says so explicitly rather than leaving the test author to infer it. |
| `.8a` with the cache left enabled constructs the very state (a served-from-cache second call) that the mutation counter is meant to detect | A5 | Fixture pinned in the row. This is the violation the decomposition was written to expose. |
| `.11a`, `.12b`, `.9b` are absence assertions over channels that carry nothing today | PC | Positive controls added as their own rows (`.11b`, `.12a`, `.9a`) rather than as a sentence inside the negative row, so a coverage map cannot show the negative as covered while the control is missing. |
| `.3a` as originally written ("advances `lastUpdatedAt`") is the whole criterion in one timestamp assertion | §3 (compound MUST) | Decomposed into `.3a`–`.3d`. The timestamp is the weakest clause of the four and was standing for all of them. |
| `.10` mixes a green-today unit assertion with a red-today served-capability assertion | §3 (compound MUST) | Split into `.10a`/`.10b`. Undecomposed, `.10` reads MET on the strength of the half TASK.1 does not own. |

The earlier `.2d` scope question is resolved by the approved expansion; §8 records
that answer. New input/restart cases require the same assertion-rule review.

## 8. Scope answers and dependencies

**Q1 — resolved by the operator-approved expansion.** The release includes the
full `input_required` round trip and all five statuses. The approval is recorded in
[the scope decision record](../requirements/RELEASE-4.0.0-scope-decisions-2026-09-06.md).
The previous recommendation to narrow `.2d` was not accepted and is superseded;
there is no pending request to remove input from 4.0. Design §13 carries the delta.

**Q2 — SUB.2 supplies the existing stream; TASKS supplies task integration.**
The registry and stream are live at delivery base `0d4df3c0`. TASKS owns owner-bound
`taskIds` admission and task notification delivery through those existing seams.
The old schedule for a wholly missing SUB.2 stream no longer describes this tree.
Legacy correlated input still has a BRIDGE dependency; its owner/check/trigger/
fallback is recorded once, in design §13.8. This plan cites it rather than creating
another schedule. A failed or absent dependency leaves the affected case open.

**Implementation unknowns:** supported upstream-job recovery, owned identity
context, filesystem crash behavior and limits/performance use the design §13.8
register. None is closed by documenting it here. Input-required and restart scope
are settled; an adapter or platform limitation is implementation evidence to resolve,
not authorization to narrow the five lifecycle requirements.

## 9. What this plan does not do

No test code. **Partially reviewed, and the boundary matters more than the verdict.** Two vendors
reviewed the 2026-09-06 `.14`–`.17` amendment and the §11.2 design delta it descends from, and both
returned SHIP on the confirmation pass (grok, run `grok-20260906T063048Z-57193`; kimi, run
`synthetic-20260906T063051Z-57626`; both processes exited 0, and per §PA the verdict is that ledger
row and that exit status, never text read out of the stream). Neither vendor reviewed the clause
rows `.1`–`.13`, which predate that round — so this document has NOT passed the §P2 plan review as
a whole, and a trailer claiming it had would be a forgery of the thing that makes the gate worth
having. The plan still enters the §P2 plan-review round riding with the TASK.1 implementation hop;
the `.12`/`.13` additions travel with it.

It also does not adopt `tests/mik_7272_task_1_acs.rs`, whose module doc names the design's §8 as
its plan. That file was untracked when this paragraph was first written; it is now committed
(`9f573b87`), which changes who may touch it but not what it covers. §8 is now a pointer, so that file was
written against a table this change superseded, and it was written before any vendor reviewed the
plan that replaced it. The order §P2 asks for is plan, then plan review, then failing tests, and
this file arrived at step three while step two is still outstanding. It therefore stays
unreconciled until the plan passes review and the file is checked against the 33-row coverage map
rather than the superseded table. Its scope carve-out has been corrected (grok, LOW, 2026-09-06:
it still called the `ttlMs`/`pollIntervalMs` gap open after §11.2 closed it, so an agent reading
the file as the scope source of truth would re-open a settled question) — a stale comment in a
committed file is a model input that poisons output, and correcting one is not the same act as
rewriting the coverage its author still owns. Nothing here is a criticism of the file: its `use mcp_gateway::protocol::cacheable::is_final`
independently corroborates the `.8f` anchor correction, which is a second measurement of the same
fact and worth more than the file cost.

## 10. Full-lifecycle amendment — review pending

The design's §13 supplies every behavior below. These cases supplement `.1`–`.17`
and correct `.3b`; they do not replace owner/subscription controls, wire-shape
tests, or cache-fixture distinctions. The old tests at `22084cfb` are not evidence
for this delta. No runtime or test code was written in this documentation increment.

### 10.1 V-model acceptance matrix

Each table row is a distinct case (a case may parameterize the two HTTP routes).
All implementation evidence cells are **pending** until reviewed failing tests,
passing output and the built revision are attached. The case column states what
could fail; a compile failure due only to a missing API is evidence of absence,
not a behavioral falsifier. Negative controls run on the same production path as
their positive half.

| case ID | acceptance criterion | case and decisive assertion | V-model level | type | evidence |
|---|---|---|---|---|---|
| ROUTE-01 | MIK-7311.LIFECYCLE.1 | Through each public route, a declaring authenticated caller with an explicit retry key starts an eligible slow backend tool. The flat task handle immediately resolves through get; release backend barrier and poll the actual final result. Reject a store-only or handler-stub pass. | integration | functional / contract | Pending |
| ROUTE-02 | MIK-7311.LIFECYCLE.1 | On the same connection, declare extension once then omit it on get/update/cancel/listen; assert -32021 plus extension object each time, and legacy era -32601. For ordinary synchronous calls without declaration assert a real core result, never a task. | integration | negative / compatibility | Pending |
| INPUT-01 | MIK-7311.LIFECYCLE.1 | A backend performs work then asks two questions. Get exposes both; update one, observe only the other; update the second, observe one backend continuation and the final tool result. Run modern MRTR on both routes. The legacy held-exchange case is separate INPUT-06, pending BRIDGE. | integration | functional / protocol | Pending |
| INPUT-02 | MIK-7311.LIFECYCLE.1 | Supply one valid key together with invented keys; the valid answer persists, unknown keys are ignored. Repeat the accepted answer and assert the same complete ack, unchanged answered value and exactly one resume. A pure no-op fixture cannot pass the positive half. | integration | adversarial / idempotency | Pending |
| INPUT-03 | MIK-7311.LIFECYCLE.1 | Wrong input map/value shape returns invalid-params with no stored-answer or revision change. Race two answers to the final outstanding key with a barrier; exactly one durable answer/worker continuation wins. | unit + integration | contract / concurrency | Pending |
| INPUT-04 | MIK-7311.LIFECYCLE.1 | Backend reuses a key in a later round: public keys differ across rounds, repeated polls within a round are stable, and a delayed old answer cannot satisfy the new question. Reload store between rounds to prove uniqueness is durable. | integration | regression / state machine | Pending |
| INPUT-05 | MIK-7311.LIFECYCLE.1 | Elicitation/sampling mode not declared on the current get/listen request refuses without disclosing its payload; a correctly declaring owner can get/answer it. Also subscribe while working without input declarations, then make the backend ask: no input payload is delivered on that stream, while a newly declaring owner stream succeeds. | integration | security / compatibility | Pending |
| RESULT-01 | MIK-7311.LIFECYCLE.1 | Backend JSON-RPC error yields failed with error object; normal `isError: true` yields completed with the original tool result. Serialize working/input_required/cancelled variants and verify only their allowed payloads. | unit + integration | contract / classification | Pending |
| OWNER-01 | MIK-7311.LIFECYCLE.2 | Disconnect the creating HTTP client after ack while backend barrier remains held. Reconnect with a new session/connection as the same verified issuer/subject, get/update/cancel its task; a refreshed credential preserves ownership. Backend runs once. | integration | reconnect / identity | Pending |
| OWNER-02 | MIK-7311.LIFECYCLE.2 | Another issuer or subject using the actual handle gets byte-identical get/update/cancel errors to a fabricated ID, with request IDs held equal. Owner positive control succeeds. Also test wrong backend route, spoofed display/agent name and missing strong identity. | integration | isolation / negative | Pending |
| OWNER-03 | MIK-7311.LIFECYCLE.2 | Owner stream receives a committed task notification and final payload. Other owner with real/fake handle receives equivalent rejection without echoed ID; a mixed owned/foreign ID set is refused atomically. Revoke access before a later notification and assert no further payload delivery. | integration | isolation / stream | Pending |
| STORE-01 | MIK-7311.LIFECYCLE.3 | Pause durable creation before file fsync/rename/directory fsync: no response handle or backend dispatch yet. After final commit release, immediate get succeeds. Inject write errors at each boundary and assert no successful acceptance on the failed path. | integration | fault injection / ordering | Pending |
| STORE-02 | MIK-7311.LIFECYCLE.3 | Start a subprocess gateway with a temporary persistent directory; save an acknowledged handle, kill process, reopen same directory in a new process and authenticate again. Handle and owner persist through the real HTTP route within TTL. | system | crash / recovery | Pending |
| MIK-7272.SUB4.STDIO.OWNER.2 | TASK ownership/recovery | Same protected store reopens/relocates and its typed stdio local operator retrieves its task; other stores and same-store HTTP owner cannot alias/retrieve it. No path/OS/env principal string or globally unique identity file. | component + store integration + acceptance | persistence / principal isolation | Pending Task integration; blocking durable acceptance and DELIVERY-01 |
| STORE-03 | MIK-7311.LIFECYCLE.3 | Commit each terminal outcome, kill/reopen, and assert identical retained result/status plus original timestamps/TTL. Repeat at an injected uncertain settlement boundary: outcome is the last fully committed result or explicit uncertainty, never a second execution. | system | durability / negative | Pending |
| STORE-04 | MIK-7311.LIFECYCLE.3 | Corrupt record, unsupported schema, second live process on one directory and settlement ENOSPC each fail readiness/write closed while preserving disk content. Clean-directory/single-owner positive control starts and serves tasks. | system | operational / data integrity | Pending |
| RECOVER-01 | MIK-7311.LIFECYCLE.4 | External backend durably records a mutation then withholds response. Kill gateway at barrier, restart, retrieve handle; result explicitly reports interrupted/unknown outcome and external effect counter remains exactly one. Poll/cancel/keyed reissue cannot repeat it. | system | safety / fault injection | Pending |
| RECOVER-02 | MIK-7311.LIFECYCLE.4 | Trusted adapter starts one read-only external job, commits its recovery handle, then gateway dies. Restart queries/reattaches that handle and obtains its result. Assert one start, at least one post-restart poll, correct owner/credential and no original-operation replay. | system | recovery / positive control | Pending adapter per design §13.8 |
| RECOVER-03 | MIK-7311.LIFECYCLE.4 | Persist accepted partial answers; restart before resume dispatch and exercise supported continuation adapter. Restart after resume-dispatch marker but before durable result: report uncertainty and do not send answers twice. Lost legacy sender uses explicit interruption. | system | crash / input lifecycle | Pending adapter per design §13.8 |
| RECOVER-04 | MIK-7311.LIFECYCLE.4 | Revoke permission or remove required credentials before recovery; also exercise get/update/cancel/listen and already-open stream delivery under revoked authorization. The retained handle never reattaches under a shared/default credential; observe safe refusal/interruption and zero additional backend starts. | integration | authorization / negative | Pending owned-context seam |
| LIMIT-01 | MIK-7311.LIFECYCLE.5 | At global/per-owner retained caps and worker cap, and one remaining shared 10,000-entry admission slot, race DISTINCT-key task/sync admissions across meta/direct routes and prove no limit is exceeded and rejected work never reaches backend. Complete tasks but keep them unreaped: they still consume record allowance. Expire/delete and prove capacity returns. | integration | concurrency / resource bound | Pending |
| LIMIT-02 | MIK-7311.LIFECYCLE.5 | Boundary-size requests, result, accumulated inputs/answers and rounds: accept limit-sized valid data; reject one-over before dispatch or return explicit oversized-result tool error after dispatch. Assert retained bytes plus reservation budget stays bounded, with no eviction of unexpired records. | integration | resource / adversarial | Pending |
| LIMIT-03 | MIK-7311.LIFECYCLE.5 | Controlled clock crosses TTL while get/update/reaper contend and config default shrinks. Existing record retains its original TTL; only live state or not-found appears across expiry, no synthetic failed window; expired updates cannot resume backend work. | integration | concurrency / expiry | Pending |
| CANCEL-01 | MIK-7311.LIFECYCLE.5 | Barrier races cancel with completion in both commit orders. First committed terminal state remains stable through late callback, repeated cancel and restart. Backend effect may still occur after cancel; response/docs never promise undo. | integration + system | concurrency / contract | Pending |
| DEDUPE-01 | MIK-7311.LIFECYCLE.3, MIK-7311.LIFECYCLE.4 | Same owner/key/fingerprint across restart returns same task; mismatch refuses; new keys create new tasks; read-only keyless repeats stay synchronous and execute independently without task handles; modern keyless external writes refuse before dispatch; another principal with same key creates its own task. Cache OFF; assert backend effect counts, not equal response bodies. | integration + system | retry safety / isolation | Pending |
| ELIGIBLE-01 | MIK-7311.LIFECYCLE.1 | On both routes, vary one eligibility input at a time: declared+keyed external call returns a resolvable task; gateway-policy-listed read-only keyless calls return ordinary results; any modern mutating/unknown tools/call (including meta work/management) without key refuses before dispatch; remote readOnlyHint alone never exempts; malformed key refuses before dispatch; incoming MRTR continuation uses existing continuation path. | integration | admission / compatibility | Pending |
| INPUT-06 | MIK-7311.LIFECYCLE.1 | A legacy stdio backend holds a correlated input request; task update delivers the answer to that exact exchange and completes without a second original call. Run both routes and wrong-owner/late-answer controls. | integration | bridge / input | Pending BRIDGE adapter |
| STORE-05 | MIK-7311.LIFECYCLE.3 | Kill after record rename+directory fsync, before HTTP handle write and before worker dispatch. Reopen, retry identical owner/key and recover the same single durable record/handle; no automatic backend dispatch occurs, outcome is interrupted-before-dispatch. Separate after-effect/before-ack cut keeps effect counter at one. | system | lost acknowledgement / retry | Pending |
| STORE-06 | MIK-7311.LIFECYCLE.3 | Malicious IDs (absolute paths, separators, traversal, encoded forms), symlink/non-regular record and lease files, directory/record permissions: no outside path is read/written; unsafe startup fails without modifying the source; clean private directory and normal records work. Assert 0700 directory, 0600 files and traversal containment through real load/get paths on Linux/macOS. | unit + system | filesystem security | Pending |
| SECURITY-01 | MIK-7311.LIFECYCLE.1, NFR.SEC.1 | Through both production task routes independently falsify request authorization/sanitization, final response Block/redaction, accounting per dispatch/resume and provenance. Use counted real backend, allowed positive controls and disabled-scanner controls. Compare with equivalent synchronous secured boundaries; a task ack is not the scanned final backend result. | integration | security parity / wiring | Pending firewall + identity boundaries |
| DEDUPE-02 | MIK-7311.LIFECYCLE.3, MIK-7311.LIFECYCLE.4, SUB.4 | Race /mcp gateway_invoke AGAINST /mcp/{backend} for one principal/key/body with and without tasks declaration; at most one execution owner/start, opposite mode conflicts. Repeat both winning orders and Task winner across restart with undeclared retry. | integration + system | cross-mode atomic admission | Pending |
| DEDUPE-03 | MIK-7311.LIFECYCLE.3, SUB.4 | Same principal/key across session/projection/`_full` changes cannot run a second effect. Stable presentation replays; changed descriptor conflicts. Distinct-key control runs twice. Include the literal two VERIFIED-owner different-key collision pair and assert its old raw-output equality before distinct new identities/results; preserve unverified R5 case separately. | integration | representation / ownership | Pending |
| DELIVERY-01 | MIK-7311.LIFECYCLE.1–5, NFR.DEMO.1 | Independent driver gets ACs and launch instructions only, uses binary built from reviewed revision, starts/answers/disconnects/reconnects/cancels/restarts a task and checks retained owner isolation and side-effect count. Record sanitized requests/results and binary hash. | acceptance | functional UAT | Pending |

For `DELIVERY-01`, list the five exact lifecycle IDs in the execution evidence
rather than relying on the compact range in this table. No test count, coverage
mention or passing earlier design receipt replaces that evidence.

### 10.2 Fixtures that preserve the failure

- **Real public construction.** Route/system cases start through the production
  builder and configured durable directory; hand-constructing a ready task service
  would miss an unwired constructor. Keep response cache OFF for effect/dedupe
  cases, and use `.8e`'s separate cache-ON fixture for the cache-write exclusion.
  SUB.4 is mandatory, so do not recreate an absent `idempotency.enabled` section
  as a negative fixture. Run same-key/different-principal with identity propagation
  OFF, plus token rotation and exact DIFFERENT-key spoof vectors from SUB4.SPOOF.1, including victim `X` versus unbound attacker `X|idp:<victim binding>`. The attacker must fail admission, never see the victim result; verified-owner crafted vectors must stay distinct.
- **External effect evidence.** The crash-test backend lives in a different process
  and stores its counter outside the gateway task directory. Killing/restarting
  only the gateway must preserve the counter. A counter inside its test process
  or a mock that never receives the request cannot establish no replay.
- **Real crash versus injected error.** Store unit faults expose individual write
  phases; system cases terminate a subprocess after observed barriers and reopen
  it. Dropping an in-memory store or constructing a second service in one process
  is not the restart case. Test both after-commit/before-ack and
  after-effect/before-settlement cuts. Always verify restored healthy startup.
- **No sleep-based expiry proof.** Controlled clocks, explicit mutation/dispatch
  barriers and observed responses decide races. Poll before/during/after expiry;
  never wait only for a reaper-completed signal that hides a transient failed state.
  Concurrent cases run both possible winning terminal commits, not merely many
  nondeterministic iterations whose outcome is always accepted.
- **Notifications need a live control.** Owner receives actual task data, foreign
  principal receives the same error as unknown, and mixed-ID admission is all-or-
  nothing. Observe the complete method set including required subscription framing.
  An empty stream cannot prove filtering, and a helper-only filter test cannot
  prove admission or authorization after access revocation.
- **Input honesty.** The fixture backend asks after task creation and must consume
  the posted answer to form the final result. Preseeding a final value or having
  the fixture finish regardless of the response makes the test tautological.
  Input request IDs are generated by production code, not supplied by fixtures in
  the already-unique form the test intends to prove.

### 10.3 Validation order and thresholds

1. Review design §13 and this whole plan against the current DoR. Reconcile
   `tests/mik_7272_task_1_acs.rs` after plan review; write the smallest failing
   wire/store/public-route tests and review those tests before implementation.
2. Implement the reviewed slice and run its targeted tests, including the old
   behavior against the same fixture when a test retrofits existing code. Inspect
   failure assertions and exit status; an unavailable binary or compile error
   does not count as a passed safety scenario.
3. Run route and process-crash matrix on the supported Linux/macOS filesystems,
   followed by normal format, Clippy, broader Rust tests, and relevant release
   acceptance checks on the integrated revision. Task-state/identity critical
   paths use the canonical critical coverage/mutation thresholds; exceptions need
   their own evidence and cannot be inferred from a protocol-only sample.
4. Measure create/update/poll/expiry latency and memory with bounded full records,
   concurrent task workers and unrelated synchronous traffic. Apply the release
   NFR budgets; capture sample size, machine/config, binary hash and before/after
   results. Do not freeze a higher acceptable regression after seeing a failure.
5. Independent functional driving and dual-vendor final review return evidence
   before lifecycle rows are marked met. Re-drive behavior changed by repairs.

Before finalizing this documentation increment, run `git diff --check` on the
two owned files and validate that all five supplemental lifecycle IDs occur in
the requirements and in the matrix, with nonempty case/level/type/evidence cells.
Inspect the actual diff for lingering active input/persistence exclusions and
false reviewed/implemented claims. Those checks prove traceability and document
consistency only; runtime rows remain pending until their cases run.

### r4 finder closure cases

Carry SUB4.COMPAT.1 (actual unchanged3.5 HTTP/stdio plus modern refusal and cross-era keyed replay), SUB4.MANAGEMENT.1 (six distinct real mutation branches, post-effect response loss, same-key one effect/new-key two), and SUB4.CONTENTION.1 into the same implementation gate. SUB4.SPOOF.1 must generate verified subjects through the real OIDC builder with one configured issuer/audience; independent legacy concatenations must be byte-identical before the structured repair is exercised. Exact4096/4097byte metadata envelope vectors include JSON escaping and UTF-8. Current SUB.4 section defines the fixed tuple and exhaustive read-only classification; no raw-subject-only or cross-audience substitute is accepted.


## 11. First delivery test leg: HTTP preflight and synchronous ownership

This is an incremental execution of the approved plan, not a replacement scope
or a TASK.1/SUB.4 completion claim. Design authority remains GPT r5 SHIP plus
retained Grok r2 SHIP in SUB.4's closure receipt. The initial implementation leg
uses the existing public executable interfaces, with no task/admission source
behavior added before these failing tests. Its written tests are now separately
reviewable; their presence does not close that review gate.

Owned test files are `tests/sub4_execution_admission.rs`,
`tests/common/sub4_verified_admission.rs` and `tests/common/sub4_oidc.rs`.
The existing shared `tests/common/signing_gateway.rs` fixture gains only an
explicit child-local environment constructor; its old constructor delegates with
an empty list and preserves default behavior. Signing and firewall owners were
notified. No production AppState, verifier, identity or cache is injected: the
real CLI reads isolated YAML. Backend requests are counted with response cache
OFF, and each negative has an actual same-route invocation control.

| Current case group (meta/direct are independent cases) | Plan clauses covered in this leg | Decisive observation |
|---|---|---|
| Legacy repeated unkeyed calls | HTTP part of SUB4.COMPAT.1 | Same supported mutation reaches real backend twice without new credentials/configuration requirements |
| Modern missing-key / unverified-owner refusal | ELIGIBLE-01, SUB4.READONLY.1, R5 | Auth-disabled negatives retain legacy control; verified-owner missing-key negatives first prove a keyed modern same-route success, then refuse without extra dispatch |
| Null/empty/non-string key | SUB4.CARRIER.1 | Policy-listed modern keyless positive succeeds; malformed reserved values return invalid-params before dispatch |
| Exact read-only target / another target | SUB4.READONLY.1 | Listed target executes twice; different tool and same-tool/different-backend negatives cannot inherit exemption; the latter uses two real counters plus listed-modern and unlisted-legacy positives |
| Real OIDC positive / invalid bearer | Owner fixture control | Production HTTPS JWKS fetch occurs; malformed bearer, well-formed bad signature and missing-CA negatives refuse401 without payload/dispatch; identical issuer/token succeeds with the child-local CA |
| Token rotation / equal display labels | Synchronous portion of DEDUPE-01 and SUB4 owner binding | Same verified issuer/subject/key executes once; distinct signed subjects own distinct counted payloads |
| Meta→direct and direct→meta | Shared synchronous owner invariant | First route executes once; second-route success has its actual result structure/current request ID, or explicit RPC409 with no result/canary; never re-executes |
| Changed arguments / `_full` | SUB4 P5, SUB4.REPR.1 | Same key with changed operation or representation refuses409 with no payload; separate fresh-key `_full` controls execute twice and prove its removal from actual forwarded arguments |
| Payload key versus HTTP key | SUB4.CARRIER.1 | Header changes cannot partition payload-key ownership; new payload key does execute; authenticated header-only requests refuse; backend receives business arguments without reserved key |
| Modern→legacy keyed retry | Keyed HTTP part of SUB4.COMPAT.1 | Legacy opt-in cannot evade the same owner's modern reservation |

The OIDC fixture creates a private ephemeral CA and HTTPS JWKS listener, sends
real ES256 signed tokens to the production delegated-bearer verifier, and trusts
the CA only in the spawned Linux gateway via SSL_CERT_FILE. No OS trust store is
changed and no TLS/signature verification is disabled. The 30 OIDC cases compile
on Linux, where rustls-platform-verifier supports this environment trust source;
other platforms retain the24 preflight cases. This is Linux runtime evidence,
not macOS OIDC or cross-platform lifecycle acceptance.

Compiled red r4 on the isolated Spark source: **28 cases,7 passed,21 assertion
failures**, actual cargo exit101,2.16seconds. Command:
`cargo test --all-features --test sub4_execution_admission --jobs 4 -- --nocapture --test-threads=4`.
Full hashes/commands/output are in external evidence
`sub4-admission-red-r4/{process.json,run.log}`. The seven pass controls include
both valid OIDC/invalid-token pairs, both legacy repeats, both explicit read-only
policy repeats, and the existing meta malformed-key parser. All current red cases
fail at concrete backend dispatch counts before acceptance can be claimed.

The earlier OIDC r2 run had an infrastructure fixture error: a standard listener
was still blocking when registered with Tokio. It contributes no behavioral red
for those eight cases. `set_nonblocking(true)` repaired the fixture, and r3 then
compiled/reran20 cases with7 passing and13 semantic failures. No RUSTFLAGS bypass
was used. All attempt logs are preserved; the newer r5 evidence is below.

### First tests-as-tests review and finder repairs

Both vendors returned SHIP-WITH-FIXES on the same r1 material, with actual
process exit0 and process_status=ok. Receipt
`sub4-admission-tests-review-r1.verified.json` binds
SHA256 `3fae007745f4b7138df798f30671263e56c82b73f940fcbfba1d0de13d5776d8`,
434607 bytes (scope, NUL, stdin). Full runs are
`gpt-20260906T183249Z-69214.md` and `grok-20260906T183249Z-69213.md`.
These are valid receipts with an open test gate, not approval to implement.

| Finding / improvement | Repair and discriminating observation |
|---|---|
| GPT/Grok authenticated missing-key blind spot | Added independent meta/direct verified-owner negatives after same-route keyed modern success; header-only variants also have verified owners and no extra dispatch |
| GPT fixed transport IDs | Every actual send replaces the request ID with a new UUID and asserts the returned ID equals that attempt; only middleware401 is exempt because it runs before body parsing |
| GPT exact backend/tool policy | Two real backends expose the same tool; only the first is listed. Listed-modern and unlisted-legacy positives both work; unlisted-modern must leave both counters unchanged |
| GPT/Grok weak cross-route409 and success shape | A success must have the receiving route's actual content envelope and exact backend content. Conflict must be RPC409, contain no result/canary and use HTTP200 or409; arbitrary5xx is rejected |
| GPT TLS/signature controls | Retained malformed bearer; added a valid JWT with one signature byte flipped and a missing-CA negative followed by identical issuer/token trusted positive |
| GPT malformed loop abort | Twelve independently named meta/direct null/empty/number/boolean/array/object cases, each with policy-listed keyless positive |
| Grok `_full` classification | Added fresh-key normal/full positives with exact sanitized backend argument equality; operation-versus-representation internal descriptor proof remains a later shared-store test |
| Grok TLS readiness | Bounded HTTPS JWKS probe with the ephemeral CA, hostname validation and no_proxy; reset fixture fetch count afterward so production fetch evidence cannot come from readiness |
| Grok invalid-bearer payload | Both malformed and well-formed bad-signature401 bodies must omit the backend canary |

The409 assertion follows current `idempotency::enforce`'s JSON-RPC code and
HTTP dispatch's existing200 wrapper; the design does not prescribe a distinct
transport status. Supporting explicit HTTP409 as well does not permit a stale
success body or generic server failure. No production error mapper is changed.

Compiled red r5: **50 cases,17 passed,33 semantic assertion failures**, actual
cargo exit101,4.18seconds test runtime (8.43seconds including build). Full
`sub4-admission-red-r5/{process.json,run.log}` binds all four exact test/helper
hashes. All six TLS/bearer controls passed, including real trusted/untrusted
construction; six existing meta malformed-key cases passed; both legacy and
read-only repeats passed; meta `_full` removal passed. The other33 fail at
forbidden backend dispatch/re-dispatch or direct `_full` forwarding, with no
compiler or fixture failures. The same targeted command above was used.
Scoped rustfmt and diff-whitespace checks passed. Finder review of these repairs
is required before production implementation; no test gate is inferred from red.

### Second finder disposition

The r2 pair bound SHA256
`484237a51d3b2e76a4bfdc32d984f15ee51f999564d8aea3a1f9346b9075b292`,
198273 bytes, with both actual process exits0 and process_status=ok.
`grok-20260906T190019Z-47569.md` returned SHIP, confirming the original NOW
findings closed. `gpt-20260906T190018Z-47568.md` returned SHIP-WITH-FIXES for
one additional test-observation gap: backend HTTP headers were not captured.
Receipt: `sub4-admission-tests-review-r2.verified.json`; the test gate remains
open until the repair's finder confirmation.

The signed-off fixture ownership boundary was extended narrowly: BackendFixture
now stores each real request's HeaderMap alongside its existing JSON under one
mutex, preserves calls() output and adds call_headers(). The carrier cases
require no outgoing idempotency-key header on every observed backend call;
the actual application/json header is a positive control against an empty
header recorder. Neither auth header contents nor bearer values are printed.
Signing and firewall owners approved/acknowledged the hunk and received the
new helper SHA256
`bd6bb8ad731bac3f6190e5ec49e872a5a6318f61b40538414694b50efe43425e`.
GitNexus returned UNKNOWN for the new untracked start/calls symbols; the static
four-consumer check and owner coordination are recorded in
`sub4-header-fixture-impact.json`.

All five optional r2 improvements were adopted: authenticated policy-listed
keyless positives on both routes; malformed metadata requires HTTP400 alongside
RPC-32602 (matching current meta dispatch); distinct configured verified issuers
with the same subject/key own independent payloads; middleware401 must have an
explicit null ID/error envelope without a result; and modern same-route
authenticated successes require their actual route structure and exact payload.
The modern→legacy compatibility control deliberately retains the legacy reply
shape. Different-issuer cases use the real HTTPS verifier with both trusted
issuer configurations, no injected identity; the exact signed R6 collision
fixture remains a separate pending requirement.

The expanded r6 baseline compiled **54 cases:19 passed,35 semantic assertion
failures**, actual cargo101,4.97seconds test runtime. The authenticated read-only
positives and all TLS/signature/malformed-meta controls passed. Distinct-owner
retries now fail at the stronger exact-payload assertion (Bob/second-issuer
instead of Alice/first-issuer), not a fixture error. The remaining reds are
forbidden dispatch/re-dispatch and direct `_full` forwarding. After adding the
positive application/json header-recorder check, r7 is the final frozen rerun;
its exact result is recorded below before finder review. No behavior fix is
included in either red run. Final r7 compiled **54 cases:19 passed,35 semantic
assertion failures**, actual cargo101,4.47seconds test runtime (8.31seconds
including build). Header-recorder positive checks passed before the existing
carrier re-dispatch red. Full source hashes/process/output are retained in
`sub4-admission-red-r7/{process.json,run.log}`. Scoped rustfmt/diff checks passed.

Final r3 finder pair: **GPT SHIP and Grok SHIP**, both actual process exit0 and
process_status=ok, with identical SHA256
`2b126699137234dcce636d9f4b08d69b6aaf821b1c2eb5f0f2936a8617da35a6`,
156778 bytes. Full runs: `gpt-20260906T192109Z-13614.md` and
`grok-20260906T192109Z-13617.md`; exact-byte/process verification is in
`sub4-admission-tests-review-r3.verified.json`. This closes the first HTTP
test-leg gate only. Both full outputs were read. Optional media-type tolerance,
combined recorder accessor, tighter401 code, earlier header-only assertion and
separate second-issuer signing-key refinements are deferred under the operator's
time/token pause; neither vendor classified them as blockers. All running
commands were reaped. No core scaffold, admission activation or R6 probe was
started; the coordinator's milestone plan governs the next work.

Still required before the full admission/task increment can close: structured
verified-owner collision/R5 crafted spoof vectors, independent4096/4097byte and
retained-result/aggregate bounds, true concurrent admission/settlement, Task-mode
ownership and durable rebuild, explicit built-in classification/management and
orchestration effect loss, actual stdio compatibility, and all §10 lifecycle,
storage/security and independent functional cases. Their matrix rows remain
pending. This first test leg cannot be used to mark those criteria MET.

## 12. Bounded delivery leg: Task wire model and legal lifecycle

FOR: replace the two current TASK.1 model failures and complete the five-status
model needed by the store/worker increment, plus the already-approved TASK.1.5/.7
era/name mappings before the first tests-review freeze. OUT: persistence I/O, admission,
router changes/capability advertisement, durability, worker dispatch, principal
checks, transport acceptance, and ownership of gateway input-round allocation.
This implements the already-approved §3.1/§13 contract; it does not reopen the
full-lifecycle design or mark its system criteria complete. The coordinator
approved explicit-clock transitions and a private snapshot distinct from the
flat public projection. Reuse `JsonRpcError` and MRTR `InputRequired`.

Current source is pinned in `OUT/task-model-baseline.json`: delivery HEAD
`0d4df3c0`, task model SHA `b971f73f16879fb40891fa9355a8718df23cbf69f3a493bfb0ea960e244f4280`.
The design gate is GPT r5 SHIP, actual0, authoritative material
`bd1e78c214242a7a8c6bbc0310293ccdb56351a2d7d1fd9bfd18f7c00d60eeb7`,
210396 bytes, retaining Grok r2 SHIP. Earlier external r5 manifests hashed a
shorter payload; the canonical ledger binding is authoritative, not that stale
manifest. Original change identity and findings are preserved.

| Case | Existing acceptance | Model observation and meaningful falsifier |
|---|---|---|
| MODEL-01 | TASK.1.2 / §3.1 | Five exact status spellings; flat wire fields with ISO timestamps, required nullable `ttlMs`, optional `pollIntervalMs`/`statusMessage`, opaque v4 UUID ID. Missing/extra payload or secret internal field fails. |
| MODEL-02 | TASK.1.6 | Rewrite the two old string assertions to check the JSON value's actual object type and exact code/message/data. Ordinary tool result with `isError:true` remains completed. No serialized JSON-inside-String compatibility shim. |
| MODEL-03 | TASK.1.2 / CANCEL-01 model half | Complete/fail/cancel from working and input-required; every terminal state resists every later transition with byte-identical wire and snapshot, including timestamp. Test both ordering choices explicitly; no concurrency/store-commit claim. |
| MODEL-04 | INPUT-01/02 model half | Partial valid responses remove only their outstanding keys and return only the accepted subset; unknown/already-answered keys are ignored without timestamp change. Final response returns working exactly once. Invalid top-level/entry response types reject atomically before a valid peer entry can mutate. |
| MODEL-05 | INPUT-03 model half | Preserve supplied gateway keys; reject duplicate/reused keys and replacing an outstanding round. Later disjoint keys work. Store remains the allocator of durable round numbers and owner of resume revisions. |
| MODEL-06 | TASK.1.2 / §13.3 | Explicit timestamps advance on accepted mutation, never on no-op/rejection, never move backward; creation/TTL/poll values stay immutable through every lifecycle change. No expiry/default-reload claim. |
| MODEL-07 | §13.3 model prerequisite | Private snapshot round-trip preserves tool and consumed-key history while public projection excludes them and opaque backend requestState. Unsupported snapshot version or inconsistent task state fails. This is serialization validation, not durable storage or restart acceptance. |

MODEL-08 additionally covers TASK.1.5/.7 (§3): the modern-method set includes
`tasks/cancel` and `notifications/tasks`, preserves subscription membership and
excludes existing core methods. The actual shared `HeaderCheck` rejects missing,
wrong and decoy task names and accepts the exact `taskId`; existing core method
name/URI behavior and non-name methods remain controls. These validate the
protocol dependency, not HTTP caller execution or advertised Tasks support.
The coordinator's GitNexus impact is HIGH14 for name mapping (three direct
callers, one router process), and LOW0 graph references for the added-method
constant; its real era-gate caller was confirmed statically. The runtime maps
remain unchanged until the combined tests gate closes.

Cheap first check: the two existing object-error cases must compile and fail on
actual string payloads. Added API-only scaffolding is then compiled with the
new finite model cases; no-op placeholders are temporary and cannot count as an
implementation or a compiler-error RED. Separate tests-as-tests gate precedes
runtime behavior. Then implement, run focused cases, Clippy/fmt, critical model
coverage/mutations and final dual code review. Coordinator-owned public driving
waits for the store/routes and is explicitly not satisfied by these model tests.

Model test checkpoint: the original two error-object cases each compiled and
failed on an actual bare string (`task-model-original{,-task-acs}-red.log`).
The new finite model set plus rewritten existing cases then compiled: 12
assertion failures and 6 positive controls, actual101, in
`task-model-tests-red-r1.log`. No compiler failure is counted. The delivery
base emits 57 library warnings from parallel unfinished modules; the full log
preserves them. Only a stale three-status comment was removed after this run;
assertions and scaffolding are unchanged for tests-as-tests review.

Combined wire/model RED checkpoint: `task-model-tests-red-r2.log` compiled all
three targets and produced16 assertion failures /6controls, actual101. The four
added failures are missingcancel era membership, missingtask notification era
membership, missingtaskId mapping, and actual HeaderCheck accepting absentname.
An unused nested import introduced during testediting was removed; it changes
no assertion or behavior. The exact cleaned test source is rerun beforefreeze.

The separate tests gate ran as `mcp-v4-task-model-tests-20260907-r1` on
actual bound material `7b2ea78698be13746b3b61cd35012aa1de180564d5938d13cf5e884a3086f8a2`,
50626bytes: GPT SHIP-WITH-FIXES and Grok SHIP, both processok/actual0;
`OUT/task-model-tests-r1-initial.verified.json` retains the authoritative rows.
GPT's two NOW findings were confirmed and repaired only in the test helpers:
exact allowed fields/private fixture values for all five public statuses, and
public timestamp plus immutable-record fields after every accepted event in the
existing transition matrix. No contract or runtime change. Optional refinements
from either vendor remain deferred. The repaired sources compiled with the same
16 assertion failures/6controls (`task-model-tests-red-r3.log`, actual101).
Narrow finder confirmation is `mcp-v4-task-model-tests-20260907-r2`, material
`7af3b3071c39f2161055b04a97fa9da39b961c8fe5c3b6389f14e35d56e18b8c`,23169bytes.
The unindexed test helpers have static test-only callers. The `apply` impact
query was made after its edit (UNKNOWN/not-found), an ordering lapse recorded
without claiming pre-edit graph verification; no production symbol was involved.

## 13. Next executable milestone: durable Task store prerequisite

The coordinator accepted this bounded next delivery on 2026-09-07. FOR: the
STORE-01/03/04/06 and CANCEL-01 persistence primitives already specified in §10
and design §13.3, using the reviewed Task model. OUT of this first milestone:
router/stdio edits, Task advertisement, backend execution/resume, subscriptions,
and a second admission authority. Their existing system rows remain pending.
Target paths are new `src/gateway/task_service/{mod,record,store}.rs` and focused
child tests; coordinate the one module registration with the release lead.

First executable result: a clean private directory accepts an explicitly
pre-admitted record; owner-bound reads and legal mutations persist; reopening
retains exact terminal wire/state/timestamps and consumed-key history. Wrong
owners, malformed IDs, conflicting revisions, unsafe file types/permissions,
corrupt/version-unknown records and a second directory owner refuse without
silently resetting bytes. File/fsync/rename/directory-sync fault injection must
keep uncommitted state unpublished; uncertain durability poisons readiness.
These component/system primitives do not close the HTTP crash/recovery rows.

The shared admission owner retains `Lease` publication/recovery extensions.
The durable record needs admission-owned identity and stable-principal digests,
operation/representation digests, metadata reservation and Task-mode proof.
Construction comes from the owned lease; the store must not duplicate
`Request::prepare` hashing/accounting or use synchronous `complete_secured`.
The first primitive can consume an explicit pre-admitted boundary; live Task
publication and startup rebuild wait for that typed seam. Task IDs are the
model's canonical `task-` plus UUIDv4 (41 ASCII bytes). Existing root lint and
production finalizer integration remain release-lead ownership.

Model implementation checkpoint (2026-09-07): the separate tests gate closed
before runtime (GPT finder r2 SHIP, retained Grok r1 SHIP). Final focused runtime
`task-model-green-r3` is59/59 PASS, actual0. Coverage-r2 is214/214 model lines,
26/26 functions and271/273 regions; branches were not instrumented. Initial
mutations found10 real oracle gaps; bounded MODEL-05/07 tests catch all10 after
repair. The final mapped evidence is54/54 viable candidates caught and8 compiler-
unviable candidates excluded across two pinned snapshots, not a whole-corpus
final-SHA claim. `OUT/task-model-mutation-incremental-binding.json` proves exact
unchanged function bodies and candidate identities for retained results.

Final code r1 was GPT SHIP-WITH-FIXES/Grok SHIP on actual material
`cf3c85004266a6e8b12301959cfbb8304688e70d9469f3ff0571a18c89499a8d`,49838bytes.
A public-API snapshot probe compiled and confirmed GPT's explicit-null data-loss
finding (1 assertion failure/2controls, actual101); the private error decoder now
preserves null, absence and nested values. GPT finder r2 is SHIP/processok/actual0
on `d4e747d86f9e087c12e85dfbc267b4a7c42bfd422c25ef7fe3d8cddae7bd5608`,22854bytes;
`OUT/task-model-code-finder-r2.verified.json` retains the exact receipt. Optional
wrapper and extra decoder-oracle suggestions remain deferred. Model source SHA
is `28087114cba4df85db40b92c644ac3480e38e7d1546846cd2be17419870f77ff`.
The global strict lint and production Task service/public acceptance/delivery
chain remain open; no complete Task lifecycle or release DoD is claimed here.

### 13.1 Store primitive executable test boundary

The first store packet reuses §13.3's approved design and §10's test rows. It
adds no identity derivation: the release lead settled stdio as an admission-owned
`StdioLocalOperator` binding within the protected store/service realm, without a
path hash or a new identity file. The store only consumes admission-owned values.
Its temporary `PreparedTask::for_test` constructor is cfg(test); production Task-
lease conversion, publication and recovery remain admission-owner dependencies.

Twelve focused tests cover: create/read/reopen; all three terminal outcomes and
consumed-key history; owner/revision refusal with disk/view preservation; both
terminal commit orders; corrupt/unknown-version/duplicate binding refusal; prompt
second-owner refusal and close/reopen; malformed IDs; Unix private permissions
and unsafe file types/symlinks; five create I/O fault boundaries; the same five
settlement boundaries; an actual paused directory-sync acknowledgement/view
barrier; and independently exercised per-owner/count/record/logical-byte caps.
The hook is a test-only fault seam at the real ordered writer boundaries. The
pause is bounded and released before assertions, not a sleep-based proof.

This primitive retains committed snapshots on reopen; startup execution-outcome
reconciliation, dispatch markers, input-round allocation, expiry/dedupe deletion,
TaskBinding index rebuild and cross-process/HTTP crash tests remain the following
service integration work. These tests do not claim those system rows passed.
The backend/tool and binding record is private and has no raw token/session field.
A single new `pub(crate) mod task_service` registration is the only shared-file
change. New TaskStore impact is UNKNOWN/not indexed; static consumers are these
new tests until service wiring. Initial11 cases compiled and failed on the explicit
Unavailable scaffold, actual101; no compiler-error RED is counted. Self-QA added
the settlement-fault oracle and separated logical capacity from the count cap
before tests-as-tests freeze. No persistence behavior is implemented at this gate.

Store P2 r1 returned GPT/Grok SHIP-WITH-FIXES, both processok/actual0 on
`1d69fc155a371b4587ead6091778d53e6b39c6a3e5676715bfdc7992254c61fe`,51717bytes.
`OUT/task-store-tests-r1-initial.verified.json` retains both receipts. The only
plan drift during those reads was the coordinator-authorized pending
STDIO.OWNER.2 row; removing that one row reconstructs the exact original plan
hash. No test/scaffold changed during either live-source review. The finder
binds the current plan, including that row, without altering historical ledgers.

All six mandatory oracle findings were confirmed and repaired: stage-specific
file layouts plus reopen after each pre-rename creation failure; a symlink-aware
manifest of kind/inode/mode/target/bytes after refused startup; lease and temporary
0600 permissions; discovery of the actual created lease sidecar; planted valid
Task payloads at traversal/absolute/encoded targets entirely inside the tempfile;
and a count limit whose logical-byte budget still has space. The separate logical
budget case is retained. Test helpers moved into `store_tests/support.rs` to keep
each source file below800 lines; assertions are not replaced by a fake store.

The test seam names now have an exact intended position: Write after creation of
the private unique temp but before bytes; Flush after complete write; FileSync
after flush; Rename after file sync; DirectorySync after rename. Each callback
precedes its named operation. A paused Write observes private empty temporary
state; a paused DirectorySync observes the complete final file while the handle
and committed view remain unpublished. The hook cannot itself prove power-loss
durability or replace the later process/system rows. Final repaired12 cases
compiled/assertion-RED, actual101 (`task-store-tests-red-r3.log`), before any store
runtime behavior. Optional live-duplicate and timestamp refinements are deferred;
no transport, identity or lifecycle acceptance was removed.

Store runtime checkpoint, 2026-09-07 (Claude implementation slice). The tests P2 gate is
CLOSED: run `mcp-v4-task-store-closure-20260907-r3`, material
`4debcd8aa1ee55780b351de18432f474ee214ea2b832fc988290958a048f0c52`/53869bytes, GPT and Grok
both SHIP, both processok/actual0, both bound to head `0d4df3c0`. Grok's remaining
resolve-the-ID-through-the-production-join suggestion stayed an IMPROVEMENT, not a NOW finding,
and is disposed as a recorded observation: reads are served from the committed in-memory image
and the identifier is model-validated before any filename is derived, so there is no single
production join for a fixture to borrow. `OUT/task-store-claude-closure-r3.verified.json`
retains both ledger rows and `gate_closed:true`.

The runtime now exists. One ordered writer; a lifetime custody lease through the existing
`ExclusiveFileLock::try_acquire` rather than the blocking `acquire`; the reviewed atomic order
mirrored from `control_plane::store::write_atomic` without altering that module — private0600
temp, payload, file sync, rename, parent-directory sync. Reads are served from committed
snapshots, so an inbound identifier is only ever a map key and a filename is derived only from
an identifier `Task::from_snapshot` already validated. A foreign owner reads as NotFound.
Failure before the rename is a clean refusal leaving the committed view and on-disk record
untouched; failure at or after it poisons readiness instead of reporting a state memory cannot
vouch for. All twelve reviewed cases pass, actual0 (`task-store-claude-green-r1.log`).

OBSERVABLE CONTRACT CHANGE, recorded as a design event rather than left for review to discover:
`StoreError` gained one variant, `InvalidTransition`. The reviewed scaffold had no truthful
answer for "the model refused this event and nothing was written". `Storage` would name the
filesystem for a caller-contract violation; returning the unchanged view would make a refusal
indistinguishable from a legitimate late no-op, and that distinction is load-bearing because a
late terminal outcome IS Ok while a malformed payload is not. Scope: one variant on an internal
`pub(super)` enum with no wire projection and no production consumer; no acceptance criterion,
protocol payload or model behavior changes. It is pinned by
`store_03_refused_events_never_reach_the_writer_or_change_the_committed_view`, whose oracle is a
commit hook that counts entries and fails on any of them, so an implementation validating after
serialization answers `Storage` and the case fails.

Two persistence negatives were added to the corruption oracle for runtime behavior no existing
case observed: `rebound` (an intact record moved under another legal task name must not rebind
to it) and `snapshot` (legal JSON the model refuses to restore must surface as a corrupt
record, not an accepted task). Each row now names itself in its assertion message.

Those three assertions were written after the code they check, so under the retrofitting
exception each carries a falsifier probe that restores pre-fix content, runs, and verifies the
restore by RE-RUNNING rather than by `git status` (`task-store-claude-falsifier-probe.log`,
script retained). Defeating the refusal mapping fails the refusal test at its own assertion,
actual101; defeating the record-name binding fails the `rebound` row, actual101; defeating the
unrestorable-snapshot mapping fails the `snapshot` row, actual101. Each restore returns actual0.
Honest limit on that evidence: the capture filter kept the panic location but not the panic
message, so row attribution inside the corruption oracle rests on line231 plus row order rather
than on a captured label.

THE STATIC INTEGRATION GATE IS OPEN AND IS REPORTED OPEN. The module has no production
consumer, so its symbols warn; a blanket `#![allow(dead_code)]` was introduced during
implementation and REMOVED on root instruction, not replaced. A measured probe enumerated
exactly35 items it had been hiding — every type, constant and function in `store.rs` and
`record.rs` — and because Rust's dead-code analysis is reachability-based, each of the20
private helpers was separately confirmed to have a caller inside the module; none is orphaned.
One further warning is left visible: `close()` is an `async fn` with no `.await`, which is the
reviewed scaffold signature the tests already await, and is not rewritten to silence a lint.
The 76 inherited crate clippy errors are pre-existing and outside this slice. Coverage and
mutation for `store.rs` are NOT measured. No route integration, transport publication,
TaskBinding rebuild, dispatch checkpoint, expiry, dedupe deletion, cross-process lease
contention, HTTP/stdio routing or UAT row is claimed. FUNCTIONAL PASS is N/A for this slice:
nothing in production constructs a `PreparedTask`, so there is no running surface to drive.

Store runtime review and repair, 2026-09-07. The runtime code review returned GPT
SHIP-WITH-FIXES and Grok SHIP on material
`3055ae826be0269ec6d4bc31ca7de06e0efa1801e70368bb65e3b78a23bddc21`/107075bytes, both
processok/actual0. Four defects were confirmed at source, three of them raised independently by
both vendors: shutdown releasing custody without joining an in-flight writer AND the ordering
lock living in the caller's future so a cancelled call dropped exclusivity and skipped
publish/poison; `create` rejecting neither a live task id nor a live admission identity;
startup `load` applying no `StoreLimits` at the disk trust boundary; and the temporary-file
counter restarting at zero so a crash orphan collided with the next attempt.

The first was answered by CHANGING THE APPROACH rather than patching, per repair-protocol step
zero: validate, admit, write and publish-or-poison now run to completion inside one blocking
task under a std ordering mutex, and `close` takes the same lock, which is the "one ordered
store worker owns mutations" §13.3 asked for. Cancelling a caller can lose the ANSWER; it can no
longer lose the publish. Temporary naming reuses the reviewed in-repo
`oauth::storage::create_secret_tmp` shape — bounded nonce retry, process id in the name, and
only a path this attempt created is ever removed, so a colliding orphan is stepped over rather
than consumed. An earlier draft seeded the counter from wall-clock nanoseconds; that is
improbability, not uniqueness, and it was withdrawn.

SECOND OBSERVABLE CONTRACT CHANGE: `StoreError::Duplicate`, disclosed as a design event on the
same terms as `InvalidTransition`. One variant on an internal `pub(super)` enum, no wire
projection, no production consumer, added because the loader already enforces uniqueness and a
writer that does not can produce a directory that refuses to open.

Six repair-driven cases were added in `store_tests/durability.rs`, every wait a channel
handshake or a join on the ordering lock and no sleeps anywhere. They were written AFTER the
repair, so under the retrofitting exception each was run against the exact pre-fix runtime
`031d2450…` in an isolated probe source and shown to fail there: 1 passed/6 failed, actual101,
against 8 passed/0 failed, actual0, on the repaired runtime `0b6d581e…`
(`task-store-claude-prefix-probe-r3.log`). That is RECOVERY for tests written after code, not
evidence that test-first order was followed. Two probe rounds were needed because the first
exposed two defects in the fixtures themselves — a close oracle that PASSED against the broken
runtime, and a single-use pause channel that panicked a worker on re-entry. The shutdown attempt
is now witnessed by a handshake sent from inside the shutdown task, and the cancellation is
proven landed (`JoinError::is_cancelled`) before the write is released.

Full suite on the repaired runtime: 21 passed, 0 failed, actual0. `rustfmt --edition 2024
--style-edition 2024`: actual0. Three real clippy lints in the new code were fixed rather than
allowed. The dead-code warnings remain and the STATIC INTEGRATION GATE REMAINS OPEN. Coverage
measured on the pre-fix revision (314/320 lines, 98.12%, 48/48 functions) is STALE for this one
and is re-measured with mutation against the frozen repaired source; neither number is claimed
here. No route integration, transport publication, TaskBinding rebuild, expiry, dedupe deletion,
cross-process lease contention or UAT row is claimed.
