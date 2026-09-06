# TASK.1 — tasks extension: §P2 test plan

**Status:** §P2 test plan, awaiting dual-vendor review. No test code exists yet; this document is
what the test code will be written from, and what a reviewer reads *instead of* the tests on the
first pass.

**Design:** `docs/design/2026-08-31-task-1-tasks-extension.md` (§P1, dual-vendor SHIP-WITH-FIXES).
That note is the survivor; the 2026-09-05 duplicate was deleted in `cb00805a` and must not be
resurrected.

**Dependency:** commit `8ab52da8` gates the *code* this plan describes, not the plan. The plan is
reviewable and mergeable ahead of it; no row here waits on it to be written.

**Ledger position:** `MIK-7272.TASK.1` is one row. `.12` and `.13` are design-note criteria under
that parent row, not ledger rows of their own — settled by the team lead on 2026-09-06, not
reopened here.

## 0. Scope

**FOR:** one test case per acceptance-criterion clause of `MIK-7272.TASK.1`, each with its V-model
level, its type, and an honest statement of whether it can fail against HEAD.

**OUT:**
- test code (that is §P2's second half, not this document)
- the criterion *text* — the design owns it. Where this plan disagrees with the design's wording,
  the design wins and this plan is wrong.
- SUB.2's own criteria. `.9` and `.12` name SUB.2 as a trigger; they do not specify it.
- the four deferred §P1 fields for anything already deferred there.

**Authority split:** the design owns *what must be true*. This plan owns *which case proves it and
whether that case can fail*. A row here that invents a requirement the design does not carry is a
defect in this plan, and the repair is to delete the row, not to widen the design.

## 1. Row order is deliberate

The table runs `.1 .. .9`, then `.11`, then `.10`, then `.12`, `.13`. `.11` precedes `.10` because
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
| `.3` | timestamp advance; refusal of unmatched `inputResponses` keys; the empty `complete` ack shape; the cooperative-cancel licence |
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

One row per clause. The last column is the honest one: can this case fail against HEAD `22084cfb`,
and why. A row that cannot fail for a *behavioural* reason names its trigger — which assertion goes
live, in which increment, owned by whom — inline. A vacuous row without that triple is not a plan
row, it is a wish.

| clause | case | level | type | red on HEAD `22084cfb`? |
|---|---|---|---|---|
| `.1` | task-augmented `tools/call` from a declaring client returns `CreateTaskResult` with `resultType: "task"`, and `tasks/get` resolves the returned id **in the same test** | integration | functional | **No — vacuous.** No arm in `handlers.rs`; red for absence. Any stub passes. **Trigger:** the `tools/call` task arm; increment TASK.1 piece 4; owner TASK.1. |
| `.2a` | `working` serialises with no `result` and no `error` | unit | contract | **Yes.** `TaskStatus` exists with three variants; this one is assertable now. |
| `.2b` | `completed` carries `result` | unit | contract | **Yes.** |
| `.2c` | `failed` carries `error` | unit | contract | **Yes** — and see `.6a`: it fails to *compile* against the current `Option<String>`, which is the intended red. |
| `.2d` | `input_required` carries `inputRequests` | unit | contract | **No — the variant does not exist**, so this does not compile. §11.2 puts `input_required` out of scope for this release. **See §8 Q1 — this row may be the wrong row.** |
| `.2e` | `cancelled` serialises with neither `result` nor `error` | unit | contract | **No — the variant does not exist.** **Trigger:** the enum gains the variant; increment TASK.1 piece 2; owner TASK.1. |
| `.3a` | `tasks/update` advances `lastUpdatedAt` | unit | functional | **No — vacuous twice.** `lastUpdatedAt` is not on `Task` (compile-red) *and* nothing dispatches `tasks/update`. **Trigger:** the field, then the dispatch arm; TASK.1 pieces 2 and 4. |
| `.3b` | `tasks/update` **refuses** an `inputResponses` key matching no outstanding input request — and with `input_required` out of scope there are never outstanding keys, so any non-empty map is refused | unit | contract | **No — vacuous.** No handler. **Trigger:** the `tasks/update` arm; piece 4; owner TASK.1. This is the clause a timestamp assertion silently drops. |
| `.3c` | the acknowledgement is the empty `resultType: "complete"` shape | unit | contract | **No — vacuous.** Same trigger as `.3b`. |
| `.3d` | `tasks/cancel` marks the task cancelled and returns **without** the backend call having stopped (cooperative cancel is licensed, not a defect) | integration | functional | **No — vacuous.** Depends on `.2e`'s variant *and* the dispatch arm. Written now so the licence is asserted rather than discovered by a reviewer as a bug. |
| `.4a` | a client declaring on request 1 and omitting on request 2 gets `MISSING_REQUIRED_CLIENT_CAPABILITY` on request 2 — not a task | integration | negative | **Yes — the row that catches a stub.** A dispatcher returning tasks unconditionally passes `.1` and fails this. |
| `.4b` | the error carries `data.requiredCapabilities.extensions["io.modelcontextprotocol/tasks"]` | integration | contract | **Yes, and for a shape reason, not only a routing one.** The number is settled: `MISSING_REQUIRED_CLIENT_CAPABILITY = -32021` (`src/protocol/era.rs:58`), confirmed by the pinned 2026-07-28 text — nothing deferred. What is red is the **payload**: today's guard (`src/gateway/router/handlers.rs:804`) emits `data.requiredCapabilities` as a **list of capability strings**, not the `extensions["io.modelcontextprotocol/tasks"]` map this clause asserts. Assert the serialised `data`, never the code alone. Note also that the handler emits `-32021` as a **bare literal** rather than the constant (as does `meta_mcp/invoke.rs:690`), so a unit case asserting the constant cannot observe a handler that drifts from it — assert the wire value. Measured on both emitters (HEAD `22084cfb`): `invoke.rs`'s `undeclared_input_request` builds `REQUIRED_CAPABILITIES_DATA_KEY: [capability]` — the same list of strings — so the `tools/call` path this clause actually runs on is red for the same shape reason the router is, not merely by inheritance from it. |
| `.5` | a 2025-era peer calling `tasks/cancel` is refused `-32601` by the era gate | unit + integration | negative | **Yes, red now, for a real reason.** `ADDED_IN_2026_07_28` does not list `tasks/cancel`, so the gate lets it through today. Independent of the dispatcher — a list-membership assertion plus one router case. |
| `.6a` | a `failed` task carries the JSON-RPC `error` **object** | unit | contract | **Yes, red now.** The field is `Option<String>`; an object cannot be represented, so this fails to compile. |
| `.6b` | a tool result with `isError: true` is `completed` with `result`, **never** `failed` | unit | classification | **No — vacuous.** Nothing classifies backend results yet. **Trigger:** the result-to-status mapping; piece 4; owner TASK.1. |
| `.7` | `Mcp-Name` on `tasks/get`, `tasks/update`, `tasks/cancel` mirrors `params.taskId` | unit | contract | **Yes, red now.** `mcp_name_body_field` returns `None` for all three ("exactly these three" methods); no dispatcher involved. |
| `.8a` | a retried call carrying the **same client idempotency key** returns the **same** `taskId` and runs the backend **once** — mutation counter on the mock tool asserts 1 | integration | functional | **No for the dedupe half.** Needs the store. **Fixture is binding:** `config.cache.enabled = false`, because the response cache is written after the backend result and before the client stream, so an enabled cache passes this vacuously. Assert the counter, never the body. **Trigger:** the idempotency store; piece 3; owner TASK.1. |
| `.8b` | the dedupe key is `(authenticated principal, client idempotency key)`, and a same-key/different-body call is **rejected** against the stored fingerprint | integration | negative | **No — vacuous.** No store, no fingerprint. **Trigger:** same as `.8a`. Written separately because a key on the idempotency string alone passes `.8a` and lets one principal claim another's task. |
| `.8c` | two identical calls carrying **different** keys produce **two** `taskId`s and a mutation counter of **2** | integration | functional | **No — vacuous**, and it is the row that stops `.8a` being satisfied by a global "one task per body" cache. |
| `.8d` | a **keyless** repeat gets a new task every time | integration | functional | **No — vacuous.** Same trigger. The clause exists because "retried identical call" reads as body-identity until this row says otherwise. |
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

**Tally.** Of 33 clause rows — 32 cases plus `.12c`, which is a verdict rule and not a test — 11
can fail against HEAD for a behavioural or compile reason: `.2a`,
`.2b`, `.2c`, `.4a`, `.4b`, `.5`, `.6a`, `.7`, `.8e`, `.8f`, `.10b` — with `.13a`/`.13b` partial.
The rest wait on the dispatcher or on SUB.2 and must be written **against the spec text**, not
against whatever the dispatcher turns out to do. That asymmetry is the plan's headline finding:
TASK.1 is mostly new surface, and the tests that constrain it on day one are the ones asserting
against code that already exists.

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

No violation found that this plan then committed. `.2d` is not a rule violation — it is a scope
question, and it is in §8.

## 8. Open questions

**Q1 — `.2d` and the `input_required` scope boundary. For the lead.**
`.2` asserts five status shapes. §11.2 of the design puts `input_required` **out of scope for this
release** — its own words: "with `input_required` out of scope there are never outstanding keys, so
any non-empty map is refused". `.3b` is written against exactly that reading. So `.2d` asserts a
shape this release does not ship, and `.2e` asserts a variant that does not exist either.

Two coherent answers, and choosing between them is not this plan's call — narrowing a criterion
needs the requester's recorded agreement (repair protocol, step 0):

1. **Narrow `.2` to the statuses this release ships.** `.2d` is deleted, `.2e` stays only if
   `cancelled` ships (it must, for `.3d`). Cleanest, and makes the ledger row honest.
2. **Keep all five and mark `.2d` deferred**, with the four §P1 deferred-unknown fields (owner,
   what resolves it, when, what if it resolves badly), alongside the four fields already carried
   there.

Recommendation: (1) for `.2d`, because a criterion asserting a shape the release does not ship
cannot be met and will read as a permanent amber cell; (2) is right only if `input_required` is
coming back inside 4.0.0. **Not decided here.**

**Q2 — SUB.2 owns the triggers for `.9` and `.12`, and TASK.1 cannot close them.**
Both rows name SUB.2's emit and admission paths as what makes them non-vacuous. That is a
cross-criterion dependency, not a TASK.1 deliverable. Question for the lead: do `.9` and `.12`
carry SUB.2's four deferred-unknown fields in the design (owner SUB.2, resolved by the emit path
landing, when = SUB.2's increment, fallback = the criterion stays open), or does TASK.1 hold them
open under its own row? The plan is written for the first reading; the second changes who is
blocked when SUB.2 slips.

**Q3 — no third question is open.** Recorded so silence is not read as an omission.

### Answers

**Q2 — answered: SUB.2 owns the fields; these rows cite, they do not restate.** Two documents
carrying the same four fields is two owners for one fact, and the repair protocol's remedy for
"two components can disagree about X" is one owner of X, not a check that detects the
disagreement. So `.9` and `.12` name SUB.2 as owner and stop there; when SUB.2 slips, one date
moves and both rows follow it.

That answer exposes a gap in the other document rather than closing one here.
`docs/design/2026-08-29-subscriptions-listen-stream.md` is 135 lines with no deferred-unknown
section at all — measured 2026-09-06, zero matches for owner, defer or fallback across the file —
so the fields this plan cites do not yet exist to be cited. That is a §P1 finding against SUB.2,
disposed as **write it into the design**, owner the SUB.2 author, and it is not this plan's to
repair: editing another workstream's committed design to supply its missing fields would put a
second author's words under the first author's name. Until they land, `.9` and `.12` are blocked
on a dependency whose own schedule is unrecorded, and the rows should say exactly that rather
than implying a date nobody has given.

**Q1 — not answered, and deliberately not.** Narrowing an acceptance criterion needs the
requester's recorded agreement before it happens, and no lead can supply it on their behalf; a
ruling written here would be the agreement forging itself. The recommendation that goes to the
requester is (1), for the reason this section already gives. Until they answer, the plan holds at
the shape of (2) — `.2d` stays, red, marked deferred with its four fields — because that is the
state that presupposes neither answer, and (1) destroys the row that records the question.

The consequence is worth stating plainly rather than leaving to be discovered: a deferred item
blocks whatever depends on it, and the `TaskStatus` variant list depends on this one. That list
is where the decision becomes irreversible in code, so it does not get written until the
requester answers. Work elsewhere in TASK.1 is not blocked.

## 9. What this plan does not do

No test code. No verdict trailers — no vendor has reviewed this document, and stamping one would
be a forgery of the thing that makes the gate worth having. This plan enters the §P2 plan-review
round riding with the TASK.1 implementation hop; the `.12`/`.13` additions travel with it.
