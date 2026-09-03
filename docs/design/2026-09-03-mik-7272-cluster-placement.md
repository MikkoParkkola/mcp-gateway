# MIK-7272 — which design owns each of the seven open protocol criteria, and what they change together

**Status**: proposed, for dual review before any implementation
**Scope item**: MIK-7272 (MCP 2026 protocol conformance) · `docs/requirements/RELEASE-4.0.0-criteria-status.md:196-219`

## Scope (§P0)

**FOR** — for each of the seven MIK-7272 criteria still open, name the design that owns its
placement, state what the seven changes together mean for an existing deployment, and place the one
constraint that review found stated in one design and owned by none.

**OUT** — writing the code; **re-deciding anything an existing per-row design already settled**;
the MRTR rows; test code; fixing the stale source locations in the tracking files; every criterion
already marked MET.

## What this document is, after review round 2

It was commissioned on the premise that no design exists for this cluster. That premise is false
for **all seven rows**, and the correction is the document: a first draft made independent
placement decisions for ORDER.2, SUB.2b, EXT.1 and OTEL.1, and two of those contradicted reviewed
designs that had already chosen differently. Those sections are removed rather than repaired —
elimination, not a patch, because a second copy of a decision drifts from the first and an
implementer cannot tell which one binds.

| row | owning design | state of that design |
|---|---|---|
| ORDER.2a / ORDER.2b | `docs/design/2026-08-31-cluster-b-connection-invariance.md` §I | decided; its §4.1 records the operator's answer of 2026-08-31, which selects option (b) |
| SUB.2b | same document, §II | decided; its §4.3 records the operator's answer of 2026-08-31, option (i) |
| SUB.4 | `docs/design/2026-08-31-sub-4-idempotency-wiring.md` (rev 4) | decided; one operator question open |
| EXT.1 | `docs/design/2026-08-31-cluster-b-capability-and-trace-metadata.md` §3.1-3.2 | decided |
| OTEL.1 | same document, §3.3-3.5 | decided; two numeric bounds deferred |
| TASK.1 | `docs/design/2026-08-31-task-1-tasks-extension.md` | decided |

Every one of the seven is therefore designed, by **four** design documents — the count of documents
is smaller than the count of rows because two of them each own two rows. **What was genuinely
missing is not placement — it is the cross-row view**, and that is all this document now contains:
the decisions that only appear when the four designs are read together, the order they have to land
in, and the deployment impact none of them can state alone because it is the sum of the others.

## Three cross-row facts, none of which a single-row design can state

**1. Re-issue safety has one owner, and TASK.1 already named it.** *When the tasks extension is
negotiated on a request, the task store owns re-issue safety; the idempotency cache is neither
consulted nor written for that call* (TASK.1 design §4). One structure decides; the second cannot
disagree because it is not asked.

That rule survives a change underneath it, and the change is only visible across the two documents.
TASK.1 §4 argues the rule from a live defect — `resolve_idempotency_key` auto-derives a key for any
keyless call, so a task-augmented call would get one. SUB.4's operator-answered decision **deletes
that derivation** (`_meta` carries the key on both routes; "keeping automatic derivation" is listed
among the rejected options). So the collision TASK.1 describes is a property of today's code, not of
SUB.4's. The rule still has to exist — a client that sends both a key and a task-augmented call
would otherwise be judged twice — but its stated mechanism does not survive SUB.4. TASK.1's §4 is
correct in its conclusion and stale in its premise; correcting that sentence belongs to whichever of
the two lands second.

**2. SUB.4's both-routes answer settles an OTEL.1 question that OTEL.1 left open.** The
capability-and-trace design's §4.4.3 asks whether the direct route `POST /mcp/{name}` needs trace
propagation, and answers it by inheritance: *"This is the same two-route question SUB.4 already put
to the operator… If the answer for SUB.4 is 'both routes', OTEL.1's scope grows with it."* SUB.4's
design now records that answer — both routes, decided 2026-08-31. **OTEL.1 therefore covers the
direct route**, and no operator question remains on it. Nobody reading OTEL.1 alone can see this,
because the answer landed in a different document after that sentence was written.

**3. TASK.1 states a constraint on SUB.2's design that SUB.2's design does not record.** TASK.1 §5:
a task-scoped `subscriptions/listen` stream carries `notifications/tasks/status` only, and must not
carry `notifications/progress` or `notifications/message`; it says *"SUB.2's design owns
request-scoped notification routing; this is a constraint on it, recorded here because TASK.1 is
what discovered it."* Checked: `docs/design/2026-08-29-subscriptions-listen-stream.md` contains no
occurrence of "task", and the connection-invariance design's §II does not carry it either. **The
constraint is stated in one document and owned by none.** It is assigned here, and this is the one
placement this document makes: **the filter ships in the TASK.1 increment**, because TASK.1 is what
makes a task-scoped stream exist and TASK.1's own acceptance criterion `MIK-7272.TASK.1.9` already
tests it. SUB.2b implements the routing; TASK.1 adds the task-scoped case to it.

## Order, and why it is not free choice

| land | before | because |
|---|---|---|
| EXT.1 | TASK.1 | TASK.1 is an extension and needs the negotiated set; building it second means building a private negotiation path and then deleting it |
| SUB.4 | or with TASK.1 | SUB.4 deletes the automatic key derivation. TASK.1 landing first, alone, ships the two-mechanism collision its own §4 describes; SUB.4 landing first removes the mechanism that causes it |
| SUB.2b | or with TASK.1 | TASK.1's task-scoped stream filter is a case of SUB.2b's routing; TASK.1 alone would have to build the routing to filter it |
| ORDER.2 | — | independent; its own design closes every writer of the session profile |
| OTEL.1 | — | independent; its design already makes `src/protocol/trace.rs` the sole owner and deletes the competing implementation |

## Deployment impact, as a sum

Each design states its own impact. Three things are only visible across all four. They land on
**two different peers**, and the first draft of this section wrote them as if there were one.

1. **A modern client sees the tool surface stop moving.** ORDER.2 closes every connection-derived
   input to the tool list at once. A deployment that today varies tools per session or per
   connection loses that on the modern path in a single release, not incrementally.
2. **Clients see two new things on the wire; backends see a third.** New keys in the initialize
   response (EXT.1) and notification frames on response streams that previously carried only a
   result (SUB.2b) go **to the client**. The new `_meta` of OTEL.1 goes **to the backend**, on
   outbound calls — a backend that rejects unknown `_meta` keys is the peer at risk there, not the
   client. Each is additive and spec-permitted; together they are enough that compatibility testing
   has to cover both directions, and the release note should say so once rather than three times.
3. **Two of the seven change nothing until a client opts in.** SUB.4 protects only calls that carry
   a key; TASK.1 serves methods only when the extension is negotiated. Neither is a migration.

The era gate covers ORDER.2 and SUB.2b, whose designs place them on the modern path explicitly. It
does **not** demonstrably cover EXT.1: that design's chosen option puts `"extensions": {}` in the
initialize response unconditionally, and neither it nor this document found an era condition on it.
A legacy-era client would receive the new key. That is recorded as an unknown below rather than
asserted either way.

## Unknowns

Resolved — question, check run, result, what it changed:

| question | check | result | changed |
|---|---|---|---|
| Does a design already exist for these rows? | listed `docs/design/`, read headings and decision blocks of every match | four designs cover all seven rows; the first draft missed most of them | the document's placement sections were **deleted**; it now cites and states only the cross-row view |
| Is the SUB.4 / TASK.1 branch open? | read §4 of the TASK.1 design and the carrier decision in the SUB.4 design | decided: the task store owns re-issue safety when the extension is negotiated — and TASK.1's stated mechanism for the collision is removed by SUB.4 | a sequencing constraint and a stale-premise note, instead of an operator question |
| Are the ORDER.2 and SUB.2b operator questions still open? | read §4.1 and §4.3 of the connection-invariance design | both **RESOLVED 2026-08-31** by the operator: option (b), and option (i) | the citation map's state column was corrected; no operator question is carried for either row |
| Does OTEL.1 cover the direct route? | read §4.4.3 of the capability-and-trace design against the SUB.4 coverage decision | §4.4.3 inherits SUB.4's answer, and that answer is now "both routes" | recorded as cross-row fact 2; OTEL.1 carries no open operator question on this |
| Is the task-scoped stream filter owned? | searched the SUB.2 listen-stream design and the connection-invariance §II for "task" | zero occurrences in either; TASK.1 §5 states it as a constraint on a document that does not carry it | this document **places** it, in the TASK.1 increment — the one placement it makes |
| How many connection-derived inputs feed the tool list? | read §I.2 of the connection-invariance design | that design classifies *every* input, and there are more than the two the first draft named | the first draft's "two axes" count was withdrawn; the owning design's classification stands |
| Do the source locations cited by the tracking files hold? | read the two cited locations | the criteria row cites `meta_mcp/mod.rs:393` for the SUB.4 `None` initialisation, which is at `:433`; the release plan cites `active_profile` at `mod.rs:996-1005`, which is at `:1038` | recorded as an **observation** per §P0, no ticket — correcting the tracking files is outside this FOR |

Deferred — one, and it is this document's own:

| field | value |
|---|---|
| unknown | Is EXT.1's `"extensions": {}` in the initialize response era-gated, or does a legacy-era client receive it? |
| owner | the implementer of EXT.1, in the capability-and-trace design's increment |
| what would resolve it | read `build_initialize_result` for an era condition; if there is none, decide whether to add one |
| when | before EXT.1 merges — it is one condition in the code that increment writes |
| what if it resolves badly | if the key ships ungated and a legacy client rejects it, the release note has to name EXT.1 as affecting every era, and the cluster's "modern path only" framing loses one row |

Nothing in this document depends on that answer: it changes one sentence of a release note, not a
placement.

Other deferred unknowns are held by the owning designs — SUB.4's TTL and window questions, OTEL.1's
numeric bounds, and the disposal of `src/tracing_context/`. This document adds none of those and
closes none of them.

## Open for the operator

**One question, unanswered here, carried forward rather than re-asked as new.** SUB.4's scope was
decided by the team lead on 2026-08-31 while the operator was away: both the meta-MCP surface and
the direct backend route are in scope, and protection is mandatory with no kill switch. **Does that
stand?** Recommendation: **let it stand.** The criterion says a re-issued side-effecting call MUST
be protected; a configuration switch makes that unverifiable in any deployment whose running
configuration differs from the shipped default, and the direct route is a documented way in that
would otherwise ship unprotected. The cost of letting it stand is that operators get no way to turn
the behaviour off if a client's retry pattern interacts badly with it, and the recovery is a
release rather than a configuration change. The same record lives in the SUB.4 design's open
questions; one answer settles both, and neither closes without it.

The operator-only questions collected in the capability-and-trace design's §4.4 belong to that
document and are **not** duplicated here. Asking them twice would produce two records of one
answer. ORDER.2 and SUB.2b carry no open operator question at all — both were answered on
2026-08-31 and the answers are recorded in their own design.

## Documents this change makes untrue

None. Nothing described here is built. The one placement this document makes — the task-scoped
stream filter, in the TASK.1 increment — does not contradict any existing document, because no
existing document claims it. When each row lands, its criteria-status row and release-plan entry
become untrue and ship updated inside that change, per §P4a.
