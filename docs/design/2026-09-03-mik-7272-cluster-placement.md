# MIK-7272 — which design owns each of the seven open protocol criteria, and what they change together

**Status**: proposed, for dual review before any implementation
**Scope item**: MIK-7272 (MCP 2026 protocol conformance) · `docs/requirements/RELEASE-4.0.0-criteria-status.md:196-219`

## Scope (§P0)

**FOR** — for each of the seven MIK-7272 criteria still open, name the design that owns its
placement, and state what the seven changes together mean for an existing deployment.

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
is smaller than the count of rows because one of them owns three rows and another owns two.
**What was genuinely missing is not placement — it is the cross-row view**, and that is all this
document now contains: the decisions that only appear when the four designs are read together,
the one ordering constraint that survives review, and the deployment impact none of them can state
alone because it is the sum of the others.

## Three cross-row checks — two facts and one refutation

**1. Re-issue safety has one owner, and TASK.1 already named it.** *When the tasks extension is
negotiated on a request, the task store owns re-issue safety; the idempotency cache is neither
consulted nor written for that call* (TASK.1 design §4). One structure decides; the second cannot
disagree because it is not asked.

That rule survives a change underneath it, and the change is only visible across the two documents
and the tree. TASK.1 §4 argues the rule from a live defect — `resolve_idempotency_key`, a name that appears nowhere in `src/`, auto-derives
a key for any keyless call, so a task-augmented call would get one. **That premise no longer holds
in this tree.** `idempotency_key_for` (`src/gateway/meta_mcp/support.rs:35-45`) takes the client key
and nothing else — *"there is no other source. A call without one is not protected"* — and SUB.4's
design lists *"keeping automatic derivation"* among its rejected options. The collision TASK.1
describes therefore cannot arise today, from either mechanism. The rule still has to exist — a
client that sends both a key and a task-augmented call would otherwise be judged twice — but its
stated cause is gone. TASK.1's §4 is correct in its conclusion and stale in its premise; correcting
that sentence belongs to TASK.1's own increment, and **no landing order follows from it**, which is
the opposite of what an earlier revision of this document concluded.

**2. SUB.4's both-routes answer settles an OTEL.1 question that OTEL.1 left open.** The
capability-and-trace design's §4.4.3 asks whether the direct route `POST /mcp/{name}` needs trace
propagation, and answers it by inheritance: *"This is the same two-route question SUB.4 already put
to the operator… If the answer for SUB.4 is 'both routes', OTEL.1's scope grows with it."* SUB.4's
design now records that answer — both routes, decided 2026-08-31. **OTEL.1 therefore covers the
direct route**, and no operator question remains on it. Two consequences the owning design cannot
show: its §5 still lists *"trace propagation on `POST /mcp/{name}`"* as out of scope **until 4.4.3
is answered**, and that condition is now met — the entry is stale, and deleting it is part of
OTEL.1's increment, not a separate task. Nobody reading OTEL.1 alone can see either, because the
answer landed in a different document after both sentences were written.

A second citation defect surfaced in the same check and is recorded here because this document
cites the decision: **SUB.4's design contradicts itself on the carrier.** Its decision line and its
open-question row both say `_meta` on both routes, rejecting *"a header on both routes"* and *"an
HTTP header alone"*; its body prose still says the direct route *"takes the key from an
`Idempotency-Key` HTTP header"* (`docs/design/2026-08-31-sub-4-idempotency-wiring.md:161-169`
against `:154-155` and `:178`). The decided row binds — it is the operator-answered one — and
correcting the prose belongs to SUB.4's increment. An implementer who reads only the prose builds
the rejected option.

**3. The constraint TASK.1 hands to SUB.2 is already satisfied there, in other words.** TASK.1 §5:
a task-scoped `subscriptions/listen` stream carries `notifications/tasks/status` only, and must not
carry `notifications/progress` or `notifications/message`; it says *"SUB.2's design owns
request-scoped notification routing; this is a constraint on it, recorded here because TASK.1 is
what discovered it."* An earlier revision of this document searched the SUB.2 listen-stream design
for "task", found nothing, concluded the constraint was owned by no document, and **placed** it.
That was wrong, and a second search under the constraint's own vocabulary is what found it:
`docs/design/2026-08-29-subscriptions-listen-stream.md:52-65` filters by allowlist — four kinds are
delivered and *"anything else — `notifications/progress`, `notifications/message` — is **never**
delivered here… the existing `NotificationKind::from_method` already refuses to map them, and there
is a test for it."* The prohibition half of TASK.1's constraint is therefore already designed,
already implemented and already tested. What is left is the permission half: `notifications/tasks/
status` has to become a fifth deliverable kind, which is TASK.1's own work under its own acceptance
criterion `MIK-7272.TASK.1.9`. **No seam, no placement, and this document makes none.** The lesson
is retained deliberately: a keyword search for the *subject* of a constraint does not find a design
that states the constraint over its *objects*.

## Order, and why it is not free choice

| land | before | because |
|---|---|---|
| EXT.1 | TASK.1 | TASK.1 is an extension and needs the negotiated set; building it second means building a private negotiation path and then deleting it |
| SUB.4 | — | independent. An earlier revision ordered it against TASK.1 on the automatic key derivation; that derivation is already gone from the tree, so the constraint had no subject |
| SUB.2b | — | independent of TASK.1. The task-scoped stream is a `subscriptions/listen` stream, which SUB.2's shipped design owns; SUB.2b is request-scoped routing on response streams |
| ORDER.2 | — | independent; its own design closes every writer of the session profile |
| OTEL.1 | — | independent; its design already makes `src/protocol/trace.rs` the sole propagation owner. What becomes of the competing `src/tracing_context/` — deletion or isolation — is that design's own deferred question, which this order does not decide |

**One ordering constraint survives review, not five.** That is the honest result: the cluster is
less entangled than it looked, and every other row carries no order of its own.

That is an order *within* the cluster, not a schedule. The operator settled the merge strategy as a
sequence of per-cluster pull requests, so these seven rows land together in cluster C's, and the
`EXT.1` constraint binds the commit series inside it rather than a release date. One constraint
points outward: cluster F flips `server.modern_protocol` to true, and the rollup makes that flip
"a gating dependency on clusters A and C, not an independent switch"
(`docs/requirements/RELEASE-4.0.0-blocking-rollup.md:355`) — a default install that serves
`2026-07-28` before this cluster serves it completely turns every gap here into a first-run defect.
So **C lands before F**.

## Deployment impact, as a sum

Each design states its own impact. Three things are only visible across all four. They land on
**two different peers**, and the first draft of this section wrote them as if there were one.

1. **A client of any era sees the tool surface stop moving, and one control disappear.** The
   operator chose option (b) for ORDER.2 — *"remove per-session routing profiles entirely, **for
   every era**"* (`…connection-invariance.md:169`). An earlier revision of this section called this
   modern-path-only; it is not, and that makes it the one **breaking** change in the cluster. A
   deployment that today varies tools per session or per connection loses that capability outright,
   in a single release, on every path: both `gateway_set_profile` and `gateway_get_profile`
   (`src/gateway/meta_mcp_tool_defs.rs:379`) go with the mechanism they read and write. It belongs in
   the release note as a removal, not as a conformance fix.
2. **Clients see two new things on the wire; backends see a third.** New keys in the initialize
   response (EXT.1) and notification frames on response streams that previously carried only a
   result (SUB.2b) go **to the client**. The new `_meta` of OTEL.1 goes **to the backend**, on
   outbound calls — a backend that rejects unknown `_meta` keys is the peer at risk there, not the
   client. Each is additive and spec-permitted; together they are enough that compatibility testing
   has to cover both directions, and the release note should say so once rather than three times.
3. **Two of the seven change nothing until a client opts in.** SUB.4 protects only calls that carry
   a key; TASK.1 serves methods only when the extension is negotiated. Neither is a migration.

**Two rows are era-gated, and they are gated on opposite sides of the same handshake.** ORDER.2 is
not one of them, by the operator's own choice of option (b) above. EXT.1 is not either, and that is
decided rather than unknown: `build_initialize_result` (`src/gateway/meta_mcp_helpers.rs:145-166`)
takes the negotiated version only to echo it and branches on nothing, both entry points share it,
and the owning design rejected the discover-only option precisely because it would leave *"a legacy
client blind to an extension the gateway supports"*. A legacy-era client will receive
`"extensions": {}`. TASK.1, in contrast, **is** era-gated, at the router rather than the
declaration: its `MIK-7272.TASK.1.5` requires that *"a 2025-era peer calling `tasks/cancel` is
refused `-32601` by the era gate"*. SUB.2b's own design states no era exposure at all, and this map
does not invent one for it.

**That pairing is itself a cross-row constraint.** The
extensions map is unconditional; the task methods are refused by era. So a Tasks entry added to that
shared builder without an era condition tells a legacy client about an extension whose every method
it will then be refused — the declaration and the refusal disagree about the same peer. The entry
belongs to TASK.1's increment, which is already ordered after EXT.1. Two reasons, one order: the
order table gives the build-sequencing one — TASK.1 needs the negotiated set — and this pairing is a
second, independent of it. EXT.1 builds the map, TASK.1 fills it, and TASK.1 owns the condition on
its own row. This document makes no placement — the work sits where it already sat.
What was only visible across the two designs is that the condition has to exist at all.

The release note should say so rather than implying the cluster is a modern-path affair.

## Unknowns

Resolved — question, check run, result, what it changed:

| question | check | result | changed |
|---|---|---|---|
| Does a design already exist for these rows? | listed `docs/design/`, read headings and decision blocks of every match | four designs cover all seven rows; the first draft missed most of them | the document's placement sections were **deleted**; it now cites and states only the cross-row view |
| Is the SUB.4 / TASK.1 branch open? | read §4 of the TASK.1 design, the carrier decision in the SUB.4 design, and `idempotency_key_for` in `src/gateway/meta_mcp/support.rs` | decided: the task store owns re-issue safety when the extension is negotiated — and TASK.1's stated cause for the collision, automatic key derivation, is **already absent from the tree** | a stale-premise note for TASK.1's increment, and the **removal** of the landing-order constraint an earlier revision derived from it |
| Are the ORDER.2 and SUB.2b operator questions still open? | read §4.1 and §4.3 of the connection-invariance design | both **RESOLVED 2026-08-31** by the operator: option (b), and option (i) | the citation map's state column was corrected; no operator question is carried for either row |
| Which eras does ORDER.2 affect? | read the option (b) text the operator selected | *"for every era"* — it is a removal on every path, not a modern-path change | deployment item 1 rewritten as the cluster's one breaking change |
| Does OTEL.1 cover the direct route? | read §4.4.3 and §5 of the capability-and-trace design against the SUB.4 coverage decision | §4.4.3 inherits SUB.4's answer, that answer is now "both routes", and §5's out-of-scope entry is conditional on the same question | recorded as cross-row fact 2, with the stale §5 entry named for OTEL.1's increment |
| Does SUB.4's design state one carrier per route? | read `:154-155`, `:161-169` and `:178` of that design | **no** — the decision says `_meta` on both routes, the body prose still says an `Idempotency-Key` header on the direct route | recorded as a citation defect for SUB.4's increment; this document cites the decided row |
| Is the task-scoped stream filter owned? | first searched the SUB.2 listen-stream design for "task" (nothing); then searched it for the constraint's objects — `progress`, `message`, `filter` | `:52-65` already delivers by allowlist and names both prohibited kinds as *never* delivered, with an existing refusal in `NotificationKind::from_method` and a test | the placement an earlier revision made was **withdrawn**; nothing is unowned |
| Is EXT.1's `"extensions": {}` era-gated? | read `build_initialize_result` (`src/gateway/meta_mcp_helpers.rs:145-166`) and the owning design's rejected option C | no era branch exists and the design rejects withholding the field from a legacy client; it ships to every era, deliberately | a deferred unknown an earlier revision recorded was **closed by running its own check**; the answer is now in deployment item 3's paragraph |
| How many connection-derived inputs feed the tool list? | read §I.2 of the connection-invariance design | that design classifies *every* input, and there are more than the two the first draft named | the first draft's "two axes" count was withdrawn; the owning design's classification stands |
| Do the source locations cited by the tracking files hold? | read the two cited locations | the criteria row cites `meta_mcp/mod.rs:393` for the SUB.4 `None` initialisation, which is at `:433`; the release plan cites `active_profile` at `mod.rs:996-1005`, which is at `:1038` | recorded as an **observation** per §P0, no ticket — correcting the tracking files is outside this FOR |

Deferred — **none**. This document held one deferred unknown after round 2, the EXT.1 era gate; its
own resolver was a single file read, so round 3 ran it rather than scheduling it. An unknown whose
check costs less than its four fields should be answered, not deferred.

Other deferred unknowns are held by the owning designs — OTEL.1's numeric bounds and the disposal
of `src/tracing_context/`. SUB.4 has none: its design says *"Nothing is deferred"* (`:184`) and
resolves the TTL question at `:66`. This document adds none of those and
closes none of them.

## Open for the operator

**One question, unanswered anywhere, and it is not the one an earlier revision asked.** SUB.4's
carrier question *was* put to the operator and answered on 2026-08-31 — `_meta` on both routes —
so there is nothing to ratify there. What was never asked is the other half: SUB.4's design records
*"May an operator disable protection a criterion states as MUST? **DECIDED on the requirement
rather than asked: no.**"* That row is a design decision standing in for an operator answer, and it
is the only one in the cluster. **Does it stand — no kill switch, protection mandatory wherever a
key is present, on both routes?** Recommendation: **let it stand.** The criterion says a re-issued
side-effecting call MUST be protected; a configuration switch makes that unverifiable in any
deployment whose running configuration differs from the shipped default, and the direct route is a
documented way in that would otherwise ship unprotected. The cost of letting it stand is that
operators get no way to turn the behaviour off if a client's retry pattern interacts badly with it,
and the recovery is a release rather than a configuration change. One answer settles this document
and that row; neither closes without it.

The operator-only questions collected in the capability-and-trace design's §4.4 belong to that
document and are **not** duplicated here. Asking them twice would produce two records of one
answer. ORDER.2 and SUB.2b carry no open operator question at all — both were answered on
2026-08-31 and the answers are recorded in their own design.

## Documents this change makes untrue

None of its own — nothing described here is built, and this document now makes **no** placement of
its own, so it contradicts nothing. What review did find is three statements in the owning designs
that their own increments must correct, listed here because a citation map is the only place they
are visible together:

| document | stale statement | who corrects it |
|---|---|---|
| `2026-08-31-sub-4-idempotency-wiring.md:161-169` | body prose says the direct route takes an `Idempotency-Key` header; the decision at `:154-155`/`:178` says `_meta` on both routes | SUB.4's increment |
| `2026-08-31-cluster-b-capability-and-trace-metadata.md:404-408` | direct-route trace propagation listed out of scope *until 4.4.3 is answered*; it is answered | OTEL.1's increment |
| `2026-08-31-task-1-tasks-extension.md:64`, `:228` | argues its rule from an automatic key derivation the tree no longer has | TASK.1's increment |

Each is a sentence inside a document that increment already opens. When each row lands, its
criteria-status row and release-plan entry become untrue and ship updated inside that change, per
§P4a.

## Carried findings — raised in review, owned elsewhere

The final review raised three defects that live inside TASK.1's design rather than in this map.
Repairing another design's decision is outside what this document declared itself for, so they are
recorded rather than fixed, and none of them changes an ownership row above.

| finding | why it is not repaired here |
|---|---|
| a task-scoped stream that filters only by notification kind would still broadcast every task's status to every listener — the filter has to be by requested `taskIds` **and** by the authenticated owner | this is the substance of `MIK-7272.TASK.1.9`, which TASK.1 already owns; it strengthens that criterion rather than moving it |
| the notification is spelled `notifications/tasks/status` throughout TASK.1's design; one reviewer reads the pinned model as `notifications/tasks` | a wire-name conflict is settled against the spec text by the increment that writes the constant, not by a citation map |
| the OTEL.1 direct route may already forward `_meta` unchanged, which would make new injection there a duplicate rather than a fix | source-checkable in one read by OTEL.1's increment; this document's own claim about that route is the stale out-of-scope entry recorded above, not the injection design |

These are residual risk, stated so the next reader of this cluster meets them once. A fourth round
of review on this map would not close them — it would only re-raise findings whose owners are three
other documents.
