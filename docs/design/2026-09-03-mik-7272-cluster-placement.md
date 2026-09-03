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
| ORDER.2a / ORDER.2b | `docs/design/2026-08-31-cluster-b-connection-invariance.md` §I | recommendation made; one option needs the operator's recorded agreement |
| SUB.2b | same document, §II | blocked on a deferred transport question, (i) vs (ii) |
| SUB.4 | `docs/design/2026-08-31-sub-4-idempotency-wiring.md` (rev 4) | decided; one operator question open |
| EXT.1 | `docs/design/2026-08-31-cluster-b-capability-and-trace-metadata.md` §3.1-3.2 | decided |
| OTEL.1 | same document, §3.3-3.5 | decided; two numeric bounds deferred |
| TASK.1 | `docs/design/2026-08-31-task-1-tasks-extension.md` | decided |

Every one of the seven is therefore designed. **What was genuinely missing is not placement — it is
the cross-row view**, and that is all this document now contains: the decisions that only appear
when the six designs are read together, the order they have to land in, and the deployment impact
none of them can state alone because it is the sum of the others.

## The one cross-row decision, and it was already made

The only decision in this cluster that no single-row design could make alone is **who owns re-issue
safety when both the idempotency cache and the tasks extension are available** — and the TASK.1
design already made it, in §4: *when the tasks extension is negotiated on a request, the task store
owns re-issue safety; the idempotency cache is neither consulted nor written for that call.* One
structure decides; the second cannot disagree because it is not asked.

The direction matters for sequencing rather than for design: TASK.1 does not depend on SUB.4, but
it changes when SUB.4's key derivation runs. SUB.4's own note still says TASK.1 is out of scope and
that it "neither builds it nor depends on it"; that sentence is stale in one direction, and its
correction is already scheduled in the TASK.1 design — owner: the session implementing SUB.4, due
before SUB.4 merges. Nothing here re-opens it.

## Order, and why it is not free choice

| land | before | because |
|---|---|---|
| EXT.1 | TASK.1 | TASK.1 is an extension and needs the negotiated set; building it second means building a private negotiation path and then deleting it |
| SUB.4 | or with TASK.1 | TASK.1 changes SUB.4's derivation condition — shipping automatic derivation first is the deadlock the TASK.1 design names |
| ORDER.2 | — | independent; its own design closes every writer of the session profile |
| OTEL.1 | — | independent; its design already makes `src/protocol/trace.rs` the sole owner and deletes the competing implementation |
| SUB.2b | — | gated on its own design's deferred transport question, not on any other row |

## Deployment impact, as a sum

Each design states its own impact. Three things are only visible across all six.

1. **A modern client sees the tool surface stop moving.** ORDER.2 closes every connection-derived
   input to the tool list at once. A deployment that today varies tools per session or per
   connection loses that on the modern path in a single release, not incrementally.
2. **A modern client sees three new fields it never received.** New keys in the initialize response
   (EXT.1), new `_meta` on outbound backend calls (OTEL.1), and notification frames on response
   streams that previously carried only a result (SUB.2b). Each is additive and spec-permitted;
   together they are enough that a strict client which rejects unknown fields breaks in three
   places on one upgrade, and the release note should say so once rather than three times.
3. **Two of the seven change nothing until a client opts in.** SUB.4 protects only calls that carry
   a key; TASK.1 serves methods only when the extension is negotiated. Neither is a migration.

Legacy-era clients see none of this. That is a property of the era gate, not of these changes, and
it is the reason the cluster can land inside a minor release at all.

## Unknowns

Resolved — question, check run, result, what it changed:

| question | check | result | changed |
|---|---|---|---|
| Does a design already exist for these rows? | listed `docs/design/`, read headings and decision blocks of every match | six designs cover all seven rows; four were missed by the first draft | the document's placement sections were **deleted**; it now cites and states only the cross-row view |
| Is the SUB.4 / TASK.1 branch open? | read §4 of the TASK.1 design | decided: the task store owns re-issue safety when the extension is negotiated | a sequencing constraint is recorded instead of an operator question |
| How many connection-derived inputs feed the tool list? | read §I.2 of the connection-invariance design | that design classifies *every* input, and there are more than the two the first draft named | the first draft's "two axes" count was withdrawn; the owning design's classification stands |
| Do the source locations cited by the tracking files hold? | read the two cited locations | the criteria row cites `meta_mcp/mod.rs:393` for the SUB.4 `None` initialisation, which is at `:433`; the release plan cites `active_profile` at `mod.rs:996-1005`, which is at `:1038` | recorded as an **observation** per §P0, no ticket — correcting the tracking files is outside this FOR |

Deferred unknowns are held by the owning designs — SUB.4's kill switch, SUB.2b's transport
question, OTEL.1's numeric bounds and the disposal of `src/tracing_context/`. This document adds
none and closes none.

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

The ORDER.2 option that needs the operator's recorded agreement, and the operator-only questions
collected in the capability-and-trace design's §4.4, belong to those documents and are **not**
duplicated here. Asking them twice would produce two records of one answer.

## Documents this change makes untrue

None. Nothing described here is built, and this document now asserts no placement of its own. When
each row lands, its criteria-status row and release-plan entry become untrue and ship updated
inside that change, per §P4a.
