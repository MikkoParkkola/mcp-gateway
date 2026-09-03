# MIK-7272 — where the seven open protocol criteria get wired, and what that changes for deployments

**Status**: proposed, for dual review before any implementation
**Scope item**: MIK-7272 (MCP 2026 protocol conformance) · `docs/requirements/RELEASE-4.0.0-criteria-status.md:196-219`

## Scope (§P0)

**FOR** — decide, for each of the seven MIK-7272 criteria still open, WHERE the wiring belongs in
this tree and WHAT it changes for an existing deployment.

**OUT** — writing the code; re-deciding anything the three existing per-row designs already
settled; the MRTR rows; test code (§P2 plan is a separate artefact); fixing the stale line numbers
in the criteria-status file; every criterion already marked MET.

**A brief this design corrects.** The task that commissioned it states that no design document
exists for this cluster. That is false for three of the seven rows, and the correction is
load-bearing rather than pedantic: two of those three documents contain frozen decisions, and a
cluster design that re-decided them would be re-litigating a reviewed design outside its own FOR.

| row | existing design | this document's role |
|---|---|---|
| SUB.4 | `docs/design/2026-08-31-sub-4-idempotency-wiring.md` (rev 4) | cite; carry its one blocked question forward |
| TASK.1 | `docs/design/2026-08-31-task-1-tasks-extension.md` | cite; its §4 already owns the SUB.4 branch |
| SUB.2b | `docs/design/2026-08-29-subscriptions-listen-stream.md` | partial — that design owns the *subscription* stream, not the *response* stream |
| ORDER.2a, ORDER.2b, EXT.1, OTEL.1 | none | this document decides placement |

## The problem, stated as what is on disk

Six of the seven rows are not missing ideas. They are **built and unreached** — types, fields and
constructors exist, compile, and have no production consumer. That is a specific failure shape and
it matters for placement, because the decision in each case is not "what to build" but "which seam
owns the call".

| row | what exists | what reaches it |
|---|---|---|
| ORDER.2a/2b | `MetaMcp::active_profile` (`src/gateway/meta_mcp/mod.rs:1038`) varies the surfaced tool set per session; `?codemode=search_and_execute` (`src/gateway/router/handlers.rs:495-499`) varies it per connection | both are live — the defect is that they vary at all on the modern path |
| SUB.2b | request-scoped notification routing | nothing outside `subscription_*` paths |
| SUB.4 | `IdempotencyCache`; `enable_idempotency` carries `#[allow(dead_code)]`; the cache is initialised `None` at `meta_mcp/mod.rs:433` | nothing; no client-visible key carrier exists on either route |
| EXT.1 | `ExtensionSet::gateway_declares()` — exactly one occurrence in `src/`, its own definition | nothing |
| OTEL.1 | `TraceContext` with `traceparent`/`tracestate`/`baggage`, and `to_meta()` | no non-test caller |
| TASK.1 | `src/protocol/tasks.rs`, 111 lines of `Task`/`TaskStatus` types | zero consumers in `src/` |

Read for a reviewer with no filesystem: four of these rows are dead code in the literal compiler
sense (SUB.4, EXT.1, OTEL.1's outbound half, TASK.1). SUB.2b's machinery is live but reached only
on subscription paths, and ORDER.2 is live code doing the opposite of what the criterion requires.

## Constraints, measured in this tree rather than assumed

1. **`active_profile` is one chokepoint, but not the only variation axis.** The profile is read at
   six call sites (`surfaced.rs:107`, `search.rs:376`, `:629`, `:728`, `invoke.rs:1048`,
   `mod.rs:1691`) and produced in one place (`mod.rs:1038`), so a change there is an edit rather
   than a sweep. The `codemode=search_and_execute` URL query override is a **second** axis with its
   own plumbing (`handlers.rs:495-499` parsing, `meta_mcp/mod.rs:1306` field) and it varies the
   tool surface per connection by design. ORDER.2a cannot be closed by touching only one of them.
2. **The direct backend route is a real second ingress with different plumbing.** The
   per-backend POST handler at `src/gateway/router/backend_handlers.rs:724` does not go through
   `invoke_tool_traced`, and `:594` has no per-user cache. Any criterion whose wiring hangs off the
   invoke path (SUB.4, OTEL.1, TASK.1) has to answer for this seam explicitly or ship a documented
   hole.
3. **Two line numbers cited by the tracking artefacts are stale.** The SUB.4 criteria-status row
   cites `meta_mcp/mod.rs:393` for the `None` initialisation; it is at `:433`. The release plan
   cites `active_profile` at `mod.rs:996-1005`; it is at `:1038`. Disposal per §P0:
   **observation**, recorded here, no ticket — correcting the tracking files is outside this
   document's FOR, and the numbers used below are the verified ones.

## Placement, per row

Each row answers two questions: which seam owns the wiring, and what an existing deployment sees.

### ORDER.2a / ORDER.2b — list results must not vary per connection, or as a side effect

**Placement: at the producer, `MetaMcp::active_profile` (`mod.rs:1038`), plus the codemode
override at its parse site (`handlers.rs:495-499`) — not at the six readers.**

Two options were considered. *Move the variation under authorization* keeps per-session profiles
and makes them a function of the authenticated principal rather than of the connection; it
preserves a shipped feature but leaves a per-connection input (the codemode query override) that no
authorization decision covers, so ORDER.2a stays open unless that override is removed anyway.
*Stop varying on the modern path* makes both axes inert once the modern protocol version is
negotiated, and is the smaller, checkable change: one producer returns the configured profile, one
parser ignores the query parameter, both gated on era. Rejected the first because it does not close
ORDER.2a on its own and costs an authorization design; **chosen the second**.

ORDER.3b in the criteria file already records this as the same remediation, which is why that row
is N/A rather than a separate piece of work.

**Deployment impact — the largest user-visible change in the cluster.** A deployment relying today
on per-session routing profiles, or on the codemode query override, sees the tool surface stop
changing per connection once a client negotiates the modern version. Legacy-era clients are
unaffected. This is a behaviour removal and needs a release note, not only a changelog line.

### SUB.2b — request-scoped notifications on the response stream of their own request

**Placement: the response stream, not the subscriber registry.** The existing design
(`docs/design/2026-08-29-subscriptions-listen-stream.md`) builds a subscriber registry for
`subscriptions/listen` and explicitly owns *subscription*-scoped delivery; SUB.2a (already MET)
shows notifications are classified and filtered there. SUB.2b is the complementary half:
`notifications/progress` and `notifications/message` belong on the stream of the request that
caused them, which is a different stream with a different lifetime.

Rejected: reusing the subscriber registry with a per-request pseudo-subscription. It makes the
registry's lifetime rule ("a subscriber outlives a request") false for one member class, and the
lagging-client disconnect rule written for subscribers would then be able to kill a half-delivered
response.

**Deployment impact**: streams that carried no notifications begin carrying them. A client
treating any non-result frame on a response stream as a protocol error breaks. Modern path only.

### SUB.4 — idempotency for a re-issued side-effecting call

**Placement: settled by `docs/design/2026-08-31-sub-4-idempotency-wiring.md`, not re-decided
here.** That design binds protection in the key *derivation* rather than at each call site, covers
both routes, and records the key carrier as a `_meta` entry on the meta route and an
`Idempotency-Key` HTTP header on the direct backend route — an operator answer given 2026-08-31.
Automatic derivation is deleted: protection applies when a key is present and never otherwise.

**One question that document leaves blocked is inherited here**, and it is not re-asked as if new:
whether an operator may disable protection the criterion states as a MUST. That design decided
*no* on the requirement and recorded the decision as overrulable in one line. Carried forward as a
deferred unknown:

| field | value |
|---|---|
| owner | the operator (asked 2026-08-31, away; the team lead's provisional reading stands) |
| what resolves it | one line confirming or overruling "mandatory, no kill switch" |
| when | before SUB.4 implementation merges |
| if it resolves badly | a config switch is added, and the criterion becomes unverifiable in any deployment whose running configuration differs from the shipped default — the row would then be MET(I), not MET |

**Deployment impact**: a client-visible schema addition — a `_meta` key on the meta route, a header
on the direct route. No existing client sends either, so nothing changes until one does.

### EXT.1 — the gateway declares its own extensions through server capabilities

**Placement: a write side at `build_initialize_result`, plus a read side at negotiation.**
`ExtensionSet::gateway_declares()` exists and has exactly one occurrence in the source tree — its
own definition. The criterion has two halves and only the first is a wiring: *declare* the
gateway's extensions in the `extensions` field of server capabilities, and *honour* a client that
does not support one. The second half is what makes this more than a serialisation change: a
declared extension whose client did not echo it must not be exercised on that session, so the
negotiated set has to be stored per session and consulted where each extension acts.

Rejected: declaring extensions statically from configuration without recording the client's reply.
It closes the visible half of the criterion and leaves the gateway free to use an extension the
client rejected, which is the failure the second half exists to prevent.

This row is upstream of TASK.1, which is itself an extension and needs the same negotiated set;
building EXT.1 second would mean building a private negotiation path for tasks and then replacing
it.

**Deployment impact**: the initialize response grows keys. A client that rejects unknown fields in
server capabilities would break, though such a client is already out of spec. The *honour* half has
no deployment impact today and that is a stated finding rather than an omission: no extension is
currently exercised at all — `gateway_declares()` has no caller and TASK.1 is unbuilt — so there is
no session in which the gateway is using an extension a client declined. The honour half is
therefore a constraint on what TASK.1 may do, not a change to existing behaviour.

### OTEL.1 — trace context propagated through `_meta` across the gateway hop

**Placement: the outbound hop, both routes. The inbound half already has an owner on one route and
none on the other.** `TraceContext` carries `traceparent`, `tracestate` and `baggage`. Inbound
extraction exists on the meta route — `TraceContext::from_meta` is called at
`src/gateway/meta_mcp/invoke.rs:1814` — and does not exist on the direct backend route. Outbound
injection exists nowhere: `to_meta()` has no non-test caller. So the wiring is one call at the
point where the gateway builds the request it sends to a backend, plus an extraction on the direct
route to give that call something to propagate. That point is not single: the traced invoke path is
one owner, and the direct backend route at `backend_handlers.rs:724` bypasses it. Naming the second
owner is the whole decision here — otherwise this ships as "propagated except on the route nobody
measured".

Rejected: propagating at the transport layer, below the router. It would cover both routes with one
edit, but the transport has no view of which hop is a backend tool call and which is the gateway's
own bookkeeping, so it would stamp trace context on requests that are not part of the client's
trace.

**Deployment impact**: backends begin receiving `_meta` keys they did not receive before. A backend
that rejects unknown `_meta` entries would break; the specification does not permit that, so this
is a compatibility note rather than a migration.

### TASK.1 — the tasks extension

**Placement: settled by `docs/design/2026-08-31-task-1-tasks-extension.md`, not re-decided here.**
That design also settles this cluster's one genuinely cross-row decision, so it is quoted rather
than paraphrased: *when the tasks extension is negotiated on a request, the task store owns
re-issue safety; the idempotency cache is neither consulted nor written for that call.* The task
store carries a secondary index on the same derived key, so a retried identical call resolves to
the same task and the backend runs once.

**The branch is therefore decided, not open**, and the direction matters for sequencing: TASK.1
does not depend on SUB.4, but it changes when SUB.4's derivation runs. SUB.4's own note still
declares TASK.1 out of scope and says it neither builds nor depends on it; that sentence is stale
in one direction and its correction is already scheduled in the TASK.1 design, owned by the session
implementing SUB.4, due before SUB.4 merges.

`src/protocol/tasks.rs` is 111 lines of `Task` and `TaskStatus` types with zero consumers in the
source tree, so this row is a build on top of existing types rather than from nothing.

**Deployment impact**: methods currently refused begin being served. This is additive for clients
that never negotiate the extension.

## Sequencing, and why it is not free choice

| order | why |
|---|---|
| EXT.1 first | TASK.1 and any future extension need the negotiated set; building it later means building a private one twice |
| ORDER.2 independently | one producer, one parser, no dependency on the others |
| SUB.4 before or with TASK.1 | TASK.1 changes SUB.4's derivation condition; shipping SUB.4's auto-derivation first is the failure the TASK.1 design names |
| OTEL.1 independently | one call at the outbound hop, twice |
| SUB.2b after `NotificationKind::from_method` is reachable from the response path | it reuses that classification, not the subscriber registry; SUB.2a is already MET, so the classifier exists — the precondition is a caller on the response stream, which is checkable rather than a wait on a document |

## Unknowns

Resolved — question, what was run, what came back, what it changed:

| question | check | result | changed |
|---|---|---|---|
| Does a design already exist for these rows? | listed `docs/design/` and read the headings and decision blocks of the three matches | SUB.4 (rev 4), TASK.1 and the listen-stream design exist and carry frozen decisions | this document cites rather than decides three of seven rows; the commissioning brief's premise is corrected in the scope section |
| Is `active_profile` the only per-connection variation axis? | searched the source for `codemode` | a per-connection URL override with its own parse site and field, plus three tests asserting it activates per connection | ORDER.2's placement gained a second edit site; "one chokepoint" would have been wrong |
| Is the SUB.4 / TASK.1 branch open? | read §4 of the TASK.1 design | it is decided: the task store owns re-issue safety when the extension is negotiated | this document records a sequencing constraint instead of asking the operator to choose a branch |
| Do the cited line numbers hold? | read the two cited locations | both are stale by 40 and 33 lines | the numbers used here are the verified ones; the drift is recorded as an observation |
| Is `src/protocol/tasks.rs` reachable? | searched the source tree for consumers | 111 lines, zero consumers | TASK.1 counted as a sixth built-and-unreached row rather than as new work |

Deferred — the SUB.4 kill-switch question, with its four fields, in the SUB.4 section above. It
blocks nothing in this document; it blocks SUB.4's merge.

## Open for the operator

**One question, and one notification.** They are different things and the difference is deliberate:
a question this design may not answer, and a decision it made on the requirement which the operator
can overrule in a line.

**QUESTION — SUB.4's scope was decided by the team lead on 2026-08-31 while you were away: both the
meta-MCP surface and the direct backend route are in scope, and protection is mandatory with no
kill switch. Does that stand?** Recommendation: **let it stand.** The criterion says a re-issued
side-effecting call MUST be protected; an operator switch makes that unverifiable in any deployment
whose running configuration differs from the shipped default, and the direct route is a documented
ingress that would otherwise ship unprotected. The cost is that operators get no way to turn the
behaviour off if a client's retry pattern interacts badly with it, and the recovery is a release
rather than a configuration change. This is the same record as the deferred unknown in the SUB.4
section above — one answer settles both rows, and neither is closed without it.

**NOTIFICATION — ORDER.2 removes BOTH per-connection variation axes on the modern path, not just
the session profile.** Decided here on the requirement rather than asked, because the criterion
reads "list results MUST NOT vary per connection" and the codemode query override is exactly a
per-connection variation; a design that kept it would be marking a row MET while the mechanism that
falsifies it still runs. Recorded so it can be overruled, not so it can be confirmed. The cost, if
overruled: a client using the query parameter to opt into Code Mode keeps that ability, and
ORDER.2a becomes MET(I) at best — met by inference, with a live counter-example in the tree.

## Documents this change makes untrue

None yet — this is a design, and nothing it describes has been built. When each row lands, the
criteria-status row and the release plan entry for that row become untrue and ship updated inside
that change, per §P4a.
