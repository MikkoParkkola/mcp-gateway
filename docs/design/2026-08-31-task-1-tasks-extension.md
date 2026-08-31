# TASK.1 — the `io.modelcontextprotocol/tasks` extension

Design note. No code. §P1 of `rules-source/workflows/development-process.md`.

Every `file:line` below is read at commit `112a392c3cc66c2b8fa00d71dd39c9972f351705`
("docs(mcp): design extension declaration and trace metadata"). Line numbers move; the commit
does not, so a reader who finds a citation off by a few lines has a way to check rather than a
reason to distrust the note.

Criterion (`docs/requirements/RELEASE-4.0.0-criteria-status.md:160`, status ABSENT, blocking):

> the tasks extension (`io.modelcontextprotocol/tasks`) MUST be supported for long-running
> backend calls, with `tasks/get` polling and `tasks/update`

## 0. This note overturns a recorded decision

`docs/requirements/RELEASE-4.0.0-dod-check.md:557-584` records the opposite disposition —
"4.0.0 does not advertise the tasks extension" — put to the operator, unanswered inside the
window, and written down as the decision with the sentence "One line overturns it."

The operator's full-scope direction on 2026-08-31 is that line. `RELEASE-4.0.0-plan.md:110-112`
already carries the overturn; `dod-check.md` does not. Two status documents in the tree
disagree until that is fixed, and this note may only write one path.

**Scheduled** — owner: whoever lands the first TASK.1 code commit. What resolves it: replacing
the `dod-check.md:557-584` disposition with a pointer to this note. When: in the same commit
series as the first implementation change, before it merges. If it resolves badly (nobody
updates it): a reviewer reads `dod-check.md`, believes the extension is deliberately absent,
and rejects the implementation as out of scope — which is exactly how a stale status document
costs a review round.

## 1. Source, and what it is not

**Corrected 2026-08-31, later the same day: a versioned artifact does exist.** The paragraph this
replaces said there was none, on the evidence of a draft URL and the core schema. Both halves of
that evidence still hold; the conclusion did not.

Wire shape is pinned to `modelcontextprotocol/ext-tasks`, tree
`0d0a6bd4c258b35caa3c810a1dd506cf105b1501`, file `specification/2026-07-28/tasks.md`, blob
`5d6a202eacbaab3444f9d0727ce6587598e7e077` (34,148 bytes, 911 lines), fetched raw from
`raw.githubusercontent.com` at that tree. It is a dated, versioned directory in a git repository,
so it is pinnable by hash rather than re-fetchable by hope. Line references of the form `L<n>`
elsewhere in this note are that blob's.

What remains true from the earlier reading: the core `schema/2026-07-28/schema.json` (181,834
bytes) contains no `Task` type — one occurrence of the string, at line 3145, as an *example key*
in the `ServerCapabilities.extensions` description. The extension is versioned separately from
the core revision. And `https://tasks.extensions.modelcontextprotocol.io/specification`, the path
the extension index links, returns **404** — which is why the published-site route looked like the
only one and produced the wrong conclusion. The draft at `.../specification/draft/tasks` (200 OK,
163,394 bytes) stays useful as a drift check against the pinned blob; it is no longer the source.

## 2. Constraints measured in this tree

| where | what it says | why it binds |
|---|---|---|
| `src/protocol/tasks.rs:1-111` | `TaskStatus` = `Working \| Completed \| Failed`; `Task { id, tool, status, result, error }`; `error: Option<String>` at `:37`; id is `format!("task-{}", Uuid::new_v4())` | three of the spec's five statuses; no `createdAt`, `lastUpdatedAt`, `ttlMs`; the failure payload is a string where the spec requires a JSON-RPC error object |
| `src/protocol/extensions.rs:30,38,46,52-56` | `Extension::Tasks -> "io.modelcontextprotocol/tasks"`, `ExtensionSet`, `gateway_declares()`; `from_capabilities` rejects non-object values | the declaration path exists and is unwired ("Nothing calls this in 4.0.0") |
| `src/protocol/meta.rs:247` | `ADDED_IN_2026_07_28 = ["subscriptions/listen", "tasks/get", "tasks/update"]` | short by `tasks/cancel` and `notifications/tasks/status` |
| `src/gateway/router/handlers.rs:828` | `if !is_modern && ADDED_IN_2026_07_28.contains(&method)` -> `-32601` | a 2025-era client can reach `tasks/cancel` today, because the list does not name it |
| `src/gateway/router/handlers.rs:842` | `"subscriptions/listen"` returns an SSE stream, ack first | the stream a task's notifications must ride, and must not carry progress/message |
| `src/protocol/headers.rs:36-52` | `mcp_name_required` / `mcp_name_body_field`, "exactly these three" | the extension adds a fourth..sixth: `tasks/get\|update\|cancel` mirror `taskId`, not `name` |
| `src/protocol/era.rs:39-40` | `MISSING_REQUIRED_CLIENT_CAPABILITY: i32 = -32021` — "(was `-32003`)" | the draft still says `-32003`; the pinned 2026-07-28 text says `-32021`, and so does this tree |
| `src/gateway/meta_mcp/support.rs:26-45` | `resolve_idempotency_key` auto-derives from `(server, tool, arguments)` for every keyless call | SUB.4 would key a task-augmented call too, unless told not to |
| `src/protocol/cacheable.rs:99-101` | `is_final(result) == (resultType == "complete")` | `resultType: "task"` is non-final, so neither the response cache nor `mark_completed` can swallow a `CreateTaskResult` |

`src/gateway/meta_mcp/invoke.rs:1291` is the response-cache write (`cache.set`), after the
backend result and before the client stream. Any test that observes whether a backend ran twice
must set `config.cache.enabled = false` and assert on a mutation counter on the mock tool —
never on the response body, which the cache will happily replay.

Correction to the tree: the doc comment at `extensions.rs:52-56` says the gap is "two statuses,
two required fields and the shape of the failure payload". Measured against the pinned blob it is also
a third method (`tasks/cancel`), a notification (`notifications/tasks/status`), a required
nullable `ttlMs`, and an optional `pollIntervalMs`. That comment is part of the change.

## 3. The design

**The gateway originates tasks. It does not proxy a backend's.** No backend in the catalogue
speaks the extension — cluster C (`RELEASE-4.0.0-plan.md:52-56`) exists precisely because
backends are mostly pre-2026. So the gateway is the task *server*: it accepts a task-augmented
`tools/call`, returns a `CreateTaskResult` immediately, runs the backend call on its own, and
serves `tasks/get` / `tasks/update` / `tasks/cancel` from its own record.

Five pieces, in dependency order.

1. **`tasks.rs` grows into the spec's shape.** Five statuses (`working`, `input_required`,
   `completed`, `cancelled`, `failed`); `createdAt` and `lastUpdatedAt` required;
   `ttlMs: Option<...>` present-and-nullable, not absent; `pollIntervalMs` optional; `error`
   becomes a JSON-RPC error object, not a `String`. `Task::create` keeps a v4 UUID — the spec
   makes task IDs bearer-token-grade, so entropy is a requirement, not an aesthetic.

   **Changing `error` to an object turns a currently green test red, and that red is this change
   working.** `ac_task_1_a_failed_task_reports_its_failure_rather_than_an_absence`
   (`tests/mik_7272_exploit_acs.rs:189`) asserts `task.error() == Some("upstream refused")` — a
   `String`, the shape the pinned spec forbids. It passes today because the defect is present, so
   it fails at the moment the defect is removed. Rewrite it against the error object. Do not
   preserve the `String` to keep it green: that reads as repairing a regression and cements the
   wrong wire shape, which is the one thing this piece exists to change. Section 8a says why the
   other four cases in that file are not this problem.

2. **A task store.** Insert-if-absent, TTL-reaped, holding the record plus a secondary index
   (see §4). It is the *same defect class* as the consumed-continuation ledger recorded open in
   `dod-check.md` finding #1: process-local today, needs a shared atomic insert-if-absent store
   before production, and `tasks/get` reaching the replica that owns the task is the same
   replica-affinity problem cluster A is solving in `src/protocol/continuation.rs`. It inherits
   that gate rather than inventing a second one. A new store designed independently of cluster
   A's would be two mechanisms deciding the same thing.

3. **Capability gating is wiring, not construction.** `KEY_CLIENT_CAPABILITIES`
   (`meta.rs:44`), `classify_request` (`meta.rs:117`) and `ExtensionSet::from_capabilities`
   already read the per-request `_meta` envelope. The spec's MUST — never return a
   `CreateTaskResult` to a client that did not declare the extension *on that request,
   regardless of prior declarations* — maps onto a per-request read the gateway already
   performs. Non-declaring client, task-only path: `MISSING_REQUIRED_CLIENT_CAPABILITY` with
   `data.requiredCapabilities.extensions["io.modelcontextprotocol/tasks"]`.

4. **Method registration.** `ADDED_IN_2026_07_28` gains `tasks/cancel` and
   `notifications/tasks/status`; `handlers.rs` gains the four arms;
   `mcp_name_body_field` gains three entries mirroring `taskId`.

5. **Declaration.** *Corrected after designB2's EXT.1 note
   (`docs/design/2026-08-31-cluster-b-capability-and-trace-metadata.md`, anchored `5c7e64f4`).* An
   earlier revision of this note said `gateway_declares()` "is called from `server/discover`".
   That named a call site narrower than the real one and skipped a prior problem: **there is
   nowhere to put the declaration.** `ServerCapabilities` (`src/protocol/types.rs:231-254`) has
   seven fields and `extensions` is not among them — `rg -n 'extensions' src/protocol/types.rs`
   returns nothing. So EXT.1 is not a wiring job with a missing caller; the wire struct needs the
   field before any caller can matter.

   EXT.1 owns that decision and has made it: add `extensions` to `ServerCapabilities`, populate
   from `gateway_declares()` in `build_initialize_result`. That note gives the builder's path as
   `src/gateway/meta_mcp/meta_mcp_helpers.rs:144`; the file is at
   `src/gateway/meta_mcp_helpers.rs:144`, a sibling of the `meta_mcp/` directory rather than a
   member of it. The claim it carries survives the correction, and was checked here rather than
   taken: `rg -n 'build_initialize_result\(' src/` finds two production callers,
   `handle_initialize` (`src/gateway/meta_mcp/mod.rs:1084`) and `discover_document`
   (`:1003`), and discovery emits `"capabilities": handshake.capabilities` (`:1037`) — the whole
   struct, serialised as it stands. So one populate does reach both surfaces, and the second
   surface needs no code of its own.

   One detail the seam has to carry: the builder sets four capabilities explicitly and closes with
   `..Default::default()`. A new `extensions` field therefore arrives as its default on every
   response until EXT.1 assigns it there. **TASK.1 consumes that seam and does not restate it.**
   One seam, two consumers: EXT.1 owns the field and the call site, TASK.1 supplies the entry
   `io.modelcontextprotocol/tasks`. Neither closes alone, and TASK.1 does not need a second site.

### The two non-spec tasks capability structs

`src/protocol/types.rs` defines `ServerTasksCapability` (`:262`, reached from
`ServerCapabilities.tasks` at `:250`) and `ClientTasksCapability` (`:373`, from
`ClientCapabilities.tasks` at `:346`). Neither appears in the 2026-07-28 core schema, whose
`ServerCapabilities` has seven properties and `ClientCapabilities` five, with no `tasks` in
either.

**TASK.1 does not read, write or depend on either type**, and this note is correct whether they
are retired or kept. `rg -n 'ServerTasksCapability|ClientTasksCapability' -g '!target' .` returns
four matches, all four inside `types.rs` itself: the two definitions and the two struct fields.
No production code, no test, no serialisation path outside the derive. They are unreachable
today, so nothing TASK.1 builds can collide with them.

Their provenance is worth recording before the retire-or-keep call is made, because "locally
invented" would be the wrong reason to delete them. Both carry a `list` field — and the pinned
2026-07-28 extension text says there is deliberately no `tasks/list`, calling its absence "an
improvement over the `2025-11-25` tasks specification, in which a poorly-scoped list could expose
unrelated task IDs". A `tasks` capability advertising `cancel`, `list` and augmentable request
types is the **2025-11-25** shape. So the decision is not "delete a mistake" but "drop a
superseded revision's declaration surface", which is a different question with a different
answer if anything still speaks 2025-11-25 — and nothing here does, since the types have no
readers at all.

**Kept, on that reading.** Unread types cost nothing to leave in place, and deleting a public wire
type is an API break this release has no reason to take. The retire question survives as a
scheduled unknown in §6 rather than an open one here; it is owned, and nothing in TASK.1 waits on
its answer.

6. **Every task-related request is authorised against the task's owner.** The pinned text makes
   this a MUST in its own right, *beside* the entropy requirement and not satisfied by it: a
   server "MUST perform authentication and authorization checks on each task-related request to
   ensure that the client has permission to access a task". Unguessable IDs stop enumeration;
   they do not stop a caller who legitimately holds someone else's ID from reading it back. So
   the store record carries the authenticated principal that created the task, and the three
   retrieval methods compare the caller's principal against it before answering — returning the
   same not-found shape either way, because a distinguishable "exists but forbidden" turns an
   authorisation check back into an enumeration oracle.

   The principal is the one cluster E is making authoritative (`principal_window.rs`,
   `tenant_guard.rs` under the firewall module; TENANT.1: "keyed on authenticated principal, not
   session"). TASK.1 reads that key; it does not define a second notion of caller identity. If
   cluster E has not landed when TASK.1 is implemented, the check binds to whatever the request's
   authenticated principal is at that point and is revisited when cluster E lands — the ordering
   is the implementer's, the requirement is not optional either way. The spec's own reasoning
   supports the narrow read: it notes there is deliberately no `tasks/list`, "so a server cannot
   inadvertently leak the existence of one caller's tasks to another". Cross-caller leakage is a
   threat the extension designed against, and a gateway serving many principals is precisely
   where it reappears.

### Options considered

| option | rejected because |
|---|---|
| **Pass through a backend's own tasks** rather than originating | no backend speaks the extension; the criterion says "long-running *backend* calls", and pass-through would close it for zero real backends. Kept as a later addition, not a 4.0.0 shape. |
| **Reuse `subscriptions/listen` as the only retrieval path**, skip `tasks/get` | the criterion names `tasks/get` polling explicitly, and the spec requires `tasks/get` to be resolvable *before* a `CreateTaskResult` is returned. A stream-only design cannot satisfy the durability MUST. |
| **Derive `taskId` deterministically from the idempotency key** — elegant dedupe, no second index | violates the spec's entropy requirement: task IDs MAY act as bearer tokens, and a task ID derivable from `(server, tool, arguments)` is guessable by anyone who can guess the call. |
| **Let the response cache hold the `CreateTaskResult`** | it cannot: `is_final` (`cacheable.rs:99-101`) is false for `resultType: "task"`. Making it cacheable would replay a *handle* as an *answer*. Verified, and the reason the existing guards need no change. |
| **A fresh distributed task store designed here** | the continuation ledger has the same requirement and is being built in cluster A. Two stores, two consistency stories, one of them wrong. |

### Explicitly out of scope

- Backend-originated tasks (gateway relaying a backend's `CreateTaskResult`).
- Task augmentation on anything but `tools/call`. The spec says only `tools/call` supports it
  today and to design for more later; designing for more *now* is the speculative half.
- `input_required` task flows end-to-end. The status and its `inputRequests` shape are modelled
  so `tasks/get` can return them, but the elicitation round-trip belongs to cluster A (MRTR) and
  cluster H, and building a second continuation mechanism here is the mistake §P0 exists to stop.
- Persisting tasks across gateway restarts.
- The `dod-check.md` edit (§0) and the `server/discover` call site (EXT.1) — both scheduled, both
  owned elsewhere.

## 4. Coexistence with SUB.4 — one owner per call, not two mechanisms

SUB.4 (`docs/design/2026-08-31-sub-4-idempotency-wiring.md`) is being implemented now in another
session. The criterion it serves reads "idempotency key **or** the tasks extension", so a
task-augmented call satisfies it by the second branch. The plan
(`RELEASE-4.0.0-plan.md:48-50,110-112`) records both as shipping. The question is therefore not
which wins but **who owns re-issue safety when both are available**.

The failure mode is concrete: `resolve_idempotency_key` (`support.rs:26-45`) auto-derives a key
for *any* keyless call, so today a task-augmented `tools/call` would get one. Two mechanisms
would then independently decide the same call is a duplicate — and they can disagree, because
the idempotency entry can never be marked completed (`is_final` is false for `resultType:
"task"`), so it would sit in-flight until TTL while the task itself finished.

**Rule: when the tasks extension is negotiated on a request, the task store owns re-issue
safety. The idempotency cache is neither consulted nor written for that call.** The task store
carries a secondary index on the *same* derived key `(server, tool, arguments)`, so a retried
identical call resolves to the same `taskId` and the backend runs once. One structure decides;
the second cannot disagree with it because it is not asked. This is elimination, not a check
that detects the disagreement.

The existing guards need no change, and that is a verified result rather than a hope:
`ResponseCache::set` and `IdempotencyCache::mark_completed` both gate on `is_final`, and
`result_type_of` returns `"task"`, so a `CreateTaskResult` cannot enter either. The change is
the *skip on the way in*, not a new guard on the way out.

**Scheduled** — SUB.4's note currently declares TASK.1 out of scope and says it "neither builds
it nor depends on it". That sentence is now wrong in one direction: SUB.4 does not depend on
TASK.1, but TASK.1 changes when SUB.4's auto-derivation runs. Owner: the sibling session
implementing SUB.4. What resolves it: one paragraph in that note recording the skip condition.
When: before SUB.4's implementation merges. If it resolves badly: SUB.4 ships auto-derivation
unconditionally, and the first task-augmented call leaves a permanent in-flight idempotency
entry — a duplicate-suppression deadlock for that exact `(server, tool, arguments)` until TTL.

## 5. Coexistence with SUB.2 — the listen stream

`subscriptions/listen` already returns a real multiplexed SSE body (`handlers.rs:842`). The spec
forbids `notifications/progress` and `notifications/message` on a *task's* stream. So the filter
is not a TASK.1 detail bolted on later: `subscriptions/listen` with `taskIds` present is a
task-scoped stream and carries `notifications/tasks/status` only. SUB.2's design owns request-
scoped notification routing; this is a constraint on it, recorded here because TASK.1 is what
makes it reachable.

## 6. Unknowns

**Resolved.**

- *Where is the tasks extension specified?* — `nab fetch` against four paths under
  `modelcontextprotocol.io/specification/...` and the `main` schema tree — all four 404
  (`.../2026-07-28/extensions/tasks` returned a 4-byte `null`); `nab fetch
  https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks` returned 200 OK,
  163,394 bytes — the 404s were wrong paths, not a missing document, and the real text
  invalidated the gap count written at `extensions.rs:52-56`. *Re-asked the same day, because
  that answer named a draft:* `nab fetch
  https://tasks.extensions.modelcontextprotocol.io/specification` — **404**, so the published site
  is not the artifact; then the extension's own repository —
  `modelcontextprotocol/ext-tasks`, tree `0d0a6bd4`, `specification/2026-07-28/tasks.md`, blob
  `5d6a202e`, 911 lines. The versioned text exists in git. That changed §1 from "no versioned
  normative artifact" to a pinned blob, and it changed the answer below.
- *Does the core 2026-07-28 schema define the task types?* — `rg -io 'task[A-Za-z]*'` over the
  181,834-byte core schema — exactly one hit, at line 3145, an example key in a description —
  the extension is versioned separately from the core revision, which is why the core schema
  cannot be the source and the search had to continue.
- *Can a `CreateTaskResult` be swallowed by the response cache or the idempotency cache?* — read
  `cacheable.rs:99-101` and the two call sites — `is_final` is `resultType == "complete"`, and
  `"task"` is not — no change needed to either guard, which is why §4's rule is a skip on entry
  rather than a new gate. This one changed nothing in those two files; saying so is the point.
- *Does `-32003` exist in this tree?* — `rg -n '32003' src/` — `era.rs:39-40` defines
  `MISSING_REQUIRED_CLIENT_CAPABILITY = -32021` with the comment "(was `-32003`)" — the draft's
  number is the *pre-renumbering* one.

- *So which number does a non-declaring client get — the draft's `-32003` or this tree's
  `-32021`?* — read the pinned blob's error table: "Missing required client capabilities:
  `-32021` (Missing Required Client Capability)". The versioned text agrees with `era.rs:39-40`;
  the draft is stale on this point. That closed what an earlier revision of this note deferred to
  the implementer with an upstream question attached — there is no divergence to record and
  nobody to ask.

Two questions this section previously deferred are answered above. Both were deferred on the
reading that no versioned text existed, so pinning one artifact closed both. Two rows remain, and
the second is new: the two non-spec capability structs were recorded above as somebody's decision
without being scheduled, which is an assumption with better manners. Scheduled here.

**Deferred.**

| open question | owner | what would resolve it | when | if it resolves badly |
|---|---|---|---|---|
| Whether `ServerTasksCapability` and `ClientTasksCapability` are retired. Kept for now: no readers, so they cost nothing, and deleting a public wire type is an API break this release has no reason to take | team lead | an operator answer on whether clients speaking the 2025-11-25 `tasks` shape are still served | when NFR.COMPAT.1 is audited. `docs/requirements/RELEASE-4.0.0-requirements.md:210` already requires that 2025-11-25 be served, which settles that such clients exist but not that these two structs serve them, since nothing reads either | deletion becomes a separate API-break change carrying its own migration note, not a line in this one. Nothing here waits on it: TASK.1 reads neither type, so this design is correct under either answer |
| Where the task store lives when the gateway runs multi-replica. | cluster A (MIK-7212), via the shared insert-if-absent store `dod-check.md` finding #1 already gates BEFORE-PRODUCTION | cluster A landing a shared ledger this can reuse | before production, not before merge | single-replica-only tasks: a `tasks/get` routed to another replica reports the task as missing while it is running. Same failure the continuation ledger has, same gate, deliberately not a second design |

## 7. MIK-7311 — reconciled, not routed around

`dod-check.md:557-584` names MIK-7311 as owner of the conformant implementation, already filed,
carrying seven acceptance criteria, and records that those criteria "were derived from the
overview and inherit these errors" and must be "corrected against the schema before that ticket
is worked".

**MIK-7311 stays the implementation ticket. This note is the correction.** The criteria below
supersede the seven derived-from-overview ones; MIK-7311's description is updated to point here
rather than a second ticket being filed (§P0 disposal: fix it in this change — the correction is
smaller than a ticket describing the correction would be).

## 8. Acceptance criteria and test plan

One row per criterion. The last column is the honest one: whether the named case can *fail
today*, and how that is known. A case that can only fail because no dispatcher exists yet would
go green against any stub — that is stated, not papered over.

| AC | criterion | case | V-model | can it fail today? |
|---|---|---|---|---|
| `MIK-7272.TASK.1.1` | a task-augmented `tools/call` from a declaring client returns `CreateTaskResult` with `resultType: "task"` and a `taskId` that `tasks/get` already resolves | integration: call, then `tasks/get` the returned id in the same test before any status change | integration | **No — vacuous until the dispatcher exists.** No arm in `handlers.rs`, so the case is red for absence, not for behaviour. Any stub returning a task passes it. Stated as the finding. |
| `MIK-7272.TASK.1.2` | `tasks/get` returns the per-status shape: `working`, `input_required` + `inputRequests`, `completed` + `result`, `cancelled`, `failed` + `error` | unit over the five `TaskStatus` variants' serialisation | unit | **Yes, partially, and for a real reason.** `tasks.rs` has three of five statuses; `input_required` and `cancelled` do not exist, so the case fails to compile against today's enum. The three that exist would pass. |
| `MIK-7272.TASK.1.3` | `tasks/update` is accepted and advances `lastUpdatedAt` | unit on the store's update path | unit | **No — vacuous twice over.** `lastUpdatedAt` does not exist on `Task` (fails to compile, so it is red) *and* nothing dispatches `tasks/update`. The compile failure is real; the behaviour is not yet observable. |
| `MIK-7272.TASK.1.4` | a client that does not declare the extension **on that request** never receives a `CreateTaskResult`, and gets `MISSING_REQUIRED_CLIENT_CAPABILITY` carrying `data.requiredCapabilities.extensions["io.modelcontextprotocol/tasks"]` — even if it declared on an earlier request | integration: declare on request 1, omit on request 2, assert request 2 is the error and not a task | integration | **Yes — this is the row that catches a stub.** A dispatcher that returns tasks unconditionally passes 1.1 and fails this. It asserts the constant from `era.rs:40`, which the pinned 2026-07-28 text confirms, so the number is settled rather than deferred. |
| `MIK-7272.TASK.1.5` | a 2025-era peer calling `tasks/cancel` is refused `-32601` by the era gate | unit on `ADDED_IN_2026_07_28` membership, plus a router case through `handlers.rs:828` | unit + integration | **Yes, red now, for a real reason.** `meta.rs:247` does not list `tasks/cancel`, so the gate lets it through today. Independent of the dispatcher — it is a list-membership assertion. |
| `MIK-7272.TASK.1.6` | a `failed` task carries the JSON-RPC `error` **object**; a tool result with `isError: true` is `completed` with `result`, never `failed` | unit: construct both, assert the serialised shapes | unit | **Yes, red now, for a real reason.** `tasks.rs:37` is `error: Option<String>`; an object cannot be represented, so the first half fails to compile. The second half is a classification assertion that has no implementation to agree with it. |
| `MIK-7272.TASK.1.7` | `Mcp-Name` on `tasks/get\|update\|cancel` mirrors `params.taskId` | unit on `mcp_name_body_field` for the three methods | unit | **Yes, red now, for a real reason.** `headers.rs:36-52` returns `None` for all three ("exactly these three" methods), so the case fails on today's code with no dispatcher involved. |
| `MIK-7272.TASK.1.8` | a retried identical task-augmented call returns the **same** `taskId` and runs the backend **once**; the `CreateTaskResult` is never written to the response cache and never marked idempotency-completed | integration with `config.cache.enabled = false` and a mutation counter on the mock tool; assert the counter is 1 and both responses carry the same `taskId` | integration | **Yes for the guards, no for the dedupe.** The two guard halves are falsifiable against the existing `is_final` gates today. The same-`taskId` half needs the store. Fixture rule is binding: the response cache is written at `invoke.rs:1291`, after the backend result and before the client stream, so a fixture that leaves it enabled passes vacuously — assert the counter, never the body. |
| `MIK-7272.TASK.1.9` | a `subscriptions/listen` carrying `taskIds` emits `notifications/tasks/status` and no `notifications/progress` or `notifications/message` | integration: drive a task that would emit progress, read the stream | integration | **No — vacuous until both TASK.1 and SUB.2 land.** Nothing emits task notifications, so an empty stream passes. Recorded as a constraint on SUB.2 (§5) so it is not discovered late. |
| `MIK-7272.TASK.1.11` | a retrieval call naming a task created by a different principal is answered as not-found, identically to a `taskId` that never existed | integration: create as principal A, retrieve as principal B, assert the response is byte-identical to retrieving an unknown id as B | integration | **No — vacuous until the dispatcher exists**, and it is the row most likely to be dropped as a nicety. Recorded here so the authorisation check lands with the dispatcher rather than after a review round. The byte-identical half is what makes it a test rather than a sentiment. |
| `MIK-7272.TASK.1.10` | the capabilities EXT.1 builds advertise `extensions["io.modelcontextprotocol/tasks"] = {}`, on both `initialize` and `server/discover` | unit on `gateway_declares()` output, plus EXT.1's discovery integration case | unit | **No, and it is not TASK.1's to close.** `gateway_declares()` already returns the entry (`extensions.rs:52-56`); the unit case is green today. It cannot go red until EXT.1 adds `extensions` to `ServerCapabilities` and populates it in `build_initialize_result` — the field does not exist yet, so this is blocked on a struct change, not on a caller. Listed so the split is visible, not to claim it. |

Five rows out of eleven cannot fail for a behavioural reason today. That is the finding: TASK.1 is
mostly new surface, and the tests that constrain it are the five that assert against *existing*
code — `ADDED_IN_2026_07_28`, `mcp_name_body_field`, the `Task` shape, the `is_final` guards, and
the per-request capability read. Those five are where the failing-tests step (§P2) has real work
on day one; the rest wait on the dispatcher and must be written against the spec text, not
against whatever the dispatcher turns out to do.

## 8a. The existing `ac_task_1_*` cases do not cover the criterion

Asked by the team lead after designB2 found two MIK-7272 AC cases that cannot go red. The five
`ac_task_1_*` cases in `tests/mik_7272_exploit_acs.rs:157-211` are a different failure from those
two, and the difference matters.

They are **not** tautologies. Each asserts real behaviour of `Task`: that a fresh task is
`Working` with a non-empty id, that `result()` is `None` before completion rather than a default,
that `fail()` records an error distinguishable from "not finished", that a second `complete()`
does not overwrite the first. Break any of those in `tasks.rs` and the case goes red. As unit
tests of that struct they are honest.

What they do not do is cover the criterion. `rg -n 'protocol::tasks' -g '!target' src/ tests/`
returns exactly one match — the `use` at `:153` of that test file. **`protocol::tasks` has no
production consumer at all**, so nothing these cases assert is reachable from a request. Read
against the criterion's own words:

| criterion clause | what the five cases exercise |
|---|---|
| "supported for long-running **backend** calls" | no backend, no gateway, no request in any body |
| "`tasks/get` polling" | `ac_task_1_a_task_is_polled_not_awaited` and `..._polling_a_working_task_yields_no_result` call `complete()` and read a field in-process; no method, no dispatch, no poll |
| "`tasks/update`" | not mentioned in any of the five, and `Task` has no update method to mention |

So the answer to "what would have to break in production for this to go red" is: **nothing can,
because none of it runs in production.** Only an edit to `tasks.rs` turns them red. TASK.1's
evidence is smaller than the status doc's coverage implies — the criterion is uncovered, and the
gap is not one an extra assertion closes.

One of the five is worse than uncovered. `ac_task_1_a_failed_task_reports_its_failure_rather_than_an_absence`
asserts `task.error() == Some("upstream refused")` — a string. §2 records that the spec requires
the failure payload to be a JSON-RPC error **object**, and §3.1 changes the field accordingly.
That case therefore goes red when TASK.1 is implemented *correctly*: it pins the defect. It is
not a test to preserve through the change; it is a test to rewrite against the object shape, and
a reviewer who sees it fail should read it as the change working.

Disposition (§P0): recorded here, not filed. The §8 table already specifies what replaces these
five, and the replacement is part of TASK.1's own work rather than a separate ticket. The wider
question — whether the same inertness runs beyond these cases — is already being swept by the
audit running against every test file in the tree, so this note points at that rather than opening
a second one.

That sweep separates two shapes, and the distinction decides the repair. A case asserting an
invariant that cannot vary is a bad test and is deleted. A case asserting real behaviour in a
module production never reaches is a *good* test waiting for its production caller, and deleting
it would destroy the specification it carries. Four of these five are the second kind: they hold
the shape `Task` is supposed to have, written down, and TASK.1's job is to build the caller that
makes them reachable — not to remove them. The fifth is the `error()` case above, which is neither:
it records the shape the spec forbids, so it is rewritten rather than kept or deleted.

## 9. Documents this change makes untrue

- `docs/requirements/RELEASE-4.0.0-dod-check.md:557-584` — scheduled in §0.
- `docs/requirements/RELEASE-4.0.0-criteria-status.md:160` — TASK.1 moves off ABSENT when the
  implementation lands, not when this note lands.
- `src/protocol/extensions.rs:52-56` — the gap count in the doc comment is wrong (§2), and the
  "Wire this up as part of MIK-7311, not before" sentence stays correct.
- `docs/design/2026-08-31-sub-4-idempotency-wiring.md` — scheduled in §4, owned by the sibling
  session.
- `RELEASE-4.0.0-plan.md:48-50` — already correct; it says a decision to build TASK.1 changes
  SUB.4's scope, and §4 is that change.
- `docs/design/2026-08-31-cluster-b-capability-and-trace-metadata.md` — not made untrue; consumed.
  It owns the `extensions` field, the `build_initialize_result` call site and the retire-or-keep
  question on the two non-spec capability structs. §3.5 cites those decisions rather than
  restating them, and this note holds under either answer to the retire question. TASK.1 touches
  no correlation or trace surface, so that note's three-trace-surfaces finding does not reach
  this design.
