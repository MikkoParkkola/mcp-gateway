# MIK-7272.SUB4.STDIO.OWNER.1–5 and SUB4.BRIDGE.LIFE.1 — the stdio owner and the held legacy RPC

Status: rev 4 (2026-09-30; rev 3 below), refreshed against `41ef8781c` (#2414 merged). Rev 3 changes:
the criteria are quoted from the release ledger rather than Linear; D1's catalogue path is
corrected (the rev 2 signature change was a public-API change); D5 is rewritten to the ledger's
LIFE.1 text; §P1b.OWNER.2 is filled; D7 adds MIK-7217.STDIO.1, which rev 2 did not cover.
Round 2 for both seats (seat 1 reviewed rev 1; seat 2 has reviewed nothing yet).

Amends `docs/design/2026-08-31-sub-4-idempotency-wiring.md`. That document (lines 36–43) records
the `MIK-7272.SUB4.STDIO.OWNER.*` criteria as invented by a reviewer, because they exist only in
Linear and not in `docs/`. They are real: Linear MIK-7272 carries OWNER.1–5 and BRIDGE.LIFE.1 as
pending acceptance criteria. This document is where they enter the tree.

Ledger row IDs (the checker needs `TICKET.COMPONENT.N`): `MIK-7272.OWNER.1`–`MIK-7272.OWNER.5`
and `MIK-7272.LIFE.1`. Tests and PR bodies use these IDs.

## §P1a — Problem definition

### The criteria, verbatim from the release ledger (authoritative)

`docs/requirements/RELEASE-4.0.0-scope-update.md:140-146`. These are what the rows are graded
against; the Linear text below is provenance only.

| Row | Criterion |
|---|---|
| MIK-7217.STDIO.1 | The stdio server/discover answer advertises 2026-07-28 when the modern protocol is on, asserted by an exact-version test (MIK-7217 AC DISCOVER.1 caveat). |
| MIK-7272.OWNER.1 | On modern stdio, keyed writes execute once and replay without another effect; a keyless write executes (no refusal); legacy unkeyed repeats execute twice; all six management branches are tested (MIK-7272 SUB4.STDIO.OWNER.1, amended by operator ruling 2026-09-30). |
| MIK-7272.OWNER.2 | The same protected task store reopens or relocates and its typed local operator retrieves the task; another store and a same-store HTTP owner cannot retrieve or alias it; exercised through store integration and the independent functional gate, with no global lookup and no new instance UUID (MIK-7272 SUB4.STDIO.OWNER.2). |
| MIK-7272.OWNER.3 | An injected principal tag or HTTP credential string equal to the stdio serialized spelling cannot select or alias the stdio local operator; only the transport creates the typed tag; same-key owner-specific outputs stay separate and the real stdio owner works (MIK-7272 SUB4.STDIO.OWNER.3). |
| MIK-7272.OWNER.4 | A ToolPolicy denial refuses a local-operator mutation before retained-output delivery with zero dispatch to the denied target, while a permitted neighbouring target works (MIK-7272 SUB4.STDIO.OWNER.4). |
| MIK-7272.OWNER.5 | The real stdio-created context carries its execution principal but no verified identity, personal account or delegated grant; account-dependent calls are refused and an ordinary local mutation works (MIK-7272 SUB4.STDIO.OWNER.5). |
| MIK-7272.LIFE.1 | A held legacy RPC can be cancelled and joined: cancelling it releases the held exchange and its waiter gets a terminal answer, with nothing left pending (MIK-7272 SUB4.BRIDGE.LIFE.1). |

### Provenance: the Linear MIK-7272 text (read 2026-09-30)

- **OWNER.1** — Real modern stdio keyed writes execute once and replay without another effect;
  missing key refuses; legacy unkeyed repeats execute twice. Preserve all six management
  branches. Validate within the same private service realm; no cross-restart Sync guarantee.
- **OWNER.2** — The same protected Task store reopens or relocates and its typed local operator
  retrieves the task; another store and a same-store HTTP owner cannot retrieve or alias it.
  Exercise store integration and the independent functional gate. No global lookup or new
  instance UUID.
- **OWNER.3** — An injected request principal tag or HTTP credential string equal to the stdio
  serialized spelling cannot select or alias StdioLocalOperator. Only the transport creates the
  typed tag; same-key owner-specific outputs remain separate and the real stdio owner works.
- **OWNER.4** — Current ToolPolicy denial refuses a typed local-operator mutation before
  retained-output delivery; a permitted neighboring target works. Capture real dispatch counts:
  denied target zero.
- **OWNER.5** — The real stdio-created context carries its execution principal but no
  VerifiedIdentity, personal-account or delegated-grant identity. Assert the actual context and
  account-dependent refusal alongside an ordinary local-mutation positive control.
- **BRIDGE.LIFE.1** — "Held legacy RPC cancellation/join remains a blocking 4.0 requirement."
  (Ticket body; no further text. Distinct from MIK-7311.LIFECYCLE.1, which is the tasks-extension
  lifecycle.)

### Operator ruling 2026-09-30 (binding, not re-opened here)

OWNER.1 is amended: a **keyless** data-changing stdio call **keeps running** — Axis 3 of the sub-4
design stands, and "missing key refuses" is withdrawn. What remains of OWNER.1: a keyed modern
stdio call executes once and replays without a second effect; an unkeyed legacy repeat executes
twice; the six management branches are tested.

### The problem, and whose it is

The stdio transport is the single-user local deployment: the client spawned the gateway, so it
is the operator. Its identity today is the string `"stdio"` (`STDIO_CREDENTIAL_PRINCIPAL`), set
on the caller context by the transport and compared as a string downstream. Everything the
gateway keys by owner — retained idempotency outputs, durable tasks, account resolution, audit
provenance — keys stdio's work by that same string that an HTTP credential could also spell.

Who feels it: (a) a stdio operator whose retained outputs or tasks could be read or replayed by
an HTTP caller whose principal string happens to equal `"stdio"` (an API key or token subject
named `stdio`, or a principal carried in request data); (b) the same operator if a denied tool's
retained output is delivered without the current policy being consulted; (c) the operator of a
stdio client that sends `notifications/cancelled` or closes stdin while a legacy RPC is held —
whether that work is cancelled, joined, or left running unobserved.

How often: every stdio deployment that also runs the HTTP surface against the same stores for
(a); every policy change between a keyed call and its replay for (b); every client cancel or
shutdown with a call in flight for (c).

### Why now

MIK-7272 lists these as pending 4.0 acceptance criteria and BRIDGE.LIFE.1 is marked blocking for
4.0. The release ledger has no rows for OWNER.2–5 or BRIDGE.LIFE.1 (audit
`.git/linear-audit-4.0.md`, MIK-7272 section: UNTRACKED). Leaving them unsolved means 4.0 ships
with an owner identity that is a forgeable string on a trust boundary, and an undefined
cancel/shutdown behavior on the default local transport.

### Measured constraints

- C1. The meta-MCP surface does not grow (CLAUDE.md, locked decision).
- C2. No `unsafe` (crate-level deny).
- C3. OWNER.2: no global lookup and no new instance UUID; the store's existing protection
  scheme is the boundary.
- C4. OWNER.1: same private service realm only; no cross-restart replay guarantee.
- C5. Keyless stdio data-changing calls execute (operator ruling above).
- C6. The existing HTTP owner semantics and every existing test keep their meaning: this lane
  changes how stdio is named, not how HTTP callers are named.
- C7. Any new public API item (pub field, type, re-export, config key) needs operator approval
  before merge.

### Acceptance signal (observable)

Each criterion above holds as stated, shown by a test that drives the real stdio dispatch path
(`run_stdio_on` or the same `dispatch_tools_call` it calls) and counts real backend dispatches,
and each test fails when the property it guards is removed:

- OWNER.1: keyed modern call → 1 dispatch across original + replay, replay returns the stored
  result; keyless modern call → executes (1 dispatch per call); legacy unkeyed call sent twice →
  2 dispatches; each of the six management branches exercised over stdio.
- OWNER.2: task created by the stdio operator is retrievable by the stdio operator after the
  same protected store is reopened/relocated; not retrievable from a different store, nor by an
  HTTP owner on the same store, including one whose principal string equals `"stdio"`.
- OWNER.3: an HTTP caller whose credential string or injected principal tag equals the stdio
  spelling neither selects the stdio owner nor reads its retained output for the same key; the
  real stdio owner still replays its own.
- OWNER.4: after a ToolPolicy denial is in force, a keyed replay of the denied target is refused
  before the retained output is returned; denied target dispatch count 0; a permitted neighbour
  works.
- OWNER.5: the context stdio actually builds has an execution principal and `None` for verified
  identity, personal account and delegated grant; an account-dependent tool is refused while an
  ordinary local mutation succeeds.
- BRIDGE.LIFE.1: for a held legacy RPC on the stdio bridge, `notifications/cancelled` naming it
  cancels it and the bridge joins it (no orphaned task; no frame for the cancelled id is
  queued once the cancel is processed; `pending` empty); stdin EOF with an RPC in flight joins or cancels it before the loop returns.
  Precise semantics are a §P1b decision, but "observable end state with no orphan" is the signal.

### Exclusions

- Cross-restart replay (C4), cross-store task lookup (C3).
- The HTTP-route idempotency wiring (sub-4 routes 1 and 3) beyond what OWNER.3/4 need to prove
  non-aliasing.
- MIK-7311.LIFECYCLE.1 (tasks lifecycle).
- Changing the keyless-write decision (ruling above).

## §P1b — Solution design

### Facts the design rests on (read at `dc44ebc7b`; rev 3 re-checked at `41ef8781c`)

- F1. One serve mode per process: `src/main.rs:295-296` runs `run_stdio_server` or `run_server`,
  never both. A stdio gateway and an HTTP gateway share nothing in memory.
- F2. Both retained-output stores are in memory, one per process: `IdempotencyCache`
  (`src/idempotency.rs:145`) and `ExecutionAdmission` (`src/idempotency/admission.rs:72-89`).
- F3. HTTP credential principals are a 12-hex-char digest (`src/gateway/auth.rs:55-60, 286`),
  `"dashboard-session"` (`:614`) or empty (`:666`). None can equal `"stdio"` today.
- F4. The operator decision is nevertheless a string match: `CallerProvenance::classify`
  (`src/identity_propagation/caller_proof.rs:71-76`) maps `Some("stdio")` to `LocalTransport`,
  and admission and cache namespace by the same string (`meta_mcp/admission.rs:112-116,182-189`;
  `meta_mcp/support.rs:163-193`, stdio → `cred:5:stdio`). Any future path that lets a string
  reach `credential_principal` (a persisted record, a header, a new auth kind) becomes the operator.
- F5. Policy runs before replay on stdio (rev 2: see D3 for the signing qualification): `admit_meta_sync` calls `check_invocation_policy`
  before `admit_sync` (`meta_mcp/admission.rs:~301`), documented at `invoke.rs:1137-1146`.
  Exception: skipped when `caller.signing.prepared_for(server, tool)`.
- F6. The six management branches are the tools `mark_management_dispatch` covers
  (`meta_mcp/admission.rs:376-424`): `gateway_kill_server`, `gateway_revive_server`,
  `gateway_set_state`, `gateway_set_profile`, `gateway_reload_config`,
  `gateway_reload_capabilities`, called at `meta_mcp/mod.rs:2326-2331`.
- F7. Stdio drops every notification, `notifications/cancelled` included
  (`server/mod.rs:3081-3084`). EOF calls `channel.close()` (held bridge prompts fail), drains for
  `STDIO_DRAIN_TIMEOUT`, then `dispatches.shutdown()` (aborts and joins) (`server/mod.rs:2669-2690`).
- F8. Aborting a dispatch is safe for admission: `Lease::drop` settles a dispatched lease as
  outcome-unknown and abandons an undispatched one (`idempotency/admission.rs:406-416`);
  `IdempotencyReservation::drop` releases or settles (`idempotency.rs:767-790`).

### D1 — the transport's mark decides, not the principal text (OWNER.3, OWNER.5; rev 4, as built in #2494)

Framing: preventive boundary hardening. F1-F3 mean no HTTP-to-stdio replay is reachable today
(`.git/security-private-4.0.md` records the reachability check). OWNER.3 removes principal text as
the thing that decides, so the next path that lets text reach `credential_principal` does not
become the operator. The I1 tests share one `MetaMcp` (one private service realm), so process
isolation cannot make them pass vacuously.

**The typed tag is `StdioNonce`, which already exists** (`server/stdio_nonce.rs`,
MIK-7570.STDIO.1). Its field and constructor are private, `StdioNonce::process` is `pub(super)` to
the stdio transport module, and its doc states the control this row needs: "only its two
caller-context builders can bind a caller as stdio. An HTTP caller has no path to the value,
whatever text it presents." `MetaMcpCallerContext` already carries it as
`stdio_nonce: Option<&StdioNonce>` (`meta_mcp/mod.rs:186`). The only production sites that set it
are `build_stdio_caller_context` (`server/mod.rs:3177`) and `with_retry`, which copies it
(`meta_mcp/mod.rs:283`); the `cfg(test)` fixture `stdio_caller_context` also sets it. Every other
constructor (HTTP, task recovery, task worker, all test fixtures) sets `None`. Batch items reach
the same builder (`dispatch_batch_with_sink` → `dispatch_single_with_sink` with a `StdioClient`,
`server/mod.rs:3391-3403`). No new type and no new context field are added: that avoids 69
struct-literal edits and a second value that could drift from the first. The ledger's "stdio local
operator" is this mark's presence.

Decisions that switch from the text to the mark. All new items are `pub(crate)` (C7); no `pub`
signature changes. `StdioNonce` gains a `pub(crate)` re-export at `gateway/mod.rs`, the same
pattern `STDIO_CREDENTIAL_PRINCIPAL` uses, so `identity_propagation` can name it.

1. **Owner text for retained results**: `MetaMcpCallerContext::owner_principal()`. A marked
   context returns the reserved constant `LOCAL_OPERATOR_PRINCIPAL = "\0local-operator.v1"`.
   Anything else returns its `credential_principal`, except text starting with the reserved
   prefix NUL, which is dropped. No presented credential can start with NUL: HTTP header values
   cannot carry it, and every principal the auth layer derives is a hex digest or a fixed word.
   Both stores read owner text only through this method:
   - admission ledger: `admit_meta_sync` (`meta_mcp/admission.rs:377`);
   - idempotency cache: `caller_cache_principal` (`meta_mcp/invoke.rs:1805`), which renders it
     under its existing length-prefixed `cred:{len}:…` arm.

   Dropped reserved text gets **no key, never an empty or shared one**. A keyed call has no
   principal and is refused -32003 (`admission.rs:294-301`), and the cache classifies the caller
   `Unresolved`: no cache key, no retry key (`support.rs:188-191`). An anonymous caller pools as
   it does today whatever its text (unchanged).
2. **Provenance**: `CallerProvenance::classify(text)` never returns `LocalTransport`; text,
   including the stdio spelling, is `Credential`. `CallerProvenance::local_transport(&StdioNonce)`
   is the only constructor of `LocalTransport`. `MetaMcpCallerContext::provenance()` picks between
   them, and the two context-bearing call sites use it (`meta_mcp/invoke.rs:1648`,
   `meta_mcp/discovery_fetch.rs:79`). The HTTP backend route keeps `classify` (no mark exists
   there).
3. **Catalogue requests** (`prompts/*`, `resources/*`) carry no caller context: stdio builds an
   `AuthenticatedClient`, which is public API and gets no tag (C7). They now classify
   `Credential`. That gives the same decision today, because `establishes_the_operator` admits
   both (`caller_proof.rs:92`), and fails closed (a visible refusal) if that rule ever tightens.
   Rev 3's plan to thread the tag through five `pub(crate)` handler siblings is dropped: it bought
   a label and no decision, at the cost of five wrappers.

`STDIO_CREDENTIAL_PRINCIPAL` stays as the audit and display principal (no audit schema change, C6).

Alternatives rejected: (a) keying off `CredentialKind::LocalTransport`, an audit enum the task
execution context carries as data (`task_service/execution/context.rs:42`), so a rebuilt context
could carry it; (b) a field on `AuthenticatedClient`, which widens public API; (c) a new
`StdioLocalOperator` type, which duplicates `StdioNonce`; (d) a principal-kind field on the
admission `Request`, which touches about 30 construction sites for what a reserved prefix does in
one place.

Risk: a stdio path that loses the mark keys by its text. It still establishes the operator
(`Credential`), so nothing visibly fails and only the separation disappears. The guard is test
coverage: I1 asserts the mark on single calls, batched calls and chain steps (T3.1-T3.7), and the
mutant batch removes it at each site.

### D2 — OWNER.1: tests over the real stdio loop, no product change expected

Keyed modern call → 1 dispatch, replay returns the stored result; keyless modern call executes
(C4); legacy unkeyed call sent twice → 2 dispatches; each of the six F6 tools called over stdio
with its management effect observed. Driven through `run_stdio_on` over `tokio::io::duplex` with
a counting backend (the `EchoBackend::tools_call_count` fixture,
`server/tests/signing_nonce_allocations_support.rs:152,257-290`, adapted to the serve loop). If a
test goes red on the current tree, the fix is scoped in the test-plan round, not here.

### D3 — OWNER.4: current policy before replay

Rev 2 correction: there is no live ToolPolicy reload. Startup compiles one immutable
`Arc<ToolPolicy>` (`server/mod.rs:929-931`), stdio borrows it for the life of the process, and
config reload classifies `security` as restart-required (`config_reload/mod.rs:565-568,635-642`).
"Current" therefore means the policy passed with the request being dispatched. Live policy
publication is not designed here; it would be a feature (4.1 by the scope rule).

Two stores can replay, and the order was re-verified against #1951 (HTTP replays the cache
before the tool-block check, `router/backend_handlers.rs:1015` vs `:1042`; meta route
`invoke.rs:~1858`). On stdio every `tools/call` runs signing preparation, then `admit_meta_sync`
(`server/mod.rs:3298-3325`), which checks policy before the admission-ledger replay
(`meta_mcp/admission.rs:~277-301`; gateway tools through `authorize_execution_plan`,
`admission_plan.rs:52,87`). Only after that does `invoke_tool_traced` reach the `IdempotencyCache`
(`invoke.rs:1855-1857`), which has no policy check of its own. Stdio is therefore protected by
caller order, not by construction. The #1951 fix belongs to the controls lane (IDEM), and this lane
does not edit `invoke.rs` or `backend_handlers.rs`; the tests below pin the stdio order so a
regression from either lane turns them red.

Mechanism exists (F5). Tests at the dispatcher level, against ONE `MetaMcp` (one admission ledger
and retained-output cache), calling the same `dispatch_single_with_sink` the stdio loop calls:

1. Keyed call to target T under policy P1 (permits T) → executes, T count 1.
2. Same key, same arguments, under P2 (denies T) → refused with the policy error, no retained
   output in the response, T count still 1 (zero dispatches for the denied attempt).
3. A neighbouring target U under P2 → executes, U count 1.
4. With P2 in force from the start, a first call to T → refused, T count 0.

Signing (rev 2 correction of F5's exception): each stdio frame builds a fresh signing context
(`server/mod.rs:2887-2891,3024-3026`), and signing preparation checks policy before it records the
target (`meta_mcp/signing.rs:169-213`); admission follows immediately (`server/mod.rs:3298-3320`).
So the skip reuses a check made moments earlier in the same request, never one from an earlier
request. Test 2 is repeated with signing enabled to pin that: the fresh preparation refuses under
P2. No product change is planned for D3; a red test reopens design.

### D4 — OWNER.5: what the stdio context carries

Test on the context the real stdio path builds (captured through the dispatcher, not the
`stdio_caller_context` fixture): `stdio_nonce` is `Some`; `verified_identity`, `grant_subject`
and `api_key_name` are `None`.

Interpretation, stated as acceptance wording (rev 2): "no personal-account identity" means no
request-carried or per-user identity. It does NOT mean no account resolves: stdio deliberately
resolves `Principal::SoleOperator` for the deployment's managed account
(`server/account_bindings.rs:89-91`; `personal_accounts/vault.rs:210-226`; test
`stdio_run_path_serves_its_operator_the_managed_account`), and that ruling is preserved. The test
asserts three things in one session:

1. the resolved principal kind is `SoleOperator` (never a per-user principal);
2. a backend configured for per-user identity propagation is refused with "the request carries no
   verified end-user identity" (`meta_mcp/invoke.rs:3153-3154`);
3. an ordinary local mutation succeeds (positive control).

### D5 — LIFE.1: cancel and join a held legacy RPC (rev 3, rewritten to the ledger text)

Vocabulary, fixed against the code. The only production `ClientChannel` caller on stdio is the
input bridge (`meta_mcp/invoke.rs:1058`, `InputBridge::run` → `ask` → `send_request`,
`gateway/input_bridge.rs:526,690`). A **held legacy RPC** is a legacy-shaped stdio `tools/call`
whose dispatch is parked in `StdioClientChannel::send_request` waiting for the client's reply to
an outbound `elicitation/create`. The **held exchange** is that outbound prompt: its entry in
`StdioClientChannel.pending` (`server/stdio_channel.rs:27`). Its **waiter** is the
`send_request` future inside the spawned dispatch task. **Nothing left pending** means: no entry
in `pending`, no task in the `JoinSet`, the inflight slot and the admission permit released.

Mechanism. The read loop handles `notifications/cancelled` before the notification drop at
`server/mod.rs:3100` (it is routed in the loop, never dispatched): when `params.requestId` names an
in-flight spawned dispatch, that task is aborted. The abort drops the dispatch future, so:

1. the waiter (the `send_request` future) is dropped at once, never resumed, instead of waiting
   out the bridge's timeout. Its terminal answer is the joined task's `Cancelled` outcome, which
   the completion arm observes; no value is delivered into the dropped future (the lead
   confirmed this reading 2026-09-30; a literal delivered value would need a new
   `DeliveryError` variant, a public-API change);
2. `PendingRequestGuard` (`stdio_channel.rs:106`) removes the held exchange from `pending`, so a
   late client reply to the prompt matches nothing (`resolve` → `false`, the existing path);
3. the slot and permit it held drop with it;
4. the completion arm (below) joins it, so no task is left.

No response frame is written for the cancelled id: MCP says the receiver SHOULD NOT answer a
cancelled request. Unknown or finished ids are ignored (spec: MAY ignore). `initialize` runs
inline, is never tracked, and cannot be cancelled (spec: MUST NOT).

Reading the ledger's "its waiter gets a terminal answer": the waiter is the gateway-side future
that awaits the held exchange, not the client, which by the spec has stopped waiting. The
alternative reading, an error frame to the client, contradicts the spec's SHOULD NOT and is
rejected. The lead confirmed this reading on 2026-09-30.

The spec text the mechanism rests on (MCP 2025-06-18, Basic > Utilities > Cancellation, the
revision a legacy RPC speaks;
https://modelcontextprotocol.io/specification/2025-06-18/basic/utilities/cancellation):

> 2. The `initialize` request **MUST NOT** be cancelled by clients
> 3. Receivers of cancellation notifications **SHOULD**:
>    * Stop processing the cancelled request
>    * Free associated resources
>    * Not send a response for the cancelled request
> 4. Receivers **MAY** ignore cancellation notifications if:
>    * The referenced request is unknown
>    * Processing has already completed
>    * The request cannot be cancelled

Why abort rather than a cooperative signal to the waiter. A targeted "resolve this dispatch's
prompts with an error" needs (a) a map from the inbound request id to the outbound prompt ids the
bridge mints, and (b) a `DeliveryError` variant for "cancelled". `DeliveryError` is a `pub` enum
without `#[non_exhaustive]` (`input_bridge.rs:159-160`), so (b) is a public-API change (C7).
Abort reaches the same end state, with no new variant and no second map.

Batched calls cannot be held. A batch runs inline in the read loop, and each item gets
`NoClientChannel` (`server/mod.rs:3403`), so an item that needs input fails at once and never
parks at the bridge. LIFE.1's held legacy RPC is therefore always a spawned single dispatch. A
test pins this: a batched call that asks for input returns its refusal without an outbound
prompt, and `pending` stays empty.

Bookkeeping:
- `HashMap<RequestId, (task::Id, AbortHandle)>`, keyed by the protocol `RequestId`, which keeps
  numeric and string ids distinct (`protocol/messages.rs:200-207`).
- Duplicate in-flight id (a client breaking the no-reuse rule): the first mapping is kept, the
  second dispatch still runs but cannot be cancelled by id, and a warning is logged. It is not
  refused, because that could break a lenient client in a live config.
- An entry is removed on completion only when the completing `task::Id` still owns it, so a stale
  completion cannot unmap a live dispatch.
- Reaping is driven by completion: the read `select!` (`server/mod.rs:2482`) gains a
  `join_next_with_id(), if !dispatches.is_empty()` arm, replacing the per-line `try_join_next`
  (`:2503`). An aborted task is joined as soon as it ends.

Response race, closed (rev 4). `abort()` does not stop a task that is already being polled, and
producing a response and queueing it are separate steps (`:2610-2631`). So the cancel handler first
records the id in a cancelled set, then aborts. The dispatch task checks that set immediately
before `send_frame` and drops its frame when the id is there. Guarantee: no frame for the id is
queued after the cancel is processed. A frame queued before the cancel arrived may still be
delivered, which the spec permits (the sender SHOULD ignore it). An entry leaves the set when the
task is joined.

Settlement matrix (unchanged from rev 2). Each row is asserted separately:

| Cancelled while | Admission state after | Re-issue with same key |
|---|---|---|
| queued before dispatch (waiting for its admission permit) | lease abandoned (`idempotency/admission.rs:406-416`) | executes once |
| held at the input bridge (the LIFE.1 case) | outer lease settled unknown; inner reservation released, having been disarmed (`meta_mcp/invoke.rs:2266-2271`) | refused as outcome-unknown, no second dispatch |
| backend call in flight | lease settled unknown | refused, no second dispatch |
| result secured, waiting to be queued | retained completed result | replays the stored result |

EOF join (unchanged from rev 2). `channel.close()` fails held prompts; dispatches drain for
`STDIO_DRAIN_TIMEOUT`, then are aborted and joined (`:2687-2703`). `writer_task.await`
(`:2718`) runs outside that bound, and the writer can block forever in `write_all`/`flush` when the
client stops reading stdout (`server/stdio_writer.rs`). The fix joins the writer under the same
bound and aborts it on timeout. Rev 4.1: one deadline covers both waits. It is taken at EOF as
`Instant::now() + STDIO_DRAIN_TIMEOUT`; the dispatch drain and the writer join each wait only
until it, so `run_stdio_on` returns within one `STDIO_DRAIN_TIMEOUT` after EOF, not two. The test
uses a duplex whose read side is never drained.

Not done (tracked as #2495, 4.0.1): forwarding the cancel upstream as the backend's own `notifications/cancelled`. The
backend call may keep running after the abort, as it does today when an HTTP client disconnects.
That is a separate feature, recorded here rather than dropped.

### D6 — OWNER.2: a typed local operator in the task store (rev 3; build ruled in scope)

Facts at `41ef8781c` (#2414 merged, which did not change them):
- Stdio never opens the task store: `task: None` (`server/mod.rs:3137,3656`). The store is opened
  only in `Gateway::run` (`:1824-1880`) through `open_runtime_with_recovery`.
- `tasks/*` is served only by the HTTP router arms (`router/handlers.rs:1843-1865`,
  `router/handlers/tasks.rs:227,374,510`), which take `&AppState`.
- A task owner is `ExecutionAdmission::owner(principal: &str)`, a digest of
  `[PRINCIPAL_TAG, principal]` (`idempotency/admission.rs:875-890`). HTTP owners come from
  `route_task_owner` (`router/handlers/tasks.rs:52-66`): `oidc:…`, `credential:…`, or
  `local:auth-disabled:tasks:v1`.
- The store lease allows one owning process per directory (`task_service/store.rs`), so stdio
  and HTTP never hold the same store at once. "Same-store HTTP owner" means sequential opens.

The row needs the stdio operator to retrieve a task. Today it has neither a store nor a route,
so this is a build item, not a test. The lead ruled it in scope for 4.0 (2026-09-30): build the
minimal version, with the existing config key and no new config. Escalate only if it forces a
public API or config change.

1. Owner (rev 4). The stdio task owner is `ExecutionAdmission::owner(LOCAL_OPERATOR_PRINCIPAL)`:
   the existing digest `canonical_json_sha256([PRINCIPAL_TAG, "\0local-operator.v1"])`, whose
   JSON-array framing already separates tag and principal. It is obtained only through the marked
   context's `owner_principal()` (D1). HTTP task owners come from `route_task_owner`: `oidc:…`,
   `credential:…` or `local:auth-disabled:tasks:v1`, never NUL-prefixed. I4 adds one guard so that
   is enforced rather than assumed: `ExecutionAdmission::owner` refuses NUL-prefixed text unless
   it is called through the marked path (`pub(crate)`, C7). The digest has no store path and no
   instance id, so it survives reopen and relocation (C3: no global lookup, no new UUID).
2. Store. Stdio opens the same store `Gateway::run` opens, from `config.tasks.store_dir` (existing
   key; no new config). The open sequence moves into one `pub(crate)` helper shared by both
   transports, so they cannot drift.
   Lease conflict (round-2 finding). A client may spawn a stdio gateway while an HTTP gateway
   already holds the same store directory, which is the default path. Stdio works in that setup
   today, so failing to start would be a regression. Rule: HTTP keeps failing fast as it does now.
   Stdio, on an open failure, logs a warning naming the path and the cause, serves without tasks
   (`tasks/*` answers -32601 as today), and leaves Tasks out of its discover answer for the life
   of the process. The advertisement then matches the surface in both outcomes (item 5). A test
   covers the leased-directory case.
   **Invariant I-OWN (shared store on disk).** Stdio and HTTP never share a process, but after I4
   they can share the task store directory on disk, one after the other: whichever opens
   `tasks.store_dir` first holds the lease, and stdio falls back only while HTTP holds it. From
   then on, the only thing that keeps a stdio-owned task unreadable to an HTTP principal is the
   reserved owner: the stdio owner's principal is NUL-prefixed, and no HTTP owner text can be
   (item 1's guard). The store keeps no other owner field that a lookup could match on instead.
   **I4 requirement from the I1 final review (GLM, F1).** A stdio-owned task is executed and
   recovered by contexts the task worker and recovery path rebuild
   (`task_service/execution/context.rs`, `router/handlers/tasks.rs:292`). Those set
   `stdio_nonce: None`, so, as built in I1, they would key retained results by the text
   `"stdio"`, not by the reserved owner. A recovered stdio task would then miss the entry its
   original dispatch wrote and could re-execute. I4 must carry the owner through: the rebuilt
   context keys under the task's persisted owner (the reserved value), never under text. An I4
   test recovers a completed stdio task after a restart and asserts no second backend dispatch.
   Not reachable in I1: stdio creates no tasks before I4 (`task: None`).
3. Route. The three `tasks/*` arms and task-augmented `tools/call` take a crate-private
   `TaskRoute { service, executor, owner }` instead of `&AppState`, extracted from the arms as
   they stand. HTTP builds it from `route_task_owner`; stdio builds it from (1).
4. Tests (store integration): the stdio operator creates a task; the store is closed and reopened
   at the same path and at a moved path, and the operator retrieves it. From a different store
   the id is absent. I-OWN test, named for the invariant: stdio writes a task into a store
   directory, the store is closed, the HTTP route opens the same directory, and HTTP owners (`"stdio"`, `local:auth-disabled:…`,
   a credential digest) get the not-found answer and cannot cancel or update it.

   **Acceptance has two legs** (the lead's definition, from "independent functional acceptance",
   `docs/design/issue-462-config-preservation.md:702`):
   - (a) Store integration: an integration test in `tests/` that spawns the built binary over
     stdio pipes, runs the reopen, relocate, second-store and HTTP-owner steps, and runs in CI.
   - (b) Independent functional drive: a separate fresh agent that is not the implementer. It gets
     only the OWNER.2 ledger text and public launch instructions, drives the CI-built image
     `ghcr.io/mikkoparkkola/mcp-gateway`, pinned by the digest from the post-merge
     release-line `docker.yml` run (recorded in the report), with `docker run -i` over stdio, and
     records every request and observation. It writes a report with N/N public assertions and an
     evidence JSONL under `.git/`. Anything without a public surface is marked
     N/A-to-public-drive and covered by leg (a).

     Conditions:
     - free disk is checked before pulling (`duf`), and below 5 GB the drive stops and reports;
     - the image is never pulled by tag;
     - afterwards the driver removes only its own containers and volumes, never the image cache.

   Leg (b) runs after I4 merges, before OWNER.2 is graded.
5. Advertisement honesty. Stdio's `server/discover` declares the Tasks extension today
   (`ExtensionSet::gateway_declares`) while stdio serves no `tasks/*`: a shipped claim the code
   does not honour. I4 makes it true and adds a test that every extension stdio's discover answer
   declares is served over stdio: a `tasks/get` for an unknown id gets the extension's
   not-found, not -32601. A second test checks the degraded case: with the store unavailable, the
   discover answer carries no Tasks. If I4 slips, the fallback strips Tasks from stdio discover;
   not now.

Size and risk: about 500+ lines across `task_service`, `router/handlers/tasks.rs` and the stdio
loop, FULL tier. No public API item, if `TaskRoute` and the helper stay crate-private.

### D7 — MIK-7217.STDIO.1: stdio discover advertises 2026-07-28 when modern is on

Facts. The stdio arm hardcodes `discover_document(false)` (`server/mod.rs:2957`); HTTP passes
`running().server.modern_protocol` (`router/handlers.rs:1192`). Stdio never reads
`server.modern_protocol`: its request classification serves modern shapes whatever the flag says
(`classify_and_observe`, `:3073`). The document's capabilities always carry the Tasks extension
(`ExtensionSet::gateway_declares`, `protocol/extensions.rs:71-75`), whatever the flag.

Dependency (the lead's rule: advertise only what stdio can serve). Advertising 2026-07-28 on stdio
while also declaring Tasks claims a modern tasks surface that stdio lacks until D6 lands. So D7
lands after D6. If the operator moves OWNER.2 out of 4.0, D7 instead drops Tasks from the stdio
discover answer, and that change of today's stdio advertisement is reported to the lead first.

Left in place and out of scope: with `server.modern_protocol` off, stdio still serves
modern-shaped requests (`classify_and_observe` ignores the flag) while discover hides
2026-07-28. D7 fixes what discover advertises and does not change what stdio serves; the
exact-version test asserts the advertisement only.

Change. `run_stdio_on` already holds the config; its `modern_protocol` value goes to the dispatcher
(a field alongside `handshake_capabilities`) and into `discover_document(modern)`. Test: exact
`supportedVersions` equality over `run_stdio_on` with modern on (contains `2026-07-28`) and off
(equals `SUPPORTED_VERSIONS`), not a `contains`-only check.

### D6 rev 5 — the worker's host, the carried mark, and the lease (supersedes D6 items 1–3 where they differ)

Rev 3 swapped `&AppState` out of the `tasks/*` arms only. The durable task worker also depends
on `AppState`, and stdio has none. The lead ruled option (A), build it in full, on 2026-10-01.
Crate-private widenings are allowed; extracting a `task_route` module is preferred over widening
scattered items.

Facts at `bf5c901e3`:
- `OwnedCallerContext` holds `state: Weak<AppState>` (`task_service/execution/context.rs:22`).
  The worker upgrades it before dispatch (`execution/worker.rs:118-125`), and so does the
  input-round resume (`execution/input_round.rs:433`). A failed upgrade settles the task
  `not_executed` / `gateway_interrupted_before_dispatch` before the backend is called
  (`worker.rs:461-469`).
- From the upgraded state the worker reads only:
  - `meta_mcp` (`worker.rs:79,146,201`; `input_round.rs:174,252`);
  - the HTTP `RouterAuthorizer`, whose `transport()` is hard-coded to `Http`
    (`router/authorization.rs:545-547`). Its field reads are `tool_policy`, `mtls_policy`,
    `agent_auth`, `ssrf_protection`, `trust_configured_backends` and `backends`
    (`authorization.rs:241-417`).

  `upstream.rs`, `recovery.rs` and `expiry.rs` hold no `AppState`.
- The rebuilt worker context sets `stdio_nonce: None` (`context.rs:199`). With no mark,
  `owner_principal()` drops a NUL-prefixed owner (`meta_mcp/mod.rs:276`). For a stdio task the
  caller's cache principal then falls to `Unresolved` (`meta_mcp/support.rs:192`), so its inner
  calls get no gateway cache key and no retry key, and `provenance()` reports `Credential`
  instead of `LocalTransport` (`meta_mcp/mod.rs:283-289`).

  Corrected from rev 4: the worker never reaches the sync admission that answers -32003. A task
  skips `admit_meta_sync` (`meta_mcp/admission.rs:411-413`). The harm is the lost duplicate
  protection and the wrong attribution, not a refusal.
- Recovery never re-dispatches. On open, each interrupted row is either settled as a failure from
  its own record, or (`working`, upstream-managed) kept for the owner's next read. Both are keyed
  only by the persisted `owner_digest` (`execution/recovery.rs:5-7,41-64`;
  `task_service/mod.rs:144-147`). An HTTP gateway that opens a store holding interrupted stdio
  tasks can therefore fail them but never run them.
- The worker follows an upstream job only for a supported direct backend job whose backend a
  trusted adapter claims (`worker.rs:131-148`: `executor.recovery()` must be installed, and trust
  is checked live). When its budget runs out, it leaves the row `working` for the owner's next
  read, a bounded upstream query re-authorized against the live caller
  (`router/handlers/tasks.rs:333-396`).
- The worker's caller carries no idempotency key: `OwnedCallerContext::new` keeps only the
  attestation from `RetryFields` (`context.rs:98-101`), for HTTP tasks as well. A task's duplicate
  protection is its durable `Mode::Task` admission, not the inner call's key.
- `task_intent_for_call` refuses when `auth_config.enabled` and there is no verified identity
  (`tasks.rs:147`). This is an HTTP rule, and stdio must not inherit it from a shared config
  file.
- HTTP refuses `tasks/*` from a client that has not declared the Tasks extension
  (`router/handlers.rs:975`). Both the modern handshake (`meta_mcp_helpers.rs:167`) and
  `server/discover` (`meta_mcp/mod.rs:1681`) advertise Tasks from `discovery_extensions()`.

Decisions:

1. **Task host.** A crate-private `enum TaskHost { Http(Weak<AppState>), Stdio(Weak<StdioTaskHost>) }`
   replaces `OwnedCallerContext.state`.
   - `StdioTaskHost` owns `Arc<MetaMcp>`, `Arc<ToolPolicy>` and the process's
     `&'static StdioNonce`. `run_stdio_on` holds the strong
     `Arc`, so a worker that outlives the stdio session fails its upgrade and settles
     `gateway_interrupted_before_dispatch`, exactly as an HTTP worker does after shutdown.
   - The worker resolves the host to the MetaMcp plus an authorizer: the `RouterAuthorizer` for
     `Http`, and `ToolPolicyAuthorizer` (the authorizer stdio already uses, `server/mod.rs:3167`) for `Stdio`.
   - No HTTP rule reaches a stdio task: no `mtls_policy`, no `agent_auth`, and no `Http` transport
     label.
2. **The mark is carried.** The rebuilt worker context takes `stdio_nonce` from the host: `Some`
   for `TaskHost::Stdio` (the nonce field of `StdioTaskHost`), and `None` for `TaskHost::Http`, so
   an HTTP-hosted context cannot hold a mark. `StdioNonce::process` stays `pub(super)` in `server`,
   which builds the host. With the mark:
   - `owner_principal()` returns the reserved owner;
   - the caller's cache principal is `Caller(_)` rather than `Unresolved`, so a stdio task's
     cacheable inner call is response-cached under the operator's principal exactly as a
     synchronous stdio call is (HTTP parity: an auth-off HTTP task caches under
     `local:auth-disabled:…`);
   - provenance is `LocalTransport`.

   The key stays cleared, as for HTTP (fact above). Carrying it would give stdio tasks a second
   dedupe layer that HTTP tasks do not have.
3. **Typed owner.** The `task_route` module takes the owner as
   `enum TaskOwnerText { Http(String), LocalOperator }`.
   - `Http` refuses NUL-prefixed text (answered as not found, like every other owner miss).
   - `LocalOperator` resolves to `LOCAL_OPERATOR_PRINCIPAL`, which is widened `private → pub(crate)`.
   - This replaces rev 3's guard inside `ExecutionAdmission::owner`, which has 0 lines of headroom
     under the file-size baseline (`idempotency/admission.rs`, baseline 984 = counted 984). The
     guard sits at the one place HTTP owner text enters the task surface.
4. **Route.** `router/handlers/tasks.rs` keeps the HTTP glue. The owner-independent bodies of
   `tasks_get`, `tasks_update` and `tasks_cancel` move to a new crate-private
   `gateway/task_route.rs`, taking `TaskRoute { service, executor, host: TaskHost, owner: TaskOwnerText }`.
   - The upstream recovery read stays HTTP-only. Stdio installs no upstream adapter:
     `tasks.recovery_adapters` stays an HTTP feature. Its store is its own directory (item 7), so
     no stdio row ever carries an upstream handle, and a stdio `tasks/get` never needs a recovery
     read.
   - On restart, stdio passes no managed adapters, so every interrupted row it holds is settled
     (`recovery.rs:57-64`).
   - The HTTP arms become thin adapters over the shared bodies, so the two transports cannot drift.
5. **Stdio creation.** A task-augmented modern `tools/call` on stdio builds its `TaskIntent` in
   the server, not through `task_intent_for_call`. Same rules except the HTTP auth gate:
   - modern request;
   - a `task` member;
   - not a retry continuation;
   - a dispatchable tool;
   - an idempotency key, with refusal texts identical to HTTP's;
   - the request itself declares Tasks, read through HTTP's parser (as built in a83d94108).

   Each rule answers exactly as HTTP answers the same request: a refusal with the same code and
   text, or the ordinary synchronous path. The owner is `TaskOwnerText::LocalOperator`. The admission request uses the reserved owner, so
   a task and a later synchronous stdio call with the same key meet at the one admission index.
6. **Store, degradation and shutdown.**
   - Stdio opens its store directory (item 7) through `open_runtime_with_recovery` with no managed
     adapters. The open sequence moves into one shared crate-private helper.
   - On any open failure, stdio:
     - logs the path and the cause;
     - serves without tasks: `tasks/*` answers -32601, and a task-augmented `tools/call` is
       answered synchronously, which is exactly today's behaviour;
     - leaves Tasks out of both the modern `initialize` answer and `server/discover`, for the life
       of the process.
   - `ServiceError` collapses a lease conflict into `Unavailable` (`task_service/service.rs:89`).
     Stdio does not need to tell the two apart.
   - The expiry loop starts from the same helper, with `tasks.expiry_interval`.
   - EOF order in `run_stdio_on`, after the dispatch drain and the writer join (D5), is HTTP's
     own task shutdown, extracted from `Gateway::run` (`server/mod.rs:2196-2223`) into the
     shared helper so the two cannot drift:
     1. Join the expiry sweep.
     2. Drain the executor (`TaskExecutor::drain`, `execution.rs:339-371`), joining handoffs, then
        worker permits, within the shutdown timeout.
     3. Close the store, which releases the lease.

     Then the existing teardown runs (`backends.stop_all`).
   - A drain that times out cancels the remaining workers and waits for them, bounded, before
     the store closes, on both transports (MIK-7757, #2669).
7. **Lease direction: decided by the lead, 2026-10-01, option (d).** Stdio derives its own
   store from the same base path: `expand_home_path(tasks.store_dir).join("stdio")`. It is
   resolved literally, with no new config key, and the derived path is logged at open.
   - **No contention by default.** HTTP keeps `tasks.store_dir` and stdio uses its `stdio`
     subdirectory, so neither holds the other's lease. The HTTP store's loader ignores the
     subdirectory: it reads only `task-*.json` names (`task_service/store.rs:665,747-749`), and
     the directory judge accepts it (`:903-905`). Rejected options:
     - (a): a running desktop-spawned stdio gateway would turn into an HTTP startup failure on the
       default config. That is an upgrade regression.
     - (b) and (c), as before.
   - **Relocation carries over.** Moving the base directory and rewriting `tasks.store_dir`
     moves the stdio store with it.
   - **A second concurrent stdio gateway** finds the lease held and degrades as in item 6: no
     durable tasks, and discover and `initialize` stay honest.
   - **Explicitly shared directory.** An operator who points HTTP's `tasks.store_dir` at another
     config's stdio subdirectory meets the existing lease rule. HTTP fails fast, and its error now
     names the likely holder: "held by another gateway process, possibly a stdio gateway using
     `<base>/stdio`". This is the only HTTP-visible change; the error text is tested.
   - **I-OWN is still tested,** by configuring HTTP explicitly onto the stdio directory once stdio
     has exited.
   - **Documented** in the `tasks.store_dir` config doc comment (`src/config/features/tasks.rs`),
     `docs/UPGRADING-4.0.md`, and `docs/runbooks/backup-restore-and-keys.md`.
     - The backup set is unchanged, because the subdirectory is inside the backed-up directory.
     - The runbook gains one line: stop every gateway, HTTP and stdio, that writes under the base
       directory before backup or restore, since the two stores are now independent writers.
8. **Placement.**
   - New code goes in sibling modules: `gateway/task_route.rs`, `gateway/task_service/host.rs`
     (`TaskHost`, `StdioTaskHost`), and `gateway/server/stdio_tasks.rs` (open, creation, the
     `tasks/*` dispatch, the degradation flag).
   - `server/mod.rs` gains only call sites, within its 45 lines of headroom.
   - `router/handlers/tasks.rs` shrinks.
9. **Size.** About 500–700 lines of product code plus 500–600 of tests, at the FULL tier. No
   public API item and no config key.

### Increments (one PR each, in order)

| # | Rows | Tier | Content |
|---|---|---|---|
| I1 | OWNER.3, OWNER.5 | FULL (identity) | D1 + D4 |
| I2 | OWNER.1, OWNER.4 | FULL (policy) | D2 + D3 tests; a fix only if red |
| I3 | LIFE.1 | FULL (it touches admission settlement) | D5 |
| I4 | OWNER.2 | FULL | D6 rev 5 (ruled in scope; option A, 2026-10-01) |
| I5 | STDIO.1 | STANDARD | D7, after I4 |

Red proof with CI as the only compiler. A failing-tests commit must fail on assertions, not fail
to compile. So the tests drive seams that exist before and after the fix: `run_stdio_on` over
`tokio::io::duplex`, `dispatch_single_with_sink`, and cache and admission separation observed
through replay behaviour. They never name new items. Helpers live in the
test files, so the fix commit does not touch them. I1's OWNER.5 half (T5.1, T5.2) and I2 may be
green on arrival: they pin properties the code already has. Its "fails when the property is removed" proof is then the mutant batch, not
a manufactured red, and the PR says so.

### Test plan pointer

Each increment's test plan is written into `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md` under
its row IDs and reviewed before its
failing tests are written.

## Review log

- Rev 1 (`90ffd60e8`), seat 1: REVISE. Three HIGH findings, all confirmed at source and repaired in
  rev 2: (1) the tag was dropped by `with_retry` and the claim that a lost tag fails closed was
  false; (2) catalogue requests had no path for the tag; (3) there is no live ToolPolicy reload.
  Five MEDIUM findings, also repaired: the signing skip (D3), D5 bookkeeping and the response race,
  the settlement matrix, the unbounded writer join at EOF, and the D4 wording. One LOW: OWNER.3
  reframed as preventive hardening (D1).
- Rev 1, seat 2: pending at the time of writing.
- Coordinator note (#1951): D3 re-verified; stdio order recorded, fix left to the controls lane.
- Rev 3 (this revision): refreshed at `41ef8781c` after 25 merges, of which only #2381 (sync
  admission now stores a `StoredDelivery` envelope) touches a cited file, with no effect on any
  decision. Criteria switched to the ledger text. D1 catalogue path corrected (public-API
  reachability via `gateway::test_helpers`). D5 rewritten to the ledger's LIFE.1 text. D6 (OWNER.2)
  and D7 (STDIO.1) added. Sent to both seats as round 2.
- Rev 3, round 2, seat 2 (`kimi-review`, content inline, SHIP-WITH-FIXES):
  (1) HIGH "batch path untagged": refuted at source. Batch items call `dispatch_single_with_sink`
  with a `StdioClient` (`server/mod.rs:3391-3403`). Recorded in D1, and I1 asserts it.
  (2) MEDIUM "batched held RPC": resolved. Batch items get `NoClientChannel` and cannot hold;
  pinned in D5.
  (3) MEDIUM "store lease conflict": accepted. Stdio degrades to serving without tasks and
  advertises none (D6 item 2).
  Improvements taken: the D7 out-of-scope note, and pre-running D2 on the current tree (it runs
  in I2's first CI). Improvement deferred: the `classify` input-enum shape, decided during I1.
- Rev 3.1: D1 reuses `StdioNonce` as the typed tag rather than adding `StdioLocalOperator`
  (found while writing the I1 test plan; the ladder rule "already in this codebase").
- Rev 3.1, round 2, seat 1 (`synthetic-review`/GLM; attempt 1 failed on output length, attempt 2
  succeeded on the design alone; SHIP-WITH-FIXES, five findings, none HIGH). All taken in rev 4:
  (1) D1 body rewritten to the as-built design, with no `StdioLocalOperator` type or field left;
  D4 and D6 retyped. (2) D5 states what the waiter receives: dropped, with the joined `Cancelled`
  outcome as its terminal answer. (3) C7 visibility stated for every new item. (4) The §P1a
  LIFE.1 signal is restated to the guaranteed end state, and a cancelled-id set closes the
  late-frame race (the review's improvement). (5) I1's OWNER.5 half is marked green on arrival.
  Improvement taken: D6 reuses `ExecutionAdmission::owner`'s framing. Improvement left to the
  lead: a tracked id for forwarding the cancel upstream (external issue creation needs
  authorization).
- I1 final review, two seats, on #2494: `kimi-review` SHIP and `synthetic-review` SHIP. All three
  kimi improvements taken, plus GLM's rename; GLM's MEDIUM (rebuilt task contexts carry no mark)
  is recorded in D6 as an I4 requirement, since it is not reachable before I4. The out-of-scope
  upstream cancel is tracked as #2495 (4.0.1).
- Rev 4 also records D1 as built in #2494: a reserved NUL-prefixed owner principal replaces rev
  3's "own domain string", and catalogue tag plumbing is dropped (no decision depends on it).
- Rev 5 (2026-10-01, at `bf5c901e3`): D6 rev 5 added after the I4 inventory found the worker's
  `AppState` dependency. Sized to the lead, who ruled option (A). Item 7 (lease direction) ruled
  option (d) by the lead: stdio uses `<store_dir>/stdio`. Sent to two seats on the design delta before code.
- Rev 5.1: both seats returned SHIP-WITH-FIXES on the design delta (seat A on `c4f9c5405`,
  seat B on `2567148cb`). Taken:
  - the worker's key is cleared, so U2 now pins the response cache;
  - upstream follow is adapter-gated, and stdio installs no adapter;
  - degraded creation stays synchronous;
  - one host shape;
  - the EOF shutdown order.

  Test-plan changes are listed in its I4 review log.
- Rev 5.1, round 2 (seat A, delta `c4f9c5405..211432dad`, SHIP-WITH-FIXES):
  - all four round-1 findings are closed, and option (d) is upheld against the loader, lease and
    relocation code;
  - the EOF order now reuses HTTP's task shutdown, with the timed-out straggler residual recorded;
  - N10's proof moves in-process (test plan);
  - the backup runbook gains the stop-every-writer line.
