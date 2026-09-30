# MIK-7272.SUB4.STDIO.OWNER.1–5 and SUB4.BRIDGE.LIFE.1 — the stdio owner and the held legacy RPC

Status: §P1a and §P1b for OWNER.1, OWNER.3, OWNER.4, OWNER.5 and LIFE.1, submitted together for
one two-seat design review 2026-09-30. §P1b.OWNER.2 is a marked stub, filled and reviewed after
#2414 lands, because that PR rewrites the task-store files it depends on.

Amends `docs/design/2026-08-31-sub-4-idempotency-wiring.md`. That document (lines 36–43) records
the `MIK-7272.SUB4.STDIO.OWNER.*` criteria as invented by a reviewer, because they exist only in
Linear and not in `docs/`. They are real: Linear MIK-7272 carries OWNER.1–5 and BRIDGE.LIFE.1 as
pending acceptance criteria. This document is where they enter the tree.

Ledger row IDs (the checker needs `TICKET.COMPONENT.N`): `MIK-7272.OWNER.1`–`MIK-7272.OWNER.5`
and `MIK-7272.LIFE.1`. Tests and PR bodies use these IDs.

## §P1a — Problem definition

### The criteria, verbatim from Linear MIK-7272 (read 2026-09-30)

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
  cancels it and the bridge joins it (no orphaned task, no late response written for the
  cancelled id); stdin EOF with an RPC in flight joins or cancels it before the loop returns.
  Precise semantics are a §P1b decision, but "observable end state with no orphan" is the signal.

### Exclusions

- Cross-restart replay (C4), cross-store task lookup (C3).
- The HTTP-route idempotency wiring (sub-4 routes 1 and 3) beyond what OWNER.3/4 need to prove
  non-aliasing.
- MIK-7311.LIFECYCLE.1 (tasks lifecycle).
- Changing the keyless-write decision (ruling above).

## §P1b — Solution design

### Facts the design rests on (read at `dc44ebc7b`)

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

### D1 — `StdioLocalOperator`, the typed tag (OWNER.3, OWNER.5; enables OWNER.1/4 tests)

Framing (rev 2): preventive boundary hardening. F1-F3 mean no HTTP-to-stdio replay is reachable
today; OWNER.3 removes the string as the thing that decides, so the next path that lets a string
reach `credential_principal` does not become the operator. Its tests share one `MetaMcp` (one
private service realm) so process isolation cannot make them pass vacuously.

A zero-sized `pub(crate) struct StdioLocalOperator(());` (`Clone, Copy`) in `src/gateway/server/`,
with the private field so only that module can construct it.

Where the tag travels (every stdio caller shape, not only `tools/call`):

1. `MetaMcpCallerContext` (crate-private: its module is private, `src/gateway/mod.rs:13`) gains
   `local_operator: Option<StdioLocalOperator>`. FRESH constructors for non-stdio transports set
   `None`: HTTP (`router/handlers.rs:1599-1630`), task recovery (`router/handlers/tasks.rs:290-315`),
   task worker (`task_service/execution/context.rs:121-170`). DERIVING constructors COPY it from
   the caller they derive from: `with_retry` (`meta_mcp/mod.rs:261-300`, used by chain steps,
   `meta_mcp/search.rs:526-534`) and any other `Self { .. }` rebuild. Stdio sets `Some` in
   `build_stdio_caller_context` and in the `stdio_caller_context` test fixture.
2. Catalogue requests (`prompts/*`, `resources/*`) have no caller context: stdio builds an
   `AuthenticatedClient` (`server/stdio_catalogue.rs:36-70`). `AuthenticatedClient` is public API
   (`pub mod auth`, all fields `pub`), so the tag does NOT go on it (C7). Instead the five
   `MetaMcp` catalogue handlers (`handle_prompts_list/get`, `handle_resources_list/read/
   templates_list`) and `handler_proof` (`meta_mcp/caller_forward.rs:34-39`) take an extra
   crate-private `local_operator: Option<StdioLocalOperator>` argument; the HTTP router passes
   `None`, `stdio_catalogue::dispatch` passes `Some`. The resource-owner lookups that classify
   (`meta_mcp/protocol.rs:163,273`; `meta_mcp/resources.rs:307,408,458`) read it from there.

Decisions that switch from the string to the tag:

1. `CallerProvenance::classify(principal, local_operator)`: `LocalTransport` iff the tag is
   present. An untagged `"stdio"` string classifies as `Credential`. Four production callers
   (`router/backend_handlers.rs:546`, `meta_mcp/discovery_fetch.rs:79`, `meta_mcp/invoke.rs:1658`,
   `meta_mcp/caller_forward.rs:39`) plus the twelve test calls (`caller_proof_tests.rs`,
   `vault_tests.rs`, `server/tests/stdio_sole_operator.rs`) are migrated.
2. Admission namespace: a tagged caller's admission identity is derived under its own domain
   string (`mcp-gateway.execution-admission.local-operator.v1`), so an untagged `"stdio"` principal
   and the real operator hash into disjoint key spaces.
3. Retained-output cache namespace: `caller_cache_principal` emits `local:` for the tag in the
   branch that today yields `cred:{len}:{digest}` (`meta_mcp/support.rs:170-190`); higher-priority
   bindings are unchanged.

`STDIO_CREDENTIAL_PRINCIPAL` stays as the audit/display principal (no audit schema change, C6).

Alternatives rejected: (a) keying off `CredentialKind::LocalTransport` — an audit enum the task
execution context carries as data (`task_service/execution/context.rs:42`), so a rebuilt context
could carry it; the ticket asks for a tag only the transport creates. (b) A field on
`AuthenticatedClient` — public API widening. (c) Leaving it because F3 makes it unreachable today.

Risk (corrected in rev 2; rev 1 claimed a lost tag fails closed, which is false): a stdio path
that loses the tag classifies as `Credential`, which still establishes the operator on a
sole-operator deployment (`caller_proof.rs:87-94`, `vault.rs:210-226`). Accounts keep working and
only the namespace separation silently disappears. So a lost tag is not self-revealing, and the
guard is test coverage: I1 asserts the tag on each stdio shape (`tools/call`, a chain step through
`with_retry`, each of the five catalogue methods).

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
`stdio_caller_context` fixture): `local_operator` is `Some`; `verified_identity`, `grant_subject`
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

### D5 — LIFE.1: cancel and join held stdio calls

Cancel. The read loop, before the spawn path, handles `notifications/cancelled`: when
`params.requestId` names an in-flight spawned dispatch, that task is aborted. Unknown or finished
ids are ignored (the MCP spec lets the receiver ignore them). `initialize` runs inline, is never
tracked, and cannot be cancelled (spec: MUST NOT).

Bookkeeping (rev 2):
- `HashMap<RequestId, (task::Id, AbortHandle)>`, keyed by the protocol `RequestId`, which keeps a
  numeric id and a string id distinct (`protocol/messages.rs:200-207`).
- Duplicate in-flight id (a client violating the spec's no-reuse rule): the first mapping is kept
  and the second dispatch still runs, but it is not cancellable by id; a warning is logged. The
  duplicate is not refused, because refusing it could break a lenient client in the operator's
  live config (lane rule "Real-config compatibility").
- An entry is removed on completion only when the completing `task::Id` still owns it, so a stale
  completion cannot unmap a live dispatch.
- Reaping is completion-driven: the read `select!` gains a
  `join_next_with_id(), if !dispatches.is_empty()` arm. An aborted task is therefore joined as
  soon as it ends, not when the next line or EOF arrives.

Response race, stated rather than promised away: `abort()` does not stop a task that is already
being polled, and producing a response and queueing it are separate steps
(`server/mod.rs:2608-2631`). The guarantee is that once the aborted task has been joined, no
further frame for that id is queued. A frame queued before the join may still be delivered, which
the spec permits.

Settlement matrix. Each row is asserted separately; one "cancel means unknown" test would encode
the wrong contract.

| Cancelled while | Admission state after | Re-issue with same key |
|---|---|---|
| queued before dispatch (waiting for its admission permit) | lease abandoned (`idempotency/admission.rs:406-416`) | executes once |
| held at the input bridge (`input_required` prompt) | outer lease settled unknown; inner reservation released, having been disarmed (`meta_mcp/invoke.rs:2266-2271`) | refused as outcome-unknown, no second dispatch |
| backend call in flight | lease settled unknown | refused, no second dispatch |
| result secured, waiting to be queued | retained completed result (`server/mod.rs:3008-3011`) | replays the stored result |

EOF. Existing mechanism (F7): held prompts fail, dispatches drain for `STDIO_DRAIN_TIMEOUT`, then
are aborted and joined. Rev 2 adds the part that is missing: `writer_task.await` runs outside
that timeout (`server/mod.rs:2688-2721`), and the writer can block indefinitely in
`write_all`/`flush` when the client stops reading stdout (`server/stdio_writer.rs:45-55`). A client
that closes stdin while leaving stdout open and unread would then keep `run_stdio_on` from ever
returning. Fix: join the writer under the same bound and abort it on timeout. The LIFE.1 test
exercises that backpressure case (a duplex whose read side is never drained), not only a
continuously drained stream.

Not done: forwarding the cancel upstream to the backend as its own `notifications/cancelled`. The
backend call may keep running after the abort, which matches today's behaviour when an HTTP client
disconnects. That is a separate feature (4.1 by the lane scope rule); it is recorded here, not
dropped silently.

### §P1b.OWNER.2 — STUB (after #2414)

Facts so far: stdio never opens the task store (`task: None`, `server/mod.rs:3115-3119`; store
opened only in `Gateway::run`, `:1812-1850`); the store lease allows one owning process per
directory (`task_service/store.rs:705-722`); owners are `route_task_owner` strings
(`router/handlers/tasks.rs:45-65`). Open design question for this stub: does OWNER.2 require
stdio to gain a task route (a 4.0 build item) or only a typed local-operator owner in the store
(so a same-store HTTP owner cannot alias it)? Filled against the post-#2414 tree and reviewed
separately.

### Increments (one PR each, in order)

| # | Rows | Tier | Content |
|---|---|---|---|
| I1 | OWNER.3, OWNER.5 | FULL (identity) | D1 + D4; failing tests first commit |
| I2 | OWNER.1, OWNER.4 | FULL (firewall/policy) | D2 + D3 tests; fix only if red |
| I3 | LIFE.1 | STANDARD | D5 |
| I4 | OWNER.2 | FULL | after #2414, own design section |

### Test plan pointer

Each increment's test plan is written into `docs/design/test-plan.md` under a
`MIK-7272.OWNER.*` / `MIK-7272.LIFE.1` heading and reviewed before its failing tests are written.

## Review log

- Rev 1 (`90ffd60e8`), seat 1: REVISE. Three HIGH findings, all confirmed at source and repaired in
  rev 2: (1) the tag was dropped by `with_retry` and the claim that a lost tag fails closed was
  false; (2) catalogue requests had no path for the tag; (3) there is no live ToolPolicy reload.
  Five MEDIUM findings, also repaired: the signing skip (D3), D5 bookkeeping and the response race,
  the settlement matrix, the unbounded writer join at EOF, and the D4 wording. One LOW: OWNER.3
  reframed as preventive hardening (D1).
- Rev 1, seat 2: pending at the time of writing.
- Coordinator note (#1951): D3 re-verified; stdio order recorded, fix left to the controls lane.
