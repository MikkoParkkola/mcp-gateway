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
- F5. Policy runs before replay on stdio: `admit_meta_sync` calls `check_invocation_policy`
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

A zero-sized `pub(crate) struct StdioLocalOperator(());` in `src/gateway/server/`, with the
private field so only that module can construct it. `MetaMcpCallerContext` (crate-private: its
module is private, `src/gateway/mod.rs:13`) gains `local_operator: Option<StdioLocalOperator>`.
`build_stdio_caller_context` and the stdio catalogue context set `Some`; every other constructor
sets `None`. No public API item is added.

Decisions that read the operator switch from the string to the tag:

1. `CallerProvenance::classify` takes the tag: `LocalTransport` iff the tag is present. A
   principal string `"stdio"` without the tag classifies as `Credential` (non-empty) — never the
   operator. Its four callers (`router/backend_handlers.rs:546`, `meta_mcp/discovery_fetch.rs:79`,
   `meta_mcp/invoke.rs:1658`, `meta_mcp/caller_forward.rs:39`) pass the caller's tag; the HTTP one
   passes `None`.
2. Admission namespace: a tagged caller's admission identity is derived under its own domain
   string (`mcp-gateway.execution-admission.local-operator.v1`), not from the principal string, so
   an untagged `"stdio"` principal and the real operator hash into disjoint key spaces.
3. Retained-output cache namespace: `caller_cache_principal` emits `local:` for the tag instead
   of `cred:{len}:{digest}`, for the same reason.

`STDIO_CREDENTIAL_PRINCIPAL` stays as the audit/display principal (no audit schema change, C6).

Alternatives rejected: (a) keying off `CredentialKind::LocalTransport` — it is an audit enum that
the task execution context carries as data (`task_service/execution/context.rs:42`), so a
persisted or rebuilt context could carry it; the ticket asks for a tag only the transport
creates. (b) Leaving it as is because F3 makes it unreachable today — OWNER.3 guards the next
path, and F4 shows the failure mode is silent.

Risk: a missed constructor leaves a stdio path untagged, which fails closed (the operator loses
sole-operator account service, a visible refusal), never open. Tests pin the real stdio path.

### D2 — OWNER.1: tests over the real stdio loop, no product change expected

Keyed modern call → 1 dispatch, replay returns the stored result; keyless modern call executes
(C4); legacy unkeyed call sent twice → 2 dispatches; each of the six F6 tools called over stdio
with its management effect observed. Driven through `run_stdio_on` over `tokio::io::duplex` with
a counting backend (the `EchoBackend::tools_call_count` fixture,
`server/tests/signing_nonce_allocations_support.rs:152,257-290`, adapted to the serve loop). If a
test goes red on the current tree, the fix is scoped in the test-plan round, not here.

### D3 — OWNER.4: policy before replay, including the signing-prepared skip

Mechanism exists (F5). Tests: keyed call executes under a permitting policy; the policy is then
changed to deny that target (live reload path stdio already wires, `server/mod.rs` reload context);
the keyed replay is refused with the policy error, the retained output is not returned, the
target's dispatch count stays at its pre-denial value (zero new dispatches); a permitted
neighbouring target still executes. A second case covers the F5 exception: a replay whose signing
was prepared must still be refused under the new policy. If `prepared_for` authorized against a
stale policy, the fix is to re-run `check_invocation_policy` on the replay arm — decided at test
red, reviewed in the final review.

### D4 — OWNER.5: what the stdio context carries

Test on the context the real stdio path builds (captured from `build_stdio_caller_context` via
the dispatcher, not the `stdio_caller_context` test fixture): `local_operator` is `Some`,
`verified_identity`, `grant_subject`, `api_key_name` are `None`. Account-dependent refusal: a
backend configured for per-user identity propagation (`invoke.rs:3153-3154`, "the request carries
no verified end-user identity") is refused over stdio; an ordinary local mutation succeeds in the
same session. Boundary kept from the existing ruling: the sole-operator deployment account stays
served on stdio (`server/account_bindings.rs:89-91`; test
`stdio_run_path_serves_its_operator_the_managed_account`). "No personal-account identity" means
no per-user account is resolved, not that the deployment's own account is withheld.

### D5 — LIFE.1: cancel and join held stdio calls

Read loop, before the spawn path: a `notifications/cancelled` frame whose `params.requestId` names
an in-flight spawned dispatch aborts that task. Bookkeeping: `HashMap<RequestId, AbortHandle>`
from `JoinSet::spawn`, plus the `tokio::task::Id` so `try_join_next_with_id` / `join_next_with_id`
remove entries when tasks end. Unknown or finished ids are ignored (MCP spec: the receiver MAY
ignore a cancellation for an unknown or completed request). `initialize` is inline and never in
the map, so it cannot be cancelled (spec: MUST NOT).

Outcome for a cancelled id: the task's future is dropped, so its `send_frame` never runs and no
response is written for that id, unless the response was already queued (spec-permitted race).
Held bridge prompts drop with it; F8 settles admission as outcome-unknown, so a re-issue with the
same key is not re-executed. The abort is joined by the existing reap/drain, so no orphan.

EOF: unchanged mechanism (F7), which already cancels held prompts and joins every task before the
loop returns. LIFE.1 adds the test that proves it: a call held at the bridge, then stdin EOF, then
`run_stdio_on` returns with the backend dispatch joined and no frame for the held id beyond the
bridge's failure response.

Not done: a work-level cancel forwarded to the backend (`notifications/cancelled` upstream). The
backend call may keep running after the abort; that is the existing behaviour for HTTP disconnects
and a separate feature (4.1 by the lane scope rule), recorded, not silently dropped.

Risk: aborting between backend send and admission settlement leaves a dispatched lease settled as
unknown; that is the intended conservative outcome (no double effect), and a test asserts it.

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
