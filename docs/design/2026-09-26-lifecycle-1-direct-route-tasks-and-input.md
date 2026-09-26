# MIK-7311.LIFECYCLE.1: tasks on the direct route, and the input round

Status: REVISION 3. Two review rounds (four reviews, all SHIP-WITH-FIXES); every finding is
dispositioned in §7 (round 1) and §8 (round 2). Revision 3 needs a delta review before code.

## 1. Problem

Criterion (`docs/requirements/RELEASE-4.0.0-scope-update.md:37`): negotiated tasks execute
through **public routes** and support **polling, input, cooperative cancellation, terminal
outcomes and expiry** under the pinned extension. The discriminating test
(`docs/requirements/RELEASE-4.0.0-scope-tests.md:24`) names both `POST /mcp` and
`POST /mcp/{backend}` and requires the test to "supply requested input".

Two conjuncts are unmet at release-line tip `137ab7acf`:

**P1. `POST /mcp/{name}` has no task handling.**
- The route is `backend_handlers::backend_handler` (`src/gateway/router/mod.rs:390`,
  `src/gateway/router/backend_handlers.rs:465`). The file contains no `task` token.
- A `tools/call` carrying `params.task` is forwarded to the backend as ordinary params, after
  the direct-route guards (idempotency `:918-954`, tool policy and sanitisation `:956-`).
- `tasks/get`, `tasks/update` and `tasks/cancel` have no arm. There is no method filter
  (the only `match method` is the attestation scope at `:182`), so they are forwarded verbatim.
- The route forwards `initialize` and `server/discover` to the backend, so what it advertises
  is the backend's capability set, not the gateway's.

**P2. The input round is refused on every route.**
- `tasks/update` refuses any non-empty `inputResponses`
  (`src/gateway/router/handlers/tasks.rs:378-382`).
- The worker turns a backend `InputRequired` result into a terminal interrupted result
  (`src/gateway/task_service/execution/settlement.rs:21-22`, `abandoned_input_round` `:36-41`).
- The task model already supports the round: `require_input` and `provide_input`
  (`src/protocol/tasks.rs:307-360`), with key-reuse and empty-set refusal, and store tests
  (`src/gateway/task_service/store_tests.rs:75-83`, `:258-310`). Nothing produces
  `RequireInput` outside tests.

**Finding F1 (security, pre-existing).** Because `tasks/*` on `/mcp/{name}` are forwarded
verbatim, a backend that creates its own tasks is polled and controlled through the gateway
with no gateway owner check. Under a shared static backend credential the backend sees one
principal, so caller B holding caller A's backend task id can read or cancel it. Not verified
against a live task-capable backend; flagged for review, not fixed here.

## 2. Prior decisions this design must respect

- The TASK.1 design put `input_required` flows out of scope and said the elicitation
  round-trip belongs to the MRTR continuation work, warning against a second continuation
  mechanism (`docs/design/2026-08-31-task-1-tasks-extension.md:318-320`). The 4.0 criterion
  now requires input; this design reuses the MRTR continuation instead of adding one.
- Backend-originated tasks are out of scope (same file, `:315`).
- The direct route bypasses `invoke_tool_traced` by design (ADR-008 rung 2; cited at
  `docs/design/2026-08-31-task-1-tasks-extension.md:722-723`) and re-applies each guard
  locally (`backend_handlers.rs:698-712`, `:918-921`).
- Upstream recovery treats `input_required` as "no continuation contract claimed"
  (`docs/design/2026-09-08-task-upstream-recovery.md:37`).

## 3. Options for P1

| option | what | cost | risk |
|---|---|---|---|
| A. gateway-owned tasks on `/mcp/{name}` | the gateway admits `tools/call`+`task` itself, answers `tasks/*` from its own owner-checked store, and adds the tasks extension to the capability set it relays on this route | medium | the worker must run the job through every direct-route guard, or a task becomes a guard bypass |
| B. relay backend tasks with owner binding | forward `task`, record (caller, backend task id) on the `CreateTaskResult`, refuse `tasks/*` for ids the caller does not own | medium | depends on each backend's task support; out-of-scope item per §2; no gateway expiry or recovery |
| C. refuse | `tools/call`+`task` and `tasks/*` on `/mcp/{name}` answer a typed refusal; amend the test spec to `/mcp` only | small | needs a maintainer decision to narrow the test spec; leaves the criterion's "public routes" plural resting on one route |

**Recommendation: A**, because it is the only option that meets the test spec as written and
it also closes F1 (the gateway answers `tasks/*` on this route; nothing forwards them).

### A in detail

1. **Admission.** In `backend_handler_inner`, for `tools/call` with `params.task` on a modern
   request, build the intent through the existing `task_intent_for_call`
   (`handlers/tasks.rs:126`) with a `DirectJob { server: name, tool, arguments }`
   (`src/gateway/meta_mcp/upstream.rs:365`). Owner comes from the one resolver
   `route_task_owner` (`handlers/tasks.rs:51`). No second eligibility rule:
   `is_task_dispatchable` (`:23`) gains a direct-job arm, nothing else.
2. **Guards run twice: before admission, and on every dispatch.** Admission is placed after
   the request-thread guards in `backend_handler_inner` (isolation `:898-916`, idempotency
   `:918-954`, tool policy and sanitisation `:956-`), so a refused call never becomes a task.
   The worker must not dispatch through the bare backend call: today it takes
   `dispatch_below_gate_native_result` (`src/gateway/task_service/execution/worker.rs:183`),
   which is below those guards. The direct-route guard chain is extracted into one function
   that both the request thread and the worker call, and the worker runs it live on EVERY
   dispatch (first dispatch and each input resume): isolation, tool policy, sanitisation,
   per-user identity headers resolved at dispatch time, and the response scan. A policy or
   isolation change during an input wait therefore refuses the resume. The extracted chain
   keeps the per-backend passthrough opt-out (`backend_handlers.rs:957-959`) exactly as today.
   Named function: `DirectRouteGuards::run`, in the router. The worker lives in `task_service`,
   so calling it may need a visibility change (for example `pub(super)` to `pub(crate)`); that
   is an owner decision, asked before code, not assumed.
2b. **Upstream-armed jobs keep today's path.** When a trusted recovery adapter claims the
   backend, the worker arms `UpstreamSubmission` (`worker.rs:113-178`) and the backend owns
   the task; its `input_required` is the backend's own task state and stays under the reviewed
   I3 treatment. The input round of §4 applies only to the un-armed path. A test pins that an
   armed job's dispatch is unchanged.
2a. **Idempotency.** The direct route's idempotency reservation (`:918-954`) completes with
   the `CreateTaskResult` at admission, keyed exactly as today, so a retry with the same key
   returns the same task handle and never admits a second task. After the task expires, a
   replayed handle answers `-32602` from `tasks/get`, the same as a `/mcp` task today.
3. **`tasks/*` on `/mcp/{name}`** are answered by the same arms as `/mcp`
   (`handlers.rs:1858-1894`), gated by the same `reaches_tasks_extension` (`handlers.rs:93`).
   A task id is owner-scoped, not route-scoped: a task created on either route is visible
   from both to its owner and to nobody else.
4. **Capability advertisement.** The route adds `io.modelcontextprotocol/tasks` to the
   `extensions` of the relayed `server/discover` and `initialize` results only for a modern
   request. Legacy responses are relayed unchanged (byte-identical pass-through stays the
   default).
5. **Backend-originated tasks** stay out of scope. A backend `CreateTaskResult` arriving on a
   non-task call is relayed as today; its `tasks/*` follow-ups are now answered by the
   gateway store (unknown id: the same `-32602` as `/mcp`). This is a behaviour change for
   any client relying on F1's forwarding and goes in UPGRADING-4.0.

## 4. Design for P2: the input round, one continuation mechanism

1. **Produce.** `classify_dispatch` gains a third outcome built from
   `InputRequired::from_result` (`src/protocol/mrtr.rs:241-276`). Three cases:
   (a) requests present: `TaskTransition::RequireInput(InputRequired)`;
   (b) no requests but a `requestState` (a state-only round): no client round; the worker
   immediately resumes with that state, bounded to 4 consecutive state-only rounds, after which
   it settles as today's abandoned result;
   (c) `claims_input_required` is true but `from_result` rejects the shape: settles as today's
   abandoned result (`settlement.rs:21-22`), unchanged. The
   backend's `requestState` is persisted on the record as an optional field with serde default
   and skip-if-none, the way the upstream handle was added (`src/gateway/task_service/record.rs:103`),
   never in `wire()`, bounded by the store byte cap; over the cap settles as today's abandoned
   result. A malformed round (empty set, reused or duplicate key, non-object value) makes
   `require_input` return `Err` (`src/protocol/tasks.rs:307-322`); that settles terminally as
   `failed` with the model error, never a stuck `working` row.
2. **Consume.** `tasks/update` stops refusing non-empty `inputResponses` when the task is
   `input_required` and applies `ProvideInput`. The model treats an answer to a key that is not
   outstanding as a silent no-op (`src/protocol/tasks.rs:350`, pinned by
   `src/gateway/task_service/store_tests.rs:297`). The refusal therefore lives INSIDE the store
   transaction, before any key is accepted: if any submitted key is not outstanding, the whole
   update is refused with `-32602` and nothing is written (no subset is accepted). A valid
   subset of the outstanding keys is accepted; the task stays `input_required` until every key
   is answered. The model's no-op behaviour is kept for its existing callers. The refusal at
   `tasks.rs:378-382` remains for a task with no outstanding round.
3. **Resume needs a new worker entry.** `tasks/update` is an acknowledgement today
   (`src/gateway/task_service/service.rs:197`) and the only spawn is create-only
   (`commit_and_run`, `worker.rs:29-56`, from `execution.rs:188`). A second entry,
   `resume_and_run`, takes the stored record (tool, arguments, owner, continuation) and
   dispatches the SAME tools/call (stored tool name and arguments) with an `OutboundRetry
   { request_state, input_responses }`, the shape the meta path already sends
   (`src/gateway/meta_mcp/invoke.rs:960-972`). `Bridge::retry_params` supplies only the
   continuation fragment. The resume runs the live guard chain of §3 A.2.
3a. **Exactly one resume.** The `input_required -> working` step is a revision
   compare-and-set in the store transaction. Only the update whose transition performed it
   spawns `resume_and_run`; a concurrent update sees a revision conflict or a `working` task
   and is refused. Same rule for replicas sharing the store.
4. **Cancel and expiry.** Cancel from `input_required` settles `cancelled` and drops the stored
   continuation. Expiry reaps an `input_required` row through the same TTL path as `working`
   (`expired_candidates`, `store.rs:1031-1046`).
5. **Restart: no resume.** Startup recovery keeps the reviewed I3 treatment for `input_required`
   rows (`src/gateway/task_service/execution/recovery.rs:41-44`): they settle as interrupted.
   The input round is resumable only in the process that stored the continuation. Skipping
   recovery would leave a live row the expiry sweep never deletes, and upstream recovery claims
   no continuation contract for that state (`docs/design/2026-09-08-task-upstream-recovery.md:37`).

## 5. Test plan outline (red-first, each named test must fail on the stated mutant)

| conjunct | test (route) | mutant that must redden it |
|---|---|---|
| direct-route create and poll | `/mcp/{name}`: slow tool with `task`, get handle, poll to `completed` | admission arm removed |
| direct-route guard parity | denied tool with `task` gets the same refusal as without, zero tasks created | admission moved before tool policy |
| owner isolation across routes | A creates on `/mcp/{name}`, B polls and cancels on both routes: not found | owner check dropped in direct arm |
| F1 closed | `tasks/get` for a backend task id on `/mcp/{name}` never reaches the backend | forward fallback restored |
| input round, both routes | backend returns InputRequired; task shows `input_required` with `inputRequests`; `tasks/update` supplies input; backend receives `requestState` and answers; task `completed` | produce arm reverted to abandoned |
| unmatched input refused | answer key not outstanding: refused, state unchanged | key check removed |
| cancel during input | cancel from `input_required` settles `cancelled`; a later update is refused | cancel arm ignoring input state |
| JSON-RPC failure vs isError | backend error settles `failed`; `isError` result settles `completed` | classification swapped |
| advertisement | modern discover on `/mcp/{name}` lists tasks; legacy initialize byte-identical | extension added unconditionally |
| live guards on resume | policy or per-user isolation revoked during the input wait: resume refused, zero backend calls | resume dispatches without the guard chain |
| idempotent admission | same idempotency key twice with `task`: one task, same handle | admission skips the idempotency store |
| malformed round | backend returns an InputRequired with a reused key: task `failed`, not `working` | model error swallowed |
| continuation over cap | `requestState` over the byte cap: abandoned result, not a stuck task | cap check removed |
| restart keeps I3 | restart while `input_required`: row settles interrupted, update refused | recovery skips `input_required` rows |
| live guards on FIRST dispatch | policy revoked between admission and the worker's first dispatch: refused, zero backend calls | worker first dispatch skips the guard chain |
| one resume under concurrency | two concurrent full-answer updates: exactly one resume dispatch, one update refused | CAS removed from the transition |
| mixed answer refused atomically | one outstanding key plus one foreign key: refused, outstanding key still outstanding | subset accepted before the check |
| partial answer | one of two outstanding keys: accepted, task still `input_required`, no dispatch | resume on first answer |
| state-only round | backend returns requestState with no requests: resumed without a client round; 5th consecutive settles abandoned | bound removed |
| rejected round shape | claims input but shape rejected: abandoned result as today | new arm swallows it |
| armed upstream unchanged | adapter-claimed backend: dispatch identical to before | input arm applied to armed path |
| resume carries the call | resume dispatch has the stored tool name and arguments plus requestState | resume sends the fragment only |
| expiry during input | TTL passes while `input_required`: row reaped, update refused | expiry skips `input_required` |

## 6. Answers to the review questions

- Q1. Capability injection is additive and only on modern requests; legacy responses stay
  byte-identical. Recorded as an UPGRADING-4.0 item together with the F1 behaviour change.
- Q2. No restart resume (§4.5).
- Q3. F1 lands first as its own small change: `tasks/*` on `/mcp/{name}` answer from the
  gateway store (an id the store does not hold gets `-32602`) instead of being forwarded.
  Both reviews called F1 real; this design builds on that change.

## 7. Review dispositions (two independent reviews, 2026-09-26, both SHIP-WITH-FIXES)

| finding | sev | check at source | disposition |
|---|---|---|---|
| restart resume conflicts with startup recovery and expiry | HIGH | recovery.rs:41-44 refuses to defer `input_required` | ADOPTED: §4.5 rewritten, restart keeps I3 |
| worker dispatch skips direct-route guards on first dispatch and resume | HIGH | worker.rs:183 dispatches below the gate | ADOPTED: §3 A.2, one shared guard chain run live on every dispatch |
| no worker re-entry after the last input | HIGH | service.rs:197 ack only; execution.rs:188 only spawn | ADOPTED: §4.3 |
| F1 is real, land it first | HIGH | no `tasks/*` arm, no method filter on the route | ADOPTED: Q3 |
| unmatched input is a model no-op, not a refusal | MEDIUM | tasks.rs:350; store_tests.rs:297 | ADOPTED: handler refuses, model unchanged |
| no restart test | MEDIUM | follows from the first finding | ADOPTED: "restart keeps I3" row |
| malformed round has no settlement path | MEDIUM | tasks.rs:307-322 returns Err | ADOPTED: settles `failed` |
| idempotency and admission unspecified | MEDIUM | backend_handlers.rs:918-954 | ADOPTED: §3 A.2a plus test row |
| build resume from Bridge::retry_params | improvement | mrtr.rs:539 | ADOPTED |
| persist requestState with serde default | improvement | record.rs:103 | ADOPTED |
| mutant for revoked policy on resume | improvement | - | ADOPTED: test row |
| byte-cap overflow test | improvement | - | ADOPTED: test row |
| UPGRADING entry for capability injection | improvement | - | ADOPTED: Q1 |
| single dispatch table behind `reaches_tasks_extension` | improvement | handlers.rs:88-97 names the drift | DEFERRED to its own change: not needed for this criterion |

## 8. Delta review dispositions (round 2, two independent reviews, both SHIP-WITH-FIXES)

| finding | sev | check at source | disposition |
|---|---|---|---|
| resume named the create-only worker | HIGH | `commit_and_run` worker.rs:29-56 commits a Create first | ADOPTED: §4.3 new `resume_and_run` entry |
| resume params were only the continuation fragment | HIGH | mrtr.rs:539-551; meta path builds OutboundRetry with tool and arguments at invoke.rs:960-972 | ADOPTED: §4.3 dispatches stored tool and arguments with OutboundRetry |
| armed UpstreamSubmission bypasses classify_dispatch | HIGH | worker.rs:113-178 | ADOPTED: §3 A.2b, input round only on the un-armed path; test row |
| concurrent updates could spawn two resumes | HIGH | update ignores revision today (service.rs:201 `_revision`) | ADOPTED: §4.3a revision CAS; test row |
| no settlement for a rejected claimed round | MEDIUM | settlement.rs:16-23; mrtr.rs:241-276 | ADOPTED: §4.1 case (c) |
| first-dispatch guard bypass had no mutant | MEDIUM | plan tested resume only | ADOPTED: test row |
| mixed answers must be refused atomically | improvement | tasks.rs:330-361 accepts subsets | ADOPTED: §4.2 in-transaction refusal |
| partial answer sets unspecified | improvement | - | ADOPTED: §4.2 plus test row |
| state-only InputRequired treated as malformed | improvement | mrtr.rs:265-276 accepts it | ADOPTED: §4.1 case (b), bounded |
| keep passthrough opt-out in the extracted chain | improvement | backend_handlers.rs:957-959 | ADOPTED: §3 A.2 |
| expiry cite and expiry-during-input test | improvement | store.rs:1031 expired_candidates | ADOPTED: §4.4 plus test row |
| name the extracted guard function | improvement | - | ADOPTED: `DirectRouteGuards::run`; visibility flagged as an owner question |
| idempotent handle after task expiry | improvement | - | ADOPTED: §3 A.2a, same answer as `/mcp` |
