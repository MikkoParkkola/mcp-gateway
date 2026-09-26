# MIK-7311.LIFECYCLE.1a: test plan (direct-route tasks, P1)

Design: `docs/design/2026-09-26-lifecycle-1-direct-route-tasks-and-input.md` (revision 9 plus the
guard-composition text at b45aee124). Increment 1a builds the design's P1 (§3 A.1-A.5) only; 1b
builds P2 (§4). This plan covers the nine §5 rows assigned to 1a (T1-T9) plus four rows added in review
(T10-T13). The other 25 §5 rows ship in 1b.

Base: 1a is written after the security lane (MIK-7597) lands, so `src/gateway/router/direct_guards.rs`,
`DirectRouteGuards::run`, `after_dispatch`, `MetaMcp::admit_backend_call` and `settle_backend_call`
already exist. 1a adds its router checks to `run`/`after_dispatch` and never adds a second chain.

## 1. End state of 1a (fails safe)

- `tools/call` + `params.task` on a modern `/mcp/{name}` request that declares the tasks extension
  is admitted as a gateway task. Legacy requests, and modern requests without `task`, are unchanged.
- `tasks/get`, `tasks/update`, `tasks/cancel` (exact case) on `/mcp/{name}` are answered by the
  same owner-checked arms as `/mcp`. Letter-case variants and `subscriptions/listen` naming
  `taskIds` keep F1's `-32601` and are never forwarded (serving `listen` on this route is not in
  the design's §3 A.3 list).
- `DirectRouteGuards::run` executes on the request thread with the live context, before the
  idempotency reservation and before admission (a refusal creates no task and reserves nothing),
  and again in the worker at dispatch time.
- The worker runs a `Direct` job through `DirectRouteGuards::run`, the backend transport, and
  `after_dispatch`. A refusal from `run` settles `failed` via `settle_cas(Fail(guard_error))`.
- A backend `InputRequired` on a direct task settles as today's abandoned result (1b adds the round).
- An adapter-claimed backend keeps the armed `UpstreamSubmission` funnel (§3 A.2b).

## 2. Fixture

In-crate router tests on the existing task suite fixture
(`src/gateway/router/tests/task_execution_adapter/support.rs`): auth ON, `key-a`/`key-b` with
verified identities `alice`/`bob`, `MockBackend` registered as `mock`. Additions (test code only):
- `post_direct(state, principal, backend, body)`: same request builder, URI `/mcp/{backend}`.
- `MockBackend`: `Answer::RpcError { code, message }` and `Answer::IsError(Value)`; a configurable
  `server/discover` / `initialize` capability object; every method recorded in `seen_methods()`
  (today only `tools/call` is recorded); `request_with_headers` records the headers it was given;
  any tool name is answered (T2 uses `echo2`); a held call's drop guard records when its future is
  dropped (T12).
- Per-row fixture options: idempotency cache enabled (T7), error-budget threshold (T10),
  passthrough identity propagation on `mock` (T11).
- Guard revocation between admission and dispatch uses the kill switch
  (`state.meta_mcp.kill_switch().kill("mock")`), reached through `run` step 1. `ToolPolicy` is an
  immutable `Arc` in `AppState` (`src/gateway/router/mod.rs:126`), so no in-process test can change
  tool policy live; the per-key `denied_tools` scope is the request-time denial used in row T2.

Holds: `MockBackend::holding` (backend reached, answer held) and `observe_dispatched` (worker paused
after the durable `Dispatched` marker, before transport). Nothing waits on a clock.

## 3. Rows

Each row names its test (all new ones in `src/gateway/router/tests/task_execution_adapter/direct_route.rs`),
its assertions, and the mutant that must redden it in CI. "Declared" = `modern(.., declares_tasks=true)`.

| # | design row | test | assertions | mutant (throwaway CI PR) |
|---|---|---|---|---|
| T1 | direct-route create and poll | `direct_task_create_then_poll_to_completed` | holding mock; `post_direct` declared `tools/call {name: echo, task:{}}` returns `result.taskId` while the backend holds the call (`status` = `working`, no result); release; `tasks/get` on `/mcp/mock` polls to `completed` carrying the backend result verbatim; `mock.calls()==1`. Controls: same call undeclared answers `MISSING_REQUIRED_CLIENT_CAPABILITY` and makes zero backend calls; same call without `task` is forwarded synchronously as today | M1 admission arm removed (call forwarded, no `taskId`) |
| T2 | direct-route guard parity | `denied_tool_with_task_is_refused_like_without_and_creates_nothing` | a key `key-deny` (own owner) with `denied_tools: [echo]` sends a declared `echo` call with `task` and idempotency key K: same error code and message as the same call without `task`; no `taskId`; `mock.calls()==0`. No record under THAT owner: `key-deny` then sends K with the allowed tool `echo2` and different arguments and gets a fresh task that completes (a record under K would answer the existing handle or the `-32602` mismatch; the `key_is_still_free` pattern, `refusals.rs:163`) | M2 admission moved before the tool-policy/sanitisation step of `run` |
| T3 | owner isolation across routes | `task_ids_are_owner_scoped_on_both_routes` | A creates on `/mcp/mock` (holding); B's `tasks/get`, `tasks/update` and `tasks/cancel` for A's id on `/mcp/mock` AND on `/mcp` answer `-32602 "no such task"`, same as a random id; A's `tasks/get` on `/mcp` sees `working` (owner-scoped, not route-scoped); release; A polls to `completed` (B's cancel had no effect). Reverse: A creates on `/mcp`, B refused on `/mcp/mock` | M3 direct arm resolves the owner without the caller (owner check dropped) |
| T4 | F1 closed | existing `src/gateway/router/direct_tasks_owner_tests.rs`, updated | "never reaches the backend" assertions kept for every row; exact-case `tasks/get`/`tasks/update`/`tasks/cancel` for a backend-minted id, declared, now answer `-32602 "no such task"` (was `-32601`); undeclared answer the capability error; case variants and `subscriptions/listen {taskIds}` keep `-32601`; `ordinary_methods_still_forward` and the 403 scope row unchanged. Control (§3 A.5): a backend `CreateTaskResult` answering a plain `tools/call` without `task` is relayed unchanged | M4 forward fallback restored for an id the store does not hold |
| T5 | JSON-RPC failure vs isError | `direct_task_rpc_error_fails_and_is_error_completes` | backend `Answer::RpcError` settles `failed` carrying the backend code/message; backend `Answer::IsError` settles `completed` with `isError: true` verbatim | M5 classification swapped for the direct branch (`failed` <-> `completed`) |
| T6 | advertisement | `direct_discover_merges_tasks_extension_modern_only` | declared modern `server/discover` and `initialize` on `/mcp/mock`: `capabilities.extensions` holds `io.modelcontextprotocol/tasks` exactly once, backend's other extensions preserved; backend that already declares it: still one entry, backend's value kept; modern request that does NOT declare tasks: still merged (advertisement keys on the era, not on the client's declaration); legacy `initialize` (no `_meta`): response body byte-identical to the backend's (id restored) | M6 extension added unconditionally (legacy also gets it) |
| T7 | idempotent admission | `direct_task_same_key_same_handle_one_task` | fixture enables the idempotency cache (the suite default is `idempotency_cache: None`); vacuity control: two identical SYNC direct calls with K make one backend call. (a) declared task call with K twice: same `taskId`, `mock.calls()==1`. (b) SYNC call with K completes, then the same call with `task` and K: answers the cached sync result byte-identical (the key's fingerprint is server, tool and arguments, `meta_mcp/direct_route.rs:83`, so `task` does not change it), no `taskId`, no second backend call. (c) task call with K first, then the SYNC call with K: answers the original `CreateTaskResult`, no dispatch beyond the task's one. (a) alone passes on the task store's own key dedupe; (b) and (c) are what redden | M7 admission skips the direct idempotency reservation; M7b reservation taken but never completed with the `CreateTaskResult` (reddens (c)) |
| T8 | live guards on FIRST dispatch | `direct_task_first_dispatch_runs_guard_chain` | `observe_dispatched` holds the worker after the marker; kill `mock`; release: task `failed` with the kill-switch refusal as its error, `mock.calls()==0`, handoff released (a cancel then answers the terminal-task refusal and `drain` completes). Control: same flow without the kill completes with one backend call | M8 worker Direct branch calls the transport without `DirectRouteGuards::run` |
| T9 | armed upstream unchanged | `adapter_claimed_direct_task_takes_the_armed_funnel` | a trusted recovery adapter claims `mock` (the `upstream_descriptor.rs` fixture); declared direct task: the upstream descriptor is persisted and the dispatch goes through `with_upstream_submission` exactly as a `/mcp` task to the same backend does (same recorded submission, same params on the wire) | M9 Direct branch taken before the arming check (armed job sent through the direct transport) |
| T10 | worker `after_dispatch` (added, review) | `direct_task_failures_feed_the_error_budget` | fixture sets the error-budget auto-kill threshold N (the security lane's DIRECT.5 fixture); N direct tasks whose backend answers `Answer::RpcError` each settle `failed`; afterwards `kill_switch().is_killed("mock")` is true and the next direct task call is refused on the request thread by `run` (no `taskId`, no task, backend count unchanged) | M10 worker Direct branch skips `after_dispatch` |
| T11 | worker consumes `GuardedCall` (added, review) | `direct_task_dispatch_uses_guarded_params_and_caller_headers` | `mock` configured for passthrough identity propagation (`required: true`, the `backend_handlers/tests.rs:18` config); `MockBackend` records `request_with_headers` headers; A sends `x-mcp-passthrough-authorization: Bearer cred-a` and arguments `{"q": "a\u0007b"}`: the task's one backend call carries `Authorization: Bearer cred-a` and arguments `{"q": "ab"}` (control character stripped by the sanitiser). The intent stores arguments as sent, so only `run` produces the sanitised form. The stored record (read through the store's existing get API) serialises with no `cred-a` bytes and no passthrough header: the credential lives only in the in-memory intent. Control: the same call without the header is refused at admission (fail-closed), no task | M11 worker sends the intent's stored arguments; M11b worker dispatches without the `GuardedCall` headers |
| T12 | owner operates own direct task (added, review) | `owner_updates_and_cancels_own_direct_task` | holding mock; A's plain `tasks/update` (no `inputResponses`) on `/mcp/mock` is acknowledged; A's `tasks/cancel` settles `cancelled`, the held backend call is aborted, the mock's drop guard records that the held transport future was dropped (abort observed on the wire side, not only in the stored status), and a later `tasks/get` reads `cancelled` | M12 direct `tasks/update` arm removed (falls back to the F1 refusal); M12b direct `tasks/cancel` arm removed |
| T13 | 1a keeps today's input settlement (added, review) | `direct_task_input_required_settles_abandoned` | backend answers an `InputRequired` result on a direct task: settles exactly as a `/mcp` task does today (the abandoned result of `settlement.rs:21-22`), not `completed` with the raw round | M13 Direct branch settles the raw backend result without `classify_dispatch` |

T9's design mutant ("input arm applied to armed path") belongs to 1b's code; 1b re-runs T9 against
that mutant. 1a's M9 is the analogous slip for the code 1a adds.

## 4. Red-first

The red commit adds T1-T13, the fixture additions, and the T4 assertion updates, with signature-only
stubs where a test names a new symbol. Expected red reasons (not compile errors):
T1/T3/T5/T7/T8/T9-T13 no `taskId` (the call is forwarded); T4 `-32601` where `-32602` is asserted; T6 no tasks extension on the modern discover. T2's denial assertions are GREEN at red (today the
denied call is refused before anything), and its `echo2` task-creation control is RED (no direct
task path yet); M2 is the proof that the denial half can fail.

## 5. Out of scope for 1a

All P2 rows (§4, 25 rows): input round, resume, `accepted_inputs`, `try_accept`, expiry and
restart of `input_required` rows. The criterion stays unmet after 1a; the ledger is not touched
and MIK-7311 is not closed by the 1a PR.

## 6. Planned module layout (size gate: backend_handlers.rs 1398/1450, handlers.rs 2174/2176, store.rs 1141/1141 by `scripts/dev/check-file-size.py`)

- `src/gateway/router/direct_guards.rs` (created by MIK-7597): 1a adds the router checks to `run`
  (isolation, propagation headers, tool policy and sanitisation, passthrough opt-out kept) and the
  response scan to `after_dispatch`, moving them out of `backend_handlers.rs` (which shrinks).
- `src/gateway/router/handlers/direct_tasks.rs` (new): the direct-route task entry. Declaration and
  unattributed checks, `route_task_owner`, admission through `task_intent_for_call`, the `tasks/*`
  arms reused from `handlers/tasks.rs`, and the modern capability merge. It lives under `handlers/`
  so the existing `pub(super)` task functions stay `pub(super)`; `handlers.rs` gains one
  `mod` line; its one entry point is a new `pub(in crate::gateway::router)` function (a new item,
  not a widening of an existing one).
- `src/gateway/task_service/execution/direct_dispatch.rs` (new): the worker's `Direct` branch
  (`run` -> transport -> `after_dispatch`, or `settle_cas(Fail)`); `worker.rs` gains the route
  branch after the arming check. The route tag (`Meta` | `Direct`) and the backend name ride on the
  in-memory intent; nothing new is persisted in 1a, so `store.rs` and `record.rs` are untouched.
- `is_task_dispatchable` gains the direct-job arm (`handlers/tasks.rs`).
- Tests: `src/gateway/router/tests/task_execution_adapter/direct_route.rs` (new) plus fixture
  additions in `support.rs` / `support/backend.rs`; `direct_tasks_owner_tests.rs` updated (T4).
- Docs: UPGRADING-4.0 item 67 amended (F1 refusal becomes the owner-checked task service; case
  variants and `listen` still refused; a key first used by a synchronous call replays that result
  to a later task call, because `task` is not part of the idempotency fingerprint); CHANGELOG `[Unreleased]`; README route table.

## 7. Questions for review

- Q1. The worker needs the caller's live context to run `run` at dispatch time, including the
  inbound headers a passthrough backend reads its per-caller credential from. 1a keeps that context
  in the in-memory intent only (never persisted), the way `/mcp` keeps `OwnedCallerContext`.
- Q2. `subscriptions/listen {taskIds}` stays `-32601` on the direct route in 1a (design §3 A.3 names
  only `tasks/*`). Serving it there is 4.0 scope and ships in 1b (design §18).

## 8. Review dispositions (round 1: two independent reviews, both SHIP-WITH-FIXES)

| finding | sev | check at source | disposition |
|---|---|---|---|
| worker `after_dispatch` unobserved | HIGH | T8 pins `run` only | ADOPTED: T10 |
| caller headers and sanitised params on the worker dispatch unobserved | MEDIUM | T1/T8 assert counts only | ADOPTED: T11 |
| T7 needs the idempotency cache the fixture disables | MEDIUM | suite fixture `idempotency_cache: None` (support.rs doc) | ADOPTED: enabled per row, sync-twice vacuity control |
| T7 misses a reservation never completed with the handle | MEDIUM | - | ADOPTED: T7(c), M7b |
| T7(b) accepted two outcomes | improvement | fingerprint is server:tool+arguments (`meta_mcp/direct_route.rs:83`) | ADOPTED: pinned to the cached sync result |
| T2 key-free check crossed owner namespaces | MEDIUM | task keys are owner-scoped | ADOPTED: same key, same owner, allowed tool `echo2` |
| no positive update/cancel, no foreign update | MEDIUM | - | ADOPTED: T12; T3 adds B's `tasks/update` |
| exact-case `tasks/update` missing from T4 | LOW | `every_task_method_and_case_variant_is_refused` | ADOPTED |
| replay-nonce consumption inside a repeated `run` | MEDIUM | security-lane design §2.3: the direct route has no nonce; with signing enforced it refuses `tools/call` | REJECTED at source. The LIFECYCLE design's §3 A.2 sentence still lists "replay nonce"; stale wording, reported to the design owner |
| design §4.3 stray `retry"., then` | LOW | present | NOT EDITED here (design text belongs to its branch); reported |
| modern undeclared advertisement | improvement | §3 A.4 keys on the era | ADOPTED: T6 |
| backend `CreateTaskResult` on a non-task call relayed | improvement | §3 A.5 | ADOPTED: T4 control |
| direct `InputRequired` regression before 1b | improvement | `settlement.rs:21-22` | ADOPTED: T13 |

## 9. Round 2 (delta; two independent reviews: SHIP-WITH-FIXES with one LOW, and SHIP)

| finding | sev | disposition |
|---|---|---|
| T2 red expectation contradicted its new `echo2` control | LOW | ADOPTED: §4 splits T2 into green denial half and red control |
| T12 abort observed only through status | improvement | ADOPTED: mock drop guard |
| T10 post-kill call: admission refusal vs worker failure | improvement | ADOPTED: refused on the request thread, no task |
| Q1 never-persisted credential not asserted | improvement | ADOPTED: T11 stored-record negative assertion |
| `run` executes twice, stated only implicitly | improvement | ADOPTED: §1 |
| T7(b) replay semantic undocumented for operators | improvement | ADOPTED: UPGRADING item 67 text |
