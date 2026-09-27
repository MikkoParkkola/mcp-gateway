# F1: refuse `tasks/*` on the per-backend route

Status: REVIEWED (two independent reviews: SHIP, SHIP-WITH-FIXES; dispositions in §7). Issue #1442, MIK-7596. Small security change. It lands before
LIFECYCLE.1 (`docs/design/2026-09-26-lifecycle-1-direct-route-tasks-and-input.md` on branch
`docs/lifecycle-1-design`, §6 Q3 and finding F1) and does not implement it.

## 1. Problem (release-line tip `f9270991f`)

- `POST /mcp/{name}` is `backend_handlers::backend_handler`
  (`src/gateway/router/mod.rs:390`, `src/gateway/router/backend_handlers.rs:465`, inner `:498`).
- The file has no task handling. The only per-caller check before forwarding is backend scope,
  `client.can_access_backend` (`:607`). Tool policy and sanitisation run for `tools/call` only
  (`:923`, `:960`).
- Every other method falls through to the generic forward (`:1032-1046`) and then
  `dispatch_in_scope` (`:428`), which calls `backend.request` or `request_with_headers`
  (`:453`/`:456`) verbatim. `era_removed_method` (`:444`) refuses only the methods that the
  2026-07-28 revision removed.
- Impact: two callers allowed on one backend share its static credential, so the backend sees
  one principal. Caller B holding caller A's backend task id can read A's result
  (`tasks/get`), change it (`tasks/update`) or cancel it (`tasks/cancel`) through the gateway.

## 2. Options

| option | what | verdict |
|---|---|---|
| A. answer from the gateway store | call the `/mcp` task arms (`handlers.rs:1858-1894`) from this route | rejected here: those arms live in the private module `handlers::tasks` (`handlers.rs:45`), and the owner resolver `route_task_owner` is `pub(super)` inside it (`handlers/tasks.rs:52`). Reaching them from `backend_handlers` means widening visibility. LIFECYCLE.1 adds that path under its own maintainer decision |
| B. copy the owner rule into `backend_handlers` | resolve the owner locally and read `state.tasks` | rejected: it creates a second owner rule, which is the drift the one-resolver design exists to prevent |
| C. refuse | `tasks/*` on `/mcp/{name}` gets a typed JSON-RPC error; no backend call | **chosen** (maintainer decision 2026-09-26) |

## 3. Design (option C)

In `backend_handler_inner`, right after the request id is known (after the notification
branch, before the retry-field check at `:704` and before identity propagation, attestation,
idempotency or any forward), add:

```rust
if is_task_method(&method) {
    return build_http_error_response(Some(id), -32601, "<method> is not served on /mcp/{name}; use /mcp", StatusCode::OK);
}
```

- `is_task_method` is a private function in `backend_handlers.rs`. It matches every method
  whose name starts with `tasks/`, compared case-insensitively. It also matches
  `subscriptions/listen` when `params.taskIds` is present, the same condition
  `reaches_tasks_extension` uses on `/mcp` (`handlers.rs:96`). A keep-in-step comment points
  at that list. The prefix covers `tasks/get`,
  `tasks/update`, `tasks/cancel`, `tasks/list` and any later `tasks/*` method. The comparison
  ignores case because some backends match method names loosely, the same reasoning
  `log_level_admin_tests.rs` uses.
- **Code -32601 (method not found).** The route has no task handler, so -32601 is the honest
  answer. The alternative, -32602 "no such task", is wrong for a task the caller owns on
  `/mcp`, and a caller could take it for a real store lookup. -32601 is also the code this
  path already uses for methods it does not serve (`era_removed_method`, `:444-449`, using
  `METHOD_NOT_FOUND_CODE`). The message names `/mcp`, the route that serves tasks.
- **HTTP 200.** This route has no revision-aware status rule. Its existing `-32601`
  (the era refusal, `:444-449`) comes back on the forward path with 200, and this refusal
  answers the same way. `/mcp` differs: on a 2026-07-28 request it answers `-32601` with 404
  (`handlers.rs:1951-1963`). Adopting that rule here would change the whole route, which is
  outside this fix.
- **Placement.** The check runs before identity propagation, attestation and idempotency, so
  a refused call mints no per-user credential, writes no mint-audit row and takes no
  idempotency slot. It runs after backend scope (`:607`) and backend lookup, so an out-of-scope
  caller still gets today's 403. The route leaks no new existence signal.
- **Not changed.** `tools/call` carrying `params.task` still forwards as it does today; adding
  task creation on this route is LIFECYCLE.1. Notifications are unchanged. `/mcp` is unchanged.

## 4. `subscriptions/listen` naming tasks

`subscriptions/listen` with `params.taskIds` also names task ids. On `/mcp` it goes through
the owner check (`handlers.rs:92-99`). Both reviews asked for it to be refused on this route
too, and it now is (§7). Without `taskIds` it forwards as it does today.

## 5. Test plan (red-first; new file `src/gateway/router/direct_tasks_owner_tests.rs`)

Fixture: two API keys, A and B, both scoped to backend `shared`, and a recording wire
(the `log_level_admin_tests.rs` pattern) that plays a backend that supports tasks. `tools/call`
answers with a created task `bt-A`, `tasks/get` answers with that task and its result, and
`tasks/cancel` acknowledges. The wire records every method it receives.

| id | test | asserts | mutant that must redden it |
|---|---|---|---|
| T1 | `caller_b_tasks_get_for_a_task_never_reaches_backend` | A creates `bt-A` via `tools/call`; B sends `tasks/get {taskId: bt-A}`; the wire saw zero `tasks/*` calls; B gets -32601 with its own id; A's result is not in the body | forward restored for `tasks/get` |
| T2 | `caller_b_tasks_cancel_for_a_task_never_reaches_backend` | same, with `tasks/cancel` | forward restored for `tasks/cancel` |
| T3 | `every_task_method_and_case_variant_is_refused` | `tasks/update`, `tasks/list`, `Tasks/Get`, `TASKS/CANCEL`, `Tasks/FutureMethod`: zero wire calls, -32601 each | prefix match made case-sensitive, or replaced by a list of known methods |
| T4 | `ordinary_methods_still_forward` | `tools/call` (with and without `params.task`), `resources/list`, and `subscriptions/listen` without `taskIds` reach the wire | refusal widened to every method |
| T5 | `caller_b_task_subscription_never_reaches_backend` | `subscriptions/listen {taskIds:[bt-A]}`: zero wire calls, -32601 | `taskIds` arm removed |
| T6 | `out_of_scope_caller_still_gets_403_for_task_methods` | a key scoped to another backend sends `tasks/get`: 403 and -32003, as today | refusal moved before the scope check |

The red commit holds T1-T4 only; the tests drive the HTTP route, so no stub is needed to compile. T1-T3 fail
on their assertions: the wire sees the forward. T4 passes on red and green. It is the
positive control.

## 6. Docs

UPGRADING-4.0 item 67. In 4.0, task calls on per-backend routes are refused until they carry
an owner check; `/mcp` still serves tasks. CHANGELOG under `[Unreleased]`, Security.

## 7. Review dispositions (two independent reviews: SHIP, SHIP-WITH-FIXES)

| finding | sev | disposition |
|---|---|---|
| `subscriptions/listen` with `taskIds` still forwards | HIGH / improvement | ADOPTED: refused as well; T5, plus a positive control without `taskIds` in T4 |
| the HTTP-200 rationale mis-cites `/mcp`, whose modern branch answers 404 | LOW | ADOPTED: rationale corrected in §3; the per-backend route stays at 200, like its existing `-32601` |
| test that the scope check still comes first | improvement | ADOPTED: T6 |
| keep-in-step comment at the new predicate | improvement | ADOPTED |
| test an unknown `tasks/*` method to pin the namespace-wide match | improvement | ADOPTED: `Tasks/FutureMethod` in T3 |
| test "no mint, no idempotency slot" with propagation and idempotency on | improvement | DECLINED: idempotency is reserved for `tools/call` only (`backend_handlers.rs:923`), so a `tasks/*` call never holds a slot. The refusal sits before propagation in source, and T1-T5 pin the security property (nothing forwarded). A MEDIUM-cost fixture for a property this change does not alter |
