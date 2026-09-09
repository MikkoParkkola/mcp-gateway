<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: MIT
-->

# TASK.1: the caller that runs a task, and the settle that ends it

Date: 2026-09-09. Scope: `MIK-7272.TASK.1`, the one clause of it that no code
reaches. Companion to `docs/design/2026-08-31-task-1-tasks-extension.md`
(the extension's shape) and
`docs/design/2026-09-06-task-1-tasks-extension-test-plan.md` (the twenty rows).
This note designs neither the wire shape nor the store; both are settled there.

## 1. The gap, stated as what the code does today

`docs/requirements/RELEASE-4.0.0-criteria-status.md:239` carries TASK.1 as
GRADED AS A WHOLE on 2026-09-08. Three of its four halves are in the tree and
verifiable at source:

| Half | Where | State |
| --- | --- | --- |
| `tasks/get`, `tasks/update`, `tasks/cancel` inbound arms | `src/gateway/router/handlers.rs:1582`, `:1591` | present |
| handle creation on a task-augmented `tools/call` | `src/gateway/router/handlers.rs:1196-1208` | present |
| `ttlMs` present-and-nullable | `src/gateway/router/handlers.rs:224` | present; `.14`-`.17` are design-decision rows, not wire behaviour |
| **the backend call ever running** | nowhere | **absent** |

The absence is precise and it is greppable: `Task::complete`
(`src/protocol/tasks.rs:107`) has **zero** callers in `src/`. The only
production writer of a terminal status is `Task::fail_with_code` at
`handlers.rs:1596`, on the `tasks/cancel` arm — a client cancelling its own
task. So every task the gateway has ever created is `working`, forever, and
`tasks/get` is a poll over a record that nothing will ever change.

The cause is the early return at `handlers.rs:1196`:

```rust
if params.as_ref().is_some_and(|p| p.get("task").is_some()) {
    let task_id = state.tasks.create(&owner, tool_name);
    ...
    return build_json_response(...);   // the tool is never invoked
}
```

The criterion's words are "supported for long-running **backend** calls". A
handle that resolves to `working` and never moves does not support a backend
call; it replaces one.

Two consequences of *where* that return sits, not just that it returns:

1. It precedes every gate in the arm — the malformed-retry refusal (`:1222`),
   the admin pre-check (`:1246`), `authorize_tool_target` (`:1254`) and the
   firewall pre-invocation scan (`:1297`). Adding `"task": {}` to a call the
   caller may not make turns a refusal into a `200` and a task record. Nothing
   is *executed* that should not be, because nothing is executed at all — but
   the refusal the caller is owed is withheld, and an unauthorized caller can
   allocate records.
2. The comment above it says the record is created "before anything is
   dispatched". That intent is right and is preserved below; the line is
   simply in the wrong place to express it.

## 2. Asynchronous, because the pinned design says so

`2026-08-31-task-1-tasks-extension.md:81-83`:

> the gateway is the task *server*: it accepts a task-augmented `tools/call`,
> returns a `CreateTaskResult` immediately, runs the backend call on its own,
> and serves `tasks/get` / `tasks/update` / `tasks/cancel` from its own record.

That settles the only real fork in this note, so it is quoted rather than
re-argued. For the record, the alternative — invoke synchronously, settle, then
return the already-terminal handle — is rejected on three counts, any one of
which is sufficient:

- It defeats the extension's purpose. The handle exists so the response does
  not wait for the call; a synchronous settle makes the response wait for the
  call *and* wraps the answer in a poll.
- It makes two of the criterion's three named behaviours unreachable.
  `Task::complete` and `Task::fail_with_code` both open with
  `if self.status != TaskStatus::Working { return; }`
  (`tasks.rs:108`, `:129`). Under a synchronous settle every task is terminal
  before the client holds its id, so `tasks/update` and `tasks/cancel` no-op
  on every task that ever exists.
- It contradicts the test plan's own rationale for `.1`, which asserts that the
  created id resolves immediately, *before any status change*.

## 3. The change

**One dispatch body, two callers.** The invoke and the firewall
post-invocation response scan (`handlers.rs:1400-1481`) move into a single
owned-context struct with one `async fn run(self) -> JsonRpcResponse`. The
ordinary path awaits it. The task path spawns it. There is no second copy of
the caller context, and no path on which the response scan is skipped —
a scan bypass reachable by appending `"task": {}` to any call would be a
security regression dressed as a feature.

The context is owned rather than borrowed because a spawned future is
`'static`. `MetaMcpCallerContext<'a>` stays exactly as it is: it is
constructed *inside* `run`, from the struct's own fields, so the borrow graph
that exists today is unchanged. The fields are the handler locals the invoke
already reads — `Arc<AppState>`, `client`, `oauth_agent_identity`,
`cert_identity`, `verified_identity`, `agent_identity`, `grant_subject`,
`declared_capabilities`, `era`, `confirmation_policy`, `retry`, `session_id`,
`tool_name`, `arguments`, `backend_targets`, `id`, and — for the settle —
`owner` and `task_id`. Ownership is not uniform and the difference matters to
whoever writes it: `tool_name` borrows `params` and becomes an owned `String`;
`state` (an `Arc`), `session_id` and `client` are cloned because the arm reads
each again after the match (`:1625` and the metrics emit); the rest are moved.

**The spawned future is deliberately detached from the request's cancellation
scope.** That is the point of owning the context rather than borrowing it: a
client that receives its `CreateTaskResult` and disconnects has done exactly
what the extension invites it to do, and the backend call must survive that.
An axum handler's future is dropped when the connection goes away; a
`tokio::spawn`ed one is not. A task whose backend call is cancelled by the
client hanging up would poll `working` forever, which is the same defect this
note exists to remove, reached by a different route.

**Creation moves to just before dispatch.** The `create` call is relocated from
`:1196` to the point after the gates and immediately before the spawn. Every
existing early return then keeps working with no orphan record, and the
comment's invariant — created before anything is dispatched — becomes true more
precisely than it is today rather than less.

**Both confirmation arms are reachable, and the first draft of this note said
otherwise.** It claimed the tasks extension is gated by `ADDED_IN_2026_07_28`,
so a caller that can ask for a task is `Era::Modern` and always gets `InBand`.
That is wrong at source: `ADDED_IN_2026_07_28` does not contain `tools/call`,
so the `!is_modern` refusal at `handlers.rs:972` never fires for a
task-augmented call. The real gate is `reaches_tasks_extension` +
`declares_tasks_extension` (`handlers.rs:166-190`, refusing at `:986-998`),
which is per request and era-blind: a 2025 client that puts
`io.modelcontextprotocol/tasks` in its `_meta` client capabilities reaches this
path as `Era::Legacy` and gets `ConfirmationChannel::Elicit`. Neither arm poses
a borrow problem — `proxy_manager` hangs off `state` and the policy is owned —
so both are constructed inside `run` exactly as they are today. What the
Legacy arm does pose is answered by the settle rule below, which refuses to
call an unfinished exchange a completed task.

**The settle.** The spawned future is `tokio::spawn`ed *inside* the outer
spawn, so the settle is keyed on the dispatch's termination rather than on its
return: a future that dies without producing a response yields a `JoinError`,
and a `JoinError` that did not settle the record would leave it `working`
forever — the very defect this note removes, reached by a third route. The
decision is a free function over an `Option`, so it is unit-testable without a
runtime and the `JoinError` mapping is the one line above it:

```rust
fn settle(task: &mut Task, outcome: Option<JsonRpcResponse>) {
    match outcome {
        None => task.fail("the dispatch ended without producing a response"),
        Some(r) => match (r.result, r.error) {
            (Some(result), _) if is_final(&result) => task.complete(result),
            (Some(_), _) => task.fail(UNFINISHED_EXCHANGE),
            (None, Some(e)) => task.fail_with_error(&e),
            (None, None) => task.fail("the dispatch returned neither a result nor an error"),
        },
    }
}
```

Four rules, in order of how easily each is got wrong:

- **A result that is not final is not a completion.** `tools/call` can answer
  with an interim step rather than an answer: an in-band destructive-action
  confirmation, or a backend's own multi-round-trip request. Those carry
  `resultType: "input_required"`, and `is_final`
  (`src/protocol/cacheable.rs:129`) is exactly the predicate that separates
  them from a finished one — its doc comment names `"input_required"` as the
  case it exists for. Settling such a result as `completed` would hand the
  client a terminal task whose "result" is a question, for a tool that never
  ran. 4.0.0 has no channel to answer that question through a task handle
  (`tasks/update`'s `inputResponses` is piece 4), so the honest answer is a
  `failed` task saying so, not a completion and not a record left `working`.
  The `.6` rule below is unaffected: `isError` is a field of a *final* result.
- **A tool result is a completion even when `isError` is true.** `isError` is a
  field of a successful `tools/call` result, so the task `completed` and its
  result says the tool failed. `failed` is reserved for the task not producing
  a final result at all. This is `tasks.md:890-891` and the test plan's `.6`
  row.
- **A JSON-RPC error is a failure carrying that error whole** — its own `code`,
  and its `data`. Not a flattened string, not a blanket `-32603`, and not the
  `{code, message}` pair alone: `data` is where `-32021` carries
  `requiredCapabilities`, which is the machine-readable instruction for
  recovering from the refusal. `Task::fail_with_code` drops it today
  (`src/protocol/tasks.rs:128-134` builds `json!({code, message})`), so this
  change adds `Task::fail_with_error(&JsonRpcError)` and makes `fail_with_code`
  delegate to it. One writer of the stored error object, not two.
- **The last two arms cannot currently happen** and are written anyway: each is
  one line, and the alternative is a task silently left `working` by a shape
  change in `handle_tools_call` or by a panic in the dispatch. Note that the
  panic route is a dev-and-test concern only — `Cargo.toml:216` sets
  `panic = "abort"` for the release profile, where the process dies instead —
  which is why the guard is one `tokio::spawn`, not a `catch_unwind` and an
  unwind-safety argument.

**`ttlMs` is not touched.** The test plan carves `.14`-`.17` out as design
decisions with no wire behaviour behind them yet, and `task_view` already emits
`ttlMs: null` for a task with no deadline. A settle does not create a deadline.

## 4. What is deliberately not in this change

- No store, no reaper, no admission caps (piece 2). A settled record is
  retained exactly as an unsettled one is today.
- No `input_required` / `cancelled` statuses, no `createdAt` /
  `lastUpdatedAt`, no `pollIntervalMs` (piece 1).
- No cooperative cancellation of a call already in flight. `tasks/cancel`
  marks the record and the spawned future runs to completion; the settle then
  finds a non-`Working` status and leaves it alone, which is the
  settled-stays-settled rule doing its job rather than a race.
- No `notifications/tasks` emission (piece 5).

Each is a real gap and each has a row already. This note closes one clause: the
tool runs, and the handle resolves to what it produced.

## 5. Tests, written to fail first

Three wire-level cases in `tests/mik_7272_task_1_acs.rs`, `mod dispatch`. All
three are red against HEAD for the same reason — nothing settles — so the
falsifier is run with the production hunk reverted, not merely asserted.

| Case | Asserts |
| --- | --- |
| a task-augmented call runs its tool | the creation response is `working` and carries no `result`, and the handle then polls to `status: "completed"` carrying the tool's own result — so the tool demonstrably executed, and executed *after* the response |
| a refused call settles as a failure | `status: "failed"` and an `error` object carrying the refusal's own `code` and its `data`, not a bare `-32603` |
| an `isError: true` result still completes | `status: "completed"` on the **wire**; the existing `.6` case is in-process only |
| the settle decision, over each outcome | unit test on the free function: a non-final result and an absent response both settle `failed`, and a `JsonRpcError` reaches the record with `data` intact |
| a gate that refuses still refuses | a task-augmented call that fails a pre-dispatch gate is answered with that gate's refusal and no handle — the assertion that the relocated `create` is strictly safer than the `:1196` one, rather than merely later |

**A limit, stated rather than left for a reviewer to find.** The first case
excludes the synchronous-settle design — a creation response reading `working`
with no `result` cannot come from one — but it does not prove the backend call
runs *concurrently* with the response. Proving that needs a backend the test
can hold open at a barrier and release after the poll, and the harness has no
such backend today. Recorded as a gap rather than closed, because a case that
cannot fail against the design it is named for is worse than a missing one.

The first supersedes `ac_task_1_1_a_created_task_id_resolves_immediately`'s
recorded caveat that it is vacuous as a constraint: the id still resolves
immediately, and now it also resolves to something.

## 6. Open, and reported rather than resolved here

TASK.1's row was graded whole on 2026-09-08 with this clause unbuilt. That is a
ledger question, not a code question: whoever owns the row decides whether it
reverts to partially-met until this lands. Recorded here so the answer is not
inferred from a commit.
