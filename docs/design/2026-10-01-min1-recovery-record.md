# MIN.1 gap 1: a settlement record for a recovered upstream task

Status: draft for review. Lead ruling 2026-10-01: option (a), an additive record value under
delegated authority. Increment of `2026-09-30-min1-tenant-attribution.md` §4.

## Problem

A task-augmented call whose backend answers with its own task is settled later by the upstream
recovery worker (`src/gateway/task_service/execution/worker.rs:350-375`). The worker runs the
recovered result through `recover_task_result` (`src/gateway/meta_mcp/upstream.rs:406-434`), or a
failure through `recover_task_error`, and settles the task. Nothing on that path writes to the
transparency log. The only invocation record for the call is the submission record, written when
the call returned the task handle (`src/gateway/meta_mcp/invoke.rs:1218-1220`), before the result
existed. So the recovered tool response is never attributed. MIN.1 says "Tool responses carry a
tenant attribution ... recorded in the audit trail whether or not it triggers a block."

## Decision

One **settlement record** per recovered upstream task, written by the worker when it settles a
recovered result or failure. It is an `invocation` record, so the existing tooling reads it.
D1-d's "one record per call" is unchanged for every call that does not recover an upstream task.
A recovered task-augmented call has two records, the submission and the settlement, joined by
`task_id`.

| Field | Value |
|---|---|
| `route` | `"task_recovery"`. Written by a new crate-private writer. The public `InvocationRoute` enum (`src/security/audit.rs:259`) is unchanged, so this needs no public API change |
| `server`, `tool` | the job's backend and tool, as the worker holds them |
| `task_id` | new field: the task's id. The submission record gains the same field when its result is a task handle, so the two records join on it |
| `request_hash` | `sha256` of the canonical `{"task_id": <id>}`. The worker does not hold the submission's request, so this hashes what it does hold. The request hash of the call is on the submission record |
| `response_hash` | `sha256` of the recovered result as settled (after the gates). Absent on a failure, as on any failed call |
| `outcome`, `error_code` | from the settled result or failure, through the existing `AuditOutcome` mapping |
| `who` | built from the principal the task was admitted under, the one the worker holds and nothing more. No credential kind, API key name or grant subject is claimed, because the worker does not hold them |
| `session_id`, `correlation_source` | the task id, as correlation source `trace_id`. The worker already passes the task id as the trace id into `recover_task_result` |
| `tenants`, `data_classes`, `attribution` | as on a live call. `recover_task_result` runs inside `with_dispatch_scope`, so the gates note the response tenants and data classes as they do live. Request-side tenants stay on the submission record |

**Write failure.** Under `FailClosed` a failed settlement write settles the task as **failed**
with `-32005`, so an unaudited recovered result is never delivered (D1-f). Under `BestEffort` the
result settles and the failure is logged.

**Not changed.** The submission record, apart from the new `task_id` field on a task-handle
result. Non-task calls. The direct route. Task results that the gateway itself executed: those
already ran inside the dispatch scope.

## Tests (written first, red on base)

- R1: a recovered result naming `cust-9` writes one settlement record, with `route == "task_recovery"`, `tenants ∋ h(cust-9)`, `data_classes` present, the job's `server`/`tool`, `task_id` equal to the task's id, and a `response_hash`.
- R2: a recovered failure writes a settlement record with `outcome` ≠ `ok`, an `error_code`, and no `response_hash`.
- R3: `FailClosed` with an unwritable log: the task settles failed with `-32005`, and the recovered content is not in the task.
- R4: the submission record of that call carries the same `task_id`.
- R5 (regression): a non-task call still writes exactly one record, with no `task_id`.
- Kill criterion: remove the settlement write and R1 must fail with no `task_recovery` record.
