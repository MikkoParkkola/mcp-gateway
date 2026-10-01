# MIN.1 gap 1: a settlement record for a recovered upstream task

Status: r3, for review. Lead ruling 2026-10-01: option (a), an additive record value under
delegated authority. This is an increment of `2026-09-30-min1-tenant-attribution.md` §4. The r1
review is in the log at the end.

## Problem

A task-augmented call can be answered by the backend with a task of its own. The gateway then
settles it later from that upstream task, on one of two paths:

- **Worker:** the recovery worker follows the upstream task (`src/gateway/task_service/execution/worker.rs:350-375`) and settles it with `settle_cas`.
- **Owner read:** a `tasks/get` by the owner queries the upstream once (`src/gateway/task_service/execution/upstream.rs:234-300`) and settles it with `commit(TaskWrite::Recover)`.

Both run the result through `recover_task_result` (`src/gateway/meta_mcp/upstream.rs:406-434`), or
a failure through `recover_task_error`. Neither writes to the transparency log, and neither runs
inside `with_dispatch_scope`, so the gates' notes are dropped (`invoke/audit.rs:56`).

The only invocation record for the call is the submission record, written when the call returned
the task handle (`src/gateway/meta_mcp/invoke.rs:1218-1220`), before the result existed. So the
recovered tool response is never attributed. MIN.1 requires: "Tool responses carry a tenant
attribution ... recorded in the audit trail whether or not it triggers a block."

## Decision

One **settlement record** per recovered upstream task, written at the one point both paths share:
the durable recovery transition.

1. **Attribution.** Both paths run `recover_task_result` and `recover_task_error` inside
   `with_dispatch_scope`. They keep the returned `DispatchNotes` next to the transition they build,
   so the response tenants and data classes noted by the gates (raw response, before any refusal)
   travel with it. This is plumbing on both paths. It is not true at the base today.
2. **Record first, then commit: the synchronous order.** On a live call the record is written
   before the result becomes durable or deliverable. `invoke_tool_sourced` awaits
   `audit_invocation` (`src/gateway/meta_mcp/invoke.rs:1218-1222`) before it returns. Only after
   that does the router store the replayable result (`execution.complete_delivery`,
   `src/gateway/router/handlers.rs:1896-1897`) and send the response. Recovery uses the same order:
   - (a) query the upstream;
   - (b) run `recover_task_result` / `recover_task_error` in the dispatch scope, giving the
     transition and its notes;
   - (c) write the settlement record from them;
   - (d) commit the transition.
   - A settlement hook between (b) and (d) on both paths runs (c). It is a closure the owner-read
     caller passes to `query_and_commit`, next to `finish` and `finish_error`; the worker calls it
     inline.
   - **No race between the two paths.** The worker and the owner read take the same per-task
     query slot (`worker.rs:432` `acquire_query_lease`, and `upstream.rs:221` and `:310`, both via
     `query_slot`), so they never settle one task concurrently. A commit can still lose to a
     non-recovery writer, such as a cancel. Then the record stands for a recovery that did not
     land, as a live call's record stands when its delivery then fails.
   - `Followed::Retained` and `Followed::Overtaken`, and a query that is `Live` or `Unavailable`,
     reach no step (c) and write nothing.
3. **One helper.** A crate-private
   `MetaMcp::audit_settlement(task, proposed, notes, principal)` assembles and writes the record
   from the proposed transition of step (b), with the same outcome mapping and serialization as
   `audit_invocation`. Both paths call it at step (c), before the commit. Under FailClosed its
   error turns the proposed transition into the `-32005` failure that is then committed. No second
   copy of the record schema.

### The record

| Field | Value |
|---|---|
| `route` | `"task_recovery"`. Written through `log_invocation_attributed` with a route string from a crate-private route type. The public `InvocationRoute` enum (`src/security/audit.rs:259`) is unchanged, so this needs no public API change. Record readers parse `route` as a string; a test round-trips the value through the log's own verifier and reader |
| `server`, `tool` | the job's backend and tool |
| `task_id` | new field: the gateway task id. It is the join key to the submission record |
| `request_hash` | `sha256` of the canonical `{"task_id": <id>}`. The recovering path does not hold the original request; the call's request hash is on the submission record |
| `response_hash` | `sha256` of the processed result from step (b). Absent when that transition is a failure (a policy refusal or a screened peer failure) |
| `outcome`, `error_code` | from the processed transition, through `audit_invocation`'s mapping. A gate refusal is a failure with its code |
| `who` | built from the principal the task was admitted under, the one the recovering path holds and nothing more. No credential kind, API key name or grant subject is claimed |
| `session_id`, `correlation_source` | correlation source `task_id` (a new value of the existing field), and `session_id` holds the task id. The record says what it is joined by rather than posing as a trace id |
| `tenants`, `data_classes`, `attribution` | from the notes of step 1, as on a live call: raw-response tenants even when a gate then refused, and data classes when the kernel ran |

**Submission record gains `task_id`.** It is attached whenever the dispatch captured a raw upstream
task handle (noted in the submission's dispatch scope when the handle is captured), whatever the
processed result became, so a refused or rewritten handle still joins.

**Write failure (D1-f, as on a live call).**
- **FailClosed:** a failed write at (c) means the recovered content is not committed. The task
  commits `Fail(-32005, "audit log unavailable")` instead, with no backend content, as a live call
  withholds its result and answers `-32005`.
- **BestEffort:** the failure is logged and the transition commits.
- A crash between (c) and (d) leaves a record and no settlement. The next recovery attempt
  re-queries and records again, so a crash can over-record but never deliver unrecorded content.
  This is the synchronous path's own window: a live call that crashes after its write and before
  `complete_delivery` has a record and no delivery.

**What the record describes.** The processed transition from (b), as a live call's record
describes the gated result before any later delivery stage. If the store then cannot hold the
result and commits its bounded failure (`store_targets.rs:150-166`), the task delivers only the
gateway's own error, with no backend content. The record keeps the raw-response attribution and
the processed result's hash. On a live call, the record likewise precedes the router's
post-invocation response scan, which may still refuse.

**Key context, unchanged here.** The worker passes `api_key_name: None` into the gates
(`worker.rs:357`), and the owner read passes the reading caller's key name
(`src/gateway/router/handlers/tasks.rs:374,386`). Pre-existing, and not a policy divergence: in the gates the key name is used
only as the context-integrity provenance `subject` label (`src/gateway/meta_mcp/invoke.rs:2702`),
and it selects no policy. The settlement record's `who` does not claim a key either (above).

**Not changed:** D1-d for every call that does not recover an upstream task; the direct route;
tasks the gateway executed itself, which already run in the dispatch scope.

## Tests (written first, red on base)

Each of R1, R3-R7 runs on both paths, the worker and the owner read.

- R1: a recovered result naming `cust-9` writes one settlement record.
  - Exact assertions: `route == "task_recovery"`, `task_id`, `server`/`tool`, `tenants == [h(cust-9)]`, non-empty `data_classes`.
  - `response_hash` equals `sha256` of the processed result, and `request_hash` equals `sha256` of the canonical `{"task_id": id}`.
  - `who` names only the admission principal, and `correlation_source == "task_id"`.
- R2 (owner read, distinct reader): the reading principal differs from the admission principal, and `who` names the admission principal.
- R3 (gate refusal): a recovered result refused by an output policy settles failed. Its record carries `tenants ∋ h(cust-9)` (raw response), `outcome` ≠ `ok`, the refusal code, and no `response_hash`.
- R4 (screened failure): a recovered peer failure whose message names a tenant writes a failure record. The code is kept, the raw-response tenants are on the record, and there is no `response_hash`.
- R5 (store bound): a recovered result over the record size limit has a record carrying its tenants and the processed hash, and the task delivers the bounded failure with no backend content.
- R6 (order): with a log that fails at (c) under FailClosed, the task commits `-32005` and none of the recovered content is stored or delivered.
- R7 (BestEffort): with an unwritable log the task commits the recovered result, and the failure is logged.
- R8 (no double record): a worker settlement and an owner read on one task produce exactly one record. Also, a cancel that wins the commit after the record was written leaves that one record and a cancelled task.
- R9 (submission join): the submission record carries the same `task_id` when the raw handle was captured, including when a response gate refused or rewrote the handle.
- R10 (regression): a non-task call writes exactly one record, with no `task_id`. A `task_recovery` record verifies with `verify_log`.
- Kill criterion: remove the settlement write and R1 must fail with no `task_recovery` record.

## Review log

- r1 (2026-10-01):
  - gpt-review SHIP-WITH-FIXES:
    - HIGH: owner-read recovery was unaudited.
    - MEDIUM: submission tagging was keyed on the processed result.
    - MEDIUM: the hash could describe a result the store replaced.
    - MEDIUM: there were no refusal or screened-failure tests.
  - synthetic-review (GLM) SHIP-WITH-FIXES:
    - MEDIUM: there was no gate-refusal test, and the scope claim contradicted the code.
    - LOW: there was no BestEffort test.
    - MEDIUM: recovery gates run key-less. Answered as pre-existing: the key only labels provenance.
    - Improvements: one helper, a route round-trip, the CAS loss, a correlation label, and no record on Retained or Overtaken.
  - All folded into r2: the shared post-commit write point, both paths scoped, R2-R10, `correlation_source: task_id`, the stated FailClosed residual.
- r2 (2026-10-01):
  - synthetic-review (GLM) SHIP. One MEDIUM: the crash window after commit.
  - gpt-review SHIP-WITH-FIXES. One HIGH: a failed post-commit write lost the record and still delivered under FailClosed. Also a correction: owner reads pass the reader's key.
  - Lead ruling: match the synchronous order if it is better. It is (write before `complete_delivery`). So r3 writes before the commit, FailClosed withholds the content as a live call does, and the crash window becomes the synchronous path's own over-record window.
- r3 (2026-10-01):
  - gpt-review SHIP-WITH-FIXES. One MEDIUM: the helper paragraph still said "after a committed transition". Fixed in r3.1: the helper takes the proposed transition at step (c). R6-R7 now run on both paths, and R8 adds the cancel case.
