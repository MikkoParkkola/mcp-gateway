# MIN.1 gap 1: a settlement record for a recovered upstream task

Status: r2, for review. Lead ruling 2026-10-01: option (a), an additive record value under
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
2. **One write, after the commit.**
   - The settlement record is written only when the store reports the recovery transition
     **committed** (`Transitioned`).
   - It describes the **committed** task: the stored result, or the store's bounded failure when
     the result was over the record size limit (`store_targets.rs:150-166`).
   - A writer that lost the race (`RevisionConflict`, or `Overtaken` on the worker) writes
     nothing. The winner's record is the one record.
   - `Followed::Retained` and `Followed::Overtaken`, and a query that is `Live` or `Unavailable`,
     settle nothing and write nothing.
3. **One helper.** A crate-private
   `MetaMcp::audit_settlement(task, committed, notes, principal)` assembles the record with the
   same outcome mapping and serialization as `audit_invocation`. Both paths call it after a
   committed transition. No second copy of the record schema.

### The record

| Field | Value |
|---|---|
| `route` | `"task_recovery"`. Written through `log_invocation_attributed` with a route string from a crate-private route type. The public `InvocationRoute` enum (`src/security/audit.rs:259`) is unchanged, so this needs no public API change. Record readers parse `route` as a string; a test round-trips the value through the log's own verifier and reader |
| `server`, `tool` | the job's backend and tool |
| `task_id` | new field: the gateway task id. It is the join key to the submission record |
| `request_hash` | `sha256` of the canonical `{"task_id": <id>}`. The recovering path does not hold the original request; the call's request hash is on the submission record |
| `response_hash` | `sha256` of the committed result. Absent when the committed transition is a failure (a policy refusal, a screened peer failure, or the store's size bound) |
| `outcome`, `error_code` | from the committed transition, through `audit_invocation`'s mapping. A gate refusal is a failure with its code |
| `who` | built from the principal the task was admitted under, the one the recovering path holds and nothing more. No credential kind, API key name or grant subject is claimed |
| `session_id`, `correlation_source` | correlation source `task_id` (a new value of the existing field), and `session_id` holds the task id. The record says what it is joined by rather than posing as a trace id |
| `tenants`, `data_classes`, `attribution` | from the notes of step 1, as on a live call: raw-response tenants even when a gate then refused, and data classes when the kernel ran. On a store size-bound failure the record carries the raw-response tenants and `attribution: "uninspected"` is not added (the response was read; only its storage failed) |

**Submission record gains `task_id`.** It is attached whenever the dispatch captured a raw upstream
task handle (noted in the submission's dispatch scope when the handle is captured), whatever the
processed result became, so a refused or rewritten handle still joins.

**Write failure.**
- **FailClosed:** before querying the upstream (worker or owner read), the recovering path probes
  the log with `admit()`, as a live dispatch does (D1-f). A degraded log leaves the task working,
  to be retried, so nothing settles unaudited while the log is known bad. A write that still fails
  after a committed transition is logged at error level and counted
  (`mcp_audit_settlement_write_failures_total`).
  - Accepted residual, stated: the result is already durable at that point and is delivered.
    Withholding it would need a second terminal transition, which the task model forbids.
- **BestEffort:** the result settles and the failure is logged.

**Key context, unchanged here.** Both paths pass `api_key_name: None` into the gates
(`worker.rs:352`). Pre-existing, and not a policy divergence: in the gates the key name is used
only as the context-integrity provenance `subject` label (`src/gateway/meta_mcp/invoke.rs:2702`),
and it selects no policy. The settlement record's `who` does not claim a key either (above).

**Not changed:** D1-d for every call that does not recover an upstream task; the direct route;
tasks the gateway executed itself, which already run in the dispatch scope.

## Tests (written first, red on base)

- R1 (worker): a recovered result naming `cust-9` writes one settlement record.
  - Exact assertions: `route == "task_recovery"`, `task_id`, `server`/`tool`, `tenants == [h(cust-9)]`, non-empty `data_classes`.
  - `response_hash` equals `sha256` of the committed result, and `request_hash` equals `sha256` of the canonical `{"task_id": id}`.
  - `who` names only the principal, and `correlation_source == "task_id"`.
- R2 (owner read): the same through a `tasks/get` that settles the task. One record, with the same assertions.
- R3 (gate refusal): a recovered result refused by an output policy settles failed. Its record carries `tenants ∋ h(cust-9)` (raw response), `outcome` ≠ `ok`, the refusal code, and no `response_hash`.
- R4 (screened failure): a recovered peer failure whose screened message names a tenant writes a failure record with the code kept and no `response_hash`.
- R5 (store bound): a recovered result over the record size limit commits as the bounded failure. Its record describes that failure: no `response_hash`, the bound's code.
- R6 (race): worker and owner read on one task produce exactly one settlement record.
- R7 (submission join): the submission record carries the same `task_id`, including when a response gate refused the handle.
- R8 (FailClosed): with a degraded log the task is not settled and no recovered content is stored. It settles on a later attempt once the log recovers.
- R9 (BestEffort): with an unwritable log the task settles with the recovered result, and the failure is logged.
- R10 (regression): a non-task call writes exactly one record, with no `task_id`. A record with `route == "task_recovery"` verifies with `verify_log`.
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
