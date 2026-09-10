# ADR-012: The idempotency guard records execution, not admission

- **Status**: Proposed, 2026-09-10
- **Criterion**: MIK-7272.SUB.4 — *a side-effecting call, re-issued after a
  broken stream with a new request id, MUST be protected by an idempotency key
  or the tasks extension*
- **Scope**: what the guard does when a call's outcome is not known. Out of
  scope: the tasks extension as an alternative protection, the key format, and
  cross-process persistence of the cache.

## Context

Three defects share one root cause. The guard tracks whether a call was
*admitted*; the criterion is about whether a side effect *executed*.

`OnDrop` (`src/idempotency.rs:505-511`) has exactly two arms, and the comment on
the first states the invariant the code then fails to enforce:

```rust
/// Nothing has been executed yet — free the key so the call can be retried.
Release,
/// The protected side effect has committed — settle with this result so a
/// retry is served the cached value instead of re-executing.
Complete(Value),
```

`Release` is the constructed default (`:520`). Nothing establishes its
precondition at drop time, so every path that neither completes nor commits
releases the key — including paths that ran after the request left for the
backend.

1. **The direct route releases on failure.** The backend-error exit at
   `router/backend_handlers.rs:862-867` never calls `settle_direct_idempotency`,
   so the reservation drops into `OnDrop::Release` and the key is removed
   (`src/idempotency.rs:562-571`). `settle_direct_idempotency` (`:937-947`)
   likewise completes only when `response.error.is_none()`. A transport failure
   *after* the backend performed the side effect is indistinguishable from one
   before it, and the retry is handed a clean key.

2. **The transport retries beneath the guard.** `src/backend/ops.rs:218` wraps
   the caller's `tools/call` in `with_retry`, and `is_retryable`
   (`src/failsafe/retry.rs:96-101`) retries on
   `Transport | BackendTimeout | Http | Io` — precisely the class where the
   backend may already have executed. Retry is on by default with three attempts
   (`src/config/features/failsafe.rs:15,65`). One admitted call can therefore
   execute three times inside a single reservation the guard still considers
   in-flight, with no client retry involved at all.

3. **A stale reservation admits a second execution.** `decide_check_plan` maps
   `StaleInFlight` to `(CheckPlan::Proceed, evict)` (`src/idempotency.rs:186-189`),
   staleness being `started.elapsed() > IN_FLIGHT_TIMEOUT` (`:84`) with the
   timeout at five minutes (`:50`). A call still running at five minutes, plus a
   retry, gives two live executions on one key.

## Decision

**A reservation has three terminal outcomes, not two, and only one of them
releases the key.**

| Outcome | Meaning | Key |
|---|---|---|
| `Complete(result)` | the side effect committed and its result is known | settled; retries served the cached result |
| `Release` | the request never left for the backend | freed; a retry is a first attempt |
| `Failed(error)` | the request was dispatched and its outcome is not known | settled as a terminal error; retries served that error |

`Release` becomes reachable only before dispatch. The reservation is marked
dispatched at the point the request bytes are handed to the backend transport;
after that mark, a drop that is neither completed nor committed settles as
`Failed`, carrying the error the caller would otherwise have seen.

Three consequences follow, one per defect:

1. The direct route's error exit settles rather than releases. A JSON-RPC error
   from a dispatched call is a terminal outcome, not an absence of one.
2. **A side-effecting `tools/call` is not retried by the transport.** Automatic
   retry is confined to calls the backend annotates `readOnlyHint` or
   `idempotentHint`, and to failures provably raised before dispatch (connection
   establishment). Retrying an unannotated mutation is a duplicate the guard
   cannot see, so the guard cannot be the place it is fixed.
3. A stale in-flight entry never becomes a second admission. `StaleInFlight`
   yields `CheckPlan::InFlight` — the retry is told the call is still running.
   The timeout keeps its memory-reclamation role for entries whose owner is
   gone, which is the only case it was introduced for.

## Consequences

**What the client sees.** A retry after an uncertain failure gets the recorded
error immediately, not a fresh execution and not a hang. The outcome cannot be
determined and the client is told so, which is the honest answer and the one the
criterion demands: the mutation cannot land twice under the same key.

**The cost, stated plainly.** A backend blip that never reached the tool now
settles the key as failed for `COMPLETED_TTL` when the failure cannot be proven
pre-dispatch. The affected caller cannot retry *that key*. It can retry with a
new key, which is the client explicitly accepting a possible duplicate — the
right party to make that trade, and the only one who knows whether the operation
is safe to repeat.

**Rejected: release on failure** (today's behaviour). It never wedges a key and
it is why the current code is shaped this way, but it converts every uncertain
failure into a licence to re-execute. That is the defect, not a tradeoff.

**Rejected: push the client's key to the backend and let it dedupe.** Backends
are under no obligation to honour an idempotency key, so this makes protection
contingent on the least trustworthy party in the chain. Worth doing as defence
in depth; not admissible as the mechanism.

## Acceptance

One test per defect, each failing against the current tree:

- a dispatched direct-route call that returns a backend error keeps its key, and
  the retry is served that error rather than reaching the backend a second time;
- a pre-dispatch failure (backend unreachable) releases its key, and the retry
  is a first attempt;
- an unannotated `tools/call` failing with `BackendTimeout` reaches the backend
  exactly once, while a `readOnlyHint` call still retries;
- a second caller arriving on a key whose reservation passed `IN_FLIGHT_TIMEOUT`
  while its owner is alive is told in-flight, not admitted.
