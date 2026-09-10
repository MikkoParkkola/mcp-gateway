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
| `Failed(error)` | the request was dispatched and the backend has not said whether it acted | settled as a terminal error; retries served that error |

The discriminator is not "did the request leave" but "did the backend say it
acted". Three cases, in order:

1. **The request never left.** Release. A retry is a first attempt.
2. **The backend answered that it did not act.** Release. A well-formed
   `input_required` interim is the backend stopping to ask a question, not a
   side effect. Route 1 already implements exactly this rule and says why
   (`meta_mcp/invoke.rs:1676-1695`), and `mark_completed` refuses a non-final
   result for the same reason (`src/idempotency.rs:531-539`). This ADR does not
   disturb it; a rule phrased purely as "release only before dispatch" would,
   and would wedge the key of a call that asked a question and got an answer.
   It also carries MIK-7212.MRTR.10b, which forbids caching an `InputRequired`
   result as completed.
3. **Anything else after dispatch.** `Failed`, carrying the error the caller
   would otherwise have seen. This is the case the guard has no arm for today.

### The `Failed` state, enumerated

`Failed` is a terminal alongside `Completed`, not a variant of in-flight, and
every place that spells out the state machine gains an arm: a live and an
expired `CacheEntryStatus`, a `CheckPlan`, and an `AdmitOutcome` carrying the
error. It ages out on `COMPLETED_TTL` under the same expiry rule as `Completed`,
so a failed key is never reclaimed by the in-flight path being changed below.
The served value keeps its JSON-RPC error envelope and adopts the retry's
request id, exactly as a served `Completed` does; a dispatched call cancelled
before any backend answer settles with a defined outcome-not-established error
rather than an absence.

Three consequences follow, one per defect:

1. The direct route's error exit settles rather than releases. A JSON-RPC error
   from a dispatched call is a terminal outcome, not an absence of one.
2. **A side-effecting `tools/call` is not resent below the guard.** Automatic
   resending is confined to calls the backend annotates `readOnlyHint` or
   `idempotentHint`, and to failures provably raised before dispatch (connection
   establishment). Retrying an unannotated mutation is a duplicate the guard
   cannot see, so the guard cannot be the place it is fixed. Retryability is
   decided at the invoke layer, where the tool's metadata is already resolved,
   and passed down as a flag; the transport does not acquire a dependency on the
   tool registry and does not look an annotation up per attempt. There are two
   resend sites, not one: `with_retry` at `src/backend/ops.rs:218`, and HTTP
   session recovery at `src/transport/http/mod.rs:1400-1410`, which re-runs
   `initialize()` and resends the same request outside `with_retry` entirely.
   Both take the flag.
3. A stale in-flight entry never becomes a second admission, and is never swept
   while its call is still running. Two changes, because either alone leaves the
   defect: `decide_check_plan` maps `StaleInFlight` to `CheckPlan::InFlight`, so
   the retry is told the call is still running; and staleness itself becomes a
   liveness question rather than a clock reading. The entry holds a weak handle
   to its `IdempotencyReservation`, and `is_expired` reports an in-flight entry
   stale only once that handle is dead. `evict_expired` (`src/idempotency.rs:398`)
   sweeps on the same predicate, so a call running past the timeout keeps its
   entry through the background cleanup as well as through admission. The
   timeout then does what it was introduced for — reclaiming entries whose owner
   is gone — and nothing else.

## Amendments from review (2026-09-10)

Two defects in the mechanism above, both raised by independent review and both
verified at source. Neither changes the decision; both change how it must be
built, which is why they are recorded here rather than discovered in code.

**A1 — a hint that was guessed is indistinguishable from one the backend
declared.** Consequence 2 says automatic resending is confined to calls the
backend annotates `readOnlyHint` or `idempotentHint`. That is unimplementable
against resolved metadata. `src/backend/annotations.rs:17` writes the inferred
value back into the same field as a declared one:

```rust
let read_only = annotations.read_only_hint.unwrap_or(inferred_read_only);
annotations.read_only_hint = Some(read_only);
```

and `idempotent_hint` is filled the same way from `infer_idempotent_tool`
(`:24-27`), which reads the tool's *name* (`:70`, `:95-98`). An unannotated
mutation whose name happens to match — `get_and_increment` against the
`get` prefix — resolves to read-only and stays retry-eligible, which is exactly
the duplicate the criterion forbids.

The flag must therefore be derived from *explicit* backend annotations, captured
before normalization overwrites them, and only an explicit `true` grants
resend permission. Absent, false, and inferred all mean no resend. Acceptance
gains: an unannotated tool with a read-only-looking name is not resent.

**A2 — a weak handle is dead before the value it points at has settled.** The
liveness rule in consequence 3 has the reservation's cache entry hold a weak
handle, reporting the entry stale once that handle is dead. `Arc` decrements the
strong count to zero *before* running the inner value's `Drop`. So there is a
window in which `Weak::upgrade` already returns `None` while the reservation's
`Drop` is still storing `Failed`. A concurrent `evict_expired` sweep landing in
that window removes the entry, and the next caller is admitted fresh against a
key whose mutation may have committed — the defect this ADR exists to close,
reintroduced by its own fix.

Liveness must therefore be a token held strongly from before the admission is
published until settlement has finished, not the reservation's own refcount.
Acceptance gains: a sweep run while a reservation's settlement is in progress
does not evict its entry.

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
  while its owner is alive is told in-flight, not admitted — and the same entry
  survives an explicit `evict_expired` sweep, which is a separate assertion
  because the sweep does not consult `decide_check_plan`;
- a dispatched call answered with a well-formed `input_required` interim
  releases its key, and the client's answer under the same key reaches the
  backend rather than being served a cached sentence;
- a backend session expiry does not resend an unannotated `tools/call` through
  the HTTP recovery path, while an annotated read-only call still recovers;
- a retry served a `Failed` terminal receives a JSON-RPC error envelope carrying
  its own request id, not the original's.
