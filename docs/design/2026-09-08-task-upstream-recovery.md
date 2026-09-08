# I5 — bounded vertical upstream task recovery (as built, 2026-09-08)

Turns the unused `UpstreamRecovery` seam into recovery of a **real** upstream job.
Authoritative behaviour is the r1 supervisor corrections; where the native r1 draft
disagrees, the corrections win, and one point where the **pinned SDK** disagrees with
both is recorded in §6.

## 1. Selection — what may become a recoverable upstream job

Exactly one shape: a **direct configured backend job**.

| outer call | upstream handle | why |
|---|---|---|
| `gateway_invoke` (`{server, tool, arguments}`) | yes | names one backend call |
| a statically surfaced tool | yes | the same single call under another name |
| `gateway_execute`, `gateway_run_playbook` | **no** | several calls, branches and gateway-side state between steps; one peer handle describes at most one step, so presenting the job as recoverable would claim that re-reading that step told us what the program did |

Unsupported shapes take the r3/I3 conservative branch **unchanged**, and capture no
handle at all. The predicate is `MetaMcp::direct_job`.

A selected job is submitted task-augmented only when a trusted adapter *claims* its
backend now: the name is in `tasks.recovery_adapters`, the backend is still configured,
the peer declared the tasks extension in `server/discover`, and the gateway's own
credential is legitimately usable for it (`identity_propagation_config().is_none()`
and `!oauth_requires_per_user_isolation()`). An identity-propagated or per-user-OAuth
backend would need a per-user credential this process does not hold after a restart.
That is a stated prerequisite; no vault and no stored token is proposed.

## 2. Crash classification (unchanged from the corrections)

| durable state | outcome |
|---|---|
| `working`, v≥2, `dispatched == false` | `not_executed` — the only state a record can prove |
| `dispatched`, no handle (sent/response lost) | `unknown` |
| `dispatched`, handle received but not yet persisted | `unknown`; the window is one write wide and stays open |
| `dispatched` + durable handle, still `working` | **managed**: query only, never resubmit |
| `input_required` | the reviewed I3 treatment; no continuation contract is claimed |

No window is closed by replaying the original operation, at any layer.

## 3. Persistence

`RECORD_VERSION = 3` and the loader widening to `1..=3` land in the same increment.
`UPSTREAM_VERSION = 3` is spelled separately, in the `MARKER_VERSION` idiom, so a later
bump cannot reclassify a v3 row that did record its handle. `Record.upstream` is
`#[serde(default, skip_serializing_if = "Option::is_none")]`, so a pre-upstream row is
byte-identical; `deny_unknown_fields` keeps the upgrade one-way, stated not hidden.

The recovery descriptor is `{handle, backend, tool, arguments, operationDigest}`. It
carries the **complete** inner `arguments` because `authorize_invocation` hands exactly
that value to the pluggable `ToolAuthorizer`. It carries **no** transport authorization
header, bearer/JWT, prior signature or fabricated `VerifiedIdentity`. The handle is
bounded at 512 bytes and the whole descriptor counts against `max_record_bytes`; an
oversized descriptor is refused **before** capture, leaving the row `unknown` rather
than authorized later with omitted arguments. `AdmissionRecord.metadata_bytes` is
untouched: the handle is gateway state, not admission input.

`TaskStore::mark_upstream` uses the `mark_dispatched` idiom — same ordering lock, refuse
a moved revision or a terminal row, no `revision` bump. **A row is recoverable only once
its handle is durable.**

## 4. Startup

`open_runtime_with_recovery` is **additive**; `open_runtime_with_admission` delegates to
it with an empty slice, so every existing caller is untouched and the no-adapter
behaviour is unchanged by construction rather than by test. A row is deferred iff it
carries a durable handle whose backend is named in `tasks.recovery_adapters` and is
still a configured backend — the weakest evaluable test, because deferral is **not** a
trust claim. A deferred row is retained as a managed `working` record; **startup issues
no upstream call at all**. Every other interrupted row keeps the exact I3 table.

## 5. The read

`tasks/get` performs the existing owner-scoped lookup first. Foreign or missing identity
gets the existing absence response and **zero** upstream calls. For an owned `working`
row the gateway then:

1. loads the descriptor and checks it still names this record's admitted operation;
2. rebuilds the `RouterAuthorizer` from *this* request's live client/OAuth/mTLS context
   via `OwnedRouterAuthorizer::capture`;
3. runs `check_invocation_policy` on the **original** target with the **current** caller
   — authorizing `tasks/get` alone is explicitly insufficient, and the gateway's own
   upstream credential grants the caller no authority;
4. issues **one** bounded read-only `tasks/get`, serialized per record/revision.

Attestation, when enforcement applies, is a fresh token in the gateway-namespaced field
`_meta["io.mcp-gateway/recovery"].attestation`, mapped into the checker's existing input.
Missing or expired denies **before** the query. Nothing spent is persisted.

Adapter removed, backend untrusted now, revoked owner, or current tool-policy denial ⇒
**zero** queries, not query-then-discard.

Pending/working, transport unavailability and a query timeout all **retain** the handle
and the `working` record, so a later authenticated read makes progress. No automatic
retry of `tools/call`, and no terminal `unknown` merely because the job is still running.

## 6. Pinned-SDK contract, and the one contradiction

Observed against fastmcp 4.0.3 / fastmcp-tasks 4.0.3 / pydocket 0.25.0:

* negotiation: `server/discover` → `capabilities.extensions["io.modelcontextprotocol/tasks"]`;
* submission and every `tasks/*` need the per-request opt-in
  `_meta["io.modelcontextprotocol/clientCapabilities"].extensions[<tasks>]`; without it
  the tool runs synchronously and `tasks/get` answers `-32021`;
* the peer's `CreateTaskResult` is flat: `{"resultType":"task","taskId",…}` with an
  opaque `taskId` that is **never** parsed as a gateway `task-<uuid>`;
* `tasks/get` answers `{status, result|error|inputRequests}`.

**Contradiction with the native draft §2:** `Tool.execution.taskSupport` is *not*
observable at 2026-07-28 — the revision removed the field and the SDK's serializer drops
it. Per-tool task capability therefore cannot be read from `tools/list`, and this
implementation asserts no enum: eligibility is configured trust plus the peer's own
declaration, and the actual reply shape decides whether a job became a task.

## 7. Recovered results

The trait is reduced to `claims(backend)` + `query(handle, deadline)`. It can name
neither a tool nor arguments, so "never resubmit the original operation" is **structural**
— there is no argument through which an implementation could be handed the original call
— and `tasks/cancel` and every other mutation are outside its vocabulary.

A recovered result is **not** taken verbatim. It passes the same output-schema
enforcement and the same response gates a live dispatch applies, from one shared
implementation (`MetaMcp::apply_response_gates`: response contract, anomaly screening,
context integrity). Dispatch *accounting* is deliberately excluded — an idempotency
reservation, a response-cache write, an error budget and predictions belong to the call
that dispatched, and a later read of an already-executed job must not consume or refresh
them. The dispatch half is unreachable from the recovery half.

Settlement is the ordinary revision-checked durable path (`TaskWrite::Recover`), naming
the owner **only** by the persisted `principal_digest`: no second hashing of a stored
digest, no fabricated identity. The read itself then leaves through the router's ordinary
tail — `shape_modern_response` and `finalize_response_for_delivery` with **this**
request's id, nonce and signing context. The creator's signature and nonce are never
reused and no delivery-specific MAC is stored as the recovered result.

## 8. One dispatch path, one declaration, one submission

There is no parallel submission path. The worker arms a task-local slot
(`upstream::UpstreamSubmission`, the idiom `gateway::trace::TRACE_ID` already uses) for
exactly one `(server, tool)`, then takes the ordinary
`dispatch_below_gate_native_result` tail. Every pre-dispatch gate therefore runs
unchanged — kill switch, per-capability cooldown, `_full`/`_claim` stripping,
idempotency, the authorization chokepoint, secret injection, outbound `_meta` — and the
backend leg of `accounted_dispatch` merely takes a different transport entry point. The
raw peer reply is offered to the slot **there**, before projection, the contract gate or
any shaping, so the `CreateTask` envelope is recognised at the one point where nothing
this gateway wrote is in the value. The worker then reads the slot: a handle means the
dispatch's return was a `working` stub rather than an answer, and settling on it would
report a job that has not run as finished.

The opt-in is declared by the **transport**
(`Transport::request_with_task_capability`), not by a marker in `params`: a JSON flag
would be forgeable by anything that can reach the ordinary request path, including
caller-supplied arguments. That method is allow-listed to `tools/call` and `tasks/get`,
refuses a peer not known to be modern, and sends without the session-expiry resubmit.

`Backend::request_with_task_capability` takes that path exactly once. `with_retry`
cannot distinguish a lost response from a request the peer never saw, so a retry would
create a second upstream job this gateway does not hold the handle for. Everything else
— pool slot, failsafe gate, concurrency permit, activity guard, outcome recording — is
unchanged.
