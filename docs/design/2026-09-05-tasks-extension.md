# Design — `io.modelcontextprotocol/tasks` conformance (MIK-7311 / TASK.1)

Status: proposed. Target: mcp-gateway 4.0.0. Author: Claude Opus 5.

## §P0 SCOPE

FOR: make `src/protocol/tasks.rs` and `src/protocol/extensions.rs` conform to the
tasks extension as specified, so `ExtensionSet::gateway_declares()` can be wired
to a real implementation instead of being held back by a shape gap.

OUT (each a separate change, not this one):
- the transport-level `subscriptions/listen` task-notification stream
- Streamable HTTP routing headers for tasks
- MRTR (`inputRequests` / `inputResponses`) payload shapes — modelled as opaque
  JSON here, borrowed from `src/protocol/mrtr.rs` when that lands
- task persistence, TTL sweeping, and the actual executor that runs a tool call
  in the background
- wiring `gateway_declares()` into the initialize/`server/discover` response

## Sources (V — two independent artifacts)

1. Prose spec, `specification/2026-07-28/tasks.md`, from the extension's own
   site `https://tasks.extensions.modelcontextprotocol.io/`.
2. TypeScript schema, `schema/2026-07-28/schema.ts`, in the backing repository.

Both agree on every shape below. SEP-2663 is **Final**. Local copies of both are
in this session's scratchpad; the citations here are to the repository paths.

?unk (I, one observation): the `draft` and `2026-07-28` copies of both files
hash differently. This design targets **2026-07-28**, the revision the gateway's
protocol module already names. Nothing here depends on `draft`.

## The problem

`src/protocol/tasks.rs` models a task with three statuses (`Working`,
`Completed`, `Failed`), an opaque `String` error, and no timestamps. The
specification requires five statuses, four more fields (two of them required),
and a JSON-RPC error *object* rather than a string. `extensions.rs:51-69` already
says so in a doc comment and deliberately leaves `gateway_declares()` uncalled
because of it. This change closes that gap.

## Decisions

### D1 — `resultType` on `tasks/get` is `"complete"`, not `"task"`

The prose spec contradicts itself: its normative line says a `GetTaskResult`
**MUST** carry `resultType: "complete"`, while its Error Handling examples show
`"resultType": "task"` on `tasks/get` responses. The schema settles it —
`schema.ts:214-224` declares `GetTaskResult.resultType: "complete"` with the
comment "The resultType field MUST be set to `"complete"`". A normative MUST in
the machine-readable schema beats an illustrative example in prose. `"task"` is
reserved for `CreateTaskResult` alone.

Recorded as an upstream defect to report, not a local workaround.

### D2 — five statuses, modelled as an enum with the payload inlined

The specification defines five statuses and pairs each with exactly one payload
field: `input_required` carries `inputRequests`, `completed` carries `result`,
`failed` carries `error`, and `working` and `cancelled` carry none. Rust's enum
carries the payload in the variant, so an impossible combination — a `cancelled`
task holding a result, a `completed` task with no result — cannot be constructed
at all. The alternative, five bare variants beside five `Option` fields, needs a
validator to say what the type could have said itself.

### D3 — `failed` means a JSON-RPC error, and nothing else

"The `failed` status **MUST NOT** be used to represent non-JSON-RPC errors, such
as a tool result that completed with `isError: true`." A tool that ran and
reported failure is `completed`, with the failure inside `result`. This is the
one rule most likely to be got wrong by a gateway that already has an internal
notion of "the call went badly", so the type enforces it: the `failed` variant
holds a JSON-RPC error object, and there is no way to reach it from a tool
result.

### D4 — settled tasks stay settled, and `cancelled` is not exempt

The existing `complete`/`fail` methods already refuse to overwrite a settled
task. Cancellation does not change that: the spec makes cancellation cooperative
and explicitly allows a task to reach a terminal status other than `cancelled`
when the work finished first. So a cancel request on a settled task is
acknowledged and ignored, never a retroactive status change.

### D5 — `ttlMs` is `Option<u64>`, and `None` means unlimited

`ttlMs: number | null` is a *required* field whose null is meaningful. Serialised
as `Option<u64>` with no `skip_serializing_if`, so `None` emits `"ttlMs": null`
rather than dropping the key. Dropping it would omit a required field.

### D6 — the capability is read per request, not once at initialize

"A server **MUST NOT** return `CreateTaskResult` to a client that did not
include the extension capability on its request, regardless of prior
declarations." The client re-declares inside each request's `_meta` under
`io.modelcontextprotocol/clientCapabilities`. `ExtensionSet::from_capabilities`
already parses that object shape and is reused unchanged; what this change adds
is reading it from `params._meta` rather than from a stored session capability.

A stored declaration is not merely redundant here — honouring one would violate
the MUST NOT above. There is no per-session task capability state, on purpose.

### D7 — `-32021` is a new error code the gateway must be able to emit

Three places require it: a non-declaring client issuing `tasks/get`,
`tasks/update` or `tasks/cancel` (MUST), a non-declaring client requesting task
notifications on `subscriptions/listen` (MUST, out of scope here), and a server
that cannot service a request without returning a `CreateTaskResult` (MUST). The
error carries `data.requiredCapabilities.extensions["io.modelcontextprotocol/tasks"] = {}`.

## Open questions — scheduled, per §P1

| # | question | form | status |
|---|---|---|---|
| U1 | does `tasks/get` carry `resultType: "task"` or `"complete"`? | checkable | **resolved** — `schema.ts:214-224` says `"complete"`; see D1. Changed the result type's serialisation. |
| U2 | is the extension spec at a dated revision or only `draft`? | checkable | **resolved** — both exist; `2026-07-28` chosen. Changed which file is cited as authority. |
| U3 | are `draft` and `2026-07-28` identical? | checkable | **resolved** — no, they hash differently. Changed nothing: this design targets the dated revision and reads `draft` not at all. |
| U4 | what shape are `inputRequests` / `inputResponses`? | checkable | **deferred** — see below. |

### U4, deferred

- **owner**: this ticket, MIK-7311, in the change that lands MRTR.
- **what would resolve it**: read the MRTR utility spec at
  `https://modelcontextprotocol.io/specification/2026-07-28/basic/utilities/mrtr`
  and compare against `src/protocol/mrtr.rs`, which already exists in this tree.
- **when**: before any code constructs an `input_required` task. Nothing in this
  change does — the variant is defined and never produced.
- **if it resolves badly** (the shapes are not what `mrtr.rs` models): the
  `InputRequired` variant's payload type changes from opaque JSON to the MRTR
  type. Nothing else moves, because no other variant references it.

Per §P1, the deferral blocks anything depending on it: this change defines the
`input_required` variant so the status enum is complete and round-trips, and
implements no path that emits one.

## What is NOT deferred and might look like it

The five statuses, the timestamps, `ttlMs`, `pollIntervalMs`, the JSON-RPC error
object, and the `"complete"` vs `"task"` discriminator are all settled above.
None of them waits on MRTR.

## Test plan

Separate document, per §P2: `docs/design/2026-09-05-tasks-extension-test-plan.md`.
One row per acceptance criterion, written before any test code.
