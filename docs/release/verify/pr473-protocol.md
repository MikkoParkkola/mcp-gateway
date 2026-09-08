# PR #473 shard review — `src/protocol/`

Pinned revision: `BASE=c3626cf8`, `HEAD=60b138bb10a869703254eae2fe500f055d96f8d7`.
Payload built from the pinned SHAs, never the worktree.

## Payload

    git diff c3626cf8 60b138bb -- src/protocol/

- sha256 `ea3ba4835ed11f4132e1d1dc87c511246eefcf5dad8e03312c74d3d07ab40e21`
- 215,675 bytes, 16 files, +4,861 / -11

Over the ~150KB single-review ceiling, so it was split at file boundaries and
each half reviewed separately.

| half | sha256 | bytes | files |
|---|---|---|---|
| A | `18c70bfafd997d793d14b055975baa5410ac7da64aff259904018aff4834f952` | 110,211 | cacheable.rs, continuation.rs, era.rs, extensions.rs, headers.rs, messages.rs |
| B | `a36157cdb6b46e6b743cc5c8bdcca32342d8e8b79d5f9edd909c0ea274ff95ee` | 105,464 | meta.rs, mod.rs, mrtr.rs, negotiate.rs, param_headers.rs, subscriptions.rs, task_store.rs, tasks.rs, trace.rs, types.rs |

## Ledger rows

| half | vendor | ts | verdict | material_sha256 | material_bytes | process_status |
|---|---|---|---|---|---|---|
| A | gpt | 2026-09-08T16:25:27Z | SHIP-WITH-FIXES | `93e2f6f81ec0980be583a86a2a903ca57da2a053313d4d88c9366d36659994f6` | 110,212 | ok |
| B | gpt | 2026-09-08T16:29:17Z | SHIP-WITH-FIXES | `3bc5f9b5c4e76d029de92fa3b656648b75e764e282ffb20e6dc677f73bf71ea3` | 105,465 | ok |
| A | grok | 2026-09-08T16:33:29Z | SHIP | `93e2f6f81ec0980be583a86a2a903ca57da2a053313d4d88c9366d36659994f6` | 110,212 | ok |
| B | grok | — | STILL RUNNING at time of writing | — | — | — |

Binding, stated because it is not the identity the brief assumes: the ledger's
`material_sha256` is not the payload sha256. The wrapper digests one NUL byte
followed by the stdin file, so each row's `material_bytes` is the half's byte
count plus one. Recomputing the digest the same way

    { printf '\0'; cat pA.diff; } | shasum -a 256

reproduces every `material_sha256` in the table exactly, for both vendors, and
that is what binds each row to what was read. Byte counts and completion
timestamps agree independently.

The four rows visible in the ledgers at 16:15–16:19Z belong to peer sessions
reviewing other shards and are not claimed here.

## Coverage limits

- The grok leg returned for half A only; half B was still running when this
  report was written. The dual-vendor gate is therefore satisfied for half A and
  NOT satisfied for half B. Grok's half-A verdict is SHIP, and it raised one
  HIGH finding that is A1 below, reached independently — the two vendors agree on
  the leaked in-flight slot without agreeing on the verdict. Its five
  improvements overlap the gpt leg on the stale comment at
  `src/protocol/continuation.rs:337-338` and add three the gpt leg did not:
  fold the mint into `begin_exchange` so hold and seal are one operation
  (`continuation.rs:883`); derive the advertised cacheable-method list from
  `assessed_methods()` rather than the second copy in `CACHEABLE_METHODS`
  (`src/gateway/router/handlers.rs:1641`); and drop the shadow `CacheScope` in
  `src/protocol_revision_telemetry.rs:115` in favour of the protocol one. None
  claims a defect.
- The worktree is dirty in this shard (`M src/protocol/extensions.rs`,
  `M src/protocol/trace.rs`). The grok run's own trace records that "the working
  tree doesn't match the review diff" and that it went to the repository, so a
  filesystem-reading reviewer read partly uncommitted content rather than the
  pinned payload. Every source citation below for those two files was taken from
  `git show 60b138bb:<path>`, not the working tree.
- No build, test run, or CI check was performed; all verdicts are source
  inspection at the pinned revision.
- Spec-conformance halves of findings are marked CANNOT-VERIFY where the
  deciding authority is an external specification that was not fetched.

## The two claims the shard was asked to settle

### CLAIM-1 — malformed `inputRequests` bypasses continuation minting and lets the backend's own `requestState` reach the client — CONFIRMED

Deciding chain, all at the pinned revision:

- `src/protocol/mrtr.rs:244` — `Some(_) => return None,` in the match on
  `result.get("inputRequests")`. A present-but-non-array `inputRequests` makes
  `InputRequired::from_result` answer `None`, the same answer a completed result
  gives.
- `src/gateway/meta_mcp/invoke.rs:1513` — the interim determination is that
  `None`.
- `src/gateway/meta_mcp/invoke.rs:1585` — the whole rewrite is inside
  `if let Some(interim) = interim {`, so it is skipped.
- `src/gateway/meta_mcp/invoke.rs:1602` — `result["requestState"] = json!(envelope);`
  is the ONLY place the backend's `requestState` is overwritten. Skipped, the
  backend's own value survives.
- `src/gateway/meta_mcp/invoke.rs:1762` then `:2072` — `apply_context_integrity`
  returns the value unchanged on the allow path
  (`findings.is_empty() && … == ContextIntegrityDecisionKind::Allow`).
- `src/gateway/meta_mcp/invoke.rs:1915-1916` — `final_result` is
  `augment_with_trace(augment_with_predictions(result, …), …)`; :1924 stamps
  provenance and :1933 signs. All additive; nothing strips a top-level key.
- `src/gateway/meta_mcp/invoke.rs:1939` — `Ok(GuardedValue::sealed_by_guard(final_result))`
  delivers it.

Violates the invariant this code names for itself at
`src/gateway/meta_mcp/invoke.rs:1573-1576`: "MRTR.2: the backend's own
`requestState` never reaches the client."

The one mitigation in the file does not cover this. `context_integrity_delivered_result`
does drop `requestState` (`invoke.rs:2215-2218`), but only when
`evaluation.policy.enforcement_applied` — the enforcement path, not the ordinary
allow path.

Blast radius is bounded on one axis: `stopped_to_ask` / `claims_input_required`
(`invoke.rs:1517`) still treats the result as interim for idempotency and cache
purposes, so the exchange is not committed and the response is not cached. What
escapes is opaque backend state, not a double side effect.

Reachability: needs a backend that answers with `inputRequests` set to a
non-array while carrying a `requestState`. That is a nonconforming backend, and
the gateway's trust boundary treats backends as untrusted.

Severity: HIGH, security and correctness — unauthenticated backend state reaches
the client and the named MRTR.2 invariant does not hold. Recommended as a 4.0.0
blocker; the operator decides. Independently reported by the half-B reviewer at
the same line.

### CLAIM-2 — a present non-string `requestState` silently becomes absent, so a continuation cannot restore backend state — CONFIRMED

- `src/protocol/mrtr.rs:246-249` —
  `result.get("requestState").and_then(Value::as_str).map(str::to_string)`.
  `as_str` on a number, object, array or bool yields `None`. No error, no log,
  no distinction from absence.
- `src/protocol/mrtr.rs:259` — `if requests.is_empty() && request_state.is_none() { return None; }`
  does not catch it: with a non-empty `inputRequests` the guard's first
  conjunct is false, and an `InputRequired` is built with `request_state: None`.
- `src/gateway/meta_mcp/invoke.rs:1586-1594` — `mint_continuation(…, interim.request_state)`
  receives `None`, so the continuation is minted carrying no backend state and
  the retry cannot restore it.

The file argues this distinction elsewhere in its own words: `mrtr.rs:229-238`
holds that absence and malformed presence are different backend faults, for
`inputRequests`. Line 248 collapses exactly that distinction for `requestState`.

Severity: MEDIUM, silent data loss — the exchange becomes unresumable and
nothing reports why. Not recommended as a release blocker.

## Reviewer findings — half A (gpt, SHIP-WITH-FIXES)

Four defects and three improvements. Improvements are not defects and are listed
without a verdict.

### A1 — a failed continuation mint leaks the in-flight slot the hold took — CONFIRMED

- `src/gateway/meta_mcp/invoke.rs:386` — `begin_exchange(...)` takes the slot.
- `src/protocol/continuation.rs:883-903` — `begin_exchange` calls
  `in_flight.hold(...)` at :891, then mints the payload. Hold first is deliberate
  (MRTR.8).
- `src/gateway/meta_mcp/invoke.rs:405-412` — the `Err(error)` arm of
  `keyring().mint(&payload)` logs, records the reason, and returns `None`. It
  does not release the hold.
- `src/protocol/continuation.rs` exposes `hold` (:709) and no release, so the
  slot is held until `expiry_for` (:136-138, `CONTINUATION_LIFETIME_SECS`) and
  only the reaper closes it.

Reachable through backend-controlled input: an oversized backend `requestState`
exceeding `MAX_ENVELOPE_LEN` fails the mint. Repeating it walks the table to
`IN_FLIGHT_CAPACITY`, and every caller is then refused a continuation for the
lifetime window.

Severity: HIGH, availability. Recommended as a 4.0.0 blocker — a remote,
input-driven denial of the continuation surface. This is the one finding both
vendors reached independently: grok's half-A leg raised it at
`src/gateway/meta_mcp/invoke.rs:399` as HIGH/POSSIBLE while still voting SHIP,
on the ground that it sits on oversized backend state rather than the happy path.
Its suggested repair is wider than the leak — bound the payload before the hold
and the seal, as well as releasing the hold on a failed mint.

### A2 — the advertised tasks extension answers with a non-conforming task object — CONFIRMED in part, KNOWN

- Missing required timestamps: CONFIRMED as fact and DOCUMENTED AS INTENDED.
  `src/protocol/tasks.rs:42-50` carries no `createdAt` / `lastUpdatedAt`;
  `src/gateway/router/handlers.rs:209-222` emits only `resultType`, `taskId`,
  `status`, `ttlMs`. The pinned `src/protocol/extensions.rs:64-69` states the
  model "is knowingly short of the extension specification for 4.0.0 … the
  intended 4.0.0 state, not an oversight", with MIK-7311 completing it.
- `resultType: "task"` on polls as well as creation: CONFIRMED at
  `src/gateway/router/handlers.rs:204-212` — one `task_view` producer, used by
  the `tools/call` handle and by every `tasks/get`. Whether the extension
  reserves that discriminator for creation is CANNOT-VERIFY: the deciding text
  is the 2026-07-28 tasks extension, which was not fetched.
- Cancellation reported as `failed`: CONFIRMED at `src/protocol/tasks.rs:33-40`
  — `TaskStatus` is `Working | Completed | Failed` with no `Cancelled`, and
  `handlers.rs:216` maps `Failed` to `"failed"`. A cancelled task is
  indistinguishable on the wire from a failed one.

Severity: MEDIUM, interoperability, with the decision to advertise while short
already recorded at the pinned revision. Does not block on its own.

### A3 — `cached_now` answers `None` under ordinary lock contention, and the caller reads `None` as legacy — CONFIRMED

- `src/protocol/era.rs:178-180` — `try_lock().ok()?`, so a held lock yields `None`.
- `src/transport/http/mod.rs:578-586` — `outbound_era` maps that to `None`, and
  its own comment states "`None` means legacy".
- The rationale at `era.rs:168-177` — a held lock means a probe is in flight —
  does not hold: `cached` (:183), `observation` (:192) and `invalidate` (:213)
  take the same lock, so an operator read or an awaiting reader can make an
  established Modern determination read as undetermined.

The window is a short critical section, so the reviewer's `POSSIBLE` is right.
Whether an intermittently legacy-formatted request then fails against a modern
backend is CANNOT-VERIFY — that turns on backend tolerance, not on this diff.

Severity: MEDIUM, intermittent and self-clearing. Does not block.

### A4 — elicitation params cannot carry an elicitation identifier — CONFIRMED in part

`ElicitationCreateParams` at `src/protocol/messages.rs:491-507` declares `mode`,
`message`, `requestedSchema` and `url` and nothing else, and
`src/gateway/router/helpers.rs:171` parses the params with
`serde_json::from_value`, which drops keys the struct does not name. The token
`elicitationId` appears nowhere under `src/`. So the type cannot carry one:
CONFIRMED.

What the reviewer inferred from that — that a live URL-mode elicitation loses an
identifier a backend sent — is CANNOT-VERIFY here. The forwarding chain was not
traced end to end and the 2025-11-25 elicitation text was not fetched, so
whether any real producer sets the field is not established. The only in-repo
producer, `src/gateway/meta_mcp/destructive_confirmation.rs:298-299`, sets
`mode` and `message` only.

Severity: MEDIUM if a forwarding path does drop it, LOW otherwise. Does not block.

### Improvements — no defect claimed

- `src/protocol/continuation.rs:749` — the in-flight scan walks every entry even
  when no deadline can have expired; a cheap earliest-deadline check would skip it.
- `src/protocol/extensions.rs:31` — the extension identifier is spelled twice, in
  `Extension::id` and `Extension::from_id`, so a new extension can be added to one
  and not the other.
- `src/protocol/continuation.rs:338` — the comment narrates the history of a past
  review rather than stating the contract that now holds.

## Reviewer findings — half B (gpt, SHIP-WITH-FIXES)

### B1 — a task-augmented `tools/call` returns a working handle and never runs the tool — CONFIRMED

`src/gateway/router/handlers.rs:1194-1206`: when the request carries a `task`
member, the handler creates a task record and returns the `task_view` handle
immediately. There is no invoke, no spawn, no queue. The only other caller of
`tasks.update` is the cancellation path at `handlers.rs:1561`, so nothing ever
moves a record out of `Working`.

A client that opts into the tasks extension therefore receives a handle for work
that was never started and polls it until it gives up. The tool does not run at
all — this is not a latency or ordering defect.

Severity: HIGH, correctness. The extension is advertised unconditionally to a
2026 peer by `gateway_declares` (`src/protocol/extensions.rs:71-75`), and the
disclosure above it (`:64-69`) speaks only to the task object's shape —
`input_required` and the timestamps, with MIK-7311 named — never to a task that
does not execute. Recommended as a release blocker; it is ordered after A1
because A1 also denies service to callers who never opted in.

### B2 — duplicate of CLAIM-1 — CONFIRMED

Independent corroboration of `src/protocol/mrtr.rs:244` from the other half of
the payload. Counted once.

### B3 — task records accumulate without bound — CONFIRMED

`src/protocol/task_store.rs:41` holds `records: Mutex<HashMap<String, Record>>`.
The store's whole surface is `new` (:39), `create` (:48, a plain insert), `get`
(:71), `owns_all` (:85) and `update` (:95). No capacity, no expiry, no removal;
cancellation rewrites the record and keeps it. Combined with B1, every
task-augmented call adds a record that nothing ever removes.

Severity: HIGH, availability. Memory grows with the number of calls an
authenticated caller makes.

### B4 — mirrored string arguments bypass the encoding the gateway requires elsewhere — CONFIRMED

Two codecs in the same repository disagree, which needs no external spec to
settle:

- `src/gateway/meta_mcp/param_headers.rs:210-212` returns a string argument raw
  whenever it contains no control character.
- `src/gateway/meta_mcp/headers.rs:118-126` (`encode_header_value`) base64-wraps
  anything that is not non-empty, sentinel-free and entirely `0x21..=0x7e`.

So a value with a space, a non-ASCII character, leading or trailing padding, or
one that literally begins with the sentinel prefix goes out unwrapped through the
mirror path and disagrees with the gateway's own decoder.

Severity: MEDIUM, correctness at a boundary.

### B5 — schema traversal reaches only the top level — CONFIRMED mechanism

`src/gateway/meta_mcp/param_headers.rs:170-172` walks
`input_schema["properties"]` and nothing else — no recursion into nested object
properties, array items or `$defs`. Whether the specification permits a mirrored
parameter to be declared nested is CANNOT-VERIFY: the deciding text was not
fetched. If it does, nested declarations are silently ignored.

Severity: MEDIUM.

### B6 — integer checks reject valid JSON numbers — CONFIRMED in part

- `is_safe_integer` at `param_headers.rs:143-150` tests `as_i64`, and
  `bounds_are_safe` at :114-116 applies it only when `type == "integer"`. A
  fractional bound such as `minimum: 0.5` on an integer parameter therefore
  yields `MirrorViolation::IntegerOutOfRange` and the tool is excluded. Such a
  schema is unusual, so materiality is LOW.
- `header_value_for` at :213-218 uses `number.as_i64()?`, so a runtime argument
  arriving as `42.0` — which JSON permits for an integer-typed field — is not
  mirrored at all. CONFIRMED, MEDIUM.

### B7 — a `traceparent` with trailing fields is accepted — CONFIRMED mechanism

`src/protocol/trace.rs:49-54` splits on `-` and validates the first four fields
without checking the field count; the comment at :44-48 asserts the
specification allows ignoring extra fields. Whether W3C permits that for version
`00` specifically is CANNOT-VERIFY — the specification was not fetched.

Severity: LOW.

### B8 — `tracestate` values containing a horizontal tab are dropped — CONFIRMED

`src/protocol/trace.rs:93-94` accepts only bytes `0x20..=0x7e`, which rejects
`0x09`. The module's own comment at :85-92 states it "cannot reject a value
either spec calls valid", so the code contradicts its stated intent regardless of
which specification is consulted.

Severity: LOW.

## Tally

- CONFIRMED (in whole or in part): 12 — CLAIM-1, CLAIM-2, A1, A2, A3, B1, B3,
  B4, B5, B6, B7, B8. B2 duplicates CLAIM-1 and is not counted again.
- CANNOT-VERIFY halves: 5 — A2's `resultType` question, A3's downstream impact,
  A4's live forwarding path, B5's nested-declaration question, B7's W3C
  strictness for version `00`. Each needs a specification fetch or a traced live
  path that this shard did not perform.
- DEAD: 0. Unusually, every finding survived inspection; the customary quarter
  that dies did not appear in this payload.
- Improvements carrying no defect claim: 3.

Recommended as 4.0.0 blockers, in order:

1. `src/protocol/mrtr.rs:244` with `src/gateway/meta_mcp/invoke.rs:1585`, `:1602`
   and `:1939` — CLAIM-1.
2. `src/gateway/meta_mcp/invoke.rs:405-412` with
   `src/protocol/continuation.rs:891` — A1, the leaked in-flight slot.
3. `src/gateway/router/handlers.rs:1194-1206` — B1, a task-augmented call that
   returns a resolvable handle and never dispatches the tool. The extension is
   advertised through `gateway_declares` (`src/protocol/extensions.rs:71-75`),
   and the disclosure at `:64-69` covers only the shape of the task object —
   `input_required` and the timestamp fields, with MIK-7311 to complete the
   model. Nothing there states that a task never executes, so this is an
   undisclosed correctness defect rather than a documented gap.
