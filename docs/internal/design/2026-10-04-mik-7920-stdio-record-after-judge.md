# MIK-7920: the stdio delivery record follows the read judge

Ticket: MIK-7920. Closes gap 1 of MIK-7407.RESPONSE.5 (PR #2919 row note). Base:
`docs/ranking-1-release-line` at `9914d8b50`.

## Problem

The `response_delivery_attempt` event has to describe the frame the client receives. On stdio
it describes the frame from before the cross-tenant read judge ran:

1. `dispatch_relay_scoped` (`src/gateway/server/mod.rs:3037`) calls
   `finalize_response_for_delivery`. That writes the event (`response_security.rs:206` →
   `delivery_record.rs:57`) over the finalized answer, then calls `complete_delivery` (`:3058`).
2. The answer comes back as a JSON value. `judge_and_commit` (`:2650`, `:2836`; batch items
   `stdio_notify.rs:124`) passes it to `StdioReads::answer` (`outbound/stdio.rs:99`). Under
   `cross_tenant_reads: block` that judge replaces the answer with a refusal. It also writes a
   second, standalone `tenant_read` record (`outbound/audit.rs:254`).

So for a refused read, the recorded `response_hash` belongs to a result the client never
received, and the frame the client did receive (the refusal) has no delivery record. The two HTTP
routes already record after the judge, in one merged record (MIK-7799):

- `POST /mcp`: `handlers.rs:1957` → `judged_answer::record_delivery` (`router/judged_answer.rs:17`)
- `POST /mcp/{name}`: `direct_audit.rs:199` (#2924)

## Decision

Stdio follows the `POST /mcp` order: `finalize_content` → judge → `judged_answer::record_delivery`
→ `complete_delivery` → relay-receipt commit. It reuses the meta route's helper, so this adds no
third record variant.

### What moves

1. **`dispatch_relay_scoped` stops recording.** It calls `finalize_content`, the content half
   of `finalize_response_for_delivery`, unchanged. It now returns `Option<StdioAnswer>` instead
   of `Option<Value>`.
   - `None` is still a notification with no response due (`:2910`, the serve loop's `None`
     arm).
   - `StdioAnswer::Built(Value)` covers the early returns: a signing envelope error and parse
     errors. They write no delivery record today and still write none.
   - `StdioAnswer::Finalized { response, tool, execution, signing }` covers everything else.
2. **One post-dispatch tail, `deliver_finalized`, records.** It takes the `frame`, the
   finalized parts, the session id and the read attribution. In order:
   1. `judged_answer::record_delivery(meta, frame, &correlation, stored)`. `stored` is a clone
      of the response, taken before the judge and only when an execution stores one.
   2. `complete_delivery_read` on the stored delivery it returns (item 4).
   3. Return the frame.

   The correlation is unchanged: `caller: "stdio"`, `external_server: "gateway"`, the same
   `external_tool`.

   `judge_and_commit` takes `&MetaMcp` and the session id as well:
   - For `Built`, nothing changes: `reads.answer(value, params, hidden)`.
   - For `Finalized`, it judges the `JsonRpcResponse` as `Payload::Response` through a new
     judge-only `StdioReads::judge(response, params, hidden)`. The arguments are the same as
     `outbound::answer`'s, with `STDIO_KEY`, so the request's tenant charging and the
     pre-transform attribution are kept. Unlike `answer`, it does not call `recorded()`. Then it
     runs `deliver_finalized`.
   - Either way, it ends with `staged.commit(frame.delivers_result())`, as now.
3. **The judge stays where it runs today**, after `dispatch_streaming_notifications` drains the
   trailing notifications (`stdio_notify.rs:51`). Judge order relative to streamed notifications
   is unchanged, so which frame of a cross-tenant pair is withheld is unchanged. Judging inside
   the dispatch was rejected because it would judge the answer before its trailing notifications.
4. **`complete_delivery` gets the read explicitly.** It reads the tenant-read scope
   (`admission.rs:110`, `in_read_scope()`/`noted()`), and after the move it runs outside that
   scope. A new `SyncLease::complete_delivery_read(response, signing, read)` takes the
   attribution. `complete_delivery` keeps its signature and delegates with the in-scope value,
   so the meta caller is untouched. Stdio passes the `hidden` attribution that `read_scoped`
   returned. That is `Some(noted)` exactly when a scope was open (`outbound/mod.rs:343`), which
   is the value the in-scope read produced.
5. **Batch items** (`dispatch_batch_read`) go through the same `judge_and_commit`, so they get
   the same record.
6. **Test-only `dispatch_single_with_sink`** runs the same tail with the judge left out. It
   takes an unjudged frame (`outbound::answer(None, None, response, None, None)`), calls
   `deliver_finalized` with read `None` (it runs in no read scope, so that is today's value),
   then `staged.commit(…)` as now. The stdio admission and replay tests that drive it
   (`dispatcher_admission_arms.rs`, `stdio_replay_audit.rs`) therefore still record, store the
   first execution and commit receipts.

### Consequences

- **One record per judged stdio answer.** The delivery record carries the `tenant_read` fields
  (`take_record_fields`), and no standalone `tenant_read` is written for it. This is the
  MIK-7799 shape the HTTP routes already have. With no log configured, nothing is written, as
  before.
- **Fail-closed.** If the log refuses the record, the frame becomes the audit-unavailable
  refusal, and so does the stored delivery (`judged_answer.rs:35-37`). That is today's stdio
  behaviour, now applied after the judge. When the log accepts the record, a read-judge Block
  leaves the stored copy as the original answer, taken before the judge ran
  (`stdio_delivery.rs:78`, `:113`; `judged_answer.rs:34-35`), and a replay restores that
  answer's first reading (`admission.rs:209`) and is judged again (`server/mod.rs:3429` →
  `:3085` → `stdio_delivery.rs:113`), so it is served only when a fresh call returning that
  answer would be.
- **`complete_delivery` runs later**: after the judge and the record, outside the relay
  collector. It touches no relay state. The meta route has the same order.
- **Code that loses its last non-test caller**: `finalize_response_for_delivery`,
  `finalize_response_after_inspection` and `MetaMcp::record_delivery`. Their remaining callers
  are tests (`chain_emission_tests`, `response_delivery_tests`, `bridge_fallthrough_tests`,
  `signing_delivery_tests`, `response_delivery_scope_tests`, `audit_degraded_tests`). They get
  `#[cfg(test)]` so the lib target has no dead code.

### Visibility (operator/lead decision requested)

`router::judged_answer` is a private module with a `pub(super)` function, so `server/` cannot
reach it. Proposal: keep the module private and widen only the function. It becomes
`pub(in crate::gateway)`, re-exported from `router/mod.rs` as
`pub(in crate::gateway) use judged_answer::record_delivery as record_judged_delivery`.
The alias keeps the name distinct from `MetaMcp::record_delivery`. That is the narrowest scope that
lets `server/` call it. `StdioReads::judge` and `SyncLease::complete_delivery_read` are `pub(crate)`, the same
as their siblings.

## Blast radius

The GitNexus index does not resolve these symbols (stale: `judge_and_commit`,
`dispatch_relay_scoped` and `record_delivery` are "not found"). The call sites come from `rg`
over all of `src`:

| Symbol | Production callers | Test callers |
|---|---|---|
| `judge_and_commit` | `server/mod.rs:2650`, `stdio_notify.rs:124` | `collusion_stdio.rs:288, :448, :459` |
| `dispatch_single_staged` | `server/mod.rs:2621`, `stdio_notify.rs:100` | `collusion_stdio.rs:244` |
| `finalize_response_for_delivery` | `server/mod.rs:3037` only | 6 test files (above) |
| `complete_delivery` | `handlers.rs:1988`, `server/mod.rs:3058` | n/a |
| `judged_answer::record_delivery` | `handlers.rs:1957` | n/a |

Risk: MEDIUM. This touches the stdio answer path for every request. The record and stored
delivery logic is reused, not rewritten.

## Test plan

New tests, written first and shown RED on CI. They drive the real serve loop
(`run_stdio_on`, `server/tests/stdio_tenant_reads.rs`) with a transparency log configured:

- **STDIO.1** `stdio_refused_read_records_the_refusal`: block mode, call A, then call B.
  - Exactly one `response_delivery_attempt` names B's tool call.
  - Its `response_hash` equals `sha256:canonical_json_sha256(served B frame)`.
  - Its `outcome`/`error_code` is the refusal's.
  - RED today: the hash is the pre-judge result's.
- **STDIO.2** `stdio_judged_read_is_one_record`: same pair. No `tenant_read` record is written,
  and B's delivery record carries `cross_tenant_read`. RED today: a standalone `tenant_read`
  is written.
- **STDIO.4** `stdio_batch_items_record_what_is_served`: a batch of `[A, B]`. Each item's delivery
  record hash equals its served item. RED today on the B item.
- **Positive control** (inside STDIO.1): A's record hash equals the served A result, so the
  assertion is not vacuous.

Existing tests that change:

- `collusion_stdio.rs:244, :288, :448, :459` take the new `judge_and_commit` and
  `dispatch_single_staged` signatures. Their assertions do not change.
- `collusion_stdio.rs:433` (`failing_audit`) arms its one-shot fault on `tenant_read`. After
  the merge no standalone `tenant_read` is written for a judged answer, so the fault would never
  fire, and `stdio_audit_withheld_read_records_no_receipt` / `…_batch_item_…` would lose their
  base case. The fault moves to `response_delivery_attempt`, the same as the direct route's
  `collusion_direct_tests/verdict.rs:122`.
  - Their assertions are unchanged: the withheld answer delivers no result and records no
    receipt, and the next read is delivered.
  - Those two tests are then the stdio cover for STDIO.3. Under the base revision the armed
    delivery record fails inside the dispatch, so they pass before and after. They are a
    regression guard, not a RED test.
- No other stdio test counts `tenant_read` records (`rg tenant_read src/gateway/server/tests`
  finds the `collusion_stdio.rs` fault and one doc comment in `stdio_tenant_reads.rs`).

Falsifier: if STDIO.1's hash assertion passes on the base revision, the defect is not what this
note claims, and the fix stops.

## Review log

- Round 1 (base `9914d8b50`):
  - GPT seat: SHIP (`gpt-20261004T181121Z-37702.md`).
  - Grok seat: SHIP-WITH-FIXES (`grok-20261004T181122Z-37815.md`). It raised one HIGH item: the
    test helper must also settle the stored delivery and commit receipts. That item is folded
    into items 1, 2 and 6, along with three improvements:
    - the explicit `judge` signature
    - a function-only re-export instead of widening the module
    - `Option<StdioAnswer>` for notifications
- Round 2 (revised note): GPT SHIP (`gpt-20261004T182055Z-79266.md`); Grok SHIP
  (`grok-20261004T182056Z-79381.md`). Grok also suggested having the test helper commit receipts
  on `frame.delivers_result()`, the predicate production uses. That is adopted. The new tail
  lives in `server/stdio_delivery.rs`, so `server/mod.rs` shrinks under the 800-line ratchet.
