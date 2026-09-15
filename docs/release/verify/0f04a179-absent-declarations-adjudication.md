# Adjudicating the ten declarations `0f04a179` added that have no trace at the release tip

**Date**: 2026-09-15 · **Line**: `origin/chore/v4-reconcile-main` · **Commit under audit**: `0f04a179` (squash of #473)

## Why this document exists

`0f04a179` added 1059 declarations to `src`; 32 are absent at the release tip.
19 are test names and 13 are production, of which 10 have no trace at the tip by
name. A name absent by grep is not a loss — the reconcile merge resolved several
files against the `main` side, and a resolution taking the other side looks
exactly like a deletion. `BridgeDispatcher` (loss) and `TaskStore` (move) were
each adjudicated individually; these ten needed the same treatment before any of
them could be published as a loss.

Method, per name: read what the declaration did in `0f04a179`, then search the
tip for the **behaviour**, never the name. Three verdicts, kept apart on purpose:

* **move** — the same behaviour, under a different name, in a different module,
  or inlined at a call site. For an extracted helper this means every one of its
  call sites, not merely a body that matches somewhere.
* **replaced-by-design** — the tip deliberately does something *different*, and
  the difference is a decision with a record. Not a loss, but a client-visible
  delta and therefore a release-note input, which is why it does not share a
  label with "move".
* **loss** — no production carrier at the tip.

The call-site rule is load-bearing, and it is what caught the one wrong verdict
an earlier draft of this table carried: a helper extracted to dedup two sites is
a loss if only one of them survives, however exactly its body is reproduced.

## Verdicts

| Declaration | `0f04a179` home | Verdict | Evidence at the tip |
|---|---|---|---|
| `is_mcp_envelope` | `meta_mcp/invoke.rs` | **LOSS** | Two call sites, and only one survives. The predicate body is reproduced inside `apply_validated_output` (`src/gateway/meta_mcp/invoke.rs:216`) — but that check is **pre-existing**, unchanged by `0f04a179`, and is the reason the helper was extracted rather than the behaviour it added. The site the commit added is the validation-target match guard, and the tip has the pre-commit code there verbatim: `extract_output_validation_target(&result).unwrap_or_else(\|\| result.clone())` at `:160-161`. See "The verdict that changed" below |
| `decorate_modern_result` | `router/handlers.rs` | **move** (renamed) | `shape_modern_response` at `src/gateway/router/handlers.rs:2018`; same `resultType` entry-or-insert and per-method `cacheScope` (`:2032`, `:2041-2043`) |
| `fail_with_code` | `protocol/tasks.rs` | **replaced-by-design** | `Task::fail(JsonRpcError)` at `src/protocol/tasks.rs:248` routes through `TaskTransition::Fail` and preserves `data` as well as `code` and `message`. Delta: a failure now carries `data` |
| `task_view` | `router/handlers.rs` | **move** (superseded) | `Task::wire()` at `src/protocol/tasks.rs:238` over `TaskWire` (`:96-118`, nullable `ttl_ms` preserved by a custom decoder), shaped by `src/gateway/router/handlers/tasks.rs:72`. Single construction site in `0f04a179`, single carrier at the tip |
| `REQUEST_CANCELLED` (`-32800`) | `protocol/tasks.rs` | **replaced-by-design** | Cancel is a terminal `TaskStatus::Cancelled` transition, not an error code; `src/gateway/router/tests/task_execution_adapter/lifecycle.rs:85-117` asserts `-32800` is the wrong answer and names design §5. Delta: a cancelled call answers with a status, not a JSON-RPC error |
| `SseExchange` | `transport/http/mod.rs` | **replaced-by-design** | The struct had exactly two fields and both are traced. `response: JsonRpcResponse` is the return value of `drain_events` (`src/transport/http/sse_decoder.rs:246`, `Ok(Some(response))` at `:260`). `notifications` was labelled `#[allow(dead_code)]` scaffold with no production reader; the tip publishes each notification as it is seen, inside the loop, via `notification_sink::publish` (`:264`). Delta: notifications reach a sink instead of riding out with the response |
| `promote_interim_envelope` | `meta_mcp/mod.rs` | **replaced-by-design** | Interim promotion lives at `src/gateway/meta_mcp/invoke.rs:1909-1937` and `:2330-2390`. Delta, and it is a fix: MRTR.2 keeps the backend's own `requestState` from reaching the client (`:1909`), where the original copied the field through |
| `redeem_carried_confirmation` | `meta_mcp/mod.rs` | **move** (inlined) | Exactly one call site in `0f04a179`. Redemption sits inside the gate's `ConfirmationChannel::InBand` arm at `src/gateway/meta_mcp/mod.rs:2633-2691`, keyed on the same `CONFIRMATION_INPUT_KEY` (`:2439`) |
| `TracingBridgeObserver` | `meta_mcp/invoke.rs` | **LOSS** | `BridgeObserver` is declared at `src/gateway/input_bridge.rs:355` and the `observer` field at `:367`, and `rg 'BridgeObserver' src/ tests/` returns **no implementor anywhere in `src/`**. The only one is `Records` at `tests/mik_7212_mrtr7_bridge_acs.rs`, the same integration test that owns `FakeBackend` |
| `BridgeDispatcher` | `meta_mcp/invoke.rs` | **LOSS** (already published) | No `impl BackendInvoker` in production; the only one is `FakeBackend` at `tests/mik_7212_mrtr7_bridge_acs.rs:206` |

## Result

**Two moves, five replaced-by-design, three losses.**

Two of the losses are the MRTR7 bridge wiring, and they are the same loss:
`TracingBridgeObserver` is the observer the dispatcher fed, so a tip with no
dispatcher has nothing to observe. They share one remedy — re-apply
`0f04a179`'s `src/gateway/meta_mcp/invoke.rs` hunks (`:834-891`) onto the line
and add one case driving the real dispatcher rather than `FakeBackend`. No
regrade follows from either: `MIK-7212.MRTR.7a` (`RELEASE-4.0.0-criteria-status.md:142`)
and `7b` (`:143`) are already **PARTIAL, blocking** on the dispatcher, and the
observer is inside that grade rather than beside it.

The third loss is new, and it is the finding.

## The verdict that changed

An earlier draft of this table called `is_mcp_envelope` a move on the strength
of a matching body at `invoke.rs:216`. A reviewer asked a question the draft had
not answered — whether the original declaration had one call site or several —
and it had two. The surviving one is the *older* of the two: the predicate
inside `apply_validated_output` is pre-commit code that `0f04a179` did not
touch, and deduplicating against it is why the helper was extracted at all. The
site the commit **added** is gone, and what stands in its place is the exact
line the commit replaced:

```rust
// src/gateway/meta_mcp/invoke.rs:160-161, at the release tip
let validation_target =
    extract_output_validation_target(&result).unwrap_or_else(|| result.clone());
```

`0f04a179` replaced that fallback with a match that returns the result
unchanged when there is no inner payload *and* the value is an MCP envelope,
and the comment it added says why in terms this release cares about: falling
back to the envelope "validates the wrong document and then republishes it under
`structuredContent` — carrying the backend's own `requestState` past the mint
that exists to replace it."

**Open question, not a regrade.** `MIK-7212.MRTR.2a` (`:131`) — *MUST NOT
forward a backend's `requestState` to a client verbatim* — is graded **MET**.
The reachability argument against it is assembled but not executed:
`enforce_output_schema` (`:142`) gates only on a present schema and a
non-`isError` result, its call sites at `:2991` and `:3137` are on the dispatch
path that returns before the interim handling at `:1909-1937` mints the
replacement, and `apply_validated_output` re-wraps the validated document into
`structuredContent` — which a top-level `requestState` replacement would not
reach. Every step of that is read, none of it is run. The cheapest disproof or
confirmation is a unit test on `enforce_output_schema` alone, fed an interim
envelope carrying a backend `requestState` and a schema it satisfies: if the
returned value carries that value under `structuredContent`, MRTR.2a is not MET
on this line. **That test is the next action, and the grade stands until it
runs.** One of the two independent reviewers rates the break CERTAIN rather than
open and would regrade now; that is recorded rather than adopted, because the
same reviewer also misidentified the `BridgeObserver` implementor two rows above
and a read-only trace is what both claims rest on. Publishing a regrade off a
read-only trace would be the same error this document exists to correct, one
level up.

**The burndown does not move on this document: 4 core open, 15 minor, 19 total,
delta 0.** Nine of ten names are resolved to something already counted or to
nothing at all. The tenth is an open question with a named experiment, and an
open question is not a defect until the experiment says so.

The instrument lesson is the call-site rule. A body that matches somewhere is
not a move; a helper extracted to dedup *n* sites is a partial loss unless all
*n* survive. Matching on the body alone would have published this as safe.
