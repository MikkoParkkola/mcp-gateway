# Cluster G — one transport is missing three things the other has

§P1 design note. No code. Reviewed by two vendors before an edit.

## FOR / OUT (§P0)

**FOR:** closing `NFR.OBS.1`, `NFR.OBS.2` and `MIK-7246.CONFIRM.1a`, all three of which
are the same defect wearing three hats: a concern implemented in the HTTP router that the
stdio dispatcher never reaches.

**OUT:**

- Whether stdio should serve the 2026-07-28 revision. That is `NFR.COMPAT.1`, and the
  stdio `server/discover` limitation recorded at `src/gateway/server/mod.rs:1687` is a
  separate row's problem.
- Whether `is_admin: true` on stdio is the right grant. It is a standing decision with a
  recorded rationale (`src/gateway/server/mod.rs:1722`). This note *uses* that decision;
  it does not reopen it. See the residual at the end.
- Any third transport. A2A does not dispatch `tools/call` through this path.

## The problem, stated once

Two call sites reach the same meta-MCP layer:

| concern | HTTP | stdio |
|---|---|---|
| per-request observed record (`NFR.OBS.1`) | `src/gateway/router/handlers.rs:719` | absent |
| `tools/list` observed record (`NFR.OBS.2`) | `src/gateway/router/handlers.rs:993` | absent |
| destructive confirmation (`MIK-7246.CONFIRM.1a`) | `src/gateway/router/handlers.rs:1196` | absent |

Both telemetry criteria say *per request* and *every* `tools/list`, unqualified by
transport. The gateway serves MCP over two transports, so one of the two is missing from
the migration telemetry entirely, and a destructive meta-tool invoked over stdio is never
announced to anyone.

## Why the obvious fix is the wrong one

The blocking rollup frames this as *"one wiring question — what the stdio dispatcher must
do before it reaches `handle_tools_call`"*. That framing prescribes the patch: add three
things to the stdio dispatcher. It closes all three rows and leaves the defect fully
describable — *a concern can be added to one transport and not the other*, which is how the
gateway arrived here. A fourth concern, or a third transport, reintroduces it at full cost.

Per the repair protocol, elimination is the default on an architecture finding, and the
test is whether the finding can still be stated afterwards. Under the patch, it can.

## What eliminates it

Move each concern to the point the two transports **already** converge on.

| concern | convergence point | both callers |
|---|---|---|
| `tools/call` (confirmation, per-request record) | `MetaMcp::handle_tools_call` | `router/handlers.rs:1272`, `server/mod.rs:1715` |
| `tools/list` record | `MetaMcp::handle_tools_list_with_params` (`meta_mcp/mod.rs:1267`) | `server/mod.rs:1700` directly; HTTP via `handle_tools_list_with_url_override:1312` |

After the move, a transport cannot omit the concern, because reaching the dispatcher *is*
the concern. The finding stops being statable rather than becoming unreachable.

### This is the third instance of a pattern already solved here

The tool policy was in exactly this state and was fixed exactly this way. Its own comment,
at `src/gateway/server/mod.rs:1707`, records the before and after:

> The tool policy is applied at the dispatch chokepoint via the authorizer below, not here.
> The inline check this replaces ran for `gateway_invoke` alone, so a stdio playbook or
> code-mode step reached a backend with no policy check at all.

Same defect, same transport, same repair. The mechanism it introduced —
`MetaMcpCallerContext.authorizer`, a borrowed trait object — is the mechanism this note
reuses. The context deliberately holds no `Arc<AppState>`; the field comment in
`src/gateway/meta_mcp/mod.rs` gives the reason ("a cycle that never frees"), which is why
the confirmation dependency must arrive the same way and not as a stashed handle.

## The one place the security framing needs correcting

The rollup calls `CONFIRM.1a` a case where a destructive meta-tool "executes with no
confirmation sought". That is literally true. The inference that a security control is
being bypassed is not, and the HTTP call site says so itself at `handlers.rs:1185`:

> NOT the control — the admin requirement is, and `gateway_kill_server`, the only tool
> carrying `destructiveHint: true`, is in the admin set. This is the prompt an honest
> client shows its user before proceeding.

On HTTP that reasoning holds. **On stdio it inverts, and that is the actual finding.**
Stdio sets `is_admin: true` unconditionally and by design, so the control the comment
defers to never says no on that transport. That leaves the confirmation prompt as the only
thing between an agent and `gateway_kill_server` — load-bearing on stdio in precisely the
way it is not on HTTP, *because* of a decision that is correct on its own terms.

The threat is not a hostile client; the stdio rationale disposes of that one correctly
(the client spawned the process and could edit the config file instead). The threat is an
**agent acting without its human** — the same principal gap the prompt exists for on HTTP,
on the transport carrying most agent traffic.

Two mechanical consequences: the confirmation moves with identical semantics on both
transports, and the "nobody could be asked" branch must not silently become "proceed" on
stdio merely because no elicitation-capable client is attached.

## Open questions, each scheduled (§P1)

| # | question | form | resolves by |
|---|---|---|---|
| 1 | Does the stdio dispatcher have the fields `NFR.OBS.1`'s record requires — notably `protocol_revision`? Its `server/discover` comment states it "has no access to the running config" (`server/mod.rs:1688`), which may bound what it can honestly report. | checkable | read the record's field list at `handlers.rs:719-730` against what is in scope at `server/mod.rs:1683`; a field that is unavailable is omitted, never fabricated |
| 2 | Does the elicitation round-trip complete over stdio, or deadlock against a dispatcher already reading stdin? `ProxyManager` is in scope (`server/mod.rs:944,1181`), so the dependency is available; that is not the same as the round-trip returning. | checkable | drive a destructive call over stdio against a client that answers, and one that does not; the second must reach the "nobody could be asked" branch, not hang |
| 3 | Is a per-request record on stdio one record per JSON-RPC message, or per session? "Per request" is unambiguous on HTTP and needs a stated reading here. | checkable | read `NFR.OBS.1` in `RELEASE-4.0.0-requirements.md`; if it does not distinguish, the reading is per JSON-RPC message and is recorded as a reading, not as the requirement |

Question 2 is the one that can change the design's shape. If the round-trip cannot complete
on stdio, the confirmation still moves to the chokepoint — but stdio always takes the
"nobody could be asked" branch, and that outcome must then be *recorded* rather than
inferred, because a silent always-proceed is indistinguishable from the defect being fixed.

## Residual risk, stated

Moving the confirmation to the chokepoint makes it apply on stdio, where `is_admin: true`
means every caller is an admin. If a client does not support elicitation the action
proceeds after a warning — the behaviour the HTTP comment already accepts. This note does
not change that and does not claim `CONFIRM.1a` makes stdio safe. It makes stdio *equal*,
which is what the criterion asks and all it asks.

## Test plan

Separate document (§P2), written before any implementation and reviewed as tests. One row
per criterion; the falsifier for each is that the *old* stdio path decides differently on
the same fixture.
