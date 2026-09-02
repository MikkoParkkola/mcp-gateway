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

Move each concern to the point the two transports **already** converge on — but that is
not one point for all three, and the first version of this note got that wrong. Review
round 1 established that `handle_tools_call` is the convergence point for exactly one of
the three concerns.

| concern | convergence point | both callers |
|---|---|---|
| destructive confirmation (`CONFIRM.1a`) | `MetaMcp::handle_tools_call` | `router/handlers.rs:1272`, `server/mod.rs:1715` |
| `tools/list` record (`NFR.OBS.2`) | **also not the dispatcher** — the same per-message transport entry as `OBS.1` | see below |
| per-request record (`NFR.OBS.1`) | **not the dispatcher** — the per-message entry of each transport | see below |

### Why `NFR.OBS.1` cannot live in the dispatcher

Verified at source. The HTTP record is emitted at `router/handlers.rs:719`, and two facts
about that position decide the design:

- It fires for **every JSON-RPC method**, recording `method` as a field. `tools/call` is
  one of many. A record placed in `handle_tools_call` would silently narrow the criterion
  from every request to every tool call.
- It fires **before** the `RequestShape::Malformed` early-return at `:726`. A request that
  declared itself modern and then omitted a required field is recorded and *then* rejected
  with `-32602`. Malformed requests never reach the dispatcher at all, so a record placed
  there would lose exactly the population the migration telemetry most wants to see.

So placing `OBS.1` at `handle_tools_call` would close the row on paper while **regressing
HTTP**, which today records both classes. The elimination is still available, one layer
lower: the record-and-classify block that spans `handlers.rs:~660-726` becomes one function
that both transports call on each inbound message, before any shape-dependent return. A
transport still cannot omit it, because parsing an inbound request *is* calling it — the
same property the dispatcher was chosen for, at the layer where it is actually true.

This preserves the elimination test. After the move the finding — *a concern can be added
to one transport and not the other* — is still not statable, because there is one function
and both message loops go through it.

### Why `NFR.OBS.2` cannot live in the dispatcher either

Round 2 found this, and it is the round-1 error one layer down: a convergence point chosen
without checking which return paths reach it.

`handle_tools_list_with_url_override` (`meta_mcp/mod.rs:~1290-1312`) does **not** always
delegate. When the Code Mode URL override applies it builds the result and returns it
directly; only the no-override branch falls through to `handle_tools_list_with_params` at
`:1312`, under a comment that says so — *"No override (or static config already handles it):
follow normal path."* A record placed in `handle_tools_list_with_params` is therefore skipped
for exactly the requests the override serves, and today's record at `handlers.rs:993` sits
above both branches and catches them all. Placing it lower would **regress HTTP**, the same way
placing `OBS.1` in the dispatcher would have.

There is a second, independent reason, and it is the stronger one. The fields the record
carries are **router-level facts that the dispatcher never receives**: `profile` comes from a
request header, and `code_mode` is `state.meta_mcp.code_mode_enabled || code_mode_url_active`
where the second disjunct is a property of the URL. A record emitted inside the meta-MCP layer
could not report them without the router passing them down — which is the coupling the
`MetaMcpCallerContext` comment already refuses for the confirmation dependency.

So `OBS.2` collapses into `OBS.1`'s chokepoint rather than getting its own. One record-and-
classify function at each transport's per-message entry emits the observed record for every
method, and adds the `tools/list` fields when the method is `tools/list`. This is a smaller
design than the one it replaces: **one** site, not two, and the finding — *a `tools/list`
return path can bypass the record* — stops being statable rather than becoming guarded.

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
| 1 | Does the stdio dispatcher have the fields `NFR.OBS.1`'s record requires — notably `protocol_revision`? Its `server/discover` comment states it "has no access to the running config" (`server/mod.rs:1688`), which may bound what it can honestly report. | checkable | read the record's field list at `handlers.rs:719-730` against what is in scope at `server/mod.rs:1683`. Round 2 corrected the fallback: stdio establishes a revision at `initialize`, so the answer is to **retain the negotiated revision** and record it with `revision_source` set to the handshake, not to omit the field. Omission was the wrong default — it would leave stdio unable to answer the one question the migration telemetry exists to ask. A field is omitted only if no handshake has occurred yet, and is never fabricated. If a field proves unreportable at all — the case this question exists to find — the answer is not a quiet omission that leaves the criterion half-met: it returns to the operator as a named gap, because a telemetry criterion that cannot answer its own question is an unmet requirement, not a partially-met one |
| 2 | **RESOLVED — there is no stdio elicitation path at all.** The question asked whether the round-trip completes or deadlocks; both readings assumed a delivery mechanism exists. `rg` for `elicit` and `NotificationMultiplexer` outside tests returns `router/helpers.rs:134-152` (HTTP parsing) and `webhooks/mod.rs`, `streaming.rs` (HTTP delivery). `run_stdio` at `server/mod.rs:1495` touches none of them. So confirmation over stdio is not a wiring detail; it is a transport that does not exist. | checkable | done — see the revised residual below |
| 3 | Is a per-request record on stdio one record per JSON-RPC message, or per session? "Per request" is unambiguous on HTTP and needs a stated reading here. | checkable | read `NFR.OBS.1` in `RELEASE-4.0.0-requirements.md`; if it does not distinguish, the reading is per JSON-RPC message and is recorded as a reading, not as the requirement |

Question 2 is the one that can change the design's shape. If the round-trip cannot complete
on stdio, the confirmation still moves to the chokepoint — but stdio always takes the
"nobody could be asked" branch, and that outcome must then be *recorded* rather than
inferred, because a silent always-proceed is indistinguishable from the defect being fixed.

## Test plan

Separate document (§P2), written before any implementation and reviewed as tests. One row
per criterion; the falsifier for each is that the *old* stdio path decides differently on
the same fixture.

## Review round 1 — two vendors, both SHIP-WITH-FIXES

Reviewed 2026-09-02 by Codex/GPT (`~/.claude/bin/gpt-review`, 5 findings) and by the
synthetic reviewer (4 findings). Both returned `SHIP-WITH-FIXES`. Grok was not used: it is
unavailable, and on Grok-authored material it would be the author reviewing the author.

Two findings were raised independently by both vendors, and both survived source
verification. They are the reason the design above changed rather than gained a footnote.

| finding | raised by | verified at source | disposition |
|---|---|---|---|
| `handle_tools_call` is not a convergence point for `NFR.OBS.1`: every non-`tools/call` method bypasses it, and HTTP records *before* the malformed early-return | both | yes — `handlers.rs:719` precedes the `Malformed` return at `:726` and logs `method` for every request | design corrected; `OBS.1` moved out of the dispatcher to the per-message transport entry |
| the `ProxyManager` reuse cannot deliver confirmation over stdio | GPT | yes — no elicitation or multiplexer reference reachable from `run_stdio` | Q2 resolved as *no path exists*; residual rewritten below |

The remaining findings — internal callers of `handle_tools_call` being unenumerated,
double-counting risk for playbook and code-mode steps — are scheduled as a check before
implementation, not answered here. Enumerating those callers is the first task of the test
plan, since a caller that is not a transport must have a stated answer for both concerns.

## Residual risk, rewritten after review

The original residual said this note makes stdio *equal* to HTTP on confirmation. Given Q2,
that claim was wrong: moving the confirmation to the chokepoint makes stdio *reach* the
confirmation code, which then has nobody to ask, on the transport where `is_admin: true`
means the admin check never says no either. Both controls would be nominally present and
neither would be able to refuse anything.

That looked like a decision the design could not make for itself, and it was put to the
operator as one. **It was not.** The criterion already states the answer:

> The destructive-operation confirmation gate MUST refuse when it cannot obtain confirmation.
> Today it proceeds when elicitation is unsupported **or there is no session** - and after this
> release there is never a session.
> -- `docs/requirements/RELEASE-4.0.0-requirements.md:195`

## RESOLVED - the stdio confirmation behaviour refuses (§P1)

| field | value |
|---|---|
| question | when confirmation cannot be sought on stdio, does the destructive call proceed with a warning, or is it refused? |
| how it was resolved | read at source - `RELEASE-4.0.0-requirements.md:195`, quoted above |
| the answer | **refuse.** Fail closed. The criterion says MUST, and it names *no session* as one of the two conditions that must now trigger refusal rather than passage |
| what it changed | the branch is specified rather than waiting; row 13 of the test plan asserts it; cluster G's scope grows by one implementable criterion |

**The question should not have been asked, and one of its options was forbidden.** It was put
to the operator with three choices, and *proceed with a warning* was among them - a behaviour
the criterion explicitly forbids. Offering a forbidden option as a live choice is worse than
asking an unnecessary question: had it been picked, the design would have carried an operator
decision that contradicts the requirement, and the contradiction would have been invisible,
because nobody re-reads a criterion after the operator has spoken. Both reviewers converged on
this from opposite directions, and both were right. The check that closes it costs one file
read, which is what the process asks for before an open question is escalated: it is
*scheduled*, and a check that can be run is run before a question that must be waited on.

**What remains genuinely open, and it is not blocking.** Refusal satisfies the criterion, so
building a stdio elicitation transport - a way to *obtain* confirmation rather than to fail
without it - is not required by this release and does not belong in this cluster. It stays
available as a later change. What does need saying out loud is the consequence: refusal is a
behaviour change for anyone driving a destructive tool such as `gateway_kill_server` over
stdio today, and those calls will start failing closed. That is a release note, not a
question - the criterion has already decided that the safety is worth the break.

**What this blocks, and what it does not.** It blocks nothing. `NFR.OBS.1` and `NFR.OBS.2` do not depend on it: both are records, neither asks anything of
a client, and the corrected convergence points for them stand on their own. Those two
proceed; the confirmation branch waits.
