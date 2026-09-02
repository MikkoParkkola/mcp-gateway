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

### Scope move, 2026-09-03 — one hidden-tool disclosure route folded into FOR

The OUT list held the hidden-tool disclosure routes for MIK-7364. One of them moves into
FOR, and only one. Writing down why, because §P0 freezes the surface at first review and a
move that is not recorded is indistinguishable from drift.

A test committed for row 18 showed the refusal for a hidden meta-tool and the fallback for a
name nobody implemented arriving with different wording — the second carries a
`JSON-RPC error -32601: ` prefix, the first does not. The difference is a name-existence
oracle: the shape of the reply tells a caller which of the two it hit, which is the
disclosure the refusal exists to prevent, relocated from the code into the message.

What makes this a repair rather than an expansion is that the source already commits to the
invariant. The comment above the refusal in `src/gateway/meta_mcp/mod.rs` states that the two
answers are built the same way and are byte-identical, and records that an earlier version
diverged in exactly this manner and was fixed for exactly this reason. The finding does not
add a requirement; it demonstrates that one the file asserts does not hold. Restoring an
invariant a module claims about itself sits inside any scope that touches the module.

The rest of MIK-7364 stays out. The other disclosure route is untouched, and this note does
not become the place where that ticket gets worked.

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
proceed on their own footing. The confirmation branch proceeds with them: it is specified,
not waiting, and the only thing it needs that they do not is a stdio path to the gate.

## What `CONFIRM.1a` already has, and what it is actually missing (§P1)

The resolution above settled *what the behaviour must be*. It did not ask *how much of it
already exists*, and the answer changes the shape of the work: the refusal is built, on one
transport, and the criterion's own wording no longer describes the code.

The gate has exactly **one call site** in the whole tree — `src/gateway/router/handlers.rs:1196`,
inside the HTTP router (V: `rg 'require_destructive_confirmation|is_destructive_meta_tool'`,
2026-09-02). Everything below follows from that single fact.

| the criterion says | the code does | evidence |
|---|---|---|
| the gate proceeds when there is no session | on the HTTP path it **already refuses** — `is_modern` selects `ConfirmationPolicy::for_modern()`, whose `on_unconfirmable()` is `REFUSE`, and the handler returns `-32001` | `handlers.rs:1226-1247` |
| ... over stdio | a destructive `tools/call` arriving on stdio **never reaches the gate at all** — there is no call site in `src/gateway/server/` | the single-call-site search above |
| ... for an internal caller | likewise ungated, see below | `authorization.rs:280-295` |

**This narrows cluster G's confirmation work and it does not shrink it.** The HTTP repair is
done and is not ours to redo. What remains is precisely the dispatch-parity problem this note
already exists to solve: the stdio loop reimplements a slice of the router and inherits none of
its gates. `CONFIRM.1a` is therefore not a fourth concern bolted onto cluster G — it is the
same defect as `NFR.OBS.1` and `NFR.OBS.2`, in its third costume, and the elimination this note
proposes closes all three or none.

**Row 13 is load-bearing, not a regression test.** A test written today against the
stdio path fails because the behaviour is absent, not because a mutation was staged for it —
which is the free failure §P2 asks for, and the reason to write them before the code.

### A comment that overstates its own reach — fix the comment, not with a test

`handlers.rs:1252-1256` reads:

> The same policy the pre-check above applied, handed to the dispatch chokepoint so the shapes
> the pre-check cannot see — a playbook step, whose targets are not in the request — face it too.

What is handed down is `RouterAuthorizer`, which holds `state`, `client`,
`oauth_agent_identity`, `cert_identity` and `principal`, and implements `ToolAuthorizer` with a
single `authorize` method (`src/gateway/router/authorization.rs:280-300`). It carries **no
confirmation policy and makes no confirmation call**. Authorization reaches the chokepoint;
confirmation does not.

Read as written, the comment tells the next reader that a playbook step invoking a destructive
tool already faces the gate. It does not — and, verified since, it never needs to. A playbook
or Code Mode step dispatches through `ToolInvoker::invoke`
(`src/playbook/engine/mod.rs:180-181`), whose only production implementor is `MetaMcpInvoker`
(`src/gateway/meta_mcp/support.rs:229-238`). That calls `invoke_tool` with a
`{server, tool, arguments}` **backend** envelope, while the confirmation gate keys on
*meta*-tool names through `is_destructive_meta_tool`
(`src/gateway/destructive_confirmation.rs:173`), reached from `handlers.rs:1196-1198` alone.
An internal step therefore cannot name a destructive meta-tool at all.

So the comment is wrong in a narrower way than it first appeared: not "this path is unguarded"
but "this path does not exist". The repair is to correct the comment, and the property it
gestures at is established by construction rather than by a case — a test for a path production
cannot take would be a test that can never go red, which is exactly what the section below
objects to. An earlier revision of this note proposed a row 14 to cover it; that row is deleted,
and the reason is recorded in the test plan's exclusions so the proposal cannot return without
first contradicting the source.

A stale comment is model input, not neutral prose. It is corrected in the same change.

### The existing test asserts the policy against itself

`tests/mik_7215_controls_acs.rs:208` and `:222` assert
`ConfirmationPolicy::for_modern().on_unconfirmable() == REFUSE` and the legacy counterpart.
That is the policy's own constant compared with the policy's own constructor: it passes whether
or not any caller consults it, which is how "written for this decision and then never consulted"
survived to be discovered in the handler comment. Row 13 asserts the *behaviour at the
boundary* instead, which is the only form of this test that can go red.
