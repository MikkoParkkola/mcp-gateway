# Cluster G — test plan (§P2)

Written before any test code and before any implementation. Reviewed as a plan, then the
tests get their own review as tests.

## Scope

Covers `NFR.OBS.1` and `NFR.OBS.2` only. `MIK-7246.CONFIRM.1a` is **not** planned here: its
behaviour on stdio is deferred to the operator (see the design note), and a test plan for a
branch whose required behaviour is undecided would be a plan for whichever behaviour I
happened to assume. It is added when the question is answered, not before.

## One row per criterion

| # | criterion | case | level | type | falsifiable how |
|---|---|---|---|---|---|
| 1 | `OBS.1` | a `tools/call` over stdio emits exactly one observed record carrying `method`, `protocol_revision`, `revision_source` | integration | positive | free — stdio emits nothing today |
| 2 | `OBS.1` | **every** non-`tools/call` method the stdio loop accepts emits a record — parameterised over the dispatch arms, not sampled | integration | positive | free — and this is the case that would have caught the round-1 design error |
| 3 | `OBS.1` | a request declaring itself modern while omitting a required field emits a record **and then** returns `-32602` | integration | negative-path | free — and it pins the ordering, not just the presence |
| 4 | `OBS.1` | the same three shapes over HTTP still emit exactly one record each | integration | regression | **not free** — see the honesty section |
| 5 | `OBS.1` | an inbound message whose handling reaches the meta-MCP layer a second time (playbook step, code-mode step) produces **exactly one** record | integration | exactly-once | free — `exactly one` fails at zero as well as at two |
| 6 | `OBS.2` | a `tools/list` over stdio emits the `tools/list` record | integration | positive | free — stdio emits nothing today |
| 7 | `OBS.2` | a `tools/list` over HTTP still emits exactly one, not two, after the change | integration | regression | **not free** — see the honesty section |
| 8 | `OBS.2` | a `tools/list` over HTTP **with the Code Mode URL override active** emits the record, carrying `code_mode` true | integration | regression | **not free** today, but free against the rejected design — see below |
| 9 | `OBS.1` | a notification (no `id`, no response — `notifications/initialized`) over stdio emits exactly one record and carries no response-shaped field | integration | boundary | free — nothing records notifications today |

Row 5 exists because both reviewers raised it independently in round 1: the design's "both
callers" tables enumerate the *transports*, and the tool-policy precedent the design leans
on records playbook and code-mode steps reaching this same layer. Those are callers too.
Whether they should produce a record is a real question — they are not inbound requests —
and the plan answers it as *no*, one record per inbound message, which is the only reading
under which "per request" counts the same thing on both transports. The row states that as
a cardinality, not as a prohibition, so it is a test rather than an assertion of intent.

## Expected values — the oracle, stated per field

Both vendors found the same hole from different sides: every row said *a record is emitted*
and no row said *what it must contain*. A test asserting presence passes against telemetry
that is fabricated, constant, or wrong — which is the failure the criterion exists to prevent,
since the whole point of `OBS.1`/`OBS.2` is to answer *which revision are clients actually
using*. Presence-only assertions would let that question be answered with a constant.

The live HTTP record at `handlers.rs:995-1004` carries exactly five fields, read at source:

| field | value under test | derived from |
|---|---|---|
| `profile` | the header's value, or the literal `none` when absent | the request header, independently of the record |
| `code_mode` | `code_mode_enabled \|\| code_mode_url_active` | the config and the URL, computed in the test |
| `query_present` | true only for a non-empty string `query` | the request params |
| `cache_scope` | `scope_for_method("tools/list")` | the same function, called by the test |
| `cache_scope_advertised` | `is_modern` — false on a legacy result, which advertises no `cacheScope` | the negotiated revision |

Each expected value is **derived independently in the test**, never copied from the record it
checks. A test that reads the record and asserts the record equals itself is the tautology
this table exists to make impossible.

For `OBS.1` the two revision fields get the same treatment:

| case | `protocol_revision` | `revision_source` |
|---|---|---|
| stdio, after `initialize` negotiated a revision | the negotiated value, exactly | the handshake |
| stdio, message arriving before any `initialize` | absent — **not** a sentinel, not a default | absent |
| HTTP, revision declared in the request | the declared value | the request |

The middle row is the one that must not drift into a constant. An absent field and a field
holding a plausible-looking default are indistinguishable to an operator reading the telemetry,
and only one of them is honest.

## Can each case actually fail? (§P2 question 2)

Rows 1, 2, 3, 5, 6 and 9 fail for free: they assert a record that no code emits today, so
writing them first produces a real red. Row 5 earns that word only because it was rewritten:
as *does not add a second record* it was a negative assertion that passes at zero records — 
the decoration class this section exists to catch, and a reviewer caught it here. As **exactly one** it fails at zero *and* at two, so the same content now carries its own red.

**Rows 4, 7 and 8 are the honest problem.** They pass today, and they will still pass if the
change is written correctly — but they would also pass if the extraction were never done at
all. A test that cannot distinguish those two states is not a regression guard, it is
decoration. They need the falsifier probe from the process, run once when the tests are
written, against a deliberately wrong implementation:

- place the record inside `MetaMcp::handle_tools_call` instead of the transport entry — the
  exact error round 1 caught. Rows 2, 3 and 4 must go red. If row 4 stays green, it is not
  measuring what it claims and is rewritten before it is trusted.
- emit the record in both the extracted function and the old HTTP site — rows 4 and 7 must
  go red on the count. If they only assert "at least one record", they will not, and
  "exactly one" is the whole content of those two rows.

Both probes restore the correct implementation and re-run, so the restore is verified by a
green run rather than by `git status`.

### Row 8 — the case that catches the round-2 design error

Round 2 found that `handle_tools_list_with_url_override` returns its result directly when the
override applies, so a record placed in `handle_tools_list_with_params` would be skipped for
exactly those requests. Row 8 is the test that fails against that implementation and passes
against the corrected one.

It is not free today — today's record at `handlers.rs:993` sits above the branch and catches
it — but it *is* free against the design the review rejected, which is what makes it worth
having: it is the falsifier for the specific mistake, and its probe is to place the record in
the dispatcher and watch row 8 go red while rows 6 and 7 stay green. That divergence is the
whole point of the row. A plan whose rows all fail together cannot tell one wrong placement
from another.

Row 8 also pins `code_mode`, because that field is `state.meta_mcp.code_mode_enabled ||
code_mode_url_active` — a router-level fact. A record emitted below the router cannot report
it, so asserting it holds the record at the transport boundary rather than merely testing that
some record exists.

### How the ordering claim in rows 3 and 9 is observed

Both vendors raised this independently: row 3 claims to pin *classifier, then record, then
return*, and naming an order is not observing one. Post-dispatch logging satisfies a
presence assertion just as well as pre-return logging does, so the row as written could not
tell the two apart — it would have been decoration wearing an ordering claim.

The mechanism is a capturing `tracing` subscriber installed for the test, holding a shared
sequence counter that both the captured record and the response write to. The assertion is on
the two stamps, not on wall-clock time and not on the order lines appear in a buffer. That
makes the ordering falsifiable by construction: move the record after the return and the
stamps invert.

### The probes are code, not a one-time manual mutation

Rows 4, 7 and 8 depend on deliberately-wrong implementations to prove they can fail. A probe
run once by hand and described in prose is unrepeatable, and by the next review round nobody
can tell whether it was run or whether the row still measures anything. Each probe is checked
in as a `#[cfg(test)]` wrong-placement variant behind a test-only switch, so re-running the
sensitivity check is a command rather than an act of trust.

## Fixtures — the trap this plan is trying to avoid

The tests drive the **real** stdio loop and the **real** HTTP handler. A fixture that stands
in for either one would be asserting against a reimplementation of the code under test, and
the record's whole value is that it fires on the path a user's request actually takes. In
particular the malformed case (row 3) must be a genuine malformed request through the real
shape classifier, not a hand-constructed `RequestShape::Malformed` — the ordering being
pinned is *classifier, then record, then return*, and a hand-built shape skips the first two.

## What this plan does not cover, stated

- **Batch requests — N/A, on verified grounds.** `rg -n "batch" src/transport/ src/protocol/`
  returns nothing: no JSON-RPC batch envelope is parsed anywhere on either transport, and the
  revision this release targets removed batching from the protocol. There is no per-element
  cardinality to test because there are no elements. If batch handling is ever added, row 1's
  cardinality assertion is the one that must be re-derived, and this line is the note that
  says so.
- The stdio confirmation branch (`CONFIRM.1a`) — deferred, and deferral is not a plan. It is
  recorded as a **cluster-exit condition**: cluster G does not close while the row is
  unanswered. Written as prose alone it would be a promise, and a promise is exactly what gets
  lost between "deferred" and a release — a third of the cluster's scope is the announcement of
  a destructive call, which is not a row to lose quietly.
- Whether `protocol_revision` is *available* to report on stdio. Round 2 narrowed this: stdio
  establishes a revision at `initialize`, so rows 1–3 assert the **negotiated** revision with
  `revision_source` set to the handshake. The open part is only what a record carries for a
  message arriving *before* any `initialize` — there the field is absent, never fabricated,
  and a row is added for that shape once the design's question 1 is answered rather than
  assumed.
