# Cluster G — test plan (§P2)

Written before any test code and before any implementation. Reviewed as a plan, then the
tests get their own review as tests.

## Scope

Covers all three cluster-G criteria: `NFR.OBS.1`, `NFR.OBS.2` and `MIK-7246.CONFIRM.1a`.

An earlier revision of this section excluded `CONFIRM.1a` on the grounds that its stdio
behaviour was waiting on the operator. That was wrong, and the reason is worth keeping: the
criterion already specifies the behaviour (fail closed, refuse), so there was never a question
to wait on. Row 13 covers it.

## One row per criterion

| # | criterion | case | level | type | falsifiable how |
|---|---|---|---|---|---|
| 1 | `OBS.1` | a `tools/call` over stdio emits exactly one observed record carrying `method`, `protocol_revision`, `revision_source` | integration | positive | free — stdio emits nothing today |
| 2 | `OBS.1` | **every** non-`tools/call` method the stdio loop accepts emits a record — parameterised over the dispatch arms, not sampled | integration | positive | free — and this is the case that would have caught the round-1 design error |
| 3 | `OBS.1` | a request declaring itself modern while omitting a required field emits a record **and then** returns `-32602` | integration | negative-path | free — and it pins the ordering, not just the presence |
| 4 | `OBS.1` | the same three shapes over HTTP still emit exactly one record each | integration | regression | **not free** — see the honesty section |
| 5 | `OBS.1` | **over stdio**, an inbound message whose handling reaches the meta-MCP layer a second time (playbook step, code-mode step) produces **exactly one** record | integration | exactly-once | free **because the transport is stdio** — `exactly one` fails at zero as well as at two |
| 6 | `OBS.2` | a `tools/list` over stdio emits **exactly one** `tools/list` record, carrying every field the oracle table names | integration | positive + cardinality | free — stdio emits nothing today |
| 7 | `OBS.2` | a `tools/list` over HTTP still emits exactly one, not two, after the change | integration | regression | **not free** — see the honesty section |
| 8 | `OBS.2` | a `tools/list` over HTTP **with the Code Mode URL override active** emits the record, carrying `code_mode` true | integration | regression | **not free** today, but free against the rejected design — see below |
| 9 | `OBS.1` | a notification (no `id`, no response — `notifications/initialized`) over stdio emits exactly one record and carries no response-shaped field | integration | boundary | free — nothing records notifications today |
| 10 | `OBS.1` | a stdio batch of **three** requests emits **exactly three** records, one per element, each carrying that element's own `method` | integration | cardinality | free — and it fails against the one-record-per-envelope shape a transport-entry record naturally takes |
| 11 | `OBS.1` | a stdio batch **mixing** requests and notifications emits one record per element **and** returns responses only for the requests | integration | cardinality + boundary | half free — see below |
| 12 | `OBS.1` | a stdio message arriving **before any `initialize`** emits a record whose `protocol_revision` and `revision_source` are both **absent** — not defaulted, not a sentinel | integration | boundary | free — nothing records it today, and it is the row that stops the absent case drifting into a constant |
| 13 | `CONFIRM.1a` | a destructive `tools/call` over stdio naming a **registered, executable** target, where no confirmation can be obtained, returns the confirmation-refusal response **and** leaves the execution sentinel untouched | integration | fail-closed |
| 14 | `OBS.2` | a `tools/list` whose profile **excludes** at least one tool records the **effective filter decisions** — which filters ran and what each removed — and the record is stamped **before** the response is written | integration | content + ordering | free — the live record names filter *inputs* only, so it cannot carry a decision | free — the gate proceeds today when there is no session, and after this release there is never a session |

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
| `cache_scope` | the literal `private`, written out in the test | the scope table at `src/protocol/cacheable.rs:65`, where `tools/list` is `for_list(true)`, and `for_list` returns `Private` for a caller-dependent list (`:46-52`) — **not** a call to `scope_for_method` |
| `cache_scope_advertised` | `is_modern` — false on a legacy result, which advertises no `cacheScope` | the negotiated revision |

Each expected value is **derived independently in the test**, never copied from the record it
checks — and never obtained by calling the same function the implementation calls. An earlier
revision of this table derived `cache_scope` from `scope_for_method("tools/list")`, which is
the production function itself: the test would have asserted that function equals itself and
stayed green against any wrong scope it returned. A reviewer caught it against this very
paragraph, two rows below the table that broke it. The expectation is now a literal read from
the criterion, so a change in `scope_for_method` shows up as a failure rather than as agreement. A test that reads the record and asserts the record equals itself is the tautology
this table exists to make impossible.

### The criterion asks for two things and the live record carries one

`NFR.OBS.2` requires a record of **which filters ran** *and* the `cacheScope`. The five fields
above cover the second and only gesture at the first: `profile` and `query_present` are the
*inputs* a filter would consume, not the decisions it reached. A profile naming a filter that
matched nothing and a profile naming no filter at all produce the same `profile` string, and an
operator reading that record cannot tell which happened. Presence of an input is not evidence a
filter ran, which is the same tautology the `cache_scope` row above was rescued from.

The site makes this structural, not an oversight. The `info!` at `handlers.rs:993-1004` is
emitted *before* `handle_tools_list_with_url_override` is called — so it runs before the list
is built and physically cannot name what the build decided. Satisfying the criterion means
moving or splitting the record so the decisions are stamped from the list-building path.

**This is a design decision the design did not make** (§P3): the change now alters where a
production record is emitted, not merely what a test asserts. It is recorded here rather than
discovered during implementation. It stays inside what §P0 declared FOR — `NFR.OBS.2` is one
of cluster G's three criteria and this is the half of it nothing covered.

| field | value under test | derived from |
|---|---|---|
| `filters_ran` | the ordered list of filter names the build actually applied — the empty list when none did, never absent | the fixture's profile definition, written out in the test |
| `filtered_out` | the count each named filter removed | the fixture's tool set minus the expected surviving set, computed in the test |

The ordering half uses row 3's mechanism unchanged: a shared sequence counter, the record's
stamp against a marker emitted immediately before the response is written. Row 14 is the only
place `OBS.2` gets an ordering assertion; the criterion's *before that field is advertised to
any real client* is otherwise a claim no case checks.

### The stdio `OBS.2` fixture, stated concretely

Row 6 asserts *every field the oracle table names*, which is only checkable once the fixture
fixes each one. The stdio case runs a gateway with **no profile header possible** (stdio
carries none), Code Mode **off** in config and no URL override, an `initialize` that negotiated
the modern revision, and the request `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` — no
`params`, therefore no `query`. That fixes all five:

| field | literal expected in the stdio case | why |
|---|---|---|
| `profile` | `none` | stdio has no header to carry one; the record's own fallback |
| `code_mode` | `false` | both disjuncts false — config off, no URL override |
| `query_present` | `false` | no `params`, so no `query` |
| `cache_scope` | `private` | as the table above, independent of transport |
| `cache_scope_advertised` | `true` | the handshake negotiated modern |

Row 14 needs a profile and so cannot run over stdio; it runs over HTTP with a profile that
excludes a known tool. That split is deliberate — the two rows check different halves of the
same criterion and cannot share one fixture.

For `OBS.1` the two revision fields get the same treatment:

| case | `protocol_revision` | `revision_source` |
|---|---|---|
| stdio, after `initialize` negotiated a revision | the negotiated value, exactly | the handshake |
| stdio, message arriving before any `initialize` | absent — **not** a sentinel, not a default | absent |
| HTTP, revision declared in the request | the declared value | `_meta` |

The middle row is the one that must not drift into a constant. An absent field and a field
holding a plausible-looking default are indistinguishable to an operator reading the telemetry,
and only one of them is honest.

## Can each case actually fail? (§P2 question 2)

Rows 1, 2, 3, 5, 6, 9, 10, 12, 13 and 14 fail for free: they assert a record that no code emits today, so
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

**Row 11 is half free.** Its record count fails today like the rest, but its second assertion —
that notification elements produce no response envelope — passes today, because `run_stdio`
already writes nothing when the response vector is empty (`src/gateway/server/mod.rs:1594`).
That half is a regression guard on existing behaviour and takes the same probe treatment: make
the batch path emit an empty array unconditionally, and row 11 must go red on the response
assertion while its record assertion stays green. Two halves that fail together would not tell
me which one the row is measuring.

**Row 13 needs no probe.** The criterion states the gate proceeds today when there is no
session, and stdio after this release has no session, so a test asserting refusal fails against
current code. The red is the defect the criterion names, which is the strongest form of the
free failure available.

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

### How the ordering claim in row 3 is observed

Row 9 is **not** covered here, and the earlier heading that claimed it was is withdrawn: a
notification has no response by definition, so there is no second event for a sequence stamp to
order the record against. Row 9 asserts presence, cardinality and the absence of a
response-shaped field — an ordering claim there would have been a promise the mechanism cannot
keep.

Both vendors raised the row 3 half independently: row 3 claims to pin *classifier, then record, then
return*, and naming an order is not observing one. Post-dispatch logging satisfies a
presence assertion just as well as pre-return logging does, so the row as written could not
tell the two apart — it would have been decoration wearing an ordering claim.

The mechanism is a capturing `tracing` subscriber installed for the test, holding a shared
sequence counter that both the captured record and a **dispatch-return marker** stamp. The
marker is emitted immediately before dispatch returns the `-32602` error, *not* when the
response is written. That distinction is the whole mechanism: a counter read at response-write
time is satisfied by logging anywhere inside dispatch, so telemetry emitted after the
classifier had already returned would still pass a claim that it ran before. The assertion is
on the two stamps, not on wall-clock time and not on the order lines appear in a buffer. That
makes the ordering falsifiable by construction: move the record after the marker and the
stamps invert.

### The probes are code, not a one-time manual mutation

Rows 4, 7 and 8 depend on deliberately-wrong implementations to prove they can fail. A probe
run once by hand and described in prose is unrepeatable, and by the next review round nobody
can tell whether it was run or whether the row still measures anything. Each probe is checked
in as a `#[cfg(test)]` wrong-placement variant behind a test-only switch, so re-running the
sensitivity check is a command rather than an act of trust.

### One review finding refused, with its reason

A reviewer asked that the `OBS.2` oracle assert *effective filters* — one derived decision
shared by list construction and telemetry — rather than the raw inputs the record carries. It
is refused, because the record's shape is a deliberate prior repair, not an oversight. The
comment above the live site (`src/gateway/router/handlers.rs:980-988`) records that a record
naming filters that "ran" would be this site's guess about another module's control flow, and
that the guess was wrong in exactly that way before: it named a session profile on every
request, including requests carrying none. Asserting effective filters would require the test
to reconstruct that control flow too, which is the reimplementation trap the fixtures section
below exists to forbid. The five fields are inputs, the record says so, and the oracle checks
them as inputs.

## Fixtures — the trap this plan is trying to avoid

The tests drive the **real** stdio loop and the **real** HTTP handler. A fixture that stands
in for either one would be asserting against a reimplementation of the code under test, and
the record's whole value is that it fires on the path a user's request actually takes. In
particular the malformed case (row 3) must be a genuine malformed request through the real
shape classifier, not a hand-constructed `RequestShape::Malformed` — the ordering being
pinned is *classifier, then record, then return*, and a hand-built shape skips the first two.

## One exclusion this plan makes, and its proof

**An internal caller reaching a destructive operation unconfirmed — no case, because the path
does not exist.** A playbook or Code Mode step dispatches through `ToolInvoker::invoke`
(`src/playbook/engine/mod.rs:180-181`); its only production implementor, `MetaMcpInvoker`
(`src/gateway/meta_mcp/support.rs:229-238`), calls `invoke_tool` with a `{server, tool,
arguments}` **backend** envelope. The confirmation gate keys on *meta*-tool names via
`is_destructive_meta_tool` (`src/gateway/destructive_confirmation.rs:173`) and is reached from
`handlers.rs:1196-1198` alone. A backend invocation cannot name a destructive meta-tool, so
there is nothing for the gate to refuse.

A row 14 asserting this was written and is deleted. It could not have gone red: the state it
tested for is unconstructible, so it would have passed on day one and every day after,
including any day the construction changed underneath it. The exclusion is stronger than the
row was — a case that cannot fail proves nothing, whereas the call chain above proves the
property outright. What would reopen it is a second `ToolInvoker` implementor, or `invoke_tool`
learning to route meta-tool names; either is a change to the cited lines, which is where a
reviewer would look.

Note the contrast with row 5, which survives: an internal step *does* re-enter the meta-MCP
layer, so it can produce a second observability record. It re-enters at `invoke_tool`, below
where the confirmation gate lives. Same caller, two concerns, and only one of them reaches it.

## Three exclusions this plan claimed, all of them withdrawn

Each entry below was written as something the plan deliberately left out. Review found all
three were covered, coverable, or already answered elsewhere, and every one is now a row. They
are kept rather than deleted because the pattern is the same in all three: an exclusion is
cheap to write and reads as rigour, so it is the easiest place for an unexamined assumption to
sit undisturbed. Nothing in this section is outside the plan.

- **Batch requests — the N/A was WRONG and is withdrawn.** An earlier revision of this plan
  recorded batch as not-applicable on the strength of a search. `run_stdio` checks
  `request.is_array()` and routes to `dispatch_batch` (`src/gateway/server/mod.rs:1585-1598`),
  so batch is live on stdio today. Two verification failures produced that claim, and both are
  mine: the first search covered `src/transport/` and `src/protocol/` while the stdio loop
  lives in `src/gateway/server/`, and the second was piped through `head -15`, which cut the
  hits — ripgrep does not sort its output, so a truncated search is not a search. Rows 10 and
  11 cover it. Recorded rather than quietly edited, because the wrong N/A is the more
  instructive artifact.
- The stdio confirmation branch (`CONFIRM.1a`) — **no longer deferred; it was never an open
  question.** The criterion reads *"the destructive-operation confirmation gate MUST refuse
  when it cannot obtain confirmation. Today it proceeds when elicitation is unsupported or
  there is no session — and after this release there is never a session"*
  (`RELEASE-4.0.0-requirements.md:195`). That is a specified fail-closed behaviour, not a
  choice awaiting the operator. Deferring it treated a settled MUST as an open trade-off, which
  would have left a destructive tool callable over stdio without confirmation — and a stated
  limit against a MUST is an unmet requirement, not an accepted risk. Row 13 covers it.
- Whether `protocol_revision` is *available* to report on stdio. Round 2 narrowed this: stdio
  establishes a revision at `initialize`, so rows 1–3 assert the **negotiated** revision with
  `revision_source` set to the handshake. The open part is only what a record carries for a
  message arriving *before* any `initialize` — there the field is absent, never fabricated,
  and a row is added for that shape once the design's question 1 is answered rather than
  assumed. Row 12 pins the absent case as a row of its own, so the decision is a test
  rather than a sentence in this document.
