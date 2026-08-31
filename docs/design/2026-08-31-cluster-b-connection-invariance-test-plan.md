<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
# Cluster B — test plan (§P2)

Plan only. No test code. Sibling of
`docs/design/2026-08-31-cluster-b-connection-invariance.md`, which this plan
serves and does not restate.

Reviewed as a plan against two questions, and nothing else:

1. does every acceptance criterion have a case, or a stated reason it has none?
2. can every named case actually FAIL?

An empty evidence cell is a finding recorded as one, never tidied away.

## 0. The plan is written against a design with two unanswered questions

The design recommends ORDER.2 option **(a)** with **(b)** as intended end state,
contingent on §4.1; and it blocks SUB.2 implementation on §4.3. A test plan
cannot be more decided than the design it tests. So each case below carries an
**option column**, and the rows that exist only under one branch say so.

This is not hedging. It is the honest shape: writing one set of cases and
labelling it "the plan" would mean deleting or inverting half of them the day the
operator answers, and a plan that must be rewritten by an answer it anticipated
is a plan that was not written.

The two questions are **independent axes**, so the coverage map carries one
column for each. A row gated on §4.3 answering (i) is not thereby a §4.1
option-(b) row, and reading it as one would silently rescope every `SUB.2` case.

| branch | what changes in this plan |
|---|---|
| §4.1 answered **(a)** — profiles preserved, modern path profile-blind | every row survives; `B-05` (legacy still narrows) is load-bearing |
| §4.1 answered **(b)** — profiles removed | `B-05` is **deleted, not inverted** (see §5); `B-03`/`B-04` collapse into "the mechanism is gone" |
| §4.3 answered **(i)** — v4.0.0 must emit | `S-02`…`S-06` are in scope now |
| §4.3 answered **(ii)** — criterion amended to capability-only | `S-02`…`S-06` move to a later release; `S-01` and `S-07` remain, and `S-07` is unaffected either way |

**`S-07` is the only SUB.2-adjacent case that is unblocked today**, because it
tests a shipped correctness defect (§II.2 HTTP first-`data:`-line) rather than
the criterion. It should be written first regardless of how §4.3 resolves.

## 1. Coverage map — one row per acceptance criterion

Levels: **U** unit, **I** integration, **E** end-to-end.

| criterion | case | level | type | §4.1 branch | §4.3 branch |
|---|---|---|---|---|---|
| `ORDER.2` clause 1 (no per-connection variation) | **B-01** two modern connections, one binding `X-MCP-Profile`, both return a tool-name set equal to the same pinned literal | I | differential conformance | a, b | n/a |
| `ORDER.2` clause 1 | **B-06** B-01 repeated with `--features spec-preview` and a pinned match-all `params.query`, covering `spec_preview.rs:46` | I | differential conformance | a, b | n/a |
| `ORDER.2` clause 1 | **B-07** a tool promoted for session A does not appear in session A's modern list, nor differ from session B's, with `params.query` set so `spec_preview.rs:111` is the executing merge | I | differential conformance | a, b | n/a |
| `ORDER.2` clause 2 (no side effect of other requests) | **B-02** `tools/list` → `gateway_set_profile` → `tools/list`, both responses equal to the same pinned literal | I | sequence/idempotence | a, b | n/a |
| `ORDER.2` clause 2 — second writer | **B-04** a modern `initialize` carrying `X-MCP-Profile` does not bind a profile that dispatch honours | I | conformance | a only | n/a |
| `ORDER.2` — listed-vs-callable split created by the fix | **B-03** a named tool the modern list advertises returns its own pinned successful result when called, and is not refused *for profile reasons* | I | invariant | a | n/a |
| `ORDER.2` — legacy unchanged | **B-05** a legacy-era connection still narrows to the pinned profile set | I | regression guard | a only | n/a |
| `ORDER.2` clause 3 (MAY vary by authorization) | **no case — permissive clause.** A `MAY` cannot be violated by not doing it, and §I.3 records that `tools/list` receives no caller context, so there is no authorization-derived variation to observe. A case here would assert the absence of a thing nobody built | — | — | — | — |
| `ORDER.3` (every list filter classified) | **no automated case.** This is a documentation criterion: its artifact is §I.2's eight-row table. **The criteria-status evidence cell does not yet point at it** — at `docs/requirements/RELEASE-4.0.0-criteria-status.md:141` `ORDER.3` still cites only RFC-0061's two-filter table (verified at source, 2026-08-31). Repointing that cell is a step of this plan (§8), not a fact it may assert. See §6 | — | doc review | a, b | n/a |
| `SUB.2` clause 2 — prerequisite | **S-01** POST `tools/call` honours `Accept`: JSON when no stream offered, SSE when offered | I | content negotiation | a, b | either |
| `SUB.2` clause 2 — the criterion | **S-02** a backend's `notifications/progress` — and, separately, its `notifications/message` — during a `tools/call` reaches that call's response stream, before the result, over **stdio** and over **HTTP** | I | forwarding | either | (i) only |
| `SUB.2` clause 2 — request scoping | **S-03** two concurrent calls on one connection, both proven in flight: the notification reaches the provoking call's stream and no other, for both notification methods and both transports | I | isolation | either | (i) only |
| `SUB.2` clause 2 — sink lifetime | **S-04** a notification arriving after the response is dropped and counted, not delivered to the staged next occupant of the slot | I | lifetime | either | (i) only |
| `SUB.2` clause 2 — sink keying | **S-05** a backend frame carrying both `method` and `id` during an in-flight call does not complete an unrelated pending caller, and its notification payload is routed by our per-invocation identity | I | keying | either | (i) only |
| `SUB.2` clause 2 — per-request filter | **S-06** with two calls concurrently in flight, each request's own `log_level` decides which `notifications/message` reach that call's stream, not the session-global value | I | filtering | either | (i) only |
| `SUB.2` — §II.2 in-scope defect | **S-07** an HTTP backend emitting a notification before its result returns the **result** as the `tools/call` response | U | correctness regression | either | either |
| `SUB.2` clause 1 (not on the subscription stream) | **no new case — already `MET` and tested** at `tests/mik_7272_subscriptions_acs.rs:171-185`; Part VI declares it out of scope. Re-testing a passing criterion inside this change adds a row to the coverage map and no evidence | — | — | — | — |
| gateway-originated progress | **no case.** Design option (c) is not recommended and invents an unrequested policy. A test would specify behaviour nobody has asked for | — | — | — | — |
| `tools/list_changed` never fired (Part III item 1) | **no case pending §4.1.** Under (b) the defect stops existing; under (a) it belongs to the ORDER.2 increment already editing that path. Writing a case now risks a case that can never go green — see §5 | — | — | — | — |
| backend-cache time variation (§I.2 last row) | **no case, by classification.** Legal-but-time-varying; a case asserting list stability across cache warm-up would fail for a legal reason. Out of scope per Part VI | — | — | — | — |

## 2. Each case, and the proof it can fail

The bar is not "the case is plausible". It is: **name the implementation that
makes it go red.** A case with no such implementation is decoration.

Notation: *falsifier* = the code state under which the case fails. *premise* =
an assertion the case makes about its own fixture, without which the case could
pass for a reason unrelated to the rule.

Every case carries both, and each premise answers two questions or it is not a
premise: **did the stimulus really happen** (the mock emitted, the store holds
the value, the promotion took), and **did the comparison receiver really exist**
(the second call was in flight, the second stream was open, the control run
returned something). A negative assertion with neither answered is satisfied by
an empty world.

### B-01 — two connections, one tool set

Two modern-era connections to one gateway. Connection A `initialize`s with
`X-MCP-Profile: narrow`; connection B with no header. Both call `tools/list`.

- assert A's tool-name set **equals a pinned literal set**, and B's equals the
  same literal. Not `set_a == set_b` — that holds when both are empty and when
  both are identically wrong (A3, A8).
- **premise, option (a) only:** in the legacy-era control run, A's set is a
  strict subset of B's. Without this the case passes whenever `narrow` happens to
  deny nothing, which is the A5 shape: the fixture stages a profile that never
  decides. **Under option (b) this premise is dropped, not weakened** — profiles
  are gone in every era, so no run can demonstrate narrowing, and a premise that
  cannot be satisfied makes the case unsatisfiable rather than strict. What
  survives under (b) is the pinned-literal assertion alone.
- *falsifier:* today's code — `active_profile(session_id)` narrows A.

### B-02 — the side-effect clause

One modern connection. `tools/list` → `gateway_set_profile("narrow")` →
`tools/list`. Assert both responses' tool-name sets equal the same pinned
literal.

- **premise:** `gateway_set_profile` returned success (or, under the chosen
  option, an explicit refusal — assert *which*, since "the profile did not
  change the list" is satisfied both by a correct fix and by a meta-tool that
  silently errored). A9: one variable, and the case must say which of the two
  outcomes it accepts.
- *falsifier:* today's code — the second list is smaller.

### B-03 — listed is callable (option (a) only)

This is the case that catches §I.5's "close every writer". The fixture writes
`narrow` into the session profile store **directly**, not through any protocol
writer: option (a) closes every modern writer, so a case that binds the profile
through one is either unsatisfiable after the fix or vacuous before it. Name a
tool `T` that is in the pinned full set and that `narrow` denies. A modern
connection lists, then calls `T`.

- **premise:** the store actually holds `narrow` for this session, and `narrow`
  denies `T` — both asserted, the second by the legacy-era control run's list
  omitting `T`. Without the second, a profile that denies nothing makes the case
  green (A5).
- assert `T` appears in the modern list, **and** that calling `T` returns `T`'s
  own successful result — pinned by the literal `content` shape the scripted
  backend returns, with `isError` absent (A2). "Not refused for profile reasons"
  is not enough on its own: tool-not-found, an admin-gate refusal, or any
  unrelated error all satisfy it (A3). The profile-refusal discrimination stays
  as a **second** assertion, so a wrong-reason refusal is still named as one.
- *falsifier:* an implementation that skips `active_profile` on the list path
  only and leaves dispatch reading the session profile. That is precisely the
  half-fix the design warns about, and no other case in this plan detects it.

### B-04 — the second writer

Modern `initialize` with `X-MCP-Profile: narrow`, then `tools/call` on the same
named tool `T` that `narrow` denies.

- **the case must say which `initialize` outcome it accepts (A9).** Two are
  permitted by the design: the header is ignored, or `initialize` refuses
  explicitly. They are different behaviours and a case accepting either proves
  neither. This plan pins **ignored**: `initialize` succeeds and the header has
  no effect. If the implementation chooses explicit refusal instead, this case is
  rewritten to assert that refusal by its pinned error code — not widened to
  accept both.
- assert calling `T` returns `T`'s own successful result, pinned the same way as
  in B-03, with the profile-refusal discrimination as the second assertion.
  Asserted through observable protocol behaviour, never by reading `MetaMcp`'s own
  profile field and comparing it to the value the module computed (A8).
- **no list-equals-full-set assertion here.** B-01 already owns that observation
  on an `initialize`-with-header fixture; repeating it adds a row to the coverage
  map and no evidence.
- *falsifier:* today's code binds at `mod.rs:1060-1068`; also fails against an
  implementation that closes `gateway_set_profile` alone.

### B-05 — legacy unchanged (option (a) only)

Legacy-era connection, `X-MCP-Profile: narrow`, `tools/list`.

- assert the set equals a **pinned narrowed literal** — not "smaller than the
  full set", which passes if the profile starts denying everything.
- *falsifier:* an era-blind fix that removes profiles for all callers.
- **under option (b) this case is deleted, not inverted.** Inverting it would
  produce a case asserting that a removed feature is absent, which is a tautology
  over deleted code and cannot fail. §5 records this.

### B-06 — the `spec-preview` entries

**B-01 only**, repeated with the feature enabled and `params.query` pinned to a
match-all value, so `spec_preview.rs:46` is the executing path. Not B-02 as well:
folding two rules into one case breaks two things at once (A9), and an unpinned
query is free to narrow the list legally, which would make the pinned-literal
assertion unsatisfiable rather than strict.

- **the case is worthless unless CI compiles the feature.** A feature-gated test
  in a matrix that never enables the feature is the purest form of a case that
  cannot fail: it never runs, and the coverage map counts it. Verifying the CI
  matrix enables `spec-preview` is a **step of this plan**, not an assumption —
  and it covers **every** `spec-preview` row, B-06 and B-07 alike.
- *falsifier:* a fix applied to `surfaced.rs`/`mod.rs` only, which the design
  explicitly says was the pre-review omission.

### B-07 — promoted tools

Promote tool `T` for session A (`spec-preview`). Modern `tools/list` on A and on
B, **with `params.query` set**, so the promotion merge at `spec_preview.rs:111`
is the code actually executing. Without that, the `:111` skip can be deleted and
every case in this plan stays green — B-06 exercises `:46` only.

- **premise, and it must name an observable (reverse A5):** in a legacy-era
  `tools/list` for session A the returned set **contains the literal `T`**, and
  session B's does not. "Assert the promotion was recorded" names nothing a test
  can read without reaching into `MetaMcp` (A8), and a promotion that silently
  no-ops would otherwise make the case green against an implementation that still
  leaks promotions.
- assert both modern sets equal the same pinned literal, and that the literal
  **does not contain `T`**.
- *falsifier:* today's `mod.rs:1156` append, and — because the query is set — a
  fix that skips the profile at `:46` while leaving the promotion merge at `:111`
  intact.

### S-01 — POST content negotiation

Three runs of one `tools/call`, varying **only** the `Accept` header (A9):
absent; `application/json`; `text/event-stream, application/json`.

- assert the response `Content-Type` equals a named literal per run —
  `application/json` for the absent-header run, `application/json` for the JSON
  run, `text/event-stream` for the SSE offer — **and, in the two JSON runs, that
  the body is a JSON-RPC response whose `id` equals the literal id the test sent
  and whose `result` matches the pinned key set**. A header assertion alone is
  satisfied by an empty or absent body (A3).
- in the SSE run, assert the stream carries exactly one JSON-RPC response whose
  `id` equals the **literal id the test sent** (A8: not `response.id ==
  request.id` read back off the same object), then closes.
- *falsifier:* today — POST inspects `Accept` nowhere, so the SSE run returns
  JSON; and an over-eager implementation that always streams fails run 2.

### S-02 — the criterion itself

A scripted mock backend emits a notification mid-call, then the result. Four
runs: **stdio** and **HTTP/SSE** — because §II.2 shows two structurally different
discard sites and a single-transport case proves the criterion for one of them —
each run once for `notifications/progress` and once for `notifications/message`.
Both methods, because the forwarding sites treat them separately and a plan that
only ever stages `progress` leaves `message` free to be dropped, or routed
session-globally, with the whole suite green.

- assert: the caller's stream carries the notification, identified by pinned
  literals from the script — the `progress` runs by `progressToken` and
  `progress`, the `message` runs by `level`, `logger` and `data`. A message
  notification carries no progress fields, so one assertion demanding both sets
  is unsatisfiable on half the runs. Then the result; in that order; and the
  result is the tool result, not the notification.
- **premise:** the mock actually emitted before the result — asserted from the
  mock's own recorded script, so a mock that silently emitted nothing cannot
  make the case pass by delivering nothing.
- **the HTTP runs are sequenced after S-07.** At HEAD the HTTP falsifier is the
  first-`data:`-line defect that S-07 owns, so running them now would go red for
  a rule that is not forwarding (A9). After S-07 lands, the HTTP falsifier is
  restated as: the remaining SSE lines are discarded rather than forwarded to the
  caller's stream.
- *falsifier:* today's stdio, which drops it (`stdio.rs:416-431`); and, after
  S-07, an HTTP path that returns the result correctly and forwards nothing
  (`http/mod.rs:929-944` is the site).

### S-03 — request scoping

Two concurrent `tools/call`s on one connection; the backend emits one
notification attributable to call 1. Run for `notifications/progress` and again
for `notifications/message`, and on **both transports** — HTTP has two streams
and stdio one pipe plus an identity, which are different ways to get the routing
wrong, and S-02 already established that one transport does not stand for both.

- **premise:** both dispatches are registered before the notification is emitted
  — a barrier the mock releases only once the harness has observed both calls
  pending. Without it, "call 2 carries zero notifications" is satisfied by a call
  2 that had not started, or had already finished, or whose stream was never
  created (A3).
- assert call 1's stream carries **that** notification (identity pinned by
  `progressToken`, or by the message payload literal, A4); call 2's carries
  **zero**; and **both calls return their own pinned results and close**. A count
  assertion alone passes when the right number arrives on the wrong stream.
- *falsifier:* any session-keyed delivery — which is every primitive in
  `streaming.rs` today, so this case is the one that fails against the most
  plausible wrong implementation (reusing `broadcast`).

### S-04 — sink lifetime

Backend emits a notification **after** its result. The design decides these are
dropped and counted.

- **the next occupant is staged, because it is the unique falsifier.** Call 1
  completes; call 2 starts and reuses the slot; only then is the late
  notification released. Assert call 2's stream does not carry it, call 2 returns
  its own pinned result, and no stream received it at all. Without the second
  call the case cannot see the defect it is named after — a sink removed after
  the response delivers into whatever occupies the slot next, and with the slot
  empty there is nothing to deliver into.
- assert a drop counter increased by **exactly one** (A1 — pin the permitted
  value, not just "greater than zero", or a fix that double-counts passes).
- run on both transports, or record here why the sink sits above the transport
  and one run therefore covers both. Not assumed silently.
- **this case imposes a requirement on the implementation**: the counter must be
  observable. If the increment is not exposed, the case degrades to "nothing was
  delivered", which is also true when the notification never left the mock. That
  degraded form is recorded in §6 as a weakness, not silently accepted.
- *falsifier:* a sink removed after the response is written rather than before
  it, which delivers into whatever occupies the slot next.

### S-05 — keying, and the frame this plan must not assume is broken

A backend sends a frame carrying **both** `method` and `id` — a server-initiated
request — while an unrelated call is in flight.

- assert: no pending caller is completed by it; **and** that a
  `notifications/progress` the mock is required to emit during the same in-flight
  call — with a `progressToken` pinned to a literal from the script — arrives on
  the stream of the call whose **request id is the literal the test sent**. The
  first draft asserted that "any notification routed during the call reaches the
  stream identified by our per-invocation identity": nothing required a
  notification to exist, so an implementation emitting none passed, and the
  expected side named the mechanism under test rather than a literal (A3, A8).
- **premise:** the mock's recorded script shows the notification was emitted
  while the frame carrying both `method` and `id` was in flight.
- **written against the fixed deserializer, and it must not restate that fix.**
  The mis-parse itself — such a frame deserialized as a response, completing an
  unrelated pending caller — is being repaired in parallel and already has its
  own written cases: `handle_response_rejects_inbound_request_and_leaves_caller_pending`
  (stdio), `parse_sse_response_rejects_inbound_request_frame` (HTTP),
  `response_deser_rejects_frame_carrying_method` (protocol), with
  `parse_sse_response_accepts_response_frame` and
  `message_enum_still_classifies_both_frame_shapes` as guards. Those are running
  tests; this row defers to them and **adds no case at the deserialization
  layer**. S-05 keeps only the rule they do not cover: which stream a
  notification reaches while such a frame is in flight.
- the stdio case's third assertion — the pending map still holds the id — is the
  reverse-A5 premise this row would otherwise have had to stage for itself:
  `is_err()` alone cannot separate a rejected frame from a silently consumed one.
  Recorded as a dependency, not duplicated.
- sequenced **after** that fix lands. At HEAD S-05 would go red for the
  mis-parse, not for its own rule (A9 — one thing broken at a time).
- **WebSocket is not a third site and gets no row.** `classify_frame` routes a
  frame carrying both `id` and `method` to `McpFrame::Request`
  (`src/transport/websocket.rs:128-130`), and the response branch (`:131-132`)
  additionally requires a result or an error. Verified at source, recorded in the
  design at `e838c037`.
- **both transports**, for the same reason as S-03: a frame carrying `method`
  and `id` reaches stdio and HTTP through different parsers, and the deserializer
  cases this row defers to are themselves per-transport.
- *falsifier, after that fix:* a sink keyed by the backend's `id`, which the
  backend is free to reuse.

### S-06 — the per-request filter

Two **concurrent** calls on one connection, differing only in the request's
`log_level` (A7 — the named value is proven by changing it, not by observing it
once). Concurrent rather than sequential: with one call in flight at a time, a
session-global filter that happens to be re-read per call is indistinguishable
from a per-request one, and F7's whole point is that `notifications/message`
must not be routed session-globally.

| call | request `log_level` | backend emits | assert |
|---|---|---|---|
| 1 | `warning` | one `debug`, one `error` message | that stream's forwarded set **equals** the single named `error` message, pinned by its payload literal |
| 2 | `debug` | the same two | that stream's forwarded set **equals** both, pinned by both payload literals |

- set equality, not "only the error one is forwarded": a stream that forwarded
  nothing also forwards no `debug` message (A3).
- **premise:** the session-global `MetaMcp::log_level` is held at one fixed value
  for the whole run, and both calls are in flight when the backend emits. Without
  the first, call 2 passing proves nothing — the session value could be doing the
  deciding, which is exactly today's behaviour (Part III item 2). Without the
  second, call 2's empty stream satisfies its own assertion vacuously.
- *falsifier:* today — `RequestFields::log_level` has no reader, so run 1 and
  run 2 behave identically.

### S-07 — the HTTP first-`data:`-line defect

Unit-level, at `src/transport/http`. Feed a scripted SSE response whose first
`data:` line is a `notifications/progress` and whose second is the JSON-RPC
result.

- assert the returned value is the **result**, with `id` equal to the literal the
  test wrote and the result payload pinned by shape (A2 — key set, not length).
- *falsifier:* today's loop returns the first `data:` line.
- unblocked by §4.3; write it first.

## 3. Why these levels, and where the plan deliberately has no unit tests

Levels were chosen from what **decides** the behaviour, not from the design's
happy path.

- **ORDER.2 is integration-only, on purpose.** The criterion is a property of the
  response two connections receive. A unit test over the resolver can assert that
  one function ignores a profile; it cannot see the second entry through
  `spec_preview.rs`, and it cannot see the listed-vs-callable split at all. A
  green unit suite over the four skip sites is compatible with a connection still
  getting a different list.
- **S-07 is unit, on purpose.** It tests one loop's framing decision with no
  gateway in the picture; an integration case for it would be slower and would add
  failure modes that are not the defect.
- **No end-to-end row anywhere.** E2E here would mean a real backend process and a
  real client over a socket. Every rule in this cluster is decided inside the
  gateway with a scripted counterpart, so an E2E case would exercise the same
  decisions with more moving parts and a worse failure message. A deliberate
  absence with its reason — an E2E smoke over `S-02` is additive and cheap once
  `S-02` exists, if the operator wants one.

## 4. A1-A9 self-sweep — what it caught in this plan

Run before review, per the protocol. Findings the author generates cost one edit;
the same findings from a reviewer cost a round each.

| rule | what the first draft did | corrected to |
|---|---|---|
| A3 | B-01 asserted `set_a == set_b` | both sides pinned to a literal set, so equality of two wrong lists no longer passes |
| A5 | B-01 had no premise, so a profile denying nothing made it green | legacy control run asserts the profile is capable of narrowing |
| A5 reverse | B-07 assumed the promotion took effect | the promotion is asserted before the lists are compared |
| A7 | S-06 was a single run at one log level | two runs differing only in the request value, with the session value pinned |
| A8 | S-01 compared the response id to the request object it had just built | pinned to the literal id the test wrote |
| A9 | S-05 would have gone red at HEAD for a defect belonging to another change | sequenced after that fix; assertion re-pointed at sink routing |
| A9 | B-03 accepted "the call did not error" | error kind discriminated: profile refusal vs admin refusal |
| A1 | S-04 asserted a counter "increased" | exact delta of one |
| A2 | S-07 asserted the result by length | pinned key set |

Two of these — A7 on `S-06` and A5 on `B-01` — are the ones the author of the
rules was most likely to miss, because both concern the fixture rather than the
assertion, and the assertions read as careful either way.

### 4a. What the sweep missed and the review caught

Recorded because a sweep table listing only its own successes is the same
self-comparison it exists to refuse. Three reviewers, eighteen findings, none
disputed; almost all were instances of four classes the sweep had already run
against and passed:

| class | where the sweep passed it | the finding |
|---|---|---|
| A3 — a negative assertion true of an empty world | `B-03`/`B-04` "not refused for profile reasons"; `S-03` "zero notifications"; `S-06` "only the error one" | tool-not-found, an absent stream, and a stream that forwarded nothing all satisfy the assertion. Every one is now a **set or result equality against a literal** |
| A5 — the case's own path is never executed | `B-06`/`B-07` never staged a promotion on the `spec_preview.rs:111` merge | the `:111` skip could be deleted with the suite green. `B-07` now sets `params.query` |
| A5 — a premise the correct fix makes unsatisfiable | `B-03` bound the profile "by whatever writer remains reachable"; `B-01`'s narrowing premise under option (b) | option (a) closes every writer and (b) removes profiles. Staging is now **direct**, and the premise is branch-scoped |
| A9 — red for the wrong rule | `S-02`'s HTTP run at HEAD is `S-07`'s defect | sequenced after `S-07`, falsifier restated |

The sweep was run and it was not sufficient. That is the honest result, and it is
the reason §8 keeps the red-run reason log as a step rather than a formality.

## 5. Cases that could not go green, and what was done about them

The failure mode a coverage map cannot see. Three candidates were written and then
removed or re-shaped:

1. **"`tools/list_changed` fires when the profile changes."** Under option (b)
   there is no profile change to announce and the case is unsatisfiable; under (a)
   the announce path belongs to an increment that has not been designed. Either
   way the case would sit red for a reason unrelated to any rule. **Not written**;
   the row in §1 says so and points at §4.1 of the design.
2. **"The legacy path still narrows", inverted for option (b).** Asserting that a
   deleted feature is absent is a tautology over code that no longer exists.
   **Deleted under (b), not inverted.**
3. **`B-06` as first drafted.** Two problems. A `spec-preview` case in a CI
   matrix that never enables the feature never runs — kept, with the CI-matrix
   check promoted to an explicit step covering `B-06` and `B-07` both, because
   the case is evidence only once something proves it executed. And it folded
   `B-01` and `B-02` into one case with an unpinned `params.query`, which breaks
   two rules at once and could be **unsatisfiable** whenever the query narrows
   the list legally. Now `B-01` only, query pinned to match-all.

**A step of this plan, not an afterthought:** when the suite is first written it
will be red end to end, and the reason of *every* case must be read individually.
An assertion failure is the free proof that the case can fail; an error — a
missing mock method, a harness panic, a fixture that cannot be constructed — means
the case would also have failed against a correct implementation. Budget it.

## 6. Criteria with no honest failing case, stated plainly

- **`ORDER.3`.** No automated case exists and none is proposed. The criterion is
  that the classification of list-affecting inputs is complete; its artifact is a
  table. A test could assert the eight inputs are the eight inputs only by
  re-deriving them from the module, which is A8. **Residual accepted:** a ninth
  input added later will not turn a test red. The mitigation is human, **and it is not in place yet**: at
  `docs/requirements/RELEASE-4.0.0-criteria-status.md:141` the `ORDER.3` evidence
  cell still cites only RFC-0061's two-filter table, not the design's eight-row
  §I.2 (verified at source). Repointing it is §8 step 2. Until then the criterion
  rests on a narrower artifact than this plan claimed. Weaker than a test either
  way, and recorded as such rather than counted as coverage.
- **`ORDER.2` clause 3 (`MAY` vary by authorization).** Permissive; there is
  nothing a test could falsify.
- **`S-04` in its degraded form.** If the drop counter is not observable, the case
  cannot distinguish "dropped correctly" from "never emitted". Recorded as a
  requirement on the implementation; if it is not met, the case is weak and this
  plan says so rather than counting it.
- **Everything gated on §4.3.** `S-02`…`S-06` cannot be finalized while that
  question is open, because the design cannot yet say what is emitted. This is the
  design's own deferred unknown, inherited unchanged, not a new one.

## 7. DoR check — applicable gates

| gate | verdict |
|---|---|
| B4 acceptance criteria | **PASS** — every row keys to a `MIK-7272.*` ID already carried in `docs/requirements/RELEASE-4.0.0-criteria-status.md`; no new IDs invented |
| C2 test strategy | **PASS** — §1 and §3 |
| C11/C12 contract tests | **PASS** — `B-01`…`B-07` and `S-01`…`S-06` are protocol-contract cases against the MCP wire surface |
| T2 existing code search | **PASS** — `SUB.2` clause 1 is already covered at `tests/mik_7272_subscriptions_acs.rs:171-185`, and the mis-parse has five running cases owned by the parallel change; neither is duplicated here |
| G6 alternatives | **PASS** — levels chosen against rejected alternatives, §3 |
| G8 risks | **PASS** — §5, §6 |
| G10-G12 fail-fast | **PASS** — `S-07` and `B-01` are the cheapest cases that would invalidate the design's central claims, and both are unblocked today |
| T0 contribution class | reliability / compliance — conformance to a published protocol revision |
| G1-G3 ROI | **N/A with reason** — release-blocking conformance criteria, mandate-justified; a conformance gate does not get an NPV |
| G13-G14 moat | **N/A with reason** — `T0` is compliance; the DoR's own auto-skip applies |
| T1, T1b beyond-SOTA | **N/A with reason** — no technology is being selected; the harness is the repository's existing `cargo test` |
| T1c PQC | **N/A with reason** — no cryptographic primitive in scope |
| T6 numerical discipline | **N/A with reason** — no quantization, parallelism or collective |
| L1-L7 legal | **N/A with reason** — no dependency, personal data, or export surface added |
| G20 profiling-first | **N/A with reason** — not a performance change |

## 8. Order of work

1. `S-07` — unblocked, covers a shipped defect, smallest. Everything HTTP in
   `S-02` waits on it, so it is first for two reasons.
2. Verify the CI matrix enables `spec-preview`; without it `B-06` and `B-07` are
   both decorative. In the same step, repoint the `ORDER.3` evidence cell at the
   design's §I.2 — §6 records that it does not point there today.
3. `B-01`, `B-02`, `B-06`, `B-07` with their premises. All four are clause-1
   cases that fail at HEAD under either §4.1 branch, so they are the design's
   fail-fast batch and none of them waits on the answer.
4. `B-03`, `B-04`, `B-05` once §4.1 returns — these are the rows the answer
   actually moves.
5. `S-01`, then `S-02`…`S-06` once §4.3 returns; `S-02`'s HTTP runs after step 1;
   `S-05` only after the parallel mis-parse fix and its five cases have landed.
6. Run the red suite, read every failure **reason**, and record which were
   assertion failures and which were errors. `B-03` and `B-04` are named
   explicitly here: both turn on a listed-vs-callable split, and a setup error in
   either reads exactly like the split they exist to detect, so neither counts as
   evidence until its red reason is classified.
