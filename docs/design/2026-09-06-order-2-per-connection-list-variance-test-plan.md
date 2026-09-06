# MIK-7272.ORDER.2 — test plan

Companion to `docs/design/2026-09-06-order-2-per-connection-list-variance.md`.
That note decides *what to build*; this decides *what proves it*. §P2 requires a
plan reviewed as a plan before any test code exists, and requires it to answer
two questions a design review cannot ask: does every acceptance criterion have a
case or a stated reason it has none, and can each named case actually fail.

**This table was §7 of the design note and has MOVED here, not been copied.** The
note now points at this file. A test plan restated in two places drifts, and the
half nobody is reading is the half that goes stale (H3).

## Scope

FOR: proving that a `tools/list` result, and the tool set shown by the discovery
surface, do not vary per connection (`MIK-7272.ORDER.2a`) or as a side effect of
other requests on the same connection (`MIK-7272.ORDER.2b`), for connections
declaring MCP 2026-07-28, in the mcp-gateway Rust codebase.

OUT: stdio and A2A transport parity, which cluster-g owns and which the design
note §8 records as uncovered by recommendation (c);
`notifications/tools/list_changed`; variation by authorization, which the
criterion permits; whether the spec-preview feature should exist.

Cases `B-01`, `B-02`, `B-06` and `B-07` live in
`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md` and are
**not** restated here — this plan carries their mapping and, for `B-07`, the
repair without which it covers nothing. Cases `B-08`, `B-09` and `B-10` are new
and are specified here in full.

**New cases continue the `B-` series.** An earlier draft called the two FSM cases
`S-01` and `S-02`; those ids are already taken in the sibling plan by the `SUB.2`
cases — `S-01` is POST content negotiation, `S-02` is notification forwarding
(`:57-58`, `:206-223`) — and an implementer following the collision would have
overwritten or split existing coverage.

## Coverage — every criterion against every surface that shows a tool set

The criteria are two. Since Q3 reads them as *what tool set a connection is
shown*, each has to be answered on both surfaces that show one: `tools/list` and
the discovery surface. That is six cells, not three legs, and the legs do not
each reach both surfaces — which is why some cells are empty on purpose.

| leg | reaches `tools/list` | reaches the discovery surface | cases |
|---|---|---|---|
| routing profile | yes — `surfaced.rs:107` (reached only from `mod.rs:1310`), `spec_preview.rs:47`. **Not** `mod.rs:1263`: that `active_profile` read feeds `observe_tools_list` telemetry (`:1259-1262`) and shapes no list | yes — `search.rs:376,629,728` | B-01 (2a), B-02 (2b) on `tools/list`; **B-06 (2a)** on the filtered `tools/list` path, which is a profile case (`spec_preview.rs:47`), not a promotion one |
| spec-preview promotion | yes — `mod.rs:1330`, `spec_preview.rs:112` | **no reader**: `promoted_tools_for_session` is not called from `search.rs` or `surfaced.rs` at all | B-07 (2a), B-10 (2b) |
| FSM workflow state | **no reader**: nothing on the `tools/list` path reads it | yes, and only here — four entry points: `code_mode_search` (`search.rs:378`), `search_tools` (`:730`), and `list_tools` / `list_tools_single_server`, which now delegate to that accessor (`76b8536c`) | B-08 (2a), B-09 (2b) |

Two empty cells need no case, because there is no behaviour in them to assert:
promotion has no discovery-surface reader, and the FSM state has no `tools/list`
reader.

The third is a judgment and is recorded as one — **the profile leg on the
discovery surface has no case of its own.** The reason: the guard is inside
`active_profile` (`mod.rs:1062-1099`), one owner for all eight of its call sites,
so a discovery duplicate of B-01 would drive the same line B-01 already drives
and could not fail independently of it. That reason is conditional on where (c)
puts its filter — see the preconditions below.

## Cases — one row per criterion per leg, with how each can fail

Every case here is an **integration-level functional test** driven through the
real meta-tool surface. None is a unit test, and that is not an oversight: each
defect lives in an *argument passed at a call site* (`invoke.rs:1826-1828`,
`mod.rs:1689`), so a unit test against the store cannot see it. The `level`
column is retained per row so a reviewer can see the uniformity is deliberate
rather than accidental.

| clause | leg | case | level | how it can FAIL |
|---|---|---|---|---|
| 2a — must not vary per connection | routing profile | **B-01**: two modern connections, one binds `X-MCP-Profile`, both tool-name sets compared against the same pinned literal | integration | The binding connection's list differs from the other's, or either differs from the pinned literal. Because the expectation is a pinned literal rather than a comparison of the two lists, a regression that changes *both* connections identically also fails, which a two-way equality assertion would miss. |
| 2a | spec-preview promotion | **B-07, repaired in the sibling plan on 2026-09-06**: as previously written (`:187-204`) the case could not fail against the defect §2 describes. Its premise promotes tool `T` for a **legacy-era** session A and observes it in A's legacy list; the two modern lists it then pins are read under the key `""`, which that promotion never touched, so the case stays green whether or not modern connections share promotions. The repair, now applied there: drive the promotion through **a modern connection's own successful `gateway_invoke`** (`invoke.rs:1826-1828` writes under `Some("")`), move the reverse-A5 observable to a **legacy control connection** whose own list must contain `T` (so a silently no-oping promotion fails the control instead of greening the case), and pin both modern lists to a literal that excludes `T` | integration | After the repair: `T` appears in the other modern connection's list — which is what happens today, because both read `""`. It also fails if the legacy control does not see `T`, which is what catches a promotion that no-ops. Before the repair it could fail on nothing, which was the finding. The fixture must not stub `promote_tool_for_session`, or the case asserts against its own fixture rather than production. |
| 2a | spec-preview preview list | **B-06**: B-01 re-run under `--features spec-preview` with a pinned match-all `params.query` | integration | The two modern connections' filtered lists differ from each other or from one pinned **filtered** literal. Not "differs from the default build's list" — an earlier draft said that, and it cannot hold: `handle_tools_list_filtered` deliberately omits the meta-tools from a filtered response (`spec_preview.rs:28-29`), so the two builds are *expected* to differ and a case asserting otherwise stays red after a correct fix. Covers `spec_preview.rs:46`. Runs only in a job that enables the feature; a suite that never enables it reports green while proving nothing, so the feature-enabled job is part of the case, not an optional extra. |
| 2b — must not vary as a side effect of other requests on the connection | routing profile | **B-02**: `tools/list`, then `gateway_set_profile`, then `tools/list`; both lists compared to the same pinned literal | integration | Either list differs from the literal. Note the case must assert on the *lists*, not on the `gateway_set_profile` response: that call now returns `NO_SESSION_FOR_PROFILE` (§1 fact 4), and a case that asserts only the refusal would pass even if the lists diverged. |
| 2b | spec-preview promotion | **B-10 (existing promotion regression)**: repaired B-07 covers the cross-connection half; the same-connection half is its own case, the sequence `tools/list` → successful `gateway_invoke` → `tools/list` on one modern connection, with **both** lists asserted against the same pinned literal and the invoke asserted to have succeeded. **The promoted tool `T` must be one that is NOT already in the first list, and the pinned literal must exclude it** — promotion is de-duplicated against already-surfaced tools (`mod.rs:1332-1335`), so invoking an already-listed tool leaves both lists identical and the case green while promotion still writes under `""`. Same constraint repaired B-07 carries — and it binds on both merges, since the filtered path de-dups the same way (`spec_preview.rs:113-114`). **Each `tools/list` in the sequence is issued twice, once unfiltered and once with `params.query` set**, so 2b covers the filtered merge (`spec_preview.rs:112`) as well as the unfiltered one (`mod.rs:1330`). Repaired B-07 already forces the query on the 2a side, so the filtered path has 2a coverage; without this, 2b reaches it only if (c) puts the guard inside `promoted_tools_for_session` rather than at the unfiltered call site — and the test plan must not be contingent on an implementation choice it also has to check. (The committed case already pins a literal excluding `echo` and asserts `before` against it; this row is where the constraint was missing.) Feature-gated: it runs only in the `--features spec-preview` job, on the same terms as B-06 | integration | Either list differs from the literal, or the invoke did not succeed. Asserting the two observed lists against each other would pass both when the invoke silently failed (nothing was promoted, so nothing changed) and when a regression moved both lists in step; the pinned literal and the invoke assertion are what remove those two green-while-broken paths. This is the direct statement of 2b and is an expected green regression against the already guarded promotion store. |
| 2a | FSM workflow state (§2b) | **B-08 / MIK-7272.ORDER2.FSM.1**: A drives the real `gateway_set_state` with `Some("")`; assert JSON-RPC protocol refusal (-32600), exact modern-aware message, no result, and no empty-key store write. B then drives all four discovery readers (list, list with server, search_tools, code_mode_search), each pinned to `STAGED_DEFAULT_TOOLS`. Both callers use the router's actual empty session key (`handlers.rs`); no caller has a session. | integration / isolation and error contract | Fails if the write guard is absent, if the method silently succeeds, or if any bystander list changes. The shared state-dependent fixture and its non-empty session staging control prove the observed membership can change. No declined-Q4 branch remains. |
| 2b | FSM workflow state (§2b) | **B-09 / MIK-7272.ORDER2.FSM.2**: on one sessionless caller, pin all four discovery lists before, drive the real state call, assert the same exact refusal and no store write, then pin all four lists after. | integration / sequence and error contract | Fails for a successful or silent-no-op response even when the lists happen to remain unchanged, or for any changed list. Q4 was ratified; success is not an allowed alternative. |

## Preconditions on the implementation — plan-blocking, not advisory

A test plan normally constrains only tests. Two of these cases are honest **only
if the implementation takes a particular shape**, so the shape is stated here as
a rule that blocks the plan rather than as a note the implementer may weigh.

**1. The fold is already complete; FSM.4 falsifies the read guard.** Base
`0d4df3c0` has one discovery-state read in `current_search_state` and all four
entry points delegate to it. No fold is required. B08/B09 pin the refused writer;
a write-only repair can pass them. FSM.4 therefore seeds old empty-key state and
drives all four real discovery readers, exposing an omitted read guard without
requiring the repaired writer to create forbidden state.

**2. The empty profile/discovery cell is conditional on the accessor guard.** The
justification above holds because the filter sits inside `active_profile`. If the
implementation guards at the eight call sites instead, that cell stops being
empty and a discovery-surface twin of B-01 is owed.

Both conditions are checkable against the diff, not against intent: does
`current_search_state` have the only `get_state` read on the discovery path, and
does `active_profile` have the only filter.

## Two properties every case keeps

**Pin a literal, never compare two observed lists.** Every case asserts the
observed tool-name set against a pinned expected set. Two observed lists compared
to each other both move in step under a regression that changes every connection
identically, and the case stays green through it.

**Drive the real meta-tool path.** A fixture calling `promote_tool_for_session`
or `SessionStateStore::set_state` directly bypasses the exact line under test.
The defects are in the arguments passed at those call sites; a fixture that
supplies its own argument asserts against itself. The explicitly named FSM.4
exception seeds an old store entry only as the read-side precondition; its
observations still drive the real discovery entry points.

## A property stated in prose is not a test

Adopted from the header-9 finding: a doc comment asserting that a handshake stays
legacy-shaped "whatever the era" read as coverage and enforced nothing, and the
era-Modern case was never written. That failure is invisible to a reviewer and to
a coverage map alike, because prose claiming a property looks identical to a test
proving one.

Binding here: **every property this plan claims is either an assertion in a named
case, or is recorded as untested.** Before these tests are submitted for review,
their files are searched for properties claimed in comments and not backed by an
assertion; each is a test owed or a line in this section. The two currently
recorded as untested:

- **stdio.** (c) closes neither leg there (`server/mod.rs:1604,1822-1824`, design
  note §5, §8). No case in this plan exercises stdio, and none should — cluster-g
  owns it per §P0. Recorded, not covered.
- **A2A.** Not measured at all. Cluster-g's deferred row.
- **The rest of cluster B.** `B-01`, `B-02`, `B-06` and `B-07` are *specified and
  not implemented*: `tests/tool_list_tests.rs` is 43 lines and contains none of
  them. So `B-08`, `B-09` and `B-10` are the first cases in this lineage to exist
  at all, and the B-07 repair this plan prescribes has no code under it to
  repair. Read this plan as **foundational, not incremental** — a reviewer who
  assumes the sibling cases are in place will judge the new rows against coverage
  that is not there. What that costs concretely: the 2a promotion leg is carried
  by B-07, so until B-07 exists, `B-10` (2b, same-connection) is the *only*
  promotion case with code behind it.

The preceding inventory preserves the original test-plan investigation. At the
prerequisite base `0d4df3c0`, the FSM consolidation `76b8536c` is already present;
it must not be repeated. Current remaining FSM cases and their gate status are
in the checkpoint at the end of this plan. No other cluster is graded here.

## Resolved decision governing B-08 and B-09

**Q4 is resolved.** The operator selected **"Ratify the refusal (recommended)"**
at `2026-09-06T11:19:59.466Z`. The actual question/answer provenance is recorded
in [the design's Q4 decision](2026-09-06-order-2-per-connection-list-variance.md#6-questions-put-to-the-requester--decisions-recorded).
The design and this plan previously retained their OPEN wording after the answer.

Q4 governs **B-08's and B-09's assertions, not their existence.** Execute the
ratified branch described in those rows: assert the refusal *and* unchanged lists,
with the session-bearing positive control proving the fixture's state-dependent
visibility. There is no alternative decline branch in the executable contract. B-10 and the repaired B-07 remain independent of Q4.
Decision recovery does not grade test execution, implementation review or release
acceptance; those remain pending until their evidence is recorded.

Both cases MUST assert the returned error, not merely that the lists did not move.
A `gateway_set_state` that silently does nothing satisfies an unchanged-list
assertion exactly as well as the ratified refusal does, so a case that discards the
call's response cannot tell the repair from its absence — the §P2 failure mode of a
case that passes while the thing it names is broken.

The message is asserted too, and it is NOT today's. HEAD returns
`gateway_set_state requires a session (send Mcp-Session-Id header)`
(`mod.rs:1696`), and the modern HTTP router deliberately ignores that header — so
the remediation it offers a modern caller cannot be followed. The refusal this plan
asserts names the condition rather than an impossible fix. B-10 and the repaired
B-07 never depended on Q4 and stay unblocked.

## Historical review record

Two independent **non-author** legs are required. This work is Claude-authored,
so `gpt`, `grok` and `kimi` are all eligible and any two make a valid pair; the
reviewer that is forbidden here is `claude-review`, not `grok`.

| leg | vendor | verdict | run |
|---|---|---|---|
| 1 | Grok | SHIP-WITH-FIXES | `grok-20260906T071032Z-19225` |
| 2 | Kimi | SHIP-WITH-FIXES (recovered ledger) | `synthetic-20260906T080350Z-26796`; differing material, not closure |
| — | Codex/GPT | MISSING | usage limit machine-wide until 2026-09-12 06:33 |

The GPT row is recorded as **availability, not substitution**: an exhausted
balance is not grounds to swap a vendor, and `MISSING` is the honest state rather
than a stamp another vendor granted. Its practical consequence is narrow — `ratify`
will not accept a stamp without it, so nothing here merges on the current pair —
and the review itself is not short a leg.

**Grok's three HIGH findings are repaired**, each in its own commit: the staged
capability set is now state-dependent (`visible_in_states`), so a leaked state is
what moves the observed set; B-10 pins a literal excluding the promoted tool `T`
and asserts the invoke succeeded; and B-08/B-09 assert A's `gateway_set_state`
outcome rather than only B's list. Grok's `list_tools_single_server` improvement
is taken (`server=` drive added), and the fourth reader `gateway_search` was
found unmapped during that repair and given a drive of its own.

**Declared for the second leg:** this plan was edited after leg 1 read it. The
edits are the repairs above plus this section and the cluster-B untested row.
Leg 2 reads the plan as it now stands, not as leg 1 saw it.


## FSM prerequisite test gate recovery — 2026-09-07

This section carries the remaining FSM requirements of the existing change.
Historical review records above are provenance, not a current passing gate.
B08/B09 currently discard the response: repairing their assertions is mandatory
before runtime integration. Both retain all four pinned discovery observations.
The exact serialized JSON-RPC `error.message` is independently pinned below.
It includes the existing `Error::Protocol` Display prefix from `error.rs`; the
inner `NO_SESSION_FOR_STATE` detail omits that prefix:

> Protocol error: The workflow state is per-session, and this connection has no session. MCP 2026-07-28 removed protocol-level sessions; capability visibility is decided by the authorization presented on each request.

| Criterion | Case and level/type | Falsifier | Result |
|---|---|---|---|
| MIK-7272.ORDER2.FSM.1 | B08: refusal and unaffected bystander; integration/isolation | Missing write guard or silent successful no-op | Pending repaired-test RED |
| MIK-7272.ORDER2.FSM.2 | B09: refusal and same caller lists unchanged; integration/sequence | Success response, impossible remediation text, changed membership | Pending repaired-test RED |
| MIK-7272.ORDER2.FSM.3 | Missing `None` key and empty `Some("")` both refuse with -32600, no result, exact message and no write; integration/boundary | Empty-only guard, missing-key old message, store mutation before refusal | Pending RED |
| MIK-7272.ORDER2.FSM.4 | Seed an old non-default empty-key entry directly as a fixture; assert it exists, then each of four real discovery calls for None/empty sees the default literal; integration/contaminated-state regression | Delete the read guard while leaving the write guard intact | Pending RED |
| MIK-7272.ORDER2.FSM.5 | Existing staging control plus non-empty legacy and `stdio-session` callers successfully change their own state and see the non-default literal while another named caller remains default; integration/compatibility | Overbroad refusal/default read; no-op mutator; shared non-empty keys | Pending control |

Seeded old empty-key state is a deliberate test precondition for the read-side
obligation; it is not reachable through the repaired modern writer and is not
claimed as public functional driving. Real HTTP driving independently exercises
FSM.1/.2, the empty-key branch of FSM.3, and the session-bearing control in FSM.5.
The `None` branch of FSM.3 is N/A to public HTTP driving because the modern router
passes `Some("")`; it is required component evidence, not a public PASS. The seed-only internal
part of FSM.4 is N/A to public drive because production exposes no operation to
create that forbidden state after the fix; its reviewed component evidence is
required instead. Full default/all-feature invocation and existing profile,
promotion and state tests provide regression coverage. No network backend needs
to answer a request for the staged capability listings.

Order: finder confirmation of plan repairs, repaired assertion RED, separate
review of the tests as tests, minimum runtime guard patch, green/fault/coverage
and focused self-QA, final dual code review with isolated functional drive.
The initial CI RED is preserved as baseline evidence and is not falsely reused
as execution of the new refusal assertions. Source line numbers in old sections
are historical; this checkpoint binds symbols and exact isolated revisions.


### Test finder repair: production caller checks

The five criteria and runtime scope are unchanged. GPT test finder r1 requests
caller-boundary regressions in addition to the reviewed component cases; the
coordinator approved this bounded repair. Add one real modern `Router::oneshot`
state-refusal case (with and without an offered session header), using the
existing modern-era fixture and exact error/no-result assertions (FSM.3), and
one `Gateway::dispatch_single` stdio transition sequence proving the previous,
current and owner values in two successful responses (FSM.5). The stdio helper reaches the production `dispatch_single_with_sink` path.
GPT finder r2 additionally requires the production `run_stdio` loop and test to
share one private `STDIO_SESSION_ID` constant, while the test retains its
independent literal owner assertion. This behavior-preserving extraction makes
an empty owner falsify the compatibility case; no OS-pipe claim is made.
These complement the existing modern session-mapping router regression and
retain all component cases, including None and the contaminated empty-key seed.
Expected final focused set: eight cases. Both new caller cases must compile;
modern refusal must assert RED on the base, and the stdio sequence is a positive
control. Independent public HTTP driving is still a final gate; these automated
caller checks do not substitute for it. No stdio/A2A transport policy changes.

Current implementation result: `order2-prerequisite-green.log` records eight
passing cases, actual exit 0; `order2-prerequisite-tests-red-r4.log` records the
pre-guard five assertion failures and three controls. GPT test finder r3 SHIP
(actual 0, material c69da711ac4fa284c21357a68e8a0f8c77569e3b4a8294c325631cbf280d8ee0)
closes the required caller seam; Grok r1 SHIP is retained. All five FSM criteria
pass at their declared component/caller levels. Independent public driving,
quantitative and final code-review gates are still pending.
