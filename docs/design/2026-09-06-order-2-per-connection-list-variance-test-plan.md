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
| routing profile | yes — `mod.rs:1263`, `spec_preview.rs:47` | yes — `search.rs:376,629,728`, `surfaced.rs:107` | B-01 (2a), B-02 (2b), on `tools/list` |
| spec-preview promotion | yes — `mod.rs:1330`, `spec_preview.rs:112` | **no reader**: `promoted_tools_for_session` is not called from `search.rs` or `surfaced.rs` at all | B-07 (2a), B-06 (2a), B-10 (2b) |
| FSM workflow state | **no reader**: nothing on the `tools/list` path reads it | yes, and only here — four entry points: `code_mode_search` (`search.rs:378`), `search_tools` (`:730`), and `list_tools` / `list_tools_single_server`, which today read the store directly (`:647-650`, `:581-584`) | B-08 (2a), B-09 (2b) |

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
| 2b | spec-preview promotion | **new — B-10**: repaired B-07 covers the cross-connection half; the same-connection half is its own case, the sequence `tools/list` → successful `gateway_invoke` → `tools/list` on one modern connection, with **both** lists asserted against the same pinned literal and the invoke asserted to have succeeded. Feature-gated: it runs only in the `--features spec-preview` job, on the same terms as B-06 | integration | Either list differs from the literal, or the invoke did not succeed. Asserting the two observed lists against each other would pass both when the invoke silently failed (nothing was promoted, so nothing changed) and when a regression moved both lists in step; the pinned literal and the invoke assertion are what remove those two green-while-broken paths. This is the direct statement of 2b and fails against §2 today. |
| 2a | FSM workflow state (§2b) | **new — B-08**: connection A calls `gateway_set_state` to a non-default state; connection B, opened independently, calls **`gateway_list_tools` and `gateway_search_tools`** — both, and not `tools/list`, which reads this store on no path (§7 matrix) — and each result is compared against the pinned default-state literal | integration | B's set differs from the literal — which is what happens today, because A wrote under the key `""` and B reads the same entry. Fails in the **default build**, no feature flag needed. It cannot pass by construction: the fixture must drive the real `gateway_set_state` meta-tool, since the defect is the argument at `mod.rs:1689`, and a fixture calling `SessionStateStore::set_state` directly bypasses the line under test. **What it asserts after (c) depends on Q4, and the case must be written for that** — B-09's row states this and this row did not, which is the asymmetry that would have shipped the weaker case. If Q4 ratifies the refusal, A's `gateway_set_state` is refused on a modern HTTP connection, so A never writes; B then reads the default literal and the case goes green **without ever constructing the leaked state it exists to observe** — green for the wrong reason, and unfalsifiable. So the case asserts *both*, exactly as B-02 does for `gateway_set_profile`: A's call is refused, **and** B's two sets equal the pinned default literal. Written that way it still fails if the refusal is dropped, if B's set moves, or if `gateway_set_state` becomes a silent no-op instead of an error. If Q4 declines the refusal, the leak assertion is the whole case **plus one stimulus pin**: A's `gateway_set_state` must be asserted to have SUCCEEDED, exactly as B-10 asserts of its `gateway_invoke`. Without it a failed or no-op write makes "B's set equals the default literal" true of a world where nothing was ever written — green over an empty stimulus. The ratify branch does not need this line, because its refusal assertion already pins the outcome of A's call; the decline branch had no such pin and that asymmetry is the gap. Note what the pairing costs nothing to say: after (c) the leak is not merely undetected, it is unconstructible from a modern HTTP connection — `session_key` gives that connection no entry to share. **Staging is part of the case, and it is an assertion, not a note**: the discovery filter is `visible_in_states` (`capability/backend.rs:342-343`, `search.rs:196-199,285-288`), and **every fixture in the tree today declares `visible_in_states: vec![]`** — always visible, in every state (V 2026-09-06: 18 sites, all empty). Against such a fixture the tool set is invariant under the FSM state, so a leaked state moves nothing and this case is green whether or not the leak exists. The fixture must therefore register one capability visible in `"default"` and **not** in the state A sets (or the reverse), the pinned literal must be pinned to that staging, and the case must assert the staging held — that the same discovery call made *while the target state is genuinely in force for that connection* returns the OTHER set. Without that last assertion the staging itself is unverified prose and the case decays back to the invariant-fixture version. |
| 2b | FSM workflow state (§2b) | **new — B-09**: on one modern connection, `gateway_list_tools` → `gateway_set_state` → `gateway_list_tools`, and the same sequence again through `gateway_search_tools`, each list compared against the same pinned literal | integration | Either list differs from the literal. Note this case's expected behaviour changes under (c): today the second list differs; after (c) the `gateway_set_state` call is *refused*, and the case must assert the refusal **and** the unchanged lists, exactly as B-02 does for `gateway_set_profile` — asserting only the refusal would pass while the lists diverged. **Staging is part of the case, and it is an assertion, not a note**: the discovery filter is `visible_in_states` (`capability/backend.rs:342-343`, `search.rs:196-199,285-288`), and **every fixture in the tree today declares `visible_in_states: vec![]`** — always visible, in every state (V 2026-09-06: 18 sites, all empty). Against such a fixture the tool set is invariant under the FSM state, so a leaked state moves nothing and this case is green whether or not the leak exists. The fixture must therefore register one capability visible in `"default"` and **not** in the state A sets (or the reverse), the pinned literal must be pinned to that staging, and the case must assert the staging held — that the same discovery call made *while the target state is genuinely in force for that connection* returns the OTHER set. Without that last assertion the staging itself is unverified prose and the case decays back to the invariant-fixture version. |

## Preconditions on the implementation — plan-blocking, not advisory

A test plan normally constrains only tests. Two of these cases are honest **only
if the implementation takes a particular shape**, so the shape is stated here as
a rule that blocks the plan rather than as a note the implementer may weigh.

**1. The fold is load-bearing.** B-08 and B-09 each drive one discovery entry
point, and that is sufficient *only because* (c) folds `list_tools` and
`list_tools_single_server` back into `current_search_state` before guarding it.
The FSM store is not single-owner today: those two read it directly
(`search.rs:581-584`, `:647-650`). If the fold is skipped and `session_key` is
applied to the accessor alone, **B-08 and B-09 go green while `gateway_list_tools`
still reads the shared entry** — a case passing over a live defect, which is
exactly what §P2's second question exists to prevent. An implementation that
skips the fold owes two more cases, one per unfolded reader, before this plan is
satisfied.

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
supplies its own argument asserts against itself.

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

## Open question this plan waits on

**Q4** — whether `gateway_set_state` should be refused on a modern connection in
the default build, as `gateway_set_profile` already is. With the operator, queued
by the team lead, not self-decidable: it changes a tool that succeeds today for a
client doing nothing wrong.

Q4 governs **B-08's and B-09's assertions, not their existence.** Both are
written to assert the refusal *and* the unchanged lists if Q4 ratifies, or the
leak alone if it declines — B-08's row says so, and that conditional phrasing is
what stops it going green without ever constructing the state it observes. B-10
and the repaired B-07 do not depend on Q4 and are unblocked.

## Review record

| leg | vendor | verdict | run |
|---|---|---|---|
| 1 (code/plan) | Codex/GPT | — | blocked: usage limit machine-wide, resets 2026-09-12 06:33 |
| 2 (code/plan) | Grok | — | pending |

Leg 1 is unavailable for every change on this machine until the reset; the
substitution question is with the operator, and the named residual if leg 2 alone
stands is that fact-verification rests on a single vendor.
