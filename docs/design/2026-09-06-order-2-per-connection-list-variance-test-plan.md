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
| 2b | spec-preview promotion | **new — B-10**: repaired B-07 covers the cross-connection half; the same-connection half is its own case, the sequence `tools/list` → successful `gateway_invoke` → `tools/list` on one modern connection, with **both** lists asserted against the same pinned literal and the invoke asserted to have succeeded. **The promoted tool `T` must be one that is NOT already in the first list, and the pinned literal must exclude it** — promotion is de-duplicated against already-surfaced tools (`mod.rs:1332-1335`), so invoking an already-listed tool leaves both lists identical and the case green while promotion still writes under `""`. Same constraint repaired B-07 carries — and it binds on both merges, since the filtered path de-dups the same way (`spec_preview.rs:113-114`). **Each `tools/list` in the sequence is issued twice, once unfiltered and once with `params.query` set**, so 2b covers the filtered merge (`spec_preview.rs:112`) as well as the unfiltered one (`mod.rs:1330`). Repaired B-07 already forces the query on the 2a side, so the filtered path has 2a coverage; without this, 2b reaches it only if (c) puts the guard inside `promoted_tools_for_session` rather than at the unfiltered call site — and the test plan must not be contingent on an implementation choice it also has to check. (The committed case already pins a literal excluding `echo` and asserts `before` against it; this row is where the constraint was missing.) Feature-gated: it runs only in the `--features spec-preview` job, on the same terms as B-06 | integration | Either list differs from the literal, or the invoke did not succeed. Asserting the two observed lists against each other would pass both when the invoke silently failed (nothing was promoted, so nothing changed) and when a regression moved both lists in step; the pinned literal and the invoke assertion are what remove those two green-while-broken paths. This is the direct statement of 2b and fails against §2 today. |
| 2a | FSM workflow state (§2b) | **new — B-08**: connection A calls `gateway_set_state` to a non-default state; connection B, opened independently, calls **`gateway_list_tools` and `gateway_search_tools`** — both, and not `tools/list`, which reads this store on no path (§7 matrix) — and each result is compared against the pinned default-state literal | integration | B's set differs from the literal — which is what happens today, because A wrote under the key `""` and B reads the same entry. Fails in the **default build**, no feature flag needed. It cannot pass by construction: the fixture must drive the real `gateway_set_state` meta-tool, since the defect is the argument at `mod.rs:1689`, and a fixture calling `SessionStateStore::set_state` directly bypasses the line under test. **Q4 was ratified on 2026-09-06 — option (c), `gateway_set_state` refuses a sessionless caller in the default build — and this row is written for that answer, not around it.** The consequence is not a caveat, it is the case's shape: A's `gateway_set_state` is now refused on a modern HTTP connection, so A never writes, B reads the default literal, and a row asserting *B's set equals the literal* goes green **without ever constructing the leaked state it exists to observe** — green for the wrong reason, and unfalsifiable. B-08 therefore asserts **the refusal**: A's `gateway_set_state` returns the `NO_SESSION_FOR_STATE` error and the store is unwritten. The list comparison stays in B-09, which reaches the store on a path that still writes. One fixture fact the row owes an implementer, because it looks like a shortcut and is not: **A and B carry the same session tuple**. A modern HTTP connection presents `Some("")` (`server/mod.rs:1604` supplies it), so below the transport two independently opened connections are one key — which is the defect this case exists to state, not a corner the fixture cut. After (c) `session_key` maps that key to `None` and neither connection can hold a state, so the shared entry stops existing rather than stops being shared. What separates this case from B-09 is therefore the claim, not the fixture: B issues no `gateway_set_state` of its own. So the case asserts *both*, exactly as B-02 does for `gateway_set_profile`: A's call is refused, **and** B's two sets equal the pinned default literal. Written that way it still fails if the refusal is dropped, if B's set moves, or if `gateway_set_state` becomes a silent no-op instead of an error. If Q4 declines the refusal, the leak assertion is the whole case **plus one stimulus pin**: A's `gateway_set_state` must be asserted to have SUCCEEDED, exactly as B-10 asserts of its `gateway_invoke`. Without it a failed or no-op write makes "B's set equals the default literal" true of a world where nothing was ever written — green over an empty stimulus. The ratify branch does not need this line, because its refusal assertion already pins the outcome of A's call; the decline branch had no such pin and that asymmetry is the gap. Note what the pairing costs nothing to say: after (c) the leak is not merely undetected, it is unconstructible from a modern HTTP connection — `session_key` gives that connection no entry to share. Each case drives a **third** discovery call, `gateway_list_tools` with `server=` set to the staged capability backend, to reach `list_tools_single_server` (`search.rs:581-584`) — the one FSM reader the other two calls do not touch. **Staging is part of the case, and it is an assertion, not a note**: the discovery filter is `visible_in_states` (`capability/backend.rs:342-343`, `search.rs:196-199,285-288`), and **every fixture in the tree today declares `visible_in_states: vec![]`** — always visible, in every state (V 2026-09-06: 18 sites, all empty). Against such a fixture the tool set is invariant under the FSM state, so a leaked state moves nothing and this case is green whether or not the leak exists. The fixture must therefore register one capability visible in `"default"` and **not** in the state A sets (or the reverse), and the pinned literal must be pinned to that staging. Without a proof that the staging held, the staging is unverified prose and the case decays back to the invariant-fixture version — but **that proof must not be phrased as a discovery call from a modern HTTP connection made while the target state is in force**. On the Q4-ratify branch no modern connection can hold a non-default state after (c) — that is what (c) is for — so a staging assertion of that shape is unsatisfiable on that branch and the case is red forever: `test-plan-honesty`'s second survivor, a case that can never go green, not the one this repair was guarding against. The proof therefore runs on a **session-bearing connection**, one that legitimately owns a session id so its `gateway_set_state` is refused under neither answer to Q4, driving the same discovery entry point: set the state, observe the OTHER set. That proves both halves the staging needs — the capability is genuinely state-dependent, and the discovery path honours the dependence — and it is Q4-independent. The leak assertion then asserts only what its own branch permits. |
| 2b | FSM workflow state (§2b) | **new — B-09**: on one modern connection, `gateway_list_tools` → `gateway_set_state` → `gateway_list_tools`, and the same sequence again through `gateway_search_tools`, each list compared against the same pinned literal | integration | Either list differs from the literal. Note this case's expected behaviour changes under (c): today the second list differs; after (c) the `gateway_set_state` call is *refused*, and the case must assert the refusal **and** the unchanged lists, exactly as B-02 does for `gateway_set_profile` — asserting only the refusal would pass while the lists diverged. Each case drives a **third** discovery call, `gateway_list_tools` with `server=` set to the staged capability backend, to reach `list_tools_single_server` (`search.rs:581-584`) — the one FSM reader the other two calls do not touch. **Staging is part of the case, and it is an assertion, not a note**: the discovery filter is `visible_in_states` (`capability/backend.rs:342-343`, `search.rs:196-199,285-288`), and **every fixture in the tree today declares `visible_in_states: vec![]`** — always visible, in every state (V 2026-09-06: 18 sites, all empty). Against such a fixture the tool set is invariant under the FSM state, so a leaked state moves nothing and this case is green whether or not the leak exists. The fixture must therefore register one capability visible in `"default"` and **not** in the state A sets (or the reverse), and the pinned literal must be pinned to that staging. Without a proof that the staging held, the staging is unverified prose and the case decays back to the invariant-fixture version — but **that proof must not be phrased as a discovery call from a modern HTTP connection made while the target state is in force**. On the Q4-ratify branch no modern connection can hold a non-default state after (c) — that is what (c) is for — so a staging assertion of that shape is unsatisfiable on that branch and the case is red forever: `test-plan-honesty`'s second survivor, a case that can never go green, not the one this repair was guarding against. The proof therefore runs on a **session-bearing connection**, one that legitimately owns a session id so its `gateway_set_state` is refused under neither answer to Q4, driving the same discovery entry point: set the state, observe the OTHER set. That proves both halves the staging needs — the capability is genuinely state-dependent, and the discovery path honours the dependence — and it is Q4-independent. The leak assertion then asserts only what its own branch permits. |

## Preconditions on the implementation — plan-blocking, not advisory

A test plan normally constrains only tests. Two of these cases are honest **only
if the implementation takes a particular shape**, so the shape is stated here as
a rule that blocks the plan rather than as a note the implementer may weigh.

**1. The fold is load-bearing.** B-08 and B-09 each drive **two** discovery entry
points — `gateway_list_tools` and `gateway_search_tools` — so a skipped fold would
already fail their `gateway_list_tools` assertion. The reader those two calls still
do not reach is **`list_tools_single_server`** (`search.rs:581-584`, inside the
function opening at `:560`), which reads the store directly on its own copy. Each
case therefore drives a **third** call, `gateway_list_tools` with `server=` set to
the capability backend carrying the staged state-dependent capability. With that
call present the fold is a correctness improvement rather than a load-bearing
precondition; without it the fold is what keeps the unfolded copy from going
unobserved, and (c) folds `list_tools` and `list_tools_single_server` back into
`current_search_state` before guarding it.
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
- **The rest of cluster B.** `B-01`, `B-02`, `B-06` and `B-07` are *specified and
  not implemented*: `tests/tool_list_tests.rs` is 43 lines and contains none of
  them. So `B-08`, `B-09` and `B-10` are the first cases in this lineage to exist
  at all, and the B-07 repair this plan prescribes has no code under it to
  repair. Read this plan as **foundational, not incremental** — a reviewer who
  assumes the sibling cases are in place will judge the new rows against coverage
  that is not there. What that costs concretely: the 2a promotion leg is carried
  by B-07, so until B-07 exists, `B-10` (2b, same-connection) is the *only*
  promotion case with code behind it.

## The question this plan waited on, and its answer

**Q4** — whether `gateway_set_state` should be refused on a modern connection in
the default build, as `gateway_set_profile` already is. Not self-decidable: it
changes a tool that succeeds today for a client doing nothing wrong.

**Asked of the operator — ratified 2026-09-06, option (c): it is refused.** What
that changed: B-08 and B-09 are no longer conditional. They assert the refusal,
and the conditional phrasing that used to stand in for the ratification comes out.

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

## Review record

Two independent **non-author** legs are required. This work is Claude-authored,
so `gpt`, `grok` and `kimi` are all eligible and any two make a valid pair; the
reviewer that is forbidden here is `claude-review`, not `grok`.

| leg | vendor | verdict | run |
|---|---|---|---|
| 1 | Grok | SHIP-WITH-FIXES | `grok-20260906T071032Z-19225` |
| 2 | Kimi | pending | material submitted inline on stdin — kimi has no filesystem |
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
