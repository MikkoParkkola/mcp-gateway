# Test plan — `MIK-6865.SCHEMA.1`, cluster G tool-schema 2020-12 validity

Design under test: `docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md` (anchors `112a392c`, Seam-3 revision `149e553a`).

This is the §P2 test plan. It is a plan, not tests: one row per acceptance
assertion, its V-model level, its type, and — the column that does the work —
the exact assertion, so a reviewer can ask whether the case can go red both ways.
No test code exists yet and none is written here.

## Criterion, quoted from the requirement, not from the status file

`docs/requirements/RELEASE-4.0.0-requirements.md:200`:

> Tool schemas exposed by the gateway MUST avoid the nested-object-in-array shapes
> that induce key invention in current models, and MUST remain valid under
> JSON Schema 2020-12 with the revision's `$ref` and composition bounds.

Three clauses, not two. `docs/requirements/RELEASE-4.0.0-criteria-status.md:101-102`
splits the criterion into two rows, and its clause-B paraphrase drops the trailing
`$ref` and composition phrase. **The design quotes the status file, so that phrase
is absent from the design as well** — `rg '\$ref|allOf|anyOf|oneOf|\$defs|composition'`
returns zero hits across the whole design document. That is the empty cell this
plan exists to expose; it is row P12.

| clause | text | status per `criteria-status.md` | this plan |
|---|---|---|---|
| A | no nested-object-in-array shapes | MET, `tests/mik_7272_exploit_acs.rs:323,343,365` via real `MetaMcp::handle_tools_list` | P11 — covered, no new case |
| B | valid under JSON Schema 2020-12 | UNTESTED | P1–P10, the design's subject |
| C | with the revision's `$ref` and composition bounds | not tracked as a row at all | P12 — **no case**, askable unknown U8 |

## Scope of this plan

FOR: proving clause B across the three populations the design names, and stating
honestly what clause C would need.
OUT: implementing any of it; choosing the validator crate; the `outputSchema`
widening decision (deferred U7); anything about clause A beyond confirming its
existing coverage.

## Document ambiguity — resolved, and it is not a supersession

Two design documents target this one criterion:

- `docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md` — **the one this plan tests.** Cited by `docs/requirements/RELEASE-4.0.0-gap-plan.md:566` (at `:47,247`). Carries the 2026-08-31 scope receipt withdrawing the backend-schema exclusion (`:353`), which is the owner ruling P5–P7 depend on.
- `docs/design/2026-08-31-cluster-g-schema-validity.md` — same criterion (`:7`), own G-table (`SCHEMA.1.A1` at `:324`), **zero inbound references repo-wide**.

`git log --follow` shows two separate histories; neither is a rename of the other,
and nothing in the tree records a retirement. So this is **two parallel design
lineages for one criterion with no recorded supersession**, not a superseded draft.
Reported, not acted on: deleting or annotating the orphan is the owner's call.
`criteria-status.md` references neither.

## Rows

Level: U = unit, I = integration (in-process, real loader/registry, mock backend),
S = system (through the published MCP surface).
"Red on HEAD" answers §P2 question 2 for the free-failure case; a row that cannot
fail on HEAD carries a falsifier obligation instead.

| id | population / obligation | level | type | red on HEAD |
|---|---|---|---|---|
| P1 | seam 2 — invalid capability YAML is rejected by the new `CAP-` code | I | negative | yes |
| P2 | seam 2 — rejected capability is absent from `tools/list` | S | negative | yes |
| P3 | seam 1 — all 19 `gateway_*` defs meta-validate | U | regression guard | no — falsifier |
| P4 | dialect — the check is 2020-12, not draft-07 | U | discrimination | yes |
| P5 | seam 3 — one invalid tool drops, the backend's others survive | I | blast radius | yes |
| P6 | seam 3 — a dropped tool is not routable, backend sees nothing | I | negative | yes |
| P7 | ruling's third obligation — rejection is logged and surfaced | I | diagnostics | n/a on HEAD |
| P8 | negative control — a valid capability still loads | I | control | no — falsifier |
| P9 | negative control — an all-valid backend rejects nothing | I | control | no — falsifier |
| P10 | seam 3 — rejected set is replaced per fetch, not accumulated | I | self-heal | n/a on HEAD |
| P11 | clause A — nested-object-in-array | S | existing | covered elsewhere |
| P12 | clause C — `$ref` and composition bounds | — | **no case** | — |

### P1 — invalid capability YAML is rejected by *this* code

Fixture: one capability file whose `schema.input` declares `required` as a string
rather than an array. One defect, nothing else wrong (A9).

Assertion: `CapabilityLoader::load_from_directory` over a load path containing
only that file returns **zero capabilities**, and the returned issue list contains
**the new `CAP-` code specifically**. A non-empty issue list is not the assertion —
the file could be rejected by any of the existing validator rules and the row would
pass with the new rule deleted (A5). The assertion names the code.

Red on HEAD: yes. Today the file loads and the issue list has no such code.

### P2 — the rejected capability does not reach the published surface

Fixture: P1's file plus at least two valid capabilities, loaded through the real
gateway startup path.

Assertion: the set of tool names returned by `tools/list` **equals** the set
derived from the two valid capabilities. Exact set equality, not "the bad name is
absent" — absence alone is satisfied by an empty list, so a validator that rejects
everything would pass an absence assertion (A3). Equality goes red in both
directions: a valid capability dropped makes the set short, the invalid one
surviving makes it long.

Red on HEAD: yes.

### P3 — the 19 compile-time meta-tool schemas meta-validate

Population: the `gateway_*` definitions in `src/gateway/meta_mcp_tool_defs.rs`.

Assertion: for every definition, `inputSchema` meta-validates against 2020-12, and
`outputSchema` meta-validates **when present**. Failure names the offending tool
and the validator's own error, so a regression says which schema broke rather than
"one of nineteen".

Also assert the **count** is 19 and, alongside it, the exact set of tool names
(A4 — a count claim names identities). A count alone passes if a definition is
deleted and another added.

Red on HEAD: no; this is expected green today and is a regression guard. Falsifier
obligation below.

### P4 — the check is 2020-12, and can tell that it is

This row exists because a validator configured to draft-07 would pass P1, P3, P5
and every other row while proving nothing about the criterion's actual dialect.

Fixture: a schema declaring `"$schema": "http://json-schema.org/draft-07/schema#"`
and using a construct that is legal in draft-07 and not in 2020-12.

Assertion: the check reports it invalid, and the reported error names the construct.

**Candidate construct, not yet a fact**: `items` in its array form
(`{"items": [{"type": "string"}]}`), since 2020-12 moved the array form to
`prefixItems`. `definitions` and `dependencies` do **not** work — 2020-12 permits
undefined keywords, so their presence is not an error.

The candidate is unverified because the validator crate is unchosen (dependency D1
below). If no construct splits the two dialects under the chosen crate, **P4 is
dropped and the result is recorded** — "this validator cannot distinguish the
dialects" is itself a finding about the enforcement, not a missing test.

Red on HEAD: yes — no dialect check exists at all.

### P5 — one invalid tool drops, the rest of the backend survives

This is the blast-radius half of the owner's ruling: drop the tool, keep the backend.

Fixture: a mock backend returning **at least three** tools — two with valid
`inputSchema`, one invalid. Two valid, not one, so a bug that keeps exactly one
survivor cannot pass.

Assertions, all three:

1. the set of names from `get_tools_shared` **equals** the set of the two valid names — exact equality again, for the same reason as P2;
2. each surviving name is still invocable end to end;
3. the backend itself is still registered and reachable — the ruling forbids removing forty-nine working tools for one broken one, and only this assertion says so.

Red on HEAD: yes.

### P6 — a dropped tool is not routable, and the backend never hears about it

`invoke.rs:1934-1938` deliberately dispatches uncached names ("We still dispatch to
the backend in case the cache is stale"), so P5 alone leaves the tool callable.

Fixture: P5's backend, then `gateway_invoke` naming the rejected tool.

Assertions, both:

1. the call is refused, and the error names **the tool** and **the validation failure** — not a generic unknown-tool error, which is what a cache miss already produces and would pass without the rejected set;
2. the mock backend's **call log is empty** for that name. Asserted on the log, not on the error text: error text alone cannot distinguish "refused before dispatch" from "dispatched, backend erred, gateway reworded it".

A tool name that is unknown but *not* rejected must keep today's dispatch-anyway
behaviour; assert that in the same case so the fix stays narrow.

Red on HEAD: yes, and it cannot go green without the per-backend rejected set.

### P7 — the rejection is logged and surfaced, which the design's own G-table omits

The owner's ruling has three obligations: the tool is dropped, it is not routable,
and it is **logged and surfaced in diagnostics**. G1–G7 cover the first two. Nothing
in the design's table asserts the third, so it is added here.

Fixture: P5's backend.

Assertions:

1. `BackendStatus` for that backend reports a rejected count of **exactly 1**, and the count for an all-valid backend in the same fixture is **exactly 0** — a pinned number asserted on both sides (A1), so a field hard-wired to 1 fails;
2. that count reaches `gateway_list_servers`, asserted on the tool's own output rather than on the struct, because the struct is not what an operator reads;
3. one `warn!` per rejected tool, naming backend, tool and error. Lower value than the count and asserted only if log capture is already available in this suite; if it is not, that is recorded here as deliberately uncovered rather than silently dropped.

Red on HEAD: n/a — the field does not exist. Cannot fail on HEAD for the same
reason it cannot pass; it is new surface, not a regression guard.

### P8 — a valid capability still loads (negative control)

Without this, P1 and P2 are both satisfied by a validator that rejects every
capability in the catalogue.

Fixture: one capability whose schemas are valid 2020-12.

Assertion: it loads, is published, and its issue list contains **no** `CAP-` code.

Red on HEAD: no — green today and required to stay green. Falsifier: configure the
new rule to reject unconditionally; P8 must go red while P1 stays green.

### P9 — an all-valid backend rejects nothing (negative control)

The seam-3 counterpart of P8, and the reason P7's zero-side assertion has something
to attach to.

Fixture: a mock backend whose tools all carry valid `inputSchema`.

Assertion: the published set **equals** the full tool set, the rejected set is
empty, and the rejected count is 0.

Red on HEAD: no. Falsifier: make the seam-3 predicate reject unconditionally;
P9 goes red while P5 stays green.

### P10 — the rejected set is replaced per fetch, not accumulated

Guards the design's self-healing claim, which is a property of the *mechanism*,
not of the criterion.

Fixture: a mock backend that returns an invalid `inputSchema` for a tool on the
first fetch and a valid one after; TTL expiry forced rather than waited on.

Assertions: after re-fetch the tool is published again **and** invocable, with no
operator action; and the rejected count for that backend returns to 0.

Also assert the guard the design names on `invalidate_tools_cache`
(`src/backend/metadata.rs:39-46`): an empty tool list is discarded so warm start
re-asks, **only when the rejected set is also empty**. A fixture where a backend
legitimately returns zero tools while holding rejections must not be treated as a
stale cache.

Red on HEAD: n/a — there is no rejected set to accumulate. It can, however, fail
against the implementation: an accumulating set keeps the corrected tool rejected
forever. That is what this row is for, so it does not read as untestable.

### P11 — clause A, nested-object-in-array

Covered, no new case. `tests/mik_7272_exploit_acs.rs:323,343,365` asserts it through
the real `MetaMcp::handle_tools_list`, and `criteria-status.md:101` records it MET.
Listed because the plan is per criterion, not per design, and a clause with no row
is indistinguishable from a clause nobody looked at.

The one thing to check when P3 lands: both walk the same 19 definitions, so P3's
set assertion and this suite's must not drift into two different ideas of the
population.

### P12 — clause C, `$ref` and composition bounds: **no case**

This is the empty cell, stated rather than filled.

The criterion binds tool schemas to "the revision's `$ref` and composition bounds".
Meta-validation gives a **partial** argument and no more: it establishes that
`$ref`, `allOf`, `anyOf`, `oneOf` and `$defs` are structurally well-formed where
they appear. It does **not** establish that a `$ref` resolves, that a remote or
recursive `$ref` is permitted or forbidden, or that composition depth sits inside
whatever bound the revision sets. A schema referencing a `$defs` entry that does
not exist meta-validates cleanly.

So the honest position is: the phrase is not covered, and it is not obvious what
it binds. It is an **askable** unknown, not a checkable one — no command settles
what "the revision's bounds" are.

**U8 (askable, blocking for a SCHEMA.1 closure comment, not for implementation):**
does "the revision's `$ref` and composition bounds" name (a) a numeric limit the
2026-11-25 revision states, (b) the gateway's own limit on what it will publish,
or (c) nothing beyond 2020-12 validity, in which case the phrase is decorative and
clause C collapses into clause B? Asked of the criterion's owner. Until answered,
no row can be written that could fail for the right reason. Implementation of
P1–P10 is not blocked by it; the closure comment is.

Secondary, and cheaper: `criteria-status.md:101-102` does not carry a row for this
clause at all. Whatever U8 returns, that file needs either a third row or a stated
reason there is none.

## Falsifier obligations

Three rows are green on HEAD and therefore carry no free failure: P3, P8, P9.
Each needs the §P2 probe before it counts as evidence. The probe restores
**pre-fix content**, not a working-tree state, under a trap, and the restore is
verified by **re-running the test**, never by `git status` — defect and repair are
both modifications and `status` reports them identically.

- **P3**: hand-edit one `gateway_*` definition to a schema the validator has already reported invalid. The test must fail **on the meta-validation assertion**, naming that tool. A compile error is not a caught defect.
- **P8**: force the new `CAP-` rule to reject unconditionally. P8 red, P1 still green.
- **P9**: force the seam-3 predicate to reject unconditionally. P9 red, P5 still green.

The P8 and P9 probes are what stop the pair of controls from being decorative: a
control that cannot be made to fail is not a control.

## Named dependencies

| id | dependency | blocks |
|---|---|---|
| D1 | the 2020-12 validator crate is unchosen; none is declared in `Cargo.toml` | every row's fixture. The plan's own rule — *an invalid fixture is chosen by running the validator on it, never by reading it* — is **unexecutable until D1 closes**. P4's candidate construct is a reading, and is marked as such above. |
| D2 | U7, `outputSchema` widening past the ruling's `inputSchema` letter | P3 and P5's `outputSchema` halves. Narrowing is one clause in one predicate, so the rows are written for the wider reading and shrink cheaply if the owner says `inputSchema` only. |
| D3 | U8, clause C | P12, and the SCHEMA.1 closure comment. Not implementation. |

## Cost row, which is a measurement and not a test

The design commits to timing `CapabilityLoader::load_from_directory` over the
110+ catalogue, before and after, same machine, median of five runs. Recorded here
so it is not mistaken for a row: it has no pass/fail assertion and belongs in the
change's evidence, not the suite. Giving it a threshold now would invent a budget
nobody set.

## What this plan does not cover, deliberately

- The OpenAPI importer (`src/gateway/ui/import.rs:172`) writes YAML into the load path, so it is covered transitively by P1/P2 and needs no seam or row of its own.
- The 19 meta-tool schemas declare no `$schema`. No row: the dialect is pinned at the check, so their silence is correct rather than a defect to detect.
- Instance validation (`src/capability/schema_validator/mod.rs`) is a different job from meta-validation and is untouched.

## Review checklist for this plan

1. Does every clause of the criterion have a row or a stated reason it has none? A: yes — clause A at P11, clause B at P1–P10, clause C at P12 with the reason.
2. Can each named case fail for the right reason? A: P1, P2, P4, P5, P6 fail free on HEAD. P3, P8, P9 carry probes. P7 and P10 are new surface, with the way they fail against the implementation stated.
3. Is any fixture staging what the rule is meant to decide? The controls P8/P9 exist to answer this for P1/P2 and P5, and the probes prove the controls.
