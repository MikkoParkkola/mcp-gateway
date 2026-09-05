# Test plan — `MIK-6865.SCHEMA.1`, cluster G tool-schema 2020-12 validity

Design under test: `docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md` (anchors `112a392c`; re-read at `832ef3d9`, which moved the seam-3 gate to the
body of `Backend::request_with_headers` and widened the direct-route cost).

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
| A | no nested-object-in-array shapes | MET, `tests/mik_7272_exploit_acs.rs:323,343,365` via real `MetaMcp::handle_tools_list` | P11 — **covered for `inputSchema` only, and a live offender sits in an `outputSchema`.** Real row, red on HEAD |
| B | valid under JSON Schema 2020-12 | UNTESTED | P1–P10, the design's subject |
| C | with the revision's `$ref` and composition bounds | not tracked as a row at all | P12a — unresolved local `$ref`, checkable now. P12b — the bounds themselves, askable unknown U9 |

## Scope of this plan

FOR: proving clause B across the three populations the design names, and stating
honestly what clause C would need.
OUT: implementing any of it; choosing the validator crate; the `outputSchema`
widening decision (deferred U7); repairing the status file, which records clause A
MET on evidence that does not cover the whole published schema — found here,
reported to the owner, not acted on.

Clause A moved from OUT to a row during review, under §P0: the review produced
source-verified proof that its existing coverage is incomplete, which is the
"confirming its existing coverage" this plan had already claimed FOR itself.

## Document ambiguity — resolved, and it is not a supersession

Two design documents target this one criterion:

- `docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md` — **the one this plan tests.** Cited by `docs/requirements/RELEASE-4.0.0-gap-plan.md:566` (at `:47,247`). Carries the 2026-08-31 scope receipt withdrawing the backend-schema exclusion (`:353`), which is the owner ruling P5–P7 depend on.
- `docs/design/2026-08-31-cluster-g-schema-validity.md` — a second design for the same criterion, with its own G-table and zero inbound references repo-wide. **Deleted 2026-09-01**, its load-bearing content merged into the design above; see that document's closing section, `One design for SCHEMA.1, not two`.

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
| P6 | seam 3 — a dropped tool is not routable on **either** production route, backend sees nothing | I | negative | yes |
| P6b | seam 3 — an unknown-but-not-rejected name still dispatches | I | control | no — falsifier |
| P7 | ruling's third obligation — rejection is logged and surfaced | I | diagnostics | n/a on HEAD |
| P8 | negative control — a valid capability still loads | I | control | no — falsifier |
| P9 | negative control — an all-valid backend rejects nothing | I | control | no — falsifier |
| P10 | seam 3 — rejected set is replaced per fetch, not accumulated | I | self-heal | n/a on HEAD |
| P10b | warm start — empty tool list discarded only when the rejected set is empty | I | guard | n/a on HEAD |
| P11 | clause A — nested-object-in-array, over **both** schema fields | S | negative | **yes** |
| P12a | clause C — every published `$ref` resolves | U | negative | yes |
| P12b | clause C — the bounds themselves | — | **no case** | — |

### P1 — invalid capability YAML is rejected by *this* code

Fixture: one capability file whose `schema.input` declares `required` as a string
rather than an array. One defect, nothing else wrong (A9).

Assertion, in two halves, because no single call exposes both facts.
`CapabilityLoader::load_directory` (`src/capability/loader.rs:29`) returns
`Result<Vec<CapabilityDefinition>>` — the issues are logged inside the skip, never
returned — so the loader proves only the drop:

1. `load_directory` over a path containing only that file returns a **zero-length**
   vector;
2. `validate_capability_definition` on the same definition reports **the new `CAP-`
   code specifically**. A non-empty issue list is not the assertion — the file could
   be rejected by any existing validator rule and the row would pass with the new
   rule deleted (A5). The assertion names the code, and the second half is where it
   can be named.

Found in review: the plan named `CapabilityLoader::load_from_directory`, which does
not exist. The discriminator the row exists for was unobservable through the API it
cited.

Red on HEAD: yes. Today the file loads and the issue list has no such code.

### P2 — the rejected capability does not reach the published surface

Fixture: P1's file plus at least two valid capabilities, loaded through the real
gateway startup path.

Assertion: the set of tool names returned by `tools/list` **equals** the 19
`gateway_*` meta-tools **union** the two names derived from the valid capabilities.
The union is not a weakening — that surface publishes the meta-tools too, so
equality against the capability names alone is red by construction and would be
"fixed" at implementation time into a vacuous absence check.

Exact set equality, not "the bad name is absent" — absence alone is satisfied by an
empty list, so a validator that rejects everything would pass an absence assertion
(A3). Equality goes red in both directions: a valid capability dropped makes the set
short, the invalid one surviving makes it long. Assert the union form, or equal the
capability-tagged subset to the two valid names; not a hand-maintained literal list
of 21, which drifts the moment a meta-tool is added.

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

Fixture: a schema using a construct that is legal in draft-07 and not in 2020-12,
declaring **no `$schema` at all**. The declaration was in the first draft of this
plan and was wrong: a spec-compliant crate honours a declared dialect, would process
the fixture as draft-07, find the construct legal, and the row could never go red
for its own reason. The plan's own model — the dialect is pinned at the check — makes
the construct sufficient and the declaration harmful.

Assertion, both directions on the **same** fixture:

1. it validates clean against the draft-07 meta-schema;
2. it validates **invalid** against `jsonschema::draft202012::meta::validator()` —
   named as the unit so a seam cannot quietly auto-detect its own dialect — and the
   reported error names the construct.

One direction is not enough: a validator that rejects everything satisfies (2) alone.

**Candidate construct, not yet a fact**: `items` in its array form
(`{"items": [{"type": "string"}]}`), since 2020-12 moved the array form to
`prefixItems`. `definitions` and `dependencies` do **not** work — 2020-12 permits
undefined keywords, so their presence is not an error.

The candidate is unverified because the validator crate is unchosen (dependency D1
below). If no construct splits the two dialects under the chosen crate, that is a
finding about the **crate**, not a licence to drop the row: a validator that cannot
tell 2020-12 from draft-07 cannot enforce a criterion whose whole content is the
dialect, and the right response is to reject the crate. Dropping P4 was an exit this
plan should not have offered — it let the one row proving the dialect be deleted by
whichever crate D1 happens to pick.

Red on HEAD: yes — no dialect check exists at all.

### P5 — one invalid tool drops, the rest of the backend survives

This is the blast-radius half of the owner's ruling: drop the tool, keep the backend.

Fixture: a mock backend returning **at least four** tools — two fully valid, one
whose `inputSchema` is invalid, one whose `outputSchema` is invalid. Two valid, not
one, so a bug that keeps exactly one survivor cannot pass; and both schema fields,
because an implementation that validates only `inputSchema` passes every rejection
row written against `inputSchema` alone. The `outputSchema` half is subject to U7
(D2) and shrinks to a stated exclusion if the owner rules `inputSchema` only — it
does not silently disappear.

Assertions, all three:

1. the set of names from `get_tools_shared` **equals** the set of the two fully valid names — exact equality again, for the same reason as P2;
2. each surviving name is still invocable end to end;
3. the backend itself is still registered and reachable — the ruling forbids removing forty-nine working tools for one broken one, and only this assertion says so.

Red on HEAD: yes.

### P6 — a dropped tool is not routable on either route, and the backend never hears about it

`invoke.rs:1934-1938` deliberately dispatches uncached names ("We still dispatch to
the backend in case the cache is stale"), so P5 alone leaves the tool callable.

**Two production routes reach a backend tool, not one.** `gateway_invoke` is the
meta-surface route; `backend_handlers.rs:747-809` forwards `tools/call` directly for
clients addressing a backend by name. The design revision at `832ef3d9` puts the
gate in the body of `Backend::request_with_headers` (`src/backend/ops.rs:151-165`)
precisely because it is the shared chokepoint — `request` is a two-line delegation
to it, so gating the signature alone would have left the header-free path open.

The first draft of this row asserted only through `gateway_invoke`. That would green
a refusal implemented one layer above the chokepoint while the direct route — the one
most MCP clients actually use — stayed open. The row is written at the chokepoint.

Fixture: P5's backend, exercised twice — once through `gateway_invoke`, once through
the direct `tools/call` handler — naming the rejected tool.

Assertions, on **each** route:

1. the call is refused, and the error names **the tool** and **the validation failure** — not a generic unknown-tool error, which is what a cache miss already produces and would pass without the rejected set;
2. `Backend::request_with_headers` is **never entered** for that name. Asserted at the chokepoint or on the mock's call log, not on the error text: error text alone cannot distinguish "refused before dispatch" from "dispatched, backend erred, gateway reworded it".

Red on HEAD: yes on both routes, and neither can go green without the per-backend
rejected set.

### P6b — an unknown-but-not-rejected name still dispatches (control)

Split out of P6, where it was parked as an aside. It is the row that keeps the fix
narrow: without it, "refuse everything not in the cache" passes P6 on both routes and
breaks the deliberate stale-cache behaviour `invoke.rs:1934-1938` exists for.

Fixture: P5's backend, then a name the cache has never seen and the rejected set does
not contain.

Assertion: the call **is** dispatched — `request_with_headers` is entered for that
name — and today's behaviour is unchanged.

Red on HEAD: no; green today and required to stay green. Falsifier: make the rejected
set consulted as a deny-by-default; P6b goes red while P6 stays green. Its own fixture,
so it can go red without the rejected-set fixture staging it.

### P7 — the rejection is logged and surfaced, which the design's own G-table omits

The owner's ruling has three obligations: the tool is dropped, it is not routable,
and it is **logged and surfaced in diagnostics**. G1–G7 cover the first two. Nothing
in the design's table asserts the third, so it is added here.

Fixture: P5's backend.

Assertions:

1. `BackendStatus` for that backend reports a rejected count of **exactly 1**, and the count for an all-valid backend in the same fixture is **exactly 0** — a pinned number asserted on both sides (A1), so a field hard-wired to 1 fails;
2. that count reaches `gateway_list_servers`, asserted on the tool's own output rather than on the struct, because the struct is not what an operator reads;
3. one `warn!` per rejected tool, naming backend, tool and error. Asserted, not conditionally asserted: the first draft made this contingent on log capture already existing in the suite, which is a test plan letting an implementation detail decide whether an obligation is covered. The log line is where an operator learns *which* tool went and *why* — the count says only that something did. If the suite has no capture, adding it is the work, not the excuse.

Red on HEAD: n/a — the field does not exist. Cannot fail on HEAD for the same
reason it cannot pass; it is new surface, not a regression guard.

### P8 — a valid capability still loads (negative control)

Without this, P1 and P2 are both satisfied by a validator that rejects every
capability in the catalogue.

Fixture: one capability whose schemas are valid 2020-12.

Assertion: it loads, is published, and its issue list contains **no instance of the
new code**. Not "no `CAP-` code at all" — an unrelated existing warning on an
otherwise valid fixture would fail this control for the wrong rule, and a control
that fails for the wrong rule teaches the next reader to weaken it.

Red on HEAD: no — green today and required to stay green. Falsifier: configure the
new rule to reject unconditionally; P8 must go red while P1 stays green.

### P9 — an all-valid backend rejects nothing (negative control)

The seam-3 counterpart of P8, and the reason P7's zero-side assertion has something
to attach to.

Fixture: a mock backend whose tools all carry valid `inputSchema`.

Assertion: the published set **equals** the full tool set, the rejected set is
empty, and the rejected count is 0.

Red on HEAD: no. Falsifier: an unconditionally-rejecting predicate does **not**
produce the split this row claims — it also breaks P5's set equality, so the probe
would prove only that both rows read the same mechanism. Use a mutant that still
drops exactly the invalid tool on P5's mixed list and rejects only when the list is
all-valid. P9 red, P5 green, and the control is shown to be independent rather than
decorative.

### P10 — the rejected set is replaced per fetch, not accumulated

Guards the design's self-healing claim, which is a property of the *mechanism*,
not of the criterion.

Fixture: a mock backend that returns an invalid `inputSchema` for a tool on the
first fetch and a valid one after; TTL expiry forced rather than waited on.

Assertions, in order, and the first is not optional:

1. **on the first fetch**, the tool is hidden, refused, and the rejected count is exactly 1;
2. after re-fetch, the tool is published again **and** invocable, with no operator action;
3. the rejected count for that backend returns to 0.

Asserting only the post-recovery state passes an implementation with validation and
the rejected set deleted outright — nothing was ever rejected, so nothing needs
un-rejecting. The before-state is what makes the after-state mean anything.

Red on HEAD: n/a — there is no rejected set to accumulate. It can, however, fail
against the implementation: an accumulating set keeps the corrected tool rejected
forever. That is what this row is for, so it does not read as untestable.

### P10b — warm start discards an empty tool list, but not a rejection

Split out of P10, where it rode along as an "also". Two mechanisms, two rows: a
failure now names which one broke, and the guard cannot be dropped as an appendix to
the TTL case.

Guard, as the design names it on `invalidate_tools_cache`
(`src/backend/metadata.rs:39-46`): an empty tool list is discarded so warm start
re-asks — **only when the rejected set is also empty**.

Fixture: a backend that legitimately returns zero tools while holding rejections.

Assertion: that state is **not** treated as a stale cache, and the rejections survive
the warm start. The complementary case — empty list, empty rejected set — is still
discarded and re-asked.

Red on HEAD: n/a — new surface, for the same reason as P10.

### P11 — clause A, nested-object-in-array, over both schema fields

**This row was "covered, no new case" until review. It is not covered, and the
offender it misses is live in the shipped surface.** Verified at source, both halves:

- The existing check walks `inputSchema` only. `tests/mik_7272_exploit_acs.rs:351`:
  `if let Some(schema) = tool.get("inputSchema")`. No branch reads `outputSchema`.
- `gateway_search_tools` publishes an `outputSchema`
  (`src/gateway/meta_mcp_tool_defs.rs:119`) whose body
  (`search_tools_output_schema`, `:78-98`) is `matches`: `"type": "array"` whose
  `items` is `"type": "object"` with four non-empty `properties`. That is
  keystroke-for-keystroke the shape the detector at `:323` looks for.

So clause A is recorded MET against a population that excludes a live instance of the
exact shape the criterion forbids. The absence assertion is true; the absence is not.

This is why the plan lists clauses it expected to be covered. A clause with no row is
indistinguishable from a clause nobody looked at — and here, looking is what found it.

Fixture: none. The real `MetaMcp::handle_tools_list` population, as today.

Assertion: extend the existing walk to run `nested_object_in_array` over
`outputSchema` as well as `inputSchema`, for every published tool, with the offender
path reported as `tool.field.path` so the failure names which field.

Red on HEAD: **yes**, at `gateway_search_tools.outputSchema.matches`. That is not a
prediction — it is the shape read out of the source above.

Two consequences beyond this plan, neither acted on here:

1. `criteria-status.md:101` records clause A MET on this evidence. The record is
   wrong in scope, not in good faith: the test does exactly what it says, and what it
   says is narrower than the criterion. The owner's call, reported (§P0: an
   observation, not a ticket — the repair is one row in a status file and one
   assertion in a test, both smaller than the ticket describing them).
2. Making P11 green requires a decision the criterion does not make: flatten
   `matches`, or accept the invention rate on an **output** schema — where the model
   is reading, not writing, and the key-invention failure mode may not apply at all.
   That decision is U7's neighbour and belongs with it, not here.

The one thing to check when P3 lands: both walk the same 19 definitions, so P3's set
assertion and this suite's must not drift into two different ideas of the population.

### P12a — clause C, every published `$ref` resolves

Part of clause C **is** checkable today, and the first draft of this plan disposed of
all of it as askable. That was one disposal too many: "does this `$ref` resolve" needs
no ruling from anybody.

Meta-validation cannot supply it — the plan already says so, in the sentence that
should have been read as a row rather than as a limitation. A schema referencing a
`$defs` entry that does not exist meta-validates cleanly, because well-formedness and
resolution are different questions.

Population: the 19 `gateway_*` definitions, both schema fields, plus every capability
schema published from the load path.

Assertion: every `$ref` in a published schema resolves to a target that exists in the
same document. Failure names the schema, the field and the dangling pointer.

Red on HEAD: yes, in the sense that no such check exists. Whether it finds an offender
today is a fact about the catalogue, not about the row; if it finds none, it stands as
a regression guard and carries a falsifier — hand-edit one `$ref` to a name that does
not exist and watch it go red on the resolution assertion.

Deliberately **not** a row: malformed composition (`allOf` whose value is not an array
of schemas, and its siblings). That is caught by meta-validation, so it is already P1's
and P3's job, and a second row asserting it would read as extra coverage while adding
none.

### P12b — clause C, the bounds themselves: **no case**

This is the empty cell that survives, stated rather than filled.

Beyond resolution, the criterion binds tool schemas to "the revision's `$ref` and
composition bounds". No command settles what those bounds are. Whether a remote or
recursive `$ref` is permitted, and whether composition depth has a ceiling, are
questions about intent, not about the tree.

**U9 (askable, blocking for a SCHEMA.1 closure comment, not for implementation):**
does "the revision's `$ref` and composition bounds" name (a) a numeric limit the
2026-11-25 revision states, (b) the gateway's own limit on what it will publish, or
(c) nothing beyond 2020-12 validity plus resolution, in which case P12a is the whole
of clause C and the rest of the phrase is decorative?

Put as confirm-or-reject, not as a blank three-way: the surviving design's U11 row
(`docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md`, carried over from the deleted
sibling's `SCHEMA.1.A5`) already reads it as (c) plus resolution, which is P12a. The owner is being asked to confirm a
written reading or name the bound — cheaper than inventing one.

Renumbered from U8 during review. **U8 is live in the design under test**
(`:410`) for the invoke-path cost measurement; reusing the id would have let a
SCHEMA.1 closure comment be written against the wrong unknown while clause C stayed
unasked. U9 is free in the design's deferred table.

Secondary, and cheaper: `criteria-status.md:101-102` does not carry a row for this
clause at all. Whatever U9 returns, that file needs either a third row or a stated
reason there is none.

## Falsifier obligations

Five rows are green on HEAD and therefore carry no free failure: P3, P6b, P8, P9,
and P12a if the catalogue happens to hold no dangling `$ref`.
Each needs the §P2 probe before it counts as evidence. The probe restores
**pre-fix content**, not a working-tree state, under a trap, and the restore is
verified by **re-running the test**, never by `git status` — defect and repair are
both modifications and `status` reports them identically.

- **P3**: hand-edit one `gateway_*` definition to a schema the validator has already reported invalid. The test must fail **on the meta-validation assertion**, naming that tool. A compile error is not a caught defect.
- **P8**: force the new `CAP-` rule to reject unconditionally. P8 red, P1 still green.
- **P9**: a mutant that still drops exactly the invalid tool on P5's mixed list and rejects only an all-valid list. P9 red, P5 green. An unconditional rejecter breaks P5 too and proves nothing about independence.

- **P6b**: consult the rejected set as a deny-by-default. P6b red, P6 green.
- **P12a**: hand-edit one `$ref` to a target that does not exist. Red **on the resolution assertion**, not on meta-validation — if meta-validation catches it, the row is redundant and should be dropped, and the probe is how that is discovered rather than assumed.

The P8 and P9 probes are what stop the pair of controls from being decorative: a
control that cannot be made to fail is not a control. P3's probe additionally
**removes or renames** one `gateway_*` definition, not only mutates a schema — the
count-and-set assertion is a separate claim from the meta-validation one and needs
its own proof of failure.

## Named dependencies

Ranked by impact x uncertainty, cheapest probe first, per G10-G12. The order is the
work order: D1 blocks everything and is settled by running something, so it goes
first; the two asks can be in flight while it runs.

| rank | id | dependency | probe | blocks | if it resolves badly |
|---|---|---|---|---|---|
| 1 | D1 | the 2020-12 validator crate is unchosen; none is declared in `Cargo.toml` | add the candidate crate, run P4's two-direction check on a scratch fixture — one afternoon, and it settles P4's construct as a fact rather than a reading | every row's fixture. The plan's own rule — *an invalid fixture is chosen by running the validator on it, never by reading it* — is **unexecutable until D1 closes** | a crate that cannot split the dialects is rejected, not accommodated (see P4); try the next candidate |
| 2 | D2 | U7, `outputSchema` widening past the ruling's `inputSchema` letter | ask the owner; one sentence either way | P3, P5 and P11's `outputSchema` halves | narrowing is one clause in one predicate, so the rows are written for the wider reading and shrink cheaply to a stated exclusion |
| 3 | D3 | U9, clause C's bounds | ask the owner as confirm-or-reject of the sibling design's reading, not as a blank three-way | P12b, and the SCHEMA.1 closure comment. **Not implementation**, and not P12a | clause C needs a real bound; P12a still stands on its own |

D1 is rank 1 on both axes — highest impact, and the only one an afternoon of running
something can close. D3 is last because it blocks a comment, not a line of code.

## Cost row, which is a measurement and not a test

The design commits to timing `CapabilityLoader::load_directory` over the
110+ catalogue, before and after, same machine, median of five runs. Recorded here
so it is not mistaken for a row: it has no pass/fail assertion and belongs in the
change's evidence, not the suite. Giving it a threshold now would invent a budget
nobody set.

## What this plan does not cover, deliberately

- The OpenAPI importer (`src/gateway/ui/import.rs:172`) writes YAML into the load path, so it is covered transitively by P1/P2 and needs no seam or row of its own.
- The 19 meta-tool schemas declare no `$schema`. No row: the dialect is pinned at the check, so their silence is correct rather than a defect to detect.
- Instance validation (`src/capability/schema_validator/mod.rs`) is a different job from meta-validation and is untouched.

## What a reviewer of this plan is asked

The three §P2 questions, unanswered. An earlier draft supplied its own answers here
and a reviewer said so: a checklist that pre-answers itself invites agreement with
the text instead of a reading of it, which is the one thing this gate exists to
prevent.

1. Does every clause of the criterion have a row, or a stated reason it has none?
2. Can each named case fail, and fail for **its own** reason?
3. Is any fixture staging the very thing its rule is meant to decide?
