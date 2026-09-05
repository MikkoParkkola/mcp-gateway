# NFR.COMPAT.4 — test plan (§P2)

Status: plan, pre-implementation. Reviewed by both legs before any test code is written.
Design: `docs/design/2026-09-02-conformance-matrix.md` (proposed).

## §P0 SCOPE

FOR: proving that the conformance matrix `--check` enforces what NFR.COMPAT.4 obliges — that
role and transport are axes carrying evidence for every requirement, that an absent cell is a
finding rather than a silence, and that an exemption is a rule with a witness rather than an
opinion.

OUT:
- populating the matrix with real evidence (the design's own out-of-scope list).
- wiring `--check` into CI (same list). U-C fixed its behaviour: report-only, exit 0.
- any change to `SUPPORTED_VERSIONS` / `MODERN_VERSIONS` or the modern request path.
- any change to what `RELEASE-4.0.0-criteria-status.md` records. That file is cluster H's;
  this plan reports its row status and does not write it.
- verifying any *other* requirement in either role. COMPAT.4 obliges the matrix to exist and to
  refuse a half-verified row; it does not itself carry another row's evidence.

## The criterion, split into clauses

| id | clause |
|---|---|
| a | every requirement is verified in the gateway-as-server role |
| b | every requirement is verified in the gateway-as-client role |
| c | every requirement is verified on every transport that implements it |
| d | role and transport are two of the conformance matrix's axes (§9 acceptance 2) |
| e | this row states the obligation and the matrix carries the evidence |

"A requirement verified in one role is verified at half" gets no case, and the reason is stated
rather than left as an empty cell: it is the rationale for (a)+(b), not a separable obligation.
Anything it could assert is asserted by the cases for (a) and (b).

## Mechanism facts this plan rests on (verified at source)

- The matrix does not exist. `docs/requirements/conformance-matrix.toml`, a renderer under
  `scripts/release/`, and a rendered `RELEASE-4.0.0-conformance-matrix.md` are all absent.
  Every case below is a *new* test against *new* code, so §P2's free failure is available and
  the retrofitting falsifier probe is not needed.
- `python3 scripts/release/count-release-criteria.py` → `Coverage: 95 criteria, 100 rows,
  66 met or non-blocking, 34 blocking.` This is the reconciliation target for population.
- Baseline: `scripts/release/test_count_release_criteria.py` → **32 passed**. It is the
  convention this plan's test file follows: pytest, `importlib` load of the script by path,
  fixtures as strings under `tmp_path`, plus cases that run against the *live* documents.
- Exemption vocabulary is CLOSED (design §Q3): `NO-SURFACE-IN-ROLE` (witness = statement text),
  `TRANSPORT-LACKS-MECHANISM` (witness = the transport's capability declaration),
  `REVISION-PREDATES-STATEMENT` (witness = the `SUPPORTED_VERSIONS`/`MODERN_VERSIONS` entry plus
  the introducing change). `--check` refuses an unknown code; a new code is a design event.
- The revision axis is the UNION of `SUPPORTED_VERSIONS` (`src/protocol/mod.rs:48`, four legacy
  revisions) and `MODERN_VERSIONS` (`2026-07-28`). Two constants, not one list with a hole.
- Transports: client-side implementors of `trait Transport` (`src/transport/mod.rs:22`) are http,
  stdio and websocket; the serving side binds an HTTP listener, spawns a WebSocket listener
  (`src/gateway/server/mod.rs:1321`) and runs stdio (`:1495`). Same three names, different code.
- The design records that a mechanical witness check passes on "a hundred cells … code present,
  witness present" without the witness being *true* (design:149). No case below closes that;
  case 12 states the bar the tests do enforce.

## Prior coverage — asked before assuming

Searching for a dual-role harness (`gateway-as-client`, `dual.role`, `both roles`,
`conformance matrix`) returns nothing outside the requirements, design and ledger prose. There
is no dual-role harness and no matrix. Prior coverage is zero — the ledger's own finding for
this row, restated here rather than rediscovered.

## Test plan — one row per clause

Target file: `scripts/release/test_render_conformance_matrix.py`, beside the renderer, matching
`test_count_release_criteria.py`. FINDING below means "named in the `--check` report"; exit
status is asserted separately by cases 10 and 11, because U-C made the two independent.

| # | clause | case | proves it | probe (fixture inversion → must fail) |
|---|---|---|---|---|
| 1 | d | a requirements row with no matrix row is a FINDING naming its id | population derives from the requirements file, so a requirement cannot enter the release unmatrixed | add the row to the fixture matrix → the finding must disappear |
| 2 | d | a matrix row whose id is in no requirements file is a FINDING | the reconciliation runs both ways; a stale row is how a matrix keeps passing after its requirement is deleted | delete the orphan → finding gone |
| 3 | a, b | a row carrying EVIDENCE in `role=server` and nothing in `role=client` reports EMPTY ≥ 1, and the EMPTY count names that cell | this is "verified at half", mechanised. It is the whole criterion in one assertion | fill the client cell with resolvable EVIDENCE → EMPTY count drops by exactly one |
| 4 | b | a client cell reading `EXEMPT` with code `NO-SURFACE-IN-ROLE` and a witness quoting the statement text is accepted, and is counted as EXEMPT, never as EVIDENCE | the operator's 2026-09-02 ruling, mechanised: exemption is per cell, with the text as witness | drop the witness → FINDING; drop the code, leave the witness → FINDING |
| 5 | a, b | `EXEMPT` with a code outside the vocabulary is a FINDING that names the code | the vocabulary is closed; a new code must cost a design event, not a commit | swap in a listed code → accepted |
| 6 | c | a row whose transport axis omits a transport reports that cell EMPTY rather than absent | the axes are a total product; "on every transport that implements it" is expressed as an exemption, not as an omission | supply the cell → EMPTY count drops |
| 7 | c | a cell reading `TRANSPORT-LACKS-MECHANISM` without a citeable capability declaration is a FINDING | closes the loophole that makes clause (c) self-certifying — see the transport-witness design event below | supply the declaration reference → accepted |
| 8 | d, e | `EMPTY` typed by hand into the TOML is a FINDING | EMPTY is renderer-generated and *is* the finding; a hand-typed EMPTY is a human asserting the absence they were meant to fill | remove the literal → the same cell is still reported EMPTY, now as generated |
| 9 | e | a cell carrying a verdict word (`PASS`, `MET`, `BLOCKING`, `FAIL`) is a FINDING | a matrix cell never carries a verdict; the ledger owns acceptance 1, the matrix acceptance 2 | replace with EVIDENCE → accepted |
| 10 | e | a T row's EVIDENCE resolves to BOTH a named test that exists AND a production call site outside `tests/`; either missing is a FINDING | the design's evidence bar (U-B, existence), and the answer to the two shipped defects where a fixture replaced the code it tested | delete the prod call site from the fixture tree → FINDING; delete the test → a different FINDING |
| 11 | d | `--check` on a matrix with findings exits 0 and prints them | U-C: report-only on every PR. A check that blocks a PR gets disabled, and a disabled check reports nothing | make the fixture clean → still exit 0, no findings printed |
| 12 | d | the pre-tag mode exits non-zero while EMPTY is non-zero, and zero when EMPTY is zero | the blocking half lives at the tag, not the PR; without this case, case 11 would prove the check can never refuse anything | set EMPTY to zero → exit 0 |
| 13 | d | the three published numbers (`cells-in-scope`, `EMPTY`, `EXEMPT`) in the rendered markdown are recomputed and compared; a hand-edited number is a FINDING | headline numbers are script-owned. The hand-maintained ones in this repo drifted three times (`scripts/release/count-release-criteria.py:5-7`) | edit one number in the fixture render → FINDING naming it |
| 14 | d | rendered markdown that disagrees with the TOML is a FINDING | the rendered file is checked in because one review leg cannot render; a stale render is a document that lies to that leg | re-render → clean |
| 15 | a, b, c | **live documents**: every criterion `count-release-criteria.py` counts has a matrix row, and the published numbers match the recomputed ones | a fixture cannot satisfy this case. It is the one case that fails if the real matrix drifts from the real requirements | none — it is the probe. Its failure mode is the drift it exists to catch |

Case 15 is the reason the fixture cases are safe to trust. Cases 1-14 run on synthetic strings,
which is exactly the shape of the two defects this repo shipped, where a fixture replaced the
production code it tested. Case 15 has no fixture to replace: it loads the renderer by path,
reads the checked-in documents, and cannot pass while they disagree.

## Can each case fail — the Q2 answer, stated per risk rather than per row

- **No case constructs its own expected value.** Every assertion names a literal (a finding's
  id string, an exit status, a count), never a value re-derived by calling the code under test.
  A case whose expectation is `check(x) == check(x)` is unfalsifiable, and case 6 of the OBS.5
  plan is labelled that way rather than pretended into a probe. No case here has that shape.
- **The module is loaded by path, once, exactly as `test_count_release_criteria.py` does.** No
  parser, no TOML reader and no ID regex is re-implemented in the test file. A local
  reimplementation is how a fixture becomes the production code, and it is banned here by
  construction, not by care.
- **Every probe is an inversion of the fixture, not of the assertion.** Weakening an assertion
  until it passes changes nothing about the fixture, which is why the probe column names a
  fixture edit in every row that has one.
- **Case 3 is the criterion.** If cases 1-15 all pass and case 3 cannot fail, the plan has
  verified nothing that COMPAT.4 asks for. Its probe is therefore the strictest: the EMPTY count
  must drop by *exactly* one, so a check that reports every cell EMPTY passes case 3's positive
  half and fails its probe.

## Decisions the design did not make (§P3 design events — named, not absorbed)

These are not findings against the plan. They are questions the plan cannot answer for itself,
and each one changes what the matrix contains. Named here so they reach the design rather than
being settled quietly by whoever writes the first row.

**DE-1 — "every requirement above" is positional, and the document has 18 requirement rows
below it.** `NFR.COMPAT.4` sits at `RELEASE-4.0.0-requirements.md:264`, the last row of §4.1.
Everything in §4.2 Security, §4.3 Performance, §4.4 Observability and §4.5 Documentation comes
after it — 18 rows, counted. Read literally, the dual-role obligation reaches no security
requirement, and does not reach `NFR.OBS.5`, whose own test plan was written yesterday. The
design assumes the whole document (population = the ledger's 100 rows). The criterion says
"above". One of the two is wrong and the plan cannot pick: it decides whether ~18 rows exist in
the matrix at all. Cheapest resolution is an operator ruling in the form of U-A, or an edit of
the word "above" to "in this document".

**DE-2 — the closed vocabulary has no code for a requirement with no wire surface in any role.**
`NFR.COMPAT.4` itself is such a requirement, and so is `MIK-7215.CONTROL.5` (a stop-the-line on
an inventory, verified by inspection). `NO-SURFACE-IN-ROLE` exempts a cell in *one* role; it
does not say what to do when neither role, no transport and no revision can constrain the
statement, because the statement constrains a document. The vocabulary is closed and `--check`
refuses an unknown code, so today these rows can be neither completed nor exempted and their
cells stay EMPTY forever — which makes the pre-tag gate (case 12) unsatisfiable by construction.
Either a fourth code exists (`NO-WIRE-SURFACE`, witness = the requirement's `Verify` method
being I or D alone), or process criteria are excluded from population, and that exclusion is
itself a rule the population check has to carry.

**DE-3 — `TRANSPORT-LACKS-MECHANISM`'s witness names an artefact that does not exist.** The
witness is "the transport's capability declaration". What the repo has is one boolean predicate
on the `Transport` trait for one mechanism — `applies_extra_headers` (MIK-6710) — and prose in
doc comments. For every other mechanism there is nothing to cite, so the exemption either gets
waved through against a doc comment (case 7 then has nothing to check) or clause (c) cannot be
exempted at all and every non-applicable transport cell stays EMPTY. Deciding this is deciding
whether transports declare their capabilities in a machine-readable form.

**DE-4 — role and transport are not independent axes.** The design applies the total product of
role × transport to every row. But the client-side transports are implementors of
`trait Transport` and the server-side transports are listeners inside the gateway server; they
are different code with different mechanisms that happen to share three names. A flat transport
list crossed with role either invents cells no code could ever satisfy, or silently reads
"stdio" as one thing when it is two. This is the axis definition, so it changes the cell count
and therefore all three published numbers.

## The changes outside the test file

The tests cannot exist without their subject. Three new files, all inside this change:

- `scripts/release/render-conformance-matrix.py` — renderer, `--check`, and the pre-tag mode.
- `docs/requirements/conformance-matrix.toml` — the source. Row skeleton only; evidence is out
  of scope by the design's own list, so the honest starting state is EMPTY-heavy and the ratchet
  publishes that number rather than hiding it.
- `docs/requirements/RELEASE-4.0.0-conformance-matrix.md` — the checked-in render.

No Rust changes. No change to `count-release-criteria.py` either: the new script reads the same
documents rather than importing it, because a shared parser makes one script's bug the other's
silence.

## Baseline

`python3 -m pytest scripts/release/test_count_release_criteria.py` → **32 passed** (0.03s).
The repo's pytest guard refuses a bare full-suite invocation (it OOMs at 72K tests) and points
at `scripts/run_tests_safe.py`, which is not present in this worktree. Reported, not chased
(RED-SIGNAL TRIAGE) — the single-file run is the baseline this change needs.

No Rust baseline is stated because this change compiles no Rust. The `nfr_obs5_flag` work and
its deliberately red suite belong to another agent and are untouched here.

## §P4a — documents this change makes untrue

- `docs/requirements/RELEASE-4.0.0-readiness-board.md:48` — cluster F's row records test plan:
  no. Peer-owned; the change carries the update, the lead rules on who applies it.
- `docs/requirements/RELEASE-4.0.0-criteria-status.md:343` — the ledger row states that no
  role/transport verification matrix exists. True until the renderer lands, false after.
  **Cluster H owns that file. Not edited here.** Reported to the lead as a row that will need to
  move once the matrix exists.
- `docs/design/2026-09-02-conformance-matrix.md` — status `proposed`, and its unknowns table is
  what DE-1 through DE-4 attach to.

## Out-of-scope observations (§P0 disposal: record, do not act)

- The ledger's `blocking=yes` for this row is about the matrix not existing, not about the role
  clause being unresolved — the operator settled that clause on 2026-09-02. Both are recorded in
  one sentence there, which is why the row reads as more contested than it is.
- `NFR.COMPAT.4` cannot honestly close on this change alone. The matrix existing is acceptance
  2's mechanism; the matrix being *full* is 34 blocking rows' worth of other people's work. This
  plan delivers the first and measures the second, which is the most a T row about evidence can
  do. It does not, however, wait on cluster A or cluster C — nothing here reads
  `SUPPORTED_VERSIONS` for anything but the revision axis's membership, and that axis is the
  union of two constants whose values are not in dispute.
