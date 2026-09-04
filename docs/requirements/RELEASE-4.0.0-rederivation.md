<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 rederivation — consolidated

## What was audited

Every row marked MET in `docs/requirements/RELEASE-4.0.0-criteria-status.md` was re-derived in three
independent bands, each covering a contiguous line range of that document: band B1 lines 26-112,
band B2 lines 113-163, band B3 lines 164-207. HEAD at audit time was `b015f575` for all three.
The band files `RELEASE-4.0.0-rederivation-b1.md`, `-b2.md` and `-b3.md` are retained unchanged;
this document consolidates them without restating their per-row notes in full.

## The vocabulary split, and why the verdicts are not comparable

The three bands did not answer the same question. B1 and B3 asked whether a green or red revision is
on record for the test a row cites, and answered in the vocabulary `SUBSTANTIATED` / `AMBIGUOUS` /
`UNSUBSTANTIATED`. B2 asked whether the cited test exists, matches the claim, and passes when run,
and ran the suites during the audit, answering `MET`.

That difference is a property of the audit, not of the code. A B3 `UNSUBSTANTIATED` means no recorded
run — no commit revision, no pass count, nothing citable — for a test that in almost every case was
confirmed to exist and to match the row's claim. It does not mean the criterion is unmet, and it is
not evidence that the criterion would fail if run. Equally, a B2 `MET` carries an in-session pass that
B1 and B3 rows do not have, and so is not the same assurance as a B1 `SUBSTANTIATED`, which rests on a
committed revision rather than a run whose output was never recorded.

Because of that, each band's verdict is preserved verbatim below in its own column, alongside the
question that band asked. Rewriting one band's verdict into another band's vocabulary would state
something false about the 24 rows B3 could not substantiate.

## All rows

| criterion ID | band | question answered | verdict (band's own) | recorded evidence |
|---|---|---|---|---|
| MIK-7213.CACHE.1a | B1 | revision on record? | AMBIGUOUS | green `98aadc57`, no red, 1 run |
| MIK-7213.CACHE.1b | B1 | revision on record? | AMBIGUOUS | green `98aadc57`, no red, 1 run |
| MIK-7213.CACHE.2 | B1 | revision on record? | SUBSTANTIATED | green `98aadc57`, no red, 1 run |
| MIK-7213.CACHE.3a | B1 | revision on record? | SUBSTANTIATED | green `cf8c6eca`, probe narrated not committed, 2 runs |
| MIK-7213.CACHE.3b | B1 | revision on record? | SUBSTANTIATED | green `cf8c6eca`, red narrated in commit message, 2 runs |
| MIK-7212.MRTR.2b | B2 | exists, matches, passes now? | MET | `cargo test --lib` rc=0, 2026-09-04 |
| MIK-7212.MRTR.4a | B2 | exists, matches, passes now? | MET | rc=0, 18/18, 2026-09-04 |
| MIK-7212.MRTR.4b | B2 | exists, matches, passes now? | MET | rc=0, 18/18, 2026-09-04 |
| MIK-7212.MRTR.5a | B2 | exists, matches, passes now? | MET | rc=0, 18/18; same-session replay refusal |
| MIK-7212.MRTR.5b | B2 | exists, matches, passes now? | MET | rc=0, 18/18, 2026-09-04 |
| MIK-7212.MRTR.5c | B2 | exists, matches, passes now? | MET | rc=0, 1/1, 2026-09-04; genuine two-task race |
| MIK-7212.MRTR.5d | B2 | exists, matches, passes now? | MET | rc=0, 18/18, 2026-09-04 |
| MIK-7212.MRTR.6 | B2 | exists, matches, passes now? | MET | rc=0, 18/18; row supplies a dated falsifier probe (2026-09-03) |
| MIK-7212.MRTR.9 | B2 | exists, matches, passes now? | MET | rc=0, 6/6 and 3/3; commits `e1713f64`, `4f41dcf8` |
| MIK-7212.MRTR.9a | B2 | exists, matches, passes now? | MET | rc=0, 7+1+5; commit `aefb41a8`; claimed 40-assertion count unverified |
| MIK-7212.MRTR.10b | B2 | exists, matches, passes now? | MET | rc=0, 7/7; commit `63042ab2` |
| MIK-6704.IDENT.1b | B2 | exists, matches, passes now? | MET | rc=0, 8/8, 2026-09-04 |
| MIK-6704.IDENT.2 | B2 | exists, matches, passes now? | MET | rc=0, 8/8, 2026-09-04 |
| MIK-6704.IDENT.3 | B2 | exists, matches, passes now? | MET | rc=0, 17/17, 2026-09-04 |
| MIK-6704.IDENT.5 | B2 | exists, matches, passes now? | MET | rc=0, 8/8, 2026-09-04 |
| MIK-6865.SCHEMA.1a | B2 | exists, matches, passes now? | MET | rc=0, 13/13, 2026-09-04 |
| MIK-6865.SCHEMA.1b | B2 | exists, matches, passes now? | MET | rc=0, 2/2; commit `17699a9e`; ships its own falsifier test |
| MIK-7084.SURFACE.1a | B2 | exists, matches, passes now? | MET | rc=0, 29/29, 2026-09-04 |
| MIK-7084.SURFACE.1b | B2 | exists, matches, passes now? | MET | rc=0, 13/13, 2026-09-04 |
| MIK-7116.TENANT.1 | B2 | exists, matches, passes now? | MET | rc=0, 11/11 with `--features firewall` |
| MIK-7252.IDENT.4 | B2 | exists, matches, passes now? | MET | rc=0, 2/2, 2026-09-04 |
| MIK-7215.CONTROL.1a | B2 | exists, matches, passes now? | MET | no test exists; naming claim only |
| MIK-7215.CONTROL.1b | B2 | exists, matches, passes now? | MET | rc=0, 12/12, 2026-09-04 |
| MIK-7215.CONTROL.2 | B2 | exists, matches, passes now? | MET | rc=0, 6/6 and 6/6, 2026-09-04 |
| MIK-7215.CONTROL.3b | B2 | exists, matches, passes now? | MET | rc=0, 3/3, 2026-09-04 |
| MIK-7215.STATELESS.1a | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.1b | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.2 | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.3a | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.3b | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.4a | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.4b | B3 | revision on record? | UNSUBSTANTIATED | none; no test names the HTTP-status half |
| MIK-7215.STATELESS.5a | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.5b | B3 | revision on record? | UNSUBSTANTIATED | none; shares 5a's test fn |
| MIK-7215.STATELESS.6a | B3 | revision on record? | UNSUBSTANTIATED | none; 1 of 3 named methods tested |
| MIK-7215.STATELESS.6b | B3 | revision on record? | UNSUBSTANTIATED | none; no test drives the legacy path |
| MIK-7215.STATELESS.7 | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.8a | B3 | revision on record? | UNSUBSTANTIATED | none; 3 tests exist and match |
| MIK-7215.STATELESS.8b | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.9a | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.9b | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.9c | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.10a | B3 | revision on record? | UNSUBSTANTIATED | none; test exists and matches |
| MIK-7215.STATELESS.10b | B3 | revision on record? | UNSUBSTANTIATED | none; shares 10a's test fn |
| MIK-7215.STATELESS.10c | B3 | revision on record? | UNSUBSTANTIATED | none; no test names the HTTP-status half |
| MIK-7272.RESULT.1 | B3 | revision on record? | UNSUBSTANTIATED | none; cited tests match by file:line |
| MIK-7272.RESULT.2 | B3 | revision on record? | SUBSTANTIATED | green `82b0e400`, 2 runs |
| MIK-7272.ERROR.1 | B3 | revision on record? | UNSUBSTANTIATED | none; row cites no test of its own |
| MIK-7272.ERROR.2 | B3 | revision on record? | SUBSTANTIATED | green `a62f446c`, 3 runs |
| MIK-7272.ORDER.1 | B3 | revision on record? | UNSUBSTANTIATED | none; row is a code-structure argument, no test |
| MIK-7272.SUB.1a | B3 | revision on record? | UNSUBSTANTIATED | none; 8 tests exist, probes narrated without revisions |

Counted from the table above in this pass: 56 rows in total — 5 from B1, 25 from B2, 26 from B3.
Of these, 24 rows carry no recorded run, all of them in B3.

## Discrepancies between the claim and the cited artifact

These are the actionable findings. Each is a case where the row's claim is not fully carried by what
it cites, or where the citation does not resolve to what it names. They are distinct from the
no-recorded-run rows above, which say nothing about whether the claim holds. Counted from the list
below in this pass: 13 rows.

**The claim is broader than the test.** `MIK-7213.CACHE.1a` claims a TTL field on all five cacheable
methods; the cited test asserts it on `tools/list` alone. `MIK-7213.CACHE.1b` claims a cache-scope
field on all five; the cited test checks four of them, omitting `resources/read`, and checks that the
scope is not public rather than that the field is present. `MIK-7215.STATELESS.4b` and
`MIK-7215.STATELESS.10c` each claim a JSON-RPC error and an HTTP 400; the cited tests assert the
JSON-RPC half only, as both rows say themselves. `MIK-7215.STATELESS.6a` names three methods and has
a test for one of them. `MIK-7084.SURFACE.1b` claims a property of the emitted payload, but all three
cited tests call the pruning function directly rather than through a dispatch round trip, so they
establish that the pruner prunes and not that production output is pruned. `MIK-7212.MRTR.10b` claims
a guard on two caches, one of which — the idempotency cache — is never populated in any deployment,
so only the response-cache half is presently exercised; the row flags this and ties it to
`MIK-7272.SUB.4`.

**The citation does not resolve.** `MIK-7215.CONTROL.1b` cites a fifth test at a location in
`src/security/firewall/mod.rs` that holds unrelated rule-matching tests; the test named exists, but
inside the acceptance-criteria file, and a different in-module test covering the same behaviour sits
elsewhere in that file. The underlying claim holds; the artifact pointer does not.
`MIK-7215.CONTROL.2` cites five in-module tests where six exist and an enum declaration one line
off — an undercount that understates rather than overstates, but a citation that does not match.

**MET is asserted with no test at all.** `MIK-7215.CONTROL.1a` is a naming and vocabulary finding,
and the row says so; nothing pins the property it asserts, so a future rename could falsify it
silently. `MIK-7215.STATELESS.6b` states its guarantee is read off a code branch rather than
asserted. `MIK-7272.ERROR.1` cites no test of its own and borrows evidence from rows that are
themselves unsubstantiated. `MIK-7272.ORDER.1` is a code-structure argument about construction order
with no test cited.

**Line drift, recorded but not counted as a discrepancy.** Several rows cite line numbers that no
longer land on the declarations they name — a consistent offset of roughly 55 lines in
`tests/mik_7272_exploit_acs.rs`, around 475 lines in `src/gateway/meta_mcp/invoke.rs`, and smaller
offsets elsewhere. In each case the named test was found in the named file and matched the claim, so
the pattern points at citations written before an edit shifted the file rather than at a wrong claim.
It is worth a bulk re-derivation of line references, not a re-audit.

## What would settle the unsubstantiated rows

Nothing about those 24 rows suggests the criteria are unmet. Every one of them except the four that
cite no test names a test that was confirmed to exist and to match its claim; what is absent is the
record of the test having been run — a revision at which it was green, a pass count, and where the
claim is strong enough to warrant one, a revision or a documented probe at which it was red.

The cost of supplying it is small and asymmetric between the two halves. The green half is a single
run of the affected suites at a known revision with the counts written into the rows: the tests
already exist, so this is recording an output rather than producing new evidence, and the rows in
question concentrate in two files. The red half is more expensive, because a break-and-restore probe
has to be performed per claim and its result narrated, and six of the 24 —
`MIK-7215.STATELESS.4b`, `.6a`, `.6b`, `.10c`, `MIK-7272.ERROR.1` and `MIK-7272.ORDER.1` — also appear
in the discrepancy list above, so for those a recorded run settles nothing on its own: extending the
tests to cover the half nothing currently asserts would close both the discrepancy and the missing
evidence in one pass, which no amount of recording can do. The other eighteen need only the run
recorded.
