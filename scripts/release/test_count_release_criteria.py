# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A number in a heading must say what it counts, immediately.

The release plan's title and one of its section headings each carried a total
that had been correct three edits earlier. Neither is reachable by the headline
check, which reads one designated line in one file, so both went stale in
public view while the derived line beside them was right.

Prose totals cannot be told from prose subtotals mechanically -- `23 blocking`
and `5 of the 10 criteria blocking` are both legitimate sentences. Headings can:
a heading states a count only as `<n> criteria` or `<n> of <m>`, so a bare
number followed by anything else is a claim nothing maintains.
"""

import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "count_release_criteria",
    pathlib.Path(__file__).with_name("count-release-criteria.py"),
)
counter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(counter)


def test_flags_a_total_that_does_not_say_what_it_counts():
    text = "\n".join(
        [
            "# v4.0.0 release plan — closing the 45 blocking criteria",
            "## 45 is still a floor, and what remains unverified is named",
        ]
    )
    assert counter.heading_counts(text) == [
        "# v4.0.0 release plan — closing the 45 blocking criteria",
        "## 45 is still a floor, and what remains unverified is named",
    ]


def test_allows_the_shapes_a_heading_may_state():
    text = "\n".join(
        [
            "# v4.0.0 release plan — closing the blocking criteria",
            "### A. MRTR continuation state — MIK-7212, 10 criteria — CRITICAL PATH",
            "### D. Header forwarding — MIK-7214, 1 criterion",
            "## MIK-7272 (RESULT, ERROR, ORDER) — partial, 7 of 17 MIK-7272 criteria",
            "## MIK-7246 (CONFIRM) — destructive-operation confirmation gate, 3 of 3",
            "## NFR (section 4 of the requirements) — 22 criteria, opened 2026-09-01",
            "### G. Schema validity — MIK-6865.SCHEMA.1",
            "# 4.0.0 release: acceptance criteria verified against source",
            "## Order of work",
        ]
    )
    assert counter.heading_counts(text) == []


def test_the_live_documents_pass():
    for doc in (counter.STATUS, counter.PLAN):
        assert counter.heading_counts(doc.read_text()) == [], doc


REQ = "| NFR.PERF.1 | routing latency stays within budget | T, M |"


def test_refuses_a_method_the_vocabulary_does_not_contain():
    methods, unreadable = counter.required_methods("| NFR.PERF.1 | latency | owner |")
    assert methods == {}
    assert unreadable == ["NFR.PERF.1 ('owner')"]


def test_reads_a_method_the_vocabulary_contains():
    methods, unreadable = counter.required_methods(REQ)
    assert methods == {"NFR.PERF.1": "T, M"}
    assert unreadable == []


def test_flags_a_status_row_whose_method_disagrees_with_the_requirement():
    methods, _ = counter.required_methods(REQ)
    row = "| NFR.PERF.1 | latency | I | MET | some evidence | no |"
    assert counter.method_mismatches(row, methods) == [
        "NFR.PERF.1 (requirement says 'T, M', row says 'I')"
    ]


def test_accepts_a_status_row_whose_method_agrees():
    methods, _ = counter.required_methods(REQ)
    row = "| NFR.PERF.1 | latency | T, M | MET | some evidence | no |"
    assert counter.method_mismatches(row, methods) == []


# A cluster's declared count and its named criteria are two statements about the
# same set, and the ledger settles both. The observed failure had a waived row
# padding one cluster while a blocking row sat in no cluster at all: two errors
# that cancelled in the SUM, which was the only thing being checked.
LEDGER = "\n".join(
    [
        "| MIK-7212.MRTR.1a | mints | T | UNWIRED | none | yes |",
        "| MIK-7212.MRTR.2a | opens | T | MET | done | no |",
        "| MIK-7212.MRTR.3a | refuses | T | UNWIRED | none | yes |",
        "| NFR.COMPAT.1 | served | T | ABSENT | none | yes |",
        "| NFR.COMPAT.3 | no config edit | D | N/A | waived | no |",
    ]
)

ROLLUP = "\n".join(
    [
        "| # | cluster | rows | count | what is actually missing |",
        "|---|---|---|---|---|",
        "| A | envelope | `MRTR.1`, `MRTR.3` | 2 | nothing mints one |",
        "| — | residue | `NFR.COMPAT.1` | 1 | genuinely independent |",
    ]
)


def membership(ledger, rollup):
    criteria, _ = counter.rows(ledger)
    return counter.rollup_membership(criteria, rollup)


def test_a_rollup_accounting_for_every_blocking_row_exactly_once_passes():
    assert membership(LEDGER, ROLLUP) == []


def test_a_blocking_row_no_cluster_names_is_flagged():
    # The failure the sum could not see: dropping a row here is invisible to any
    # check that only adds the declared counts up.
    thinned = ROLLUP.replace(
        "| — | residue | `NFR.COMPAT.1` | 1 | genuinely independent |", ""
    )
    assert membership(LEDGER, thinned) == [
        "NFR.COMPAT.1 is blocking and sits in no cluster"
    ]


def test_a_row_two_clusters_both_claim_is_flagged():
    doubled = ROLLUP + "\n| B | era | `NFR.COMPAT.1` | 1 | also here |"
    assert membership(LEDGER, doubled) == ["NFR.COMPAT.1 is claimed by 2 clusters"]


def test_a_cluster_naming_a_row_the_ledger_does_not_call_blocking_is_flagged():
    stray = ROLLUP.replace(
        "`MRTR.1`, `MRTR.3` | 2", "`MRTR.1`, `MRTR.3`, `NFR.COMPAT.3` | 2"
    )
    assert membership(LEDGER, stray) == [
        "cluster A names NFR.COMPAT.3, which no ledger row calls blocking"
    ]


def test_a_cluster_emptied_by_closure_names_its_met_criterion_and_passes():
    """A cluster whose last blocking row closed had no spelling this accepted.

    Declaring zero and naming nothing trips `names no criteria`; declaring zero
    and naming the row that closed tripped `no ledger row calls blocking`. So
    the first cluster to reach empty could not be written down at all, and the
    only way to keep the gate green was to leave a met row marked blocking --
    the gate arguing for the drift it exists to catch. A name that resolves to
    a row the ledger HAS and does not call blocking is exactly what a closure
    leaves behind, and it is only readable as a mistake while the cluster still
    claims rows.
    """
    emptied = ROLLUP + "\n| H | rate-limit typing | `NFR.COMPAT.3` | 0 | closed |"
    assert membership(LEDGER, emptied) == []


def test_an_emptied_cluster_naming_a_criterion_the_ledger_lacks_is_flagged():
    """The typo guard survives the exemption above.

    A closed cluster is recognised by its name resolving to a KNOWN row, never
    by the count being zero. Without that, `| H | ... | 0 |` would accept any
    string at all and a mistyped criterion would read as a closure.
    """
    typo = ROLLUP + "\n| H | rate-limit typing | `NFR.COMPAT.9` | 0 | closed |"
    assert membership(LEDGER, typo) == [
        "cluster H names NFR.COMPAT.9, which no ledger row calls blocking"
    ]


def test_a_declared_count_the_named_criteria_do_not_reach_is_flagged():
    assert membership(LEDGER, ROLLUP.replace("`MRTR.3` | 2", "`MRTR.3` | 5")) == [
        "cluster A declares 5 rows, its criteria resolve to 2"
    ]


def test_a_range_is_expanded_rather_than_sampled_at_its_endpoints():
    # `MRTR.2` is met and sits inside the range. Checking only the endpoints
    # reports a stale range as sound, which is how the live document carried one.
    ranged = ROLLUP.replace("`MRTR.1`, `MRTR.3` | 2", "`MRTR.1-3` | 2")
    assert membership(LEDGER, ranged) == [
        "cluster A names MRTR.2, which no ledger row calls blocking"
    ]


def test_a_malformed_range_is_reported_rather_than_expanded_into_invented_names():
    # `MRTR.1a-3` is not a range: its head ends in a clause letter, so there is no
    # number to count from. Expanding it crashed the checker, which makes the
    # document unreadable instead of reporting what is wrong with it.
    assert counter.named_criteria("`MRTR.1a-3`, `MRTR.8-3`") == (
        [],
        ["`MRTR.1a-3`", "`MRTR.8-3`"],
    )


def test_a_malformed_range_does_not_pass_as_its_own_head():
    # Keeping the head made `MRTR.1a-3` resolve to one blocking row, so a cluster
    # declaring one agreed with a token that names a range nobody can read.
    ranged = ROLLUP.replace("`MRTR.1`, `MRTR.3` | 2", "`MRTR.1a-3` | 1")
    assert membership(LEDGER, ranged) == [
        "cluster A names `MRTR.1a-3`, which is not a criterion name",
        "cluster A declares 1 rows, its criteria resolve to 0",
        "MIK-7212.MRTR.1a is blocking and sits in no cluster",
        "MIK-7212.MRTR.3a is blocking and sits in no cluster",
    ]


def test_a_token_the_parser_cannot_read_is_reported_rather_than_dropped():
    # `CACHE.4a-c` is neither a name nor a range. Dropping it leaves a cluster
    # naming nothing, and a cluster naming nothing against a declared count of
    # zero passes every other check in here.
    unreadable = ROLLUP + "\n| B | cache | `CACHE.4a-c` | 0 | nothing yet |"
    assert membership(LEDGER, unreadable) == [
        "cluster B names `CACHE.4a-c`, which is not a criterion name"
    ]


def test_an_unqualified_name_matching_two_tickets_is_flagged():
    # `MRTR.1` binds by suffix. A second ticket reusing the component name would
    # hand cluster A a row nobody put there, and the count would still add up.
    shared = LEDGER + "\n| MIK-9999.MRTR.1a | elsewhere | T | ABSENT | none | yes |"
    doubled = ROLLUP.replace("`MRTR.1`, `MRTR.3` | 2", "`MRTR.1`, `MRTR.3` | 3")
    assert membership(shared, doubled) == [
        "cluster A names MRTR.1, which matches rows under 2 tickets"
    ]


def test_a_rollup_with_no_cluster_table_is_flagged_rather_than_read_as_zero():
    assert membership(LEDGER, "# rollup\n\nprose only.\n") == [
        "no cluster table found in the rollup"
    ]


CLAUSE_LEDGER = "\n".join(
    [
        "| MIK-7246.CONFIRM.1a | refuse | T | PARTIAL | stdio ungated | yes |",
        "| MIK-7246.CONFIRM.1b | no warning | T | MET | held | no |",
    ]
)


def test_a_named_clause_is_judged_on_its_own_row_not_its_blocking_sibling():
    named_open = "| G | stdio | `MIK-7246.CONFIRM.1a` | 1 | ungated |"
    named_met = "| G | stdio | `MIK-7246.CONFIRM.1b` | 1 | ungated |"
    assert membership(CLAUSE_LEDGER, named_open) == []
    assert membership(CLAUSE_LEDGER, named_met) == [
        "cluster G names MIK-7246.CONFIRM.1b, which no ledger row calls blocking",
        "cluster G declares 1 rows, its criteria resolve to 0",
        "MIK-7246.CONFIRM.1a is blocking and sits in no cluster",
    ]


def test_a_row_named_only_in_the_notes_is_not_a_membership_claim():
    row = (
        "| G | stdio | `MIK-7246.CONFIRM.1a` | 1 | "
        "`MIK-7246.CONFIRM.1b` was in this cluster until it was met |"
    )
    assert membership(CLAUSE_LEDGER, row) == []


BOTH_BLOCKING = "\n".join(
    [
        "| MIK-7246.CONFIRM.1a | refuse | T | PARTIAL | stdio ungated | yes |",
        "| MIK-7246.CONFIRM.1b | no warning | T | UNWIRED | none | yes |",
    ]
)


def test_a_fully_qualified_parent_covering_its_clauses_is_not_read_as_two_tickets():
    # The ambiguity check exists for an unqualified name binding across tickets.
    # A fully qualified parent cannot be ambiguous -- it names its ticket -- so
    # counting its clauses as owners blocks the one spelling that is unambiguous.
    named = "| G | stdio | `MIK-7246.CONFIRM.1` | 2 | ungated |"
    assert membership(BOTH_BLOCKING, named) == []


def test_an_unterminated_backtick_span_is_reported_rather_than_ignored():
    # `CACHE.4 never closes, so no token matches and the cluster names nothing.
    # Against a declared count of zero that reads as a clean cluster, which is
    # the failure the token scanner was written to prevent.
    unterminated = ROLLUP + "\n| B | cache | `CACHE.4 | 0 | nothing yet |"
    assert membership(LEDGER, unterminated) == [
        "cluster B names `CACHE.4, which is not a criterion name"
    ]


def test_an_empty_backtick_span_is_reported_rather_than_ignored():
    empty = ROLLUP + "\n| B | cache | `` | 0 | nothing yet |"
    assert membership(LEDGER, empty) == [
        "cluster B names ``, which is not a criterion name"
    ]


def test_a_cluster_whose_cell_names_nothing_at_all_is_reported():
    # No backticks means no tokens, so neither the named nor the unreadable list
    # has anything to say and a declared zero matches an empty membership. A
    # cluster row that names no criterion is malformed however it is counted.
    prose = ROLLUP + "\n| B | cache | nothing yet | 0 | nothing yet |"
    assert membership(LEDGER, prose) == ["cluster B names no criteria"]


def test_a_cluster_row_that_does_not_parse_is_reported_rather_than_skipped():
    # Skipping an unparseable row is invisible: the row and every criterion it
    # accounts for leave the reckoning together, so the totals still balance and
    # nothing records that a cluster went missing.
    broken = ROLLUP + "\n| BB | cache | `MIK-7212.MRTR.1` | 1 | two-letter id |"
    assert membership(LEDGER, broken) == [
        "cluster row 'BB' does not parse: id must be a single capital or an em "
        "dash and the count cell a bare number, not '1'"
    ]


def test_a_cluster_id_too_long_to_look_like_one_is_still_reported():
    # The shape test that used to claim these rows accepted one to three
    # non-space characters, so a four-letter id fell through it and the row
    # vanished. Column count decides what a cluster row is; the id only decides
    # whether it parses.
    broken = ROLLUP + "\n| ABCD | cache | `MIK-7212.MRTR.1` | 1 | four letters |"
    assert membership(LEDGER, broken) == [
        "cluster row 'ABCD' does not parse: id must be a single capital or an em "
        "dash and the count cell a bare number, not '1'"
    ]


def test_a_cluster_id_that_is_not_a_letter_at_all_is_reported():
    broken = ROLLUP + "\n| A! | cache | `MIK-7212.MRTR.1` | 1 | punctuation |"
    assert membership(LEDGER, broken) == [
        "cluster row 'A!' does not parse: id must be a single capital or an em "
        "dash and the count cell a bare number, not '1'"
    ]


def test_a_count_cell_that_is_not_a_number_is_reported_rather_than_skipped():
    broken = ROLLUP + "\n| B | cache | `MIK-7212.MRTR.1` | one | spelled out |"
    assert membership(LEDGER, broken) == [
        "cluster row 'B' does not parse: id must be a single capital or an em "
        "dash and the count cell a bare number, not 'one'"
    ]


def test_a_mistyped_criterion_id_is_reported_rather_than_read_as_a_real_one():
    # Two ways to lose the row, and the anchor only closed the first. Unanchored,
    # `MRTR.1abc` matches as far as `MRTR.1a` and is counted as that criterion.
    # Anchored but merely skipped, the row vanishes from the accounting instead
    # -- still silent, and a blocking criterion is what goes missing. A row whose
    # id opens like a criterion id IS a criterion row; failing to parse makes it
    # malformed, never absent.
    table = [
        "| id | criterion | method | blocking |",
        "| --- | --- | --- | --- |",
        "| MIK-7212.MRTR.1abc | mistyped | T | yes |",
    ]
    assert counter.rows("\n".join(table)) == ([], ["MIK-7212.MRTR.1abc"])


def test_a_github_issue_id_is_read_as_a_criterion():
    # The third family. A criterion set published on an issue before it has a
    # Linear ticket is cited by the identifier the reporter can read.
    table = [
        "| id | criterion | method | blocking |",
        "| --- | --- | --- | --- |",
        "| GH475.RL.1 | a rate-limited response records nothing | T | yes |",
        "| GH475.CFG.5b | the capability threshold reaches the budget | T | yes |",
    ]
    criteria, malformed = counter.rows("\n".join(table))
    assert malformed == []
    assert criteria == [
        ("GH475.RL.1", "yes", "GH475.RL.1"),
        ("GH475.CFG.5", "yes", "GH475.CFG.5b"),
    ]


def test_a_mistyped_github_criterion_id_is_reported_rather_than_read_as_a_real_one():
    # Widening the grammar must not widen what it accepts loosely: the same
    # both-ends anchor that catches `MRTR.1abc` has to catch this one too, or
    # the new family arrives with the defect the old one had removed.
    table = [
        "| id | criterion | method | blocking |",
        "| --- | --- | --- | --- |",
        "| GH475.RL.1abc | mistyped | T | yes |",
    ]
    assert counter.rows("\n".join(table)) == ([], ["GH475.RL.1abc"])


def test_the_live_documents_agree_with_the_ledger():
    criteria, _ = counter.rows(counter.STATUS.read_text())
    assert counter.rollup_membership(criteria, counter.ROLLUP.read_text()) == []


CLAUSE_QUALIFIED = "\n".join(
    [
        "| MIK-7272.EXT.1 (clause: declare) | declare | T | MET | held | no |",
        "| MIK-7272.EXT.1 (clause: honour) | honour | T | PARTIAL | open | yes |",
    ]
)


def test_a_clause_qualified_id_is_read_as_a_criterion():
    # The ledger splits one criterion into named clauses by suffixing the id
    # with ` (clause: <word>)`. An anchored id pattern rejects that spelling,
    # so both rows fell to the malformed branch and the blocking enumeration
    # could not be produced at all.
    criteria, malformed = counter.rows(CLAUSE_QUALIFIED)
    assert malformed == []
    assert criteria == [
        ("MIK-7272.EXT.1", "no", "MIK-7272.EXT.1 (clause: declare)"),
        ("MIK-7272.EXT.1", "yes", "MIK-7272.EXT.1 (clause: honour)"),
    ]


def test_a_malformed_clause_qualifier_is_reported_rather_than_read_loosely():
    # Only the ledger's own spelling is a clause. A parenthesised word without
    # the `clause:` key is a typo, and a row that claims to be a criterion and
    # is not readable as one is malformed, never absent.
    table = "| MIK-7272.EXT.1 (declare) | declare | T | MET | held | no |"
    assert counter.rows(table) == ([], ["MIK-7272.EXT.1 (declare)"])


def test_a_clause_row_covers_the_requirement_it_splits():
    # The requirement declares the unsuffixed id; only clause rows exist for it.
    assert counter.CLAUSE.sub("", "MIK-7272.EXT.1 (clause: honour)") == (
        "MIK-7272.EXT.1"
    )


def test_a_letter_split_is_not_stripped_like_a_clause():
    # `.1a` and `.1b` are two criteria, so neither may stand in for a declared
    # `.1`; stripping them is what made every split invisible to the coverage.
    assert counter.CLAUSE.sub("", "MIK-7213.CACHE.4a") == "MIK-7213.CACHE.4a"


def test_both_selectors_see_the_same_criterion_rows():
    """The parity the shared selector exists to hold, asserted on the real file.

    Deliberately not a pin on WHICH rows disagree. That set is the content of a
    document another session edits, and three of the four rows it held moved
    between one run of this suite and the next -- a suite that asserts another
    owner's work in progress goes red on their edits, not on ours.
    `--blocking-consistency` is the path that reports the verdicts.

    What belongs here is that the two row selections still agree. They were two
    copies of one predicate before this rule was added; a third reader deciding
    on its own which rows it may see is how a rule comes to police a different
    population than the count it is compared against.
    """
    text = counter.STATUS.read_text()
    seen = [cells[0] for cells, _status in counter.criterion_cells(text)]
    counted = [suffixed for _id, _flag, suffixed in counter.rows(text)[0]]
    assert len(seen) > 100, len(seen)
    assert seen == counted, set(seen) ^ set(counted)

    # The live file holds no malformed flag today, so parity over it alone is
    # green whether or not the selector filters on the flag. One injected row
    # is what makes this assertion fail if the two ever stop agreeing on what a
    # criterion row is.
    bad = "| NFR.PERF.9 | a criterion | M | ABSENT | nothing built | maybe |"
    spiked = f"{text}\n{bad}\n"
    assert [cells[0] for cells, _status in counter.criterion_cells(spiked)] == seen
    kept, malformed = counter.rows(spiked)
    assert [suffixed for _id, _flag, suffixed in kept] == counted
    assert malformed == ["NFR.PERF.9"]


def test_a_functional_row_is_not_read_as_an_nfr_row_by_its_status_cell():
    """`T` in a functional row's status cell must not promote the evidence cell.

    Deciding the status column from the CONTENT of the third cell took `MET`
    here -- the evidence -- as the status, and a row whose real status was `T`
    passed the vocabulary check and the blocking rule both.
    """
    row = "| MIK-7212.MRTR.9 | a criterion | T | MET | no |"
    assert counter.status_violations(row) == ["MIK-7212.MRTR.9 (T)"]
    assert counter.blocking_disagreements(row) == []


def test_an_nfr_row_reads_the_cell_after_its_method_column():
    row = "| NFR.PERF.9 | a criterion | T, D | ABSENT | nothing built | no |"
    assert counter.status_violations(row) == []
    assert counter.blocking_disagreements(row)[0] == ("NFR.PERF.9", "ABSENT", "no")


def test_a_malformed_blocking_cell_is_a_defect_of_the_check_that_owns_it():
    """The selector skips it; `rows` calls it malformed and stops the run.

    Reported once, by one check. The rule below never sees the row, which is
    only safe because `main` refuses the document before it gets there.
    """
    row = "| NFR.PERF.9 | a criterion | M | ABSENT | nothing built | maybe |"
    assert counter.rows(row) == ([], ["NFR.PERF.9"])
    assert counter.blocking_disagreements(row) == []


def test_a_row_that_is_absent_and_flagged_non_blocking_is_caught():
    row = "| NFR.PERF.9 | a criterion | M | ABSENT | nothing built | no |"
    assert counter.blocking_disagreements(row)[0][0] == "NFR.PERF.9"


def test_a_row_that_is_met_and_flagged_blocking_is_caught():
    """The other direction: work that is done must not inflate the count."""
    row = "| NFR.PERF.9 | a criterion | M | MET | shipped | yes |"
    assert counter.blocking_disagreements(row)[0][0] == "NFR.PERF.9"


def test_the_two_statuses_the_rule_exempts_pass_when_flagged_non_blocking():
    rows = (
        "| NFR.PERF.9 | a criterion | M | MET | shipped | no |\n"
        "| NFR.PERF.8 | a criterion | M | N/A | out of scope | no |"
    )
    assert counter.blocking_disagreements(rows) == []


class Ledger:
    """Stands in for the status document, which `main` reads exactly once.

    A temp file would be the obvious way to do this and is the wrong one: the
    reviewers run this suite in a read-only sandbox with no writable TMPDIR,
    where `tempfile` raises before a single assertion is reached.
    """

    def __init__(self, text):
        self.text = text

    def read_text(self):
        return self.text


def gate_on(text):
    """Run the whole gate over a ledger variant, the way CI runs it.

    The rule under test is reached through `main`, so asserting on the function
    alone would pass unchanged if the call were deleted from the gate.
    """
    import contextlib
    import io
    import sys

    original, argv = counter.STATUS, sys.argv
    try:
        counter.STATUS = Ledger(text)
        sys.argv = ["count-release-criteria.py", "--check"]
        with contextlib.redirect_stdout(io.StringIO()):
            with contextlib.redirect_stderr(io.StringIO()):
                return counter.main()
    finally:
        counter.STATUS, sys.argv = original, argv


def regrade_leaving_the_flag(text):
    """Move one row out of MET and leave its `no` behind.

    The shape three rows took on 2026-09-15, and the one no other check sees:
    the blocking SET is unchanged, so the cluster rollup stays consistent and
    the headline total still adds up. Flipping a flag instead would be caught
    by the cluster check and would prove nothing about this rule.
    """
    out, done = [], False
    for line in text.splitlines(keepends=True):
        if not done and "| MET " in line and line.rstrip().endswith("| no |"):
            line, done = line.replace("| MET ", "| ABSENT ", 1), True
        out.append(line)
    assert done, "the ledger no longer holds a MET row flagged non-blocking"
    return "".join(out)


def test_the_blocking_rule_is_enforced_by_the_gate_ci_runs():
    """`--check` is what ci.yml, docker.yml and release.yml run."""
    text = counter.STATUS.read_text()
    assert gate_on(text) == 0
    mutant = regrade_leaving_the_flag(text)
    before = sum(1 for _i, b, _s in counter.rows(text)[0] if b == "yes")
    after = sum(1 for _i, b, _s in counter.rows(mutant)[0] if b == "yes")
    assert before == after, "the mutation moved the count and proves nothing"
    assert gate_on(mutant) == 1


def test_a_dated_ruling_in_the_evidence_cell_lifts_the_flag():
    """The rule the ledger states admits one exception, and it is dated.

    NFR.PERF.1 is the instance: graded PARTIAL, flagged `no`, and carrying a
    ruling that says so. Without this the row reads as a stale flag forever.
    """
    row = (
        "| NFR.PERF.1 | a criterion | M | PARTIAL | "
        "**Blocking flag lifted, 2026-09-05:** out of the release gate | no |"
    )
    assert counter.blocking_disagreements(row) == []


def test_an_undated_assertion_does_not_lift_the_flag():
    """A stale flag defends itself in exactly these words; the date is the proof."""
    row = (
        "| NFR.PERF.1 | a criterion | M | PARTIAL | "
        "**Blocking flag lifted:** out of the release gate | no |"
    )
    assert counter.blocking_disagreements(row)[0] == ("NFR.PERF.1", "PARTIAL", "no")


def test_a_qualified_status_is_read_by_its_word_not_its_parenthetical():
    """`ABSENT (regraded 2026-09-15)` is the shape three rows regraded into."""
    row = "| NFR.PERF.9 | a criterion | M | ABSENT (regraded 2026-09-15) | x | no |"
    assert counter.blocking_disagreements(row)[0][0] == "NFR.PERF.9"


def test_a_status_outside_the_vocabulary_is_left_to_the_check_that_owns_it():
    """Reporting it here too would name one defect as two, in two messages."""
    row = "| NFR.PERF.9 | a criterion | M | DONE | shipped | no |"
    assert counter.blocking_disagreements(row) == []
    assert counter.status_violations(row) != []


def test_a_functional_row_without_a_method_column_reads_its_own_status():
    """Position is decided by the method regex, not by the id's prefix."""
    row = "| MIK-7212.MRTR.9 | a criterion | ABSENT | nothing built | no |"
    assert counter.blocking_disagreements(row)[0][0] == "MIK-7212.MRTR.9"


def test_the_shared_selector_skips_what_is_not_a_criterion_row():
    text = (
        "| Group | Criteria | Audited here |\n"
        "| --- | --- | --- | --- |\n"
        "not a table row at all\n"
        "| NFR.PERF.9 | a criterion | M | MET | shipped | maybe |\n"
    )
    assert list(counter.criterion_cells(text)) == []


if __name__ == "__main__":
    # CI runs this file as a script, not under pytest. Without this the module
    # defines its tests, exits 0, and the gate reports a pass having asserted
    # nothing -- which is what it did from the day the CI step was added.
    import sys
    import traceback

    failed = []
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
        except AssertionError:
            failed.append(name)
            traceback.print_exc()
    print(
        f"{len(failed)} failed of {sum(1 for n in globals() if n.startswith('test_'))}"
    )
    sys.exit(1 if failed else 0)
