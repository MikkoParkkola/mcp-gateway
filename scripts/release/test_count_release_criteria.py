# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: MIT
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
