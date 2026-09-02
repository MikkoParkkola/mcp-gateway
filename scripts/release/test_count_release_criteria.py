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


ROLLUP_TABLE = "\n".join(
    [
        "| # | cluster | rows | count | what is actually missing |",
        "|---|---|---|---|---|",
        "| A | envelope | `MRTR.1-8` | 22 | nothing mints one |",
        "| — | residue | `NFR.SEC.1` | 9 | genuinely independent |",
    ]
)


def test_a_cluster_table_accounting_for_every_blocking_row_passes():
    assert counter.rollup_shortfall(31, ROLLUP_TABLE) is None


def test_a_cluster_table_that_groups_only_some_of_them_is_flagged():
    # The revision this catches grouped 37 of 52 and read as though it were
    # the whole set, so the plan derived from it understated the work by 15.
    assert counter.rollup_shortfall(52, ROLLUP_TABLE) == (
        "rollup clusters account for 31 rows, the ledger has 52 blocking"
    )


def test_a_rollup_with_no_cluster_table_is_flagged_rather_than_read_as_zero():
    assert counter.rollup_shortfall(52, "# rollup\n\nprose only.\n") == (
        "no cluster table found in the rollup"
    )


# A cluster row may name a criterion the ledger no longer calls blocking. The
# total alone cannot see it: the observed failure had a waived row padding one
# cluster while a blocking row sat in none, and the two errors cancelled to the
# right sum. Membership is the direction the total cannot check.
STRAY_LEDGER = "\n".join(
    [
        "| NFR.COMPAT.1 | served | T | ABSENT | none | yes |",
        "| NFR.COMPAT.3 | no config edit | D | N/A | waived | no |",
        "| NFR.PERF.4 | ceiling | T | ABSENT | none | yes |",
    ]
)

STRAY_ROLLUP = "\n".join(
    [
        "| # | cluster | rows | count | what is missing |",
        "|---|---|---|---|---|",
        "| F | compat | `NFR.COMPAT.1`, `NFR.COMPAT.3` | 2 | operator decisions |",
    ]
)


def test_a_cluster_naming_a_row_the_ledger_does_not_call_blocking_is_flagged():
    criteria, _ = counter.rows(STRAY_LEDGER)
    assert counter.rollup_strays(criteria, STRAY_ROLLUP) == ["NFR.COMPAT.3"]


def test_a_cluster_naming_only_blocking_rows_passes():
    criteria, _ = counter.rows(STRAY_LEDGER)
    clean = STRAY_ROLLUP.replace(", `NFR.COMPAT.3`", ", `NFR.PERF.4`")
    assert counter.rollup_strays(criteria, clean) == []


def test_a_range_is_checked_at_both_ends_rather_than_skipped():
    criteria, _ = counter.rows(
        "| MIK-7212.MRTR.1 | a | T | ABSENT | none | yes |\n"
        "| MIK-7212.MRTR.8 | b | T | MET | done | no |"
    )
    table = "| A | envelope | `MRTR.1-8` | 8 | nothing mints one |"
    assert counter.rollup_strays(criteria, table) == ["MRTR.8"]


CLAUSE_LEDGER = "\n".join(
    [
        "| MIK-7246.CONFIRM.1a | refuse | T | PARTIAL | stdio ungated | yes |",
        "| MIK-7246.CONFIRM.1b | no warning | T | MET | held | no |",
    ]
)


def test_a_named_clause_is_judged_on_its_own_row_not_its_blocking_sibling():
    criteria, _ = counter.rows(CLAUSE_LEDGER)
    named_met = "| G | stdio | `MIK-7246.CONFIRM.1b` | 1 | ungated |"
    named_open = "| G | stdio | `MIK-7246.CONFIRM.1a` | 1 | ungated |"
    assert counter.rollup_strays(criteria, named_open) == []
    assert counter.rollup_strays(criteria, named_met) == ["MIK-7246.CONFIRM.1b"]


def test_a_row_named_only_in_the_notes_is_not_a_membership_claim():
    criteria, _ = counter.rows(CLAUSE_LEDGER)
    row = (
        "| G | stdio | `MIK-7246.CONFIRM.1a` | 1 | "
        "`MIK-7246.CONFIRM.1b` was in this cluster until it was met |"
    )
    assert counter.rollup_strays(criteria, row) == []


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
    print(f"{len(failed)} failed of {sum(1 for n in globals() if n.startswith('test_'))}")
    sys.exit(1 if failed else 0)
