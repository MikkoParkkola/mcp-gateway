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
