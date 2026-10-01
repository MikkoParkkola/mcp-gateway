# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A finding a bot puts only in its review-summary body must reach the ledger.

The sweep read review threads only, so a bot review with no inline comment
whose body named a defect passed the final sweep unseen (GH1625.BOTREVIEW.1).
"""

import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "botreview_sweep",
    pathlib.Path(__file__).with_name("botreview_sweep.py"),
)
sweep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sweep)


def review(body, comments=0, kind="Bot"):
    return {
        "author": {"login": "copilot-pull-request-reviewer", "__typename": kind},
        "url": "https://github.com/MikkoParkkola/mcp-gateway/pull/1#pullrequestreview-7",
        "body": body,
        "comments": {"totalCount": comments},
    }


def test_a_body_only_bot_review_without_a_no_findings_marker_is_flagged():
    finding = review("### Needs a closer look\n\nThe token is logged in clear.")
    error = review("Copilot encountered an error and was unable to review this pull request.")
    assert sweep.body_findings([finding, error]) == [finding, error]


def test_reviews_that_cannot_hide_a_finding_are_not_flagged():
    clean = review("## Copilot review overview\n\n**Findings:** None\n")
    with_threads = review("Two suggestions inline.", comments=2)
    empty = review("   ")
    human = review("Looks wrong to me.", kind="User")
    assert sweep.body_findings([clean, with_threads, empty, human]) == []


def test_a_linked_review_body_is_not_missing():
    ledger = "| #1 | [review](https://github.com/MikkoParkkola/mcp-gateway/pull/1#pullrequestreview-7) |"
    assert sweep.linked_reviews(ledger) == {("1", "7")}
