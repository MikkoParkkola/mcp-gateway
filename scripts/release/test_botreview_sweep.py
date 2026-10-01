# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A finding a bot puts only in its review-summary body must reach the ledger.

The sweep read review threads only, so a bot review with no inline comment
whose body named a defect passed the final sweep unseen (GH1625.BOTREVIEW.1).
"""

import importlib.util
import pathlib
import sys
import traceback

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


CODEX = """
### 💡 Codex Review

Here are some automated review suggestions for this pull request.

**Reviewed commit:** `8b6eb7146d`


<details> <summary>ℹ️ About Codex in GitHub</summary>
<br/>

[Your team has set up Codex to review pull requests in this repo](https://chatgpt.com/codex/cloud/settings/general). Reviews are triggered when you
- Open a pull request for review
- Mark a draft as ready
- Comment "@codex review".

If Codex has suggestions, it will comment; otherwise it will react with 👍.




Codex can also answer questions or update the PR. Try commenting "@codex address that feedback".

</details>"""


def overview(findings, section=""):
    return (
        "<!-- ccr-overview-v2 -->\n## Copilot review overview\n\n**Findings:** %s\n%s"
        "<details><summary>What changed</summary>table</details>\n" % (findings, section)
    )


LINKED = "Open (1)\n- [Escape the header](#discussion_r42) · New\n"


def test_a_body_that_may_hold_more_than_its_threads_is_flagged():
    finding = review("### Needs a closer look\n\nThe token is logged in clear.")
    error = review("Copilot encountered an error and was unable to review this pull request.")
    more_than_inline = review(overview("2"), comments=1)
    two_counts = review(overview("None") + "\n**Findings:** 3\n")
    codex_plus = review(CODEX + "\nAlso: the key is written to the log.", comments=2)
    prose = review(overview("1", LINKED + "The token also leaks in logs.\n"), comments=1)
    unlinked = review(overview("1", "Open (1)\n- The token leaks in logs\n"), comments=1)
    flagged = [finding, error, more_than_inline, two_counts, codex_plus, prose, unlinked]
    assert sweep.body_findings(flagged) == flagged


def test_bodies_whose_findings_are_all_in_threads_are_not_flagged():
    none = review(overview("None"))
    counted = review(overview("1", LINKED), comments=3)
    codex = review(CODEX.replace("8b6eb7146d", "0123456789"), comments=1)
    empty = review("   ")
    human = review("Looks wrong to me.", kind="User")
    assert sweep.body_findings([none, counted, codex, empty, human]) == []


def test_a_linked_review_body_is_not_missing():
    ledger = "| #1 | [review](https://github.com/MikkoParkkola/mcp-gateway/pull/1#pullrequestreview-7) |"
    assert sweep.linked_reviews(ledger) == {("1", "7")}


if __name__ == "__main__":
    # CI runs this file as a script; without this it would define its tests
    # and exit 0 having asserted nothing.
    failed = []
    names = [n for n, fn in sorted(globals().items()) if n.startswith("test_") and callable(fn)]
    for name in names:
        try:
            globals()[name]()
        except AssertionError:
            failed.append(name)
            traceback.print_exc()
    print(f"{len(failed)} failed of {len(names)}")
    sys.exit(1 if failed else 0)
