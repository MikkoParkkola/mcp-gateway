#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""List automated-reviewer threads that the GH1625.BOTREVIEW.1 ledger lacks.

For every PR merged into the release line after #1625 closed, read its review
threads (all pages) and keep the bot-started ones. Every such thread must be
linked by its own `#discussion_r<id>` in the ledger; a count is never enough.
A bot review whose summary body may carry a finding no thread does must be
linked by its `#pullrequestreview-<id>` (see `body_findings`).
Exit 1 when any thread is unlinked or the PR list may be truncated, so the
final sweep is a diff.

Needs an authenticated `gh`. Usage:
    python3 scripts/release/botreview_sweep.py [--ledger PATH]
"""

import argparse
import json
import re
import subprocess
import sys

REPO = "MikkoParkkola/mcp-gateway"
BASE = "docs/ranking-1-release-line"
SINCE = "2026-09-29T02:27:33Z"  # #1625 closed
LEDGER = "docs/internal/release/v4.0.0-botreview-ledger.md"
LIMIT = 1000
QUERY = """query($n:Int!,$after:String){repository(owner:"MikkoParkkola",name:"mcp-gateway"){
pullRequest(number:$n){reviewThreads(first:100,after:$after){pageInfo{hasNextPage endCursor}
nodes{comments(first:1){nodes{author{login __typename} url path line originalLine}}}}
reviews(first:100){pageInfo{hasNextPage}
nodes{author{login __typename} url body comments{totalCount}}}}}}"""
# Copilot's overview states how many findings it raised; Codex's summary is a
# fixed template. A body matching neither is unaccounted for.
COPILOT_OVERVIEW = "<!-- ccr-overview-v2 -->"
COPILOT_FINDINGS = re.compile(r"\*\*Findings:\*\*\s*(None|\d+)")
SECTION_HEADING = re.compile(r"(Open|Resolved|Outdated) \(\d+\)")
CODEX_TEMPLATE = (
    "### 💡 Codex Review Here are some automated review suggestions for this pull request. "
    "**Reviewed commit:** `SHA` <details> <summary>ℹ️ About Codex in GitHub</summary> <br/> "
    "[Your team has set up Codex to review pull requests in this repo](URL Reviews are "
    "triggered when you - Open a pull request for review - Mark a draft as ready - Comment "
    "\"@codex review\". If Codex has suggestions, it will comment; otherwise it will react "
    "with 👍. Codex can also answer questions or update the PR. Try commenting "
    "\"@codex address that feedback\". </details>"
)


def _normalised(body: str) -> str:
    body = re.sub(r"https?://\S+", "URL", body)
    body = re.sub(r"(\*\*Reviewed commit:\*\* )`[0-9a-f]{7,40}`", r"\1`SHA`", body)
    return re.sub(r"\s+", " ", body).strip()


def _accounted_for(review: dict) -> bool:
    """Whether every finding this review's body could carry is in its threads."""
    body, inline = review["body"], review["comments"]["totalCount"]
    if COPILOT_OVERVIEW in body:
        return _copilot_findings_all_in_threads(body, inline)
    return _normalised(body) == CODEX_TEMPLATE


def _copilot_findings_all_in_threads(body: str, inline: int) -> bool:
    """A Copilot overview lists its findings after one `**Findings:**` line, each
    as an item linking its inline thread, under `Open (n)`-style headings. Any
    other line there, an unlinked item, or a count above the linked threads and
    the inline comments means the body may say more than the threads do."""
    stated = COPILOT_FINDINGS.findall(body)
    if len(stated) != 1:
        return False
    count = 0 if stated[0] == "None" else int(stated[0])
    start = body.index("**Findings:**")
    end = body.find("<details>", start)
    section = body[start:end if end >= 0 else len(body)].splitlines()[1:]
    linked = set()
    for line in section:
        text = re.sub(r"<[^>]+>", "", line).strip()
        if not text or SECTION_HEADING.fullmatch(text):
            continue
        thread = re.search(r"#discussion_r(\d+)", line)
        if not (text.startswith("- ") and thread):
            return False
        linked.add(thread.group(1))
    return count <= len(linked) and count <= inline


def body_findings(reviews: list[dict]) -> list[dict]:
    """Bot reviews whose summary body may hold a finding no inline thread carries.

    Fails closed: a body is passed only when it is a Copilot overview whose one
    stated findings count its inline comments cover, or the Codex summary
    template unchanged. Anything else, a new template included, must be linked.
    """
    return [
        r
        for r in reviews
        if (r.get("author") or {}).get("__typename") == "Bot"
        and r["body"].strip()
        and not _accounted_for(r)
    ]


def linked_reviews(ledger: str) -> set[tuple[str, str]]:
    """(PR, review id) pairs the ledger links by `#pullrequestreview-<id>`."""
    return set(re.findall(r"/pull/(\d+)#pullrequestreview-(\d+)", ledger))


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def merged_prs() -> list[int]:
    out = gh("pr", "list", "-R", REPO, "--state", "merged", "--base", BASE, "--limit", str(LIMIT),
             "--search", f"merged:>={SINCE}", "--json", "number")
    numbers = sorted(pr["number"] for pr in json.loads(out))
    if len(numbers) >= LIMIT:
        sys.exit(f"{len(numbers)} merged PRs reached the --limit of {LIMIT}; the list may be truncated")
    return numbers


def bot_threads(number: int) -> tuple[list[dict], list[dict]]:
    """The PR's bot-started threads (all pages) and its reviews."""
    threads, reviews, after = [], None, None
    while True:
        args = ["api", "graphql", "-f", f"query={QUERY}", "-F", f"n={number}"]
        if after:
            args += ["-f", f"after={after}"]
        pr = json.loads(gh(*args))["data"]["repository"]["pullRequest"]
        if reviews is None:
            if pr["reviews"]["pageInfo"]["hasNextPage"]:
                sys.exit(f"#{number} has more than 100 reviews; the review list is truncated")
            reviews = pr["reviews"]["nodes"]
        page = pr["reviewThreads"]
        for node in page["nodes"]:
            first = (node["comments"]["nodes"] or [None])[0]
            author = (first or {}).get("author") or {}
            if author.get("__typename") == "Bot":
                threads.append(first)
        if not page["pageInfo"]["hasNextPage"]:
            return threads, reviews
        after = page["pageInfo"]["endCursor"]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--ledger", default=LEDGER)
    ledger = open(parser.parse_args(argv).ledger, encoding="utf-8").read()
    linked = set(re.findall(r"/pull/(\d+)#discussion_r(\d+)", ledger))
    linked_bodies = linked_reviews(ledger)
    missing = 0
    for number in merged_prs():
        threads, reviews = bot_threads(number)
        for review in body_findings(reviews):
            if (str(number), review["url"].rsplit("-", 1)[1]) not in linked_bodies:
                missing += 1
                print(f"#{number}\t{review['author']['login']}\treview body\t{review['url']}")
        for thread in threads:
            if (str(number), thread["url"].rsplit("_r", 1)[1]) not in linked:
                missing += 1
                line = thread.get("line") or thread.get("originalLine")
                print(f"#{number}\t{thread['author']['login']}\t{thread['path']}:{line}\t{thread['url']}")
    print(f"{missing} bot thread(s) or review bodies not in the ledger", file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
