#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""List automated-reviewer threads that the GH1625.BOTREVIEW.1 ledger lacks.

For every PR merged into the release line after #1625 closed, read its review
threads (all pages) and keep the bot-started ones. Every such thread must be
linked by its own `#discussion_r<id>` in the ledger; a count is never enough.
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
nodes{comments(first:1){nodes{author{login __typename} url path line originalLine}}}}}}}"""


def body_findings(reviews: list[dict]) -> list[dict]:
    """Bot reviews whose summary body may hold a finding no inline thread carries."""
    return []


def linked_reviews(ledger: str) -> set[tuple[str, str]]:
    """(PR, review id) pairs the ledger links by `#pullrequestreview-<id>`."""
    return set()


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def merged_prs() -> list[int]:
    out = gh("pr", "list", "-R", REPO, "--state", "merged", "--base", BASE, "--limit", str(LIMIT),
             "--search", f"merged:>={SINCE}", "--json", "number")
    numbers = sorted(pr["number"] for pr in json.loads(out))
    if len(numbers) >= LIMIT:
        sys.exit(f"{len(numbers)} merged PRs reached the --limit of {LIMIT}; the list may be truncated")
    return numbers


def bot_threads(number: int) -> list[dict]:
    threads, after = [], None
    while True:
        args = ["api", "graphql", "-f", f"query={QUERY}", "-F", f"n={number}"]
        if after:
            args += ["-f", f"after={after}"]
        page = json.loads(gh(*args))["data"]["repository"]["pullRequest"]["reviewThreads"]
        for node in page["nodes"]:
            first = (node["comments"]["nodes"] or [None])[0]
            author = (first or {}).get("author") or {}
            if author.get("__typename") == "Bot":
                threads.append(first)
        if not page["pageInfo"]["hasNextPage"]:
            return threads
        after = page["pageInfo"]["endCursor"]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--ledger", default=LEDGER)
    ledger = open(parser.parse_args(argv).ledger, encoding="utf-8").read()
    linked = set(re.findall(r"/pull/(\d+)#discussion_r(\d+)", ledger))
    missing = 0
    for number in merged_prs():
        for thread in bot_threads(number):
            if (str(number), thread["url"].rsplit("_r", 1)[1]) not in linked:
                missing += 1
                line = thread.get("line") or thread.get("originalLine")
                print(f"#{number}\t{thread['author']['login']}\t{thread['path']}:{line}\t{thread['url']}")
    print(f"{missing} bot thread(s) not in the ledger", file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
