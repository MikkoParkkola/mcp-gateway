#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""List automated-reviewer threads that the GH1625.BOTREVIEW.1 ledger lacks.

For every PR merged into the release line after #1625 closed, read its review
threads (all pages) and keep the bot-started ones. A PR whose bot threads
outnumber its ledger rows is printed with the threads the ledger does not
link. Exit 1 when anything is missing, so the final sweep is a diff.

Needs an authenticated `gh`. Usage:
    python3 scripts/release/botreview_sweep.py [--ledger PATH]
"""

import argparse
import json
import re
import subprocess
import sys
from collections import Counter

REPO = "MikkoParkkola/mcp-gateway"
BASE = "docs/ranking-1-release-line"
SINCE = "2026-09-29T02:27:33Z"  # #1625 closed
LEDGER = "docs/internal/release/v4.0.0-botreview-ledger.md"
QUERY = """query($n:Int!,$after:String){repository(owner:"MikkoParkkola",name:"mcp-gateway"){
pullRequest(number:$n){reviewThreads(first:100,after:$after){pageInfo{hasNextPage endCursor}
nodes{comments(first:1){nodes{author{login __typename} url path line originalLine}}}}}}}"""


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def merged_prs() -> list[int]:
    out = gh("pr", "list", "-R", REPO, "--state", "merged", "--base", BASE, "--limit", "1000",
             "--search", f"merged:>={SINCE}", "--json", "number")
    return sorted(pr["number"] for pr in json.loads(out))


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
    rows = Counter(int(n) for n in re.findall(r"^\| #(\d+) \|", ledger, re.M))
    linked = set(re.findall(r"#discussion_r(\d+)", ledger))
    missing = 0
    for number in merged_prs():
        threads = bot_threads(number)
        if len(threads) <= rows[number]:
            continue
        for thread in threads:
            if thread["url"].rsplit("_r", 1)[1] not in linked:
                missing += 1
                line = thread.get("line") or thread.get("originalLine")
                print(f"#{number}\t{thread['author']['login']}\t{thread['path']}:{line}\t{thread['url']}")
    print(f"{missing} bot thread(s) not in the ledger", file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
