#!/usr/bin/env python3
"""Regenerate the operator-decision ledger from the session transcripts.

An answer given through the question tool arrives as a tool result, never as a
user turn. A search over user turns therefore returns nothing for it and the
ruling reads as invented -- which is how sixteen genuine decisions were once
withdrawn. This reads the tool results, which is where the answers actually are.
"""

import argparse
import json
import pathlib
import re
import sys

ANSWERED = re.compile(
    r"Your questions have been answered: (.*?)\. You can now continue", re.S
)
# Release-scoped by default: the transcripts carry decisions for every project
# that shares this directory, and an unfiltered ledger is unreadable.
RELEASE = re.compile(
    r"4\.0\.0|SUPPORTED_VERSIONS|exposed_meta_tools|COMPAT\.4|PERF\.4|conformance"
    r"|resumable|CONFIRM|449|idempotency|progress update|2020-12|MCP_GATEWAY"
    r"|gateway_set_profile|hardening",
    re.I,
)


def decisions(transcript: pathlib.Path, topic: re.Pattern) -> list[tuple[str, str]]:
    seen: set[str] = set()
    rows: list[tuple[str, str]] = []
    for line in transcript.read_text(errors="ignore").splitlines():
        if "Your questions have been answered" not in line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        for block in entry.get("message", {}).get("content") or []:
            if not isinstance(block, dict):
                continue
            body = block.get("content")
            if isinstance(body, list):
                body = " ".join(
                    part.get("text", "") for part in body if isinstance(part, dict)
                )
            if not isinstance(body, str):
                continue
            for match in ANSWERED.findall(body):
                pair = " ".join(match.split())
                if pair in seen or not topic.search(pair):
                    continue
                seen.add(pair)
                question, _, answer = pair.rpartition('"="')
                rows.append((question.strip().strip('"'), answer.strip().strip('"')))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("transcript", type=pathlib.Path)
    ap.add_argument(
        "--all", action="store_true", help="do not filter to release topics"
    )
    args = ap.parse_args()
    if not args.transcript.is_file():
        print(f"no such transcript: {args.transcript}", file=sys.stderr)
        return 2
    rows = decisions(args.transcript, re.compile(".") if args.all else RELEASE)
    print("| # | question put to the operator | answer |")
    print("|---|---|---|")
    for index, (question, answer) in enumerate(rows, 1):
        q = question.replace("|", r"\|")
        a = answer.replace("|", r"\|")
        print(f"| {index} | {q} | **{a}** |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
