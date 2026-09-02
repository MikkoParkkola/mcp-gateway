#!/usr/bin/env python3
"""Regenerate the operator-decision ledger from the session transcripts.

An answer given through the question tool arrives as a tool result, never as a
user turn. A search over user turns therefore returns nothing for it and the
ruling reads as invented -- which is how eleven genuine decisions were once
withdrawn. This reads the tool results, which is where the answers actually are.

Reads a whole project directory by default. A decision may have been given in
any session, so a ledger built from one transcript is silently partial, and a
partial ledger reads as an absence -- which is the failure this file exists to
stop. Each row carries the answer's date, so a dated attribution in a design
document can be checked against the row rather than against memory.
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
    r"|resumable|CONFIRM\.\d|449|idempotency|progress update|2020-12|MCP_GATEWAY"
    r"|gateway_set_profile|hardening",
    re.I,
)


def decisions(
    transcript: pathlib.Path, topic: re.Pattern
) -> list[tuple[str, str, str]]:
    seen: set[str] = set()
    rows: list[tuple[str, str, str]] = []
    for line in transcript.read_text(errors="ignore").splitlines():
        if "Your questions have been answered" not in line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        # The entry timestamp is when the operator answered.
        date = str(entry.get("timestamp") or "")[:10] or "undated"
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
                rows.append(
                    (question.strip().strip('"'), answer.strip().strip('"'), date)
                )
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "transcript",
        type=pathlib.Path,
        help="a transcript, or a project directory of them",
    )
    ap.add_argument(
        "--all", action="store_true", help="do not filter to release topics"
    )
    args = ap.parse_args()
    if args.transcript.is_dir():
        # Sorted so the ledger's numbering is stable across runs.
        sources = sorted(args.transcript.glob("*.jsonl"))
        if not sources:
            print(f"no transcripts in {args.transcript}", file=sys.stderr)
            return 2
    elif args.transcript.is_file():
        sources = [args.transcript]
    else:
        print(f"no such transcript: {args.transcript}", file=sys.stderr)
        return 2
    topic = re.compile(".") if args.all else RELEASE
    rows: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for source in sources:
        for row in decisions(source, topic):
            if row in seen:
                continue
            seen.add(row)
            rows.append(row)
    print("| # | date | question put to the operator | answer |")
    print("|---|---|---|---|")
    for index, (question, answer, date) in enumerate(rows, 1):
        q = question.replace("|", r"\|")
        a = answer.replace("|", r"\|")
        print(f"| {index} | {date} | {q} | **{a}** |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
