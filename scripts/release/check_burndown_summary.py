#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when the burndown tracker's summary disagrees with the ledger checks.

The tracker's top table restates the counts `count-release-criteria.py --check`
and `check_scope_acceptance.py --check` print. It drifted after every
criteria change because nothing compared them (MIK-7730). This compares them.
The publish-gate section restates what `check_scope_acceptance.py
--publish-check` fails on in a tag context: "fails on **N** ids" and a bulleted
id list. That drifted too (MIK-7932), so both are compared with the gate.

Usage:
    python3 scripts/release/check_burndown_summary.py
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TRACKER = ROOT / "docs/internal/release/v4.0.0-burndown-tracker.md"


CORE_ROW = re.compile(
    r"^\| Core release criteria \|[^|]*\| (\d+) rows over (\d+) criteria \| (\d+)(?= \(| \|)[^|]*\| \*\*(\d+)\*\* blocking",
    re.MULTILINE,
)
SCOPE_ROW = re.compile(
    r"^\| Scope-update criteria \|[^|]*\| (\d+) \| (\d+) \((\d+) met, (\d+) waived\) \| \*\*(\d+)\*\* \|",
    re.MULTILINE,
)
CORE_LINE = re.compile(r"Coverage: (\d+) criteria, (\d+) rows, (\d+) met or non-blocking, (\d+) blocking\.")
SCOPE_LINE = re.compile(r"Scope contract consistent: (\d+) criteria \((\d+) met / (\d+) waived / (\d+) pending\)")
PUBLISH_COUNT = re.compile(r"fails on \*\*(\w+)\*\* ids?\b")
PUBLISH_BULLET = re.compile(r"^- `([^`\n]+)`$", re.MULTILINE)
NEXT_HEADING = re.compile(r"^#{1,6} ", re.MULTILINE)
FENCED = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)
# A tag push is the context in which the gate blocks the container publish.
TAG_CONTEXT = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/tags/v4.0.0"}
NUMBER_WORDS = ("zero one two three four five six seven eight nine ten eleven twelve thirteen "
                "fourteen fifteen sixteen seventeen eighteen nineteen twenty").split()
KEYS = ("core_criteria", "core_rows", "core_ok", "core_blocking",
        "scope_total", "scope_met", "scope_waived", "scope_pending")


def tracker_counts(text: str) -> dict:
    """The counts the tracker's summary table states; empty keys if a row is missing."""
    counts = {}
    # Count rows by their label, not by the strict pattern, so a malformed
    # duplicate cannot hide behind a valid row.
    cores = re.findall(r"^\|\s*Core release criteria\s*\|", text, re.MULTILINE)
    scopes = re.findall(r"^\|\s*Scope-update criteria\s*\|", text, re.MULTILINE)
    if len(cores) > 1 or len(scopes) > 1:
        counts["duplicate_rows"] = f"{len(cores)} core and {len(scopes)} scope summary rows"
        return counts
    if core := CORE_ROW.search(text):
        rows, criteria, ok, blocking = map(int, core.groups())
        counts.update(core_criteria=criteria, core_rows=rows, core_ok=ok, core_blocking=blocking)
    if scope := SCOPE_ROW.search(text):
        total, done, met, waived, pending = map(int, scope.groups())
        if done != met + waived:
            counts["scope_inconsistent"] = f"{done} != {met} met + {waived} waived"
        counts.update(scope_total=total, scope_met=met, scope_waived=waived, scope_pending=pending)
    return counts


def core_counts(output: str) -> dict:
    """The counts in count-release-criteria.py --check output."""
    m = CORE_LINE.search(output)
    return dict(zip(KEYS[:4], map(int, m.groups()))) if m else {}


def scope_counts(output: str) -> dict:
    """The counts in check_scope_acceptance.py --check output."""
    m = SCOPE_LINE.search(output)
    return dict(zip(KEYS[4:], map(int, m.groups()))) if m else {}


def tracker_publish_gate(text: str) -> dict:
    """The publish-gate count and id list the tracker states; empty if absent.

    The list is every "- `ID`" line from the count sentence to the next
    heading, blank lines between items included, so no listed id escapes.
    """
    counts = PUBLISH_COUNT.findall(text)
    if len(counts) != 1:
        return {"problem": f"{len(counts)} 'fails on **N** ids' sentences, expected one"}
    word = counts[0].lower()
    count = int(word) if word.isdigit() else NUMBER_WORDS.index(word) if word in NUMBER_WORDS else None
    start = PUBLISH_COUNT.search(text).end()
    # A shell comment inside a fenced block is not a heading; blank the
    # fences out, keeping offsets, before looking for the next one.
    unfenced = FENCED.sub(lambda m: " " * len(m.group(0)), text)
    heading = NEXT_HEADING.search(unfenced, start)
    ids = PUBLISH_BULLET.findall(text, start, heading.start() if heading else len(text))
    return {"count": count, "ids": ids, "word": counts[0]}


def publish_ids(output: str) -> list[str]:
    """The ids `--publish-check` lists under "Release acceptance incomplete:"."""
    lines = output.splitlines()
    if "Release acceptance incomplete:" not in lines:
        return []
    ids = []
    for line in lines[lines.index("Release acceptance incomplete:") + 1:]:
        if not line.startswith("  "):
            break
        ids.append(line.strip())
    return ids


def publish_gate_trust(output: str, rc: int) -> str | None:
    """Why the --publish-check result cannot be compared, or None if it can.

    Only two outcomes are a measurement: exit 1 listing the pending ids, and
    exit 0 saying acceptance is complete with none listed. Anything else (a
    crash, a branch context, a failure for another reason) is not.
    """
    ids = publish_ids(output)
    if rc == 1 and ids:
        return None
    if rc == 0 and not ids and "Release acceptance complete." in output.splitlines():
        return None
    return f"--publish-check exited {rc} with {len(ids)} ids listed; its ids are not trusted"


def publish_gate_mismatches(stated: dict, measured: list[str]) -> list[str]:
    """One line per way the tracker's publish-gate count or list differs from the gate."""
    if "problem" in stated:
        return [f"publish-gate section: {stated['problem']}"]
    problems = []
    if stated["count"] is None:
        problems.append(f"publish-gate count: cannot read '{stated['word']}' as a number")
    elif stated["count"] != len(measured):
        problems.append(f"publish-gate count: tracker says {stated['count']}, "
                        f"--publish-check lists {len(measured)} ids")
    listed = set(stated["ids"])
    for missing in [i for i in measured if i not in listed]:
        problems.append(f"publish-gate list: --publish-check lists {missing}; the tracker does not")
    for extra in [i for i in stated["ids"] if i not in set(measured)]:
        problems.append(f"publish-gate list: the tracker lists {extra}; --publish-check does not")
    return problems


def mismatches(stated: dict, measured: dict) -> list[str]:
    """One line per count the tracker states differently, or cannot state.

    Fails closed: a count missing on either side is a mismatch.
    """
    problems = []
    if "duplicate_rows" in stated:
        problems.append(f"tracker has more than one summary row: {stated['duplicate_rows']}")
    if "scope_inconsistent" in stated:
        problems.append(f"tracker scope row does not add up: {stated['scope_inconsistent']}")
    for key in KEYS:
        if key not in measured:
            problems.append(f"{key}: the ledger check printed no value")
        elif key not in stated:
            problems.append(f"{key}: the tracker summary states no value")
        elif stated[key] != measured[key]:
            problems.append(f"{key}: tracker says {stated[key]}, ledger check says {measured[key]}")
    return problems


def run(script: str, *args: str, env: dict | None = None) -> tuple[str, int]:
    done = subprocess.run([sys.executable, str(ROOT / "scripts/release" / script), *args],
                          capture_output=True, text=True, cwd=ROOT,
                          env={**os.environ, **env} if env else None)
    return done.stdout + done.stderr, done.returncode


def main() -> int:
    text = TRACKER.read_text(encoding="utf-8")
    stated = tracker_counts(text)
    core_out, core_rc = run("count-release-criteria.py", "--check")
    scope_out, scope_rc = run("check_scope_acceptance.py", "--check")
    publish_out, publish_rc = run("check_scope_acceptance.py", "--publish-check", env=TAG_CONTEXT)
    measured = {**core_counts(core_out), **scope_counts(scope_out)}
    problems = mismatches(stated, measured)
    problems += publish_gate_mismatches(tracker_publish_gate(text), publish_ids(publish_out))
    if untrusted := publish_gate_trust(publish_out, publish_rc):
        problems.append(untrusted)
    for name, rc in (("count-release-criteria.py --check", core_rc),
                     ("check_scope_acceptance.py --check", scope_rc)):
        if rc != 0:
            problems.append(f"{name} exited {rc}; its counts are not trusted")
    for problem in problems:
        print(f"{TRACKER.name}: {problem}")
    if problems:
        print("Update the tracker's summary table, provenance line and publish-gate section "
              "from the checks.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
