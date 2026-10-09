#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""No new raw wall-clock read outside src/clock.rs (MIK-8202).

A clock earlier than 1970 makes a raw read either an error a caller papers over
with 0, or a 1969 date that reads every deadline as still ahead. `crate::clock`
reports it as an error instead. Until every existing read migrates (MIK-8202
part 2), this check holds the line: it counts the raw reads in EVERY Rust file
under src/ and tests/, and fails when

  - a file holds more raw reads than its row in the baseline allows, or
  - a file with no row holds any, or
  - the baseline itself grew against the base branch (a new row, a raised count).

So a file can lose reads freely and never gain one, and swapping one file's
allowance for another's is refused. Counting every file, not only the listed
ones, is the point: a read in an unlisted file fails however it got there.

It also refuses, with no allowance, any alias of a clock type outside
src/clock.rs (`use chrono::Utc as U`, `type Now = SystemTime`): a renamed type
would read the clock past a text match. Part 2 replaces this check with clippy
`disallowed-methods`, which resolves names and needs no such rule.

Usage:
  check_clock_baseline.py [<base-ref>]   check the tree (and, with a base, that
                                         the baseline only shrank since it)
  check_clock_baseline.py --update       rewrite the baseline from the tree
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = "docs/release/mik-8202-clock-baseline.tsv"
# The one module that may read the wall clock.
EXEMPT = {"src/clock.rs"}
# Raw wall-clock reads: the std and chrono "now" constructors, a SystemTime's
# elapsed time, and jsonwebtoken's own clock (which panics before 1970).
RAW = re.compile(
    r"\b(?:SystemTime|Utc|Local)::now\s*\("
    r"|\bUNIX_EPOCH\s*\.\s*elapsed\s*\("
    r"|\bget_current_timestamp\s*\("
)
# An alias of a clock type: `use ...Utc as X`, inside braces too, or
# `type X = ...Utc`. Its reads would not match RAW.
ALIAS = re.compile(
    r"\buse\b[^;]*\b(?:Utc|Local|SystemTime)\s+as\s+\w+"
    r"|\btype\s+\w+\s*=\s*(?:[\w:]*::)?(?:Utc|Local|SystemTime)\s*;"
)
HEADER = (
    "# MIK-8202: raw wall-clock reads each file may still hold (path, count).\n"
    "# scripts/release/check_clock_baseline.py fails when a count rises or an\n"
    "# unlisted file gains one. Rows only shrink; part 2 empties this file.\n"
)


def counts(root: Path) -> dict[str, int]:
    """Raw reads per file, for every Rust file under src/ and tests/."""
    found: dict[str, int] = {}
    for top in ("src", "tests"):
        for path in sorted((root / top).rglob("*.rs")):
            rel = path.relative_to(root).as_posix()
            if rel in EXEMPT:
                continue
            n = len(RAW.findall(path.read_text(encoding="utf-8", errors="replace")))
            if n:
                found[rel] = n
    return found


def aliases(root: Path) -> list[str]:
    """Every alias of a clock type outside the clock module, as `path:line`."""
    found = []
    for top in ("src", "tests"):
        for path in sorted((root / top).rglob("*.rs")):
            rel = path.relative_to(root).as_posix()
            if rel in EXEMPT:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in ALIAS.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                found.append(f"{rel}:{line}: aliases a clock type; read it through crate::clock")
    return found


def parse(text: str) -> dict[str, int]:
    rows: dict[str, int] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        path, count = line.split("\t")
        rows[path] = int(count)
    return rows


def render(rows: dict[str, int]) -> str:
    return HEADER + "".join(f"{path}\t{count}\n" for path, count in sorted(rows.items()))


def violations(tree: dict[str, int], baseline: dict[str, int]) -> list[str]:
    out = []
    for path, n in sorted(tree.items()):
        allowed = baseline.get(path, 0)
        if n > allowed:
            out.append(f"{path}: {n} raw clock read(s), {allowed} allowed; use crate::clock")
    return out


def grown(baseline: dict[str, int], base: dict[str, int]) -> list[str]:
    return [
        f"{path}: baseline {n} > base {base.get(path, 0)}; the baseline may only shrink"
        for path, n in sorted(baseline.items())
        if n > base.get(path, 0)
    ]


def base_baseline(ref: str) -> dict[str, int] | None:
    done = subprocess.run(
        ["git", "show", f"{ref}:{BASELINE}"], cwd=ROOT, capture_output=True, text=True
    )
    # No baseline on the base yet: this change introduces it.
    return parse(done.stdout) if done.returncode == 0 else None


def main(argv: list[str]) -> int:
    if argv[1:] == ["--update"]:
        (ROOT / BASELINE).write_text(render(counts(ROOT)), encoding="utf-8")
        return 0
    if len(argv) > 2 or (len(argv) == 2 and argv[1].startswith("-")):
        print(__doc__, file=sys.stderr)
        return 2
    baseline = parse((ROOT / BASELINE).read_text(encoding="utf-8"))
    problems = violations(counts(ROOT), baseline) + aliases(ROOT)
    if len(argv) == 2 and (base := base_baseline(argv[1])) is not None:
        problems += grown(baseline, base)
    for problem in problems:
        print(problem)
    if problems:
        return 1
    print(f"no new raw clock read ({sum(baseline.values())} grandfathered in {len(baseline)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
