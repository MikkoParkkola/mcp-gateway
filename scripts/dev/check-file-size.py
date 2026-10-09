#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Enforce the 800-line ceiling on Rust source files.

The ceiling governs a file, not a change. The files already over it do not
fail the tree; the gate ratchets instead: every offender is recorded in
``file-size-baseline.txt`` with the line count it had when recorded. A file may
shrink freely; it may not grow, and no file may newly cross the ceiling.

A module declaration (`mod child;`) and the inert attributes directly above it
are not counted. Attaching a file is the one growth that extracting code out of
an over-ceiling file cannot avoid, and a declaration carries no logic: whatever
it attaches is held to the ceiling as a file of its own (#609). An inline
`mod child { ... }` counts in full.

This is the one 800-line gate (MIK-8210); a second gate that counted raw
lines and skipped test files was retired, so a file has one verdict. Test
files are held to the ceiling like any other.

With `--base <ref>` the baseline is also a ratchet against the baseline
committed at `ref`: a row may shrink or leave, never be added or raised, so
the number of files allowed over the ceiling only falls.

Usage:
    check-file-size.py                 # check, exit 1 on a regression
    check-file-size.py --base <ref>    # also refuse a baseline that grew since <ref>
    check-file-size.py --update        # rewrite the baseline from the tree
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

CEILING = 800
ROOT = Path(__file__).resolve().parents[2]
BASELINE = Path(__file__).with_name("file-size-baseline.txt")
SCANNED = ("src", "tests", "crates")

DECLARATION = re.compile(r"^\s*(pub(\([^)]*\))?\s+)?mod\s+\w+\s*;\s*$")
# Built-in attributes that carry no code. A macro attribute above a `mod` could
# expand to anything, so it counts, and so does `cfg_attr`, which can apply one.
INERT_ATTRIBUTE = re.compile(
    r"^\s*#\[\s*(cfg|path|allow|expect|warn|deny|doc|deprecated|rustfmt::skip)"
    r"\b.*\]\s*$"
)


def counted_lines(text: str) -> int:
    """Newlines in `text`, less each module declaration and its inert attributes."""
    lines = text.split("\n")
    free = 0
    for i, line in enumerate(lines):
        if not DECLARATION.match(line):
            continue
        free += 1
        above = i - 1
        while above >= 0 and INERT_ATTRIBUTE.match(lines[above]):
            free += 1
            above -= 1
    return text.count("\n") - free


def measure() -> dict[str, int]:
    """Line counts for every Rust file over the ceiling, keyed by repo path."""
    sizes = {}
    for top in SCANNED:
        for path in sorted((ROOT / top).rglob("*.rs")):
            lines = counted_lines(path.read_text(encoding="utf-8", errors="replace"))
            if lines > CEILING:
                sizes[str(path.relative_to(ROOT))] = lines
    return sizes


def parse_baseline(text: str) -> dict[str, int]:
    entries = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        count, path = line.split(None, 1)
        entries[path] = int(count)
    return entries


def load_baseline() -> dict[str, int]:
    if not BASELINE.exists():
        return {}
    return parse_baseline(BASELINE.read_text(encoding="utf-8"))


def write_baseline(sizes: dict[str, int]) -> None:
    body = "\n".join(f"{n} {p}" for p, n in sorted(sizes.items(), key=lambda kv: -kv[1]))
    excess = sum(n - CEILING for n in sizes.values())
    BASELINE.write_text(
        f"# Rust files over the {CEILING}-line ceiling, with the count when recorded.\n"
        f"# The gate ratchets: a listed file may shrink, never grow, and nothing new\n"
        f"# may cross. Delete a row once the file drops under the ceiling.\n"
        f"# {len(sizes)} files, {excess} lines of excess.\n"
        f"{body}\n",
        encoding="utf-8",
    )


def check_ratchet(base: dict[str, int], head: dict[str, int]) -> list[str]:
    """Errors for a head baseline that adds a row or raises an allowance over `base`.

    The baseline is the count ratchet (MIK-8210): the number of files allowed
    over the ceiling may only fall. A row may shrink or leave; `--update` must
    not be the way a PR admits a new offender or buys an old one more lines.
    """
    errors = []
    for path, count in sorted(head.items()):
        if path not in base:
            errors.append(f"FAIL {path}: the baseline gains a row ({count} lines); split the file instead")
        elif count > base[path]:
            errors.append(f"FAIL {path}: the baseline allowance rises {base[path]} -> {count}; it may only fall")
    return errors


def read_base_baseline(ref: str) -> dict[str, int] | None:
    """The baseline as committed at `ref`, or None when git cannot read it."""
    try:
        rel = BASELINE.resolve().relative_to(ROOT.resolve())
        text = subprocess.run(
            ["git", "show", f"{ref}:{rel.as_posix()}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (ValueError, OSError, subprocess.CalledProcessError):
        return None
    return parse_baseline(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--base", metavar="REF", help="refuse a baseline that grew since REF")
    mode.add_argument("--update", action="store_true", help="rewrite the baseline from the tree")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    sizes = measure()

    if args.update:
        write_baseline(sizes)
        print(f"baseline updated: {len(sizes)} files over {CEILING} lines")
        return 0

    baseline = load_baseline()
    new = sorted(p for p in sizes if p not in baseline)
    grown = sorted(p for p in sizes if p in baseline and sizes[p] > baseline[p])
    fixed = sorted(p for p in baseline if p not in sizes)

    for path in new:
        print(f"FAIL {path}: {sizes[path]} lines, over the {CEILING}-line ceiling")
    for path in grown:
        print(f"FAIL {path}: grew {baseline[path]} -> {sizes[path]} lines")
    for path in fixed:
        print(f"STALE {path}: now under the ceiling, drop its baseline row")

    ratchet = []
    if args.base is not None:
        base = read_base_baseline(args.base) if args.base else None
        if base is None:
            print(f"FAIL cannot read the baseline at base {args.base!r}; the ratchet is not skipped")
            return 1
        ratchet = check_ratchet(base, baseline)
        for line in ratchet:
            print(line)

    excess = sum(n - CEILING for n in sizes.values())
    print(f"{len(sizes)} files over {CEILING} lines, {excess} lines of excess.")
    return 1 if new or grown or fixed or ratchet else 0


if __name__ == "__main__":
    raise SystemExit(main())
