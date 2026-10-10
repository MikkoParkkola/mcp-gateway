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
committed at `ref`: the total excess over the ceiling may not rise (each
row's excess counted from 0) and a listed row may not grow. A new row is
allowed only for a move (MIK-8291, split-baselines): a rename, or a split
that leaves a part over the ceiling, names its donors with one or more
`# moved-from <path>` lines directly above the row, and each donor must be a
row that shrank or left in the same change. A human reviewer judges the move,
as with `git diff --color-moved`; `--update` keeps the annotations.

Still refused: a new oversized row with no annotation, or one naming a path
that is not a listed row that shrank or left; a listed row that grows; a
total excess that rises (a split may not add more excess than it removed).

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
# A new row's donor: `# moved-from <path>` directly above the row (MIK-8291).
MOVED_FROM = re.compile(r"^#\s*moved-from\s+(\S+)\s*$")
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


def parse_moved(text: str) -> dict[str, list[str]]:
    """Each row's donors: the `# moved-from <path>` lines directly above it."""
    moved: dict[str, list[str]] = {}
    pending: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if match := MOVED_FROM.match(line):
            pending.append(match.group(1))
        elif line and not line.startswith("#"):
            if pending:
                moved[line.split(None, 1)[1]] = pending
            pending = []
        else:
            pending = []
    return moved


def load_baseline() -> dict[str, int]:
    if not BASELINE.exists():
        return {}
    return parse_baseline(BASELINE.read_text(encoding="utf-8"))


def load_moved() -> dict[str, list[str]]:
    return parse_moved(BASELINE.read_text(encoding="utf-8")) if BASELINE.exists() else {}


def write_baseline(sizes: dict[str, int], moved: dict[str, list[str]] | None = None) -> None:
    """Rewrite the baseline, keeping each surviving row's `moved-from` lines."""
    moved = moved or {}
    rows = []
    for path, n in sorted(sizes.items(), key=lambda kv: -kv[1]):
        rows.extend(f"# moved-from {donor}" for donor in moved.get(path, []))
        rows.append(f"{n} {path}")
    excess = sum(n - CEILING for n in sizes.values())
    BASELINE.write_text(
        f"# Rust files over the {CEILING}-line ceiling, with the count when recorded.\n"
        f"# The gate ratchets: a listed file may shrink, never grow, and nothing new\n"
        f"# may cross, except a move: a new row with `# moved-from <path>` above it,\n"
        f"# naming a row that shrank or left. Delete a row once the file drops under.\n"
        f"# {len(sizes)} files, {excess} lines of excess.\n"
        + "\n".join(rows)
        + "\n",
        encoding="utf-8",
    )


def check_ratchet(
    base: dict[str, int], head: dict[str, int], moved: dict[str, list[str]] | None = None
) -> list[str]:
    """Errors for a head baseline that grew over `base` (MIK-8210, MIK-8291).

    The total excess over the ceiling may not rise (each row's excess counted
    from 0, so a row under the ceiling cannot cancel growth), and a listed row
    may not grow. A new row is a move only when it names its donors with
    `# moved-from <path>` lines (`moved`) and every donor is a base row that
    shrank or left in the same change. A reviewer judges the move itself.
    """
    moved = moved or {}
    errors = []

    def excess(rows: dict[str, int]) -> int:
        return sum(max(n - CEILING, 0) for n in rows.values())

    if excess(head) > excess(base):
        errors.append(f"FAIL the total excess rises {excess(base)} -> {excess(head)} lines; it may only fall")
    for path, count in sorted(head.items()):
        if path in base:
            if count > base[path]:
                errors.append(f"FAIL {path}: the baseline allowance rises {base[path]} -> {count}; it may only fall")
            continue
        donors = moved.get(path, [])
        if not donors:
            errors.append(
                f"FAIL {path}: the baseline gains a row ({count} lines); split the file instead,"
                " or mark a move with `# moved-from <path>` above the row"
            )
        for donor in donors:
            if donor not in base or head.get(donor, 0) >= base[donor]:
                errors.append(
                    f"FAIL {path}: moved-from {donor}, which is not a baseline row that shrank or left in this change"
                )
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
        write_baseline(sizes, load_moved())
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
        ratchet = check_ratchet(base, baseline, load_moved())
        for line in ratchet:
            print(line)

    excess = sum(n - CEILING for n in sizes.values())
    print(f"{len(sizes)} files over {CEILING} lines, {excess} lines of excess.")
    return 1 if new or grown or fixed or ratchet else 0


if __name__ == "__main__":
    raise SystemExit(main())
