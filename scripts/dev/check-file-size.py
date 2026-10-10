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
that leaves a part over the ceiling, carries its row when all but
HEADER_ALLOWANCE (40) of its lines are trimmed lines gone from rows that
shrank or left, each moved line spent once (scripts/dev/ratchet_moves.py).

Still refused: a new oversized file with nothing moved, or only a handful of
lines; a listed row that grows; a new row larger than what moved plus the
allowance; a rising total. Trivial lines (blank, brackets, separators) carry
only up to twice the code lines carried. Text changed in the move does not
match and fails safe, so a move keeps moved text identical.

Usage:
    check-file-size.py                 # check, exit 1 on a regression
    check-file-size.py --base <ref>    # also refuse a baseline that grew since <ref>
    check-file-size.py --update        # rewrite the baseline from the tree
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

# The moved-text matcher shared with the clock baseline (MIK-8291).
_SPEC = importlib.util.spec_from_file_location("ratchet_moves", Path(__file__).with_name("ratchet_moves.py"))
ratchet_moves = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ratchet_moves)

CEILING = 800
# Lines a new row may hold beyond what it moved: a split-off file's own
# SPDX header, `use` lines and module docs.
HEADER_ALLOWANCE = 40
# A line with no code of its own: blank, or only brackets and separators.
TRIVIAL = re.compile(r"^[\s{}()\[\];,]*$")
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


def split_lines(text: str) -> tuple[list[str], list[str]]:
    """`text`'s trimmed lines, as (code lines, trivial lines)."""
    code, trivial = [], []
    for line in text.split("\n"):
        (trivial if TRIVIAL.match(line) else code).append(line.strip())
    return code, trivial


def check_ratchet(
    base: dict[str, int],
    head: dict[str, int],
    base_texts: dict[str, str] | None = None,
    head_texts: dict[str, str] | None = None,
) -> list[str]:
    """Errors for a head baseline that grew over `base` (MIK-8210, MIK-8291).

    The total excess over the ceiling may not rise, and a listed row may not
    grow. A new row is a move, not a new offender, only when nearly all of it
    moved: its lines less those it carries may not exceed HEADER_ALLOWANCE.
    Carried lines are trimmed lines gone from rows that shrank or left
    (`base_texts` less `head_texts`) that appear in the new file, each spent
    once. Trivial lines carry only up to twice the code lines carried, so
    braces freed by deleting code cannot fund a file. Without texts nothing
    moved, so any new row fails.
    """
    base_texts, head_texts = base_texts or {}, head_texts or {}
    errors = []

    def excess(rows: dict[str, int]) -> int:
        # From 0: a row under the ceiling may not cancel growth elsewhere.
        return sum(max(n - CEILING, 0) for n in rows.values())

    if excess(head) > excess(base):
        errors.append(f"FAIL the total excess rises {excess(base)} -> {excess(head)} lines; it may only fall")
    shrunk = [path for path, n in base.items() if head.get(path, 0) < n]
    new = [path for path in head if path not in base]
    base_split = {path: split_lines(base_texts.get(path, "")) for path in shrunk}
    head_split = {path: split_lines(head_texts.get(path, "")) for path in [*shrunk, *new]}
    code_carried = ratchet_moves.carry(
        {path: head_split[path][0] for path in new},
        ratchet_moves.gone({p: v[0] for p, v in base_split.items()}, {p: v[0] for p, v in head_split.items()}, shrunk),
    )
    trivia_carried = ratchet_moves.carry(
        {path: head_split[path][1] for path in new},
        ratchet_moves.gone({p: v[1] for p, v in base_split.items()}, {p: v[1] for p, v in head_split.items()}, shrunk),
    )
    for path, count in sorted(head.items()):
        if path in base:
            if count > base[path]:
                errors.append(f"FAIL {path}: the baseline allowance rises {base[path]} -> {count}; it may only fall")
            continue
        carried = code_carried[path] + min(trivia_carried[path], 2 * code_carried[path])
        if count - carried > HEADER_ALLOWANCE:
            errors.append(
                f"FAIL {path}: the baseline gains a row ({count} lines) that carries only {carried}"
                f" moved line(s); a new row may add at most {HEADER_ALLOWANCE}; split the file instead"
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


def moved_texts(ref: str, base: dict[str, int], head: dict[str, int]) -> tuple[dict[str, str], dict[str, str]]:
    """The texts a move is judged on: each row that shrank or left, at `ref`
    and now, and each new row now. A file git cannot show at `ref`, or that
    is gone now, reads as empty, which carries nothing."""
    shrunk = [path for path, n in base.items() if head.get(path, 0) < n]
    new = [path for path in head if path not in base]
    base_texts = {}
    for path in shrunk:
        shown = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=ROOT, capture_output=True, text=True)
        base_texts[path] = shown.stdout if shown.returncode == 0 else ""
    head_texts = {}
    for path in [*shrunk, *new]:
        file = ROOT / path
        head_texts[path] = file.read_text(encoding="utf-8", errors="replace") if file.is_file() else ""
    return base_texts, head_texts


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
        base_texts, head_texts = moved_texts(args.base, base, baseline)
        ratchet = check_ratchet(base, baseline, base_texts, head_texts)
        for line in ratchet:
            print(line)

    excess = sum(n - CEILING for n in sizes.values())
    print(f"{len(sizes)} files over {CEILING} lines, {excess} lines of excess.")
    return 1 if new or grown or fixed or ratchet else 0


if __name__ == "__main__":
    raise SystemExit(main())
