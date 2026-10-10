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
  - the baseline itself grew against the base branch: the total rose, a listed
    file's count rose, or a new row holds more than it moved (MIK-8283).

So a file can lose reads freely and never gain one, and swapping one file's
allowance for another's is refused. A split or rename may carry its reads to
a new file: a new row is allowed only for reads that moved, each matched by
its trimmed line text to a read gone from a file whose row shrank. A read
whose text changed on the way (`std::time::SystemTime::now()` becoming
`SystemTime::now()`) does not match and fails, so a move keeps the text as
it was. Counting every file, not only the listed ones, is the point: a read
in an unlisted file fails however it got there.

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

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# The moved-text matcher, shared with the file-size ratchet (MIK-8291).
_SPEC = importlib.util.spec_from_file_location(
    "ratchet_moves", Path(__file__).resolve().parents[1] / "dev" / "ratchet_moves.py"
)
ratchet_moves = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ratchet_moves)
BASELINE = "docs/release/mik-8202-clock-baseline.tsv"
# The one module that may read the wall clock.
EXEMPT = {"src/clock.rs"}
# Raw wall-clock reads: the std and chrono "now" constructors, called or
# passed as a function, any spacing around `::`; every `UNIX_EPOCH` (what an
# elapsed time or a duration since the epoch is measured from, so an epoch
# held in a variable still counts); and jsonwebtoken's own clock (which
# panics before 1970).
RAW = re.compile(
    r"\b(?:SystemTime|Utc|Local)\s*::\s*now\b"
    r"|\bUNIX_EPOCH\b"
    r"|\bget_current_timestamp\b"
)
# An alias of a clock type: `use ...Utc as X`, inside braces too, or
# `type X = ...Utc`. Its reads would not match RAW.
ALIAS = re.compile(
    r"\buse\b[^;]*\b(?:Utc|Local|SystemTime|UNIX_EPOCH|get_current_timestamp)\s+as\s+\w+"
    r"|\btype\s+\w+\s*=\s*(?:[\w:]*::)?(?:Utc|Local|SystemTime)\s*;"
    r"|\b(?:const|static)\s+\w+\s*:\s*[\w:]*SystemTime\s*=\s*[\w:]*UNIX_EPOCH\b"
)
HEADER = (
    "# MIK-8202: raw wall-clock reads each file may still hold (path, count).\n"
    "# scripts/release/check_clock_baseline.py fails when a count rises or an\n"
    "# unlisted file gains one; a new row only carries reads moved from a\n"
    "# shrinking one (MIK-8283). Part 2 empties this file.\n"
)


def reads(text: str) -> list[str]:
    """The trimmed line of each raw read in `text`, once per read."""
    out = []
    for m in RAW.finditer(text):
        start = text.rfind("\n", 0, m.start()) + 1
        end = text.find("\n", m.end())
        out.append(text[start : len(text) if end == -1 else end].strip())
    return out


def tree_reads(root: Path) -> dict[str, list[str]]:
    """Raw reads per file, as lines, for every Rust file under src/ and tests/."""
    found: dict[str, list[str]] = {}
    for top in ("src", "tests"):
        for path in sorted((root / top).rglob("*.rs")):
            rel = path.relative_to(root).as_posix()
            if rel in EXEMPT:
                continue
            lines = reads(path.read_text(encoding="utf-8", errors="replace"))
            if lines:
                found[rel] = lines
    return found


def counts(root: Path) -> dict[str, int]:
    """Raw reads per file, for every Rust file under src/ and tests/."""
    return {path: len(lines) for path, lines in tree_reads(root).items()}


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
        # A negative row would cancel growth elsewhere in the total (MIK-8283).
        if int(count) < 0:
            raise ValueError(f"{path}: a baseline count may not be negative ({count})")
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


def grown(
    baseline: dict[str, int],
    base: dict[str, int],
    base_lines: dict[str, list[str]] | None = None,
    head_lines: dict[str, list[str]] | None = None,
) -> list[str]:
    """How `baseline` grew against `base` (MIK-8283).

    The total may not rise and a listed row may not grow. A new row may hold
    only reads that moved: each of its lines (`head_lines`) must match a line
    gone from a row that shrank (`base_lines` at base less `head_lines` now).
    Without lines nothing has moved, so any new row fails.
    """
    base_lines, head_lines = base_lines or {}, head_lines or {}
    out = []
    if sum(baseline.values()) > sum(base.values()):
        out.append(f"the baseline total rose {sum(base.values())} -> {sum(baseline.values())}; it may only shrink")
    shrunk = [path for path, n in base.items() if baseline.get(path, 0) < n]
    moved = ratchet_moves.gone(base_lines, head_lines, shrunk)
    new_rows = {path: head_lines.get(path, []) for path in baseline if path not in base}
    carried_by = ratchet_moves.carry(new_rows, moved)
    for path, n in sorted(baseline.items()):
        if path in base:
            if n > base[path]:
                out.append(f"{path}: baseline {n} > base {base[path]}; the baseline may only shrink")
            continue
        carried = carried_by[path]
        if n > carried:
            out.append(
                f"{path}: a new row of {n} carries only {carried} read(s) moved from a shrinking"
                " file (matched by line text); a new file may not gain reads"
            )
    return out


def base_reads(ref: str, paths: list[str]) -> dict[str, list[str]]:
    """The raw-read lines each of `paths` held at `ref`."""
    out = {}
    for path in paths:
        done = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=ROOT, capture_output=True, text=True)
        if done.returncode == 0:
            out[path] = reads(done.stdout)
    return out


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
    try:
        baseline = parse((ROOT / BASELINE).read_text(encoding="utf-8"))
    except ValueError as error:
        print(error)
        return 1
    lines = tree_reads(ROOT)
    problems = violations({p: len(r) for p, r in lines.items()}, baseline) + aliases(ROOT)
    if len(argv) == 2 and (base := base_baseline(argv[1])) is not None:
        shrunk = [p for p, n in base.items() if baseline.get(p, 0) < n]
        problems += grown(baseline, base, base_reads(argv[1], shrunk), lines)
    for problem in problems:
        print(problem)
    if problems:
        return 1
    print(f"no new raw clock read ({sum(baseline.values())} grandfathered in {len(baseline)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
