#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every test that does not run on macOS is listed, with a reason (MIK-8174).

Usage: check_macos_exclusions.py [<root>]

Scans the tree's Rust files for a test function, or a module in a test file,
whose attributes keep it off macOS: `cfg(target_os = "linux")`,
`cfg(not(target_os = "macos"))`, `cfg(all(..., not(target_os = "macos")))` or
`cfg_attr(target_os = "macos", ignore ...)`. Fails on any such item missing
from docs/release/macos-test-exclusions.tsv, on a row with no reason, and on a
row that no longer matches an item (a stale exclusion)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

LIST = "docs/release/macos-test-exclusions.tsv"
OFF_MACOS = re.compile(
    r'#\[cfg\(target_os = "linux"\)\]'
    r'|#\[cfg\(not\(target_os = "macos"\)\)\]'
    r'|#\[cfg\(all\(.*not\(target_os = "macos"\).*\)\)\]'
    r'|#\[cfg_attr\(target_os = "macos", ignore'
)
TEST_ATTR = re.compile(r"#\[(tokio::)?test\b")
ITEM = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(fn|mod)\s+(\w+)")
TEST_FILE = re.compile(r"(^|/)tests?(/|\.rs$)|_tests?\.rs$|_tests/")


def excluded(root: Path) -> set[tuple[str, str]]:
    """(path, item) of every test function or test-file module kept off macOS."""
    found = set()
    for file in sorted(root.glob("**/*.rs")):
        rel = file.relative_to(root).as_posix()
        if rel.startswith("target/"):
            continue
        lines = [line.strip() for line in file.read_text(errors="replace").splitlines()]
        for n, line in enumerate(lines):
            if not OFF_MACOS.match(line):
                continue
            # The attribute block this gate sits in, then the item it governs.
            start = n
            while start > 0 and lines[start - 1].startswith(("#[", "///", "//")):
                start -= 1
            end = n
            while end + 1 < len(lines) and lines[end + 1].startswith(("#[", "///", "//")):
                end += 1
            block = lines[start : end + 1]
            item = ITEM.match(lines[end + 1]) if end + 1 < len(lines) else None
            if not item:
                continue
            kind, name = item.groups()
            if (kind == "fn" and any(TEST_ATTR.match(a) for a in block)) or (
                kind == "mod" and TEST_FILE.search(rel)
            ):
                found.add((rel, name))
    return found


def listed(root: Path) -> tuple[set[tuple[str, str]], list[str]]:
    rows, problems = set(), []
    for line in (root / LIST).read_text().splitlines()[1:]:
        cells = line.split("\t")
        if len(cells) < 4 or not cells[3].strip():
            problems.append(f"row without a reason: {line!r}")
            continue
        rows.add((cells[0], cells[1]))
    return rows, problems


def problems(root: Path) -> list[str]:
    rows, out = listed(root)
    items = excluded(root)
    out += [f"not run on macOS and not listed: {p} {name}" for p, name in sorted(items - rows)]
    # A ci.yml row documents a --skip in the job step; there is no attribute to find.
    out += [
        f"stale row, nothing matches: {p} {name}"
        for p, name in sorted(rows - items)
        if p != ".github/workflows/ci.yml"
    ]
    return out


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2]
    found = problems(root)
    for problem in found:
        print(problem)
    if found:
        print(f"Each test that does not run on macOS needs a row in {LIST}, with a reason.")
        return 1
    print("every test kept off macOS is listed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
