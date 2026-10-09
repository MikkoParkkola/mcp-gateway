#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every test that does not run on macOS is listed, with a reason (MIK-8174).

Usage: check_macos_exclusions.py [<root>]

Scans the tree's Rust files for a test function, or a module in a test file,
whose attributes keep it off macOS: `cfg(target_os = "linux")`,
`cfg(not(target_os = "macos"))`, `cfg(all(..., not(target_os = "macos")))` or
`cfg_attr(target_os = "macos", ignore ...)` (also `not(target_vendor = "apple")`,
and as a file-level `#![cfg(...)]`, listed with item `*`), and every `--skip` of the macOS
job's test step in .github/workflows/ci.yml. Fails on any such item missing
from docs/release/macos-test-exclusions.tsv, on a row with no reason, and on a
row that no longer matches an item (a stale exclusion)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

LIST = "docs/release/macos-test-exclusions.tsv"
WORKFLOW = ".github/workflows/ci.yml"
# `#!` is a file-level gate: the whole file is kept off macOS (row item `*`).
OFF_MACOS = re.compile(
    r'#!?\[cfg\(target_os = "linux"\)\]'
    r'|#!?\[cfg\(not\((?:target_os = "macos"|target_vendor = "apple")\)\)\]'
    r'|#!?\[cfg\(all\(.*(?:not\(target_os = "macos"\)|not\(target_vendor = "apple"\)'
    r'|target_os = "linux").*\)\)\]'
    r'|#\[cfg_attr\(target_os = "macos", ignore'
)
# The truth of each `cfg` atom on the macOS CI job (`cargo test
# --all-features`). An atom not in this table is unresolved, and a gate whose
# answer rests on one counts as off macOS: the safe side for an exclusion list.
MACOS_CFG = {
    "test": True,
    "unix": True,
    "windows": False,
    "debug_assertions": True,
    'target_os = "macos"': True,
    'target_vendor = "apple"': True,
    'target_family = "unix"': True,
    'target_family = "windows"': False,
}
CFG_TOKEN = re.compile(r'\s*(?:(\w+)\s*=\s*"([^"]*)"|(\w+)|([(),]))')


def runs_on_macos(gate: str) -> bool:
    """Whether a `#[cfg(...)]` or `#![cfg(...)]` gate is true on macOS (MIK-8181).

    Evaluates the whole predicate (`all`, `any`, `not`), so a gate that names
    macOS but also requires Linux, or excludes Apple, is still off macOS. A
    gate that cannot be parsed, or rests on an unresolved atom, is off."""
    body = re.match(r"#!?\[cfg\((.*)\)\]\s*$", gate)
    if not body:
        return False
    tokens = list(CFG_TOKEN.finditer(body.group(1)))
    pos = 0

    def atom(m: re.Match) -> bool | None:
        key, val, ident = m.group(1), m.group(2), m.group(3)
        if key == "feature":
            return True
        if key is not None:
            if f'{key} = "{val}"' in MACOS_CFG:
                return MACOS_CFG[f'{key} = "{val}"']
            # Any other target_os, target_vendor or target_family is false.
            return False if key in ("target_os", "target_vendor", "target_family") else None
        return MACOS_CFG.get(ident)

    def pred() -> bool | None:
        nonlocal pos
        m = tokens[pos]
        pos += 1
        op = m.group(3)
        if op in ("all", "any", "not") and pos < len(tokens) and tokens[pos].group(4) == "(":
            pos += 1
            args = []
            while tokens[pos].group(4) != ")":
                args.append(pred())
                if tokens[pos].group(4) == ",":
                    pos += 1
            pos += 1
            if op == "not":
                if len(args) != 1:
                    raise ValueError("not takes one predicate")
                return None if args[0] is None else not args[0]
            if op == "all":
                return False if False in args else (None if None in args else True)
            return True if True in args else (None if None in args else False)
        if m.group(4):
            raise ValueError("unexpected punctuation")
        return atom(m)

    try:
        result = pred()
    except (ValueError, IndexError):
        return False
    return pos == len(tokens) and result is True


TEST_ATTR = re.compile(r"#\[(tokio::)?test\b")
ITEM = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(fn|mod)\s+(\w+)")
TEST_CFG = re.compile(r"#\[cfg\((?:all\()?test\b")
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
            if not OFF_MACOS.match(line) or (
                not line.startswith("#[cfg_attr") and runs_on_macos(line)
            ):
                continue
            if line.startswith("#!["):
                found.add((rel, "*"))
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
            # A module is a test module in a test file, or when its own gate
            # says `test` (`cfg(all(test, ...))` in a production mod.rs).
            test_gated = any(TEST_CFG.search(a) for a in block)
            if (kind == "fn" and any(TEST_ATTR.match(a) for a in block)) or (
                kind == "mod" and (TEST_FILE.search(rel) or test_gated)
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


def skipped(root: Path) -> set[tuple[str, str]]:
    """The `--skip` filters of the macOS job's test step, as (workflow, name)."""
    text = (root / WORKFLOW).read_text()
    job = text.split("\n  macos-check:\n", 1)[1]
    job = re.split(r"\n  [A-Za-z0-9_-]+:\n", job, maxsplit=1)[0]
    return {(WORKFLOW, name) for name in re.findall(r"--skip[= ](\S+)", job)}


def problems(root: Path) -> list[str]:
    rows, out = listed(root)
    items = excluded(root) | skipped(root)
    out += [f"not run on macOS and not listed: {p} {name}" for p, name in sorted(items - rows)]
    out += [f"stale row, nothing matches: {p} {name}" for p, name in sorted(rows - items)]
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
