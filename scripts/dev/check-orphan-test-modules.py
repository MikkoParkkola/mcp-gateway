#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when a ``*_tests.rs`` under ``src/`` is in no compilation unit.

A test file that no module declares is never compiled and never run, yet it
reads exactly like coverage: it sits next to its siblings, its assertions are
specific, and it can be cited as proof of a behaviour nobody has ever observed.
``cargo test`` cannot report it, because from the compiler's side the file does
not exist. MIK-7538 found one such file being cited as evidence in a release
ledger, in two merged design documents and in three implementation briefs.

The sweep is tree-wide on purpose. A directory-scoped version of this check
reported 72 false orphans, because a module may be declared from a sibling or
a parent by ``#[path = "..."]`` rather than by a ``mod`` line next to the file.
Both spellings count as a declaration, and both are searched across every
``.rs`` in the tree.

Usage:
    check-orphan-test-modules.py    # check, exit 1 when a file is undeclared
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "target", "node_modules"}

# `mod foo;` and `mod foo { ... }`. Word-bounded on both sides so `mod
# foo_tests_extra` cannot answer for `foo_tests.rs`.
MOD_DECL = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*[;{]")
# `#[path = "some/where/foo_tests.rs"]`, matched on the basename so a relative
# prefix does not have to be resolved.
PATH_ATTR = re.compile(r"""path\s*=\s*["']([^"']+)["']""")


def rust_sources() -> list[Path]:
    """Every Rust source in the tree, minus build output and vendored code."""
    return [
        path
        for path in ROOT.rglob("*.rs")
        if not SKIP_DIRS.intersection(path.relative_to(ROOT).parts)
    ]


def declarations(sources: list[Path]) -> tuple[set[str], set[str]]:
    """Module names and `#[path]` basenames declared anywhere in the tree."""
    blob = "\n".join(
        path.read_text(encoding="utf-8", errors="replace") for path in sources
    )
    return (
        set(MOD_DECL.findall(blob)),
        {Path(raw).name for raw in PATH_ATTR.findall(blob)},
    )


def main() -> int:
    sources = rust_sources()
    declared_mods, declared_paths = declarations(sources)

    candidates = sorted(
        path
        for path in ROOT.joinpath("src").rglob("*_tests.rs")
        if not SKIP_DIRS.intersection(path.relative_to(ROOT).parts)
    )
    orphans = [
        path
        for path in candidates
        if path.stem not in declared_mods and path.name not in declared_paths
    ]

    if orphans:
        print(f"Undeclared test files ({len(orphans)}):", file=sys.stderr)
        for path in orphans:
            print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        print(
            "\nEach is compiled into nothing and run by nothing. Declare it with\n"
            '`#[cfg(test)] #[path = "<file>.rs"] mod <stem>;` in the parent\n'
            "module, or delete it. A file in no compilation unit is not a test.",
            file=sys.stderr,
        )
        return 1

    print(f"{len(candidates)} test files under src/, all declared.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
