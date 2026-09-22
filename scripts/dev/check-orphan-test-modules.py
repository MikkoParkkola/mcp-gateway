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

Two earlier versions of this check were wrong, and both failure modes are
pinned by ``test_check_orphan_test_modules.py``:

* A **directory-scoped** sweep reported 72 false orphans out of 113 files,
  because a module may be declared from a sibling by ``#[path = "..."]``
  rather than by a ``mod`` line in the directory's own ``mod.rs``.
* A **name-matching** sweep hid real orphans, because it asked only whether
  the *stem* appeared anywhere. Five stems are duplicated in this tree --
  ``admission_tests``, ``provider_tests``, ``runtime_tests``,
  ``service_tests``, ``store_tests`` -- so declaring one silently answered for
  its twin in another directory.

So declarations are resolved to the file path they actually name, following
Rust's own rules, and compared against the file on disk. Three further traps
the resolution has to avoid: a ``mod foo { .. }`` block declares an *inline*
module and backs no file; a ``mod`` line inside a comment declares nothing;
and ``#[path]`` is relative to the directory of the declaring file.

Usage:
    check-orphan-test-modules.py    # check, exit 1 when a file is undeclared
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "target", "node_modules"}

# Only `mod foo;` backs a file. `mod foo { .. }` is inline and backs none, so
# the semicolon is load-bearing rather than incidental.
MOD_DECL = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
# `#[path = "..."]` immediately preceding a `mod foo;`, allowing other
# attributes and doc comments between the two.
PATH_MOD = re.compile(
    r"""#\s*\[\s*path\s*=\s*["']([^"']+)["']\s*\]"""
    r"""(?:\s*(?:\#\s*\[[^\]]*\]|//[^\n]*))*"""
    r"""\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;""",
    re.S,
)
LINE_COMMENT = re.compile(r"//[^\n]*")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def strip_comments(text: str) -> str:
    """Blank out comments, preserving newlines so offsets stay usable.

    A `mod foo;` inside a comment declares nothing. Left in, it would let a
    commented-out declaration keep answering for a file the compiler no longer
    sees -- the exact shape this guard exists to catch.
    """
    text = BLOCK_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    return LINE_COMMENT.sub("", text)


def rust_sources() -> list[Path]:
    """Every Rust source in the tree, minus build output and vendored code."""
    return [
        path
        for path in ROOT.rglob("*.rs")
        if not SKIP_DIRS.intersection(path.relative_to(ROOT).parts)
    ]


def module_dir(source: Path) -> Path:
    """The directory a plain `mod foo;` in `source` resolves against.

    `mod.rs`, `lib.rs` and `main.rs` own their directory; any other file owns a
    subdirectory named after itself.
    """
    if source.name in {"mod.rs", "lib.rs", "main.rs"}:
        return source.parent
    return source.parent / source.stem


def declared_files(sources: list[Path]) -> set[Path]:
    """Resolve every declaration to the file path it names."""
    declared: set[Path] = set()
    for source in sources:
        text = strip_comments(source.read_text(encoding="utf-8", errors="replace"))

        # `#[path = "rel"] mod name;` -- relative to the DECLARING FILE'S
        # directory, per the Rust reference, not to the module directory.
        for rel, _name in PATH_MOD.findall(text):
            declared.add((source.parent / rel).resolve())

        # Plain `mod name;` -- `dir/name.rs` or `dir/name/mod.rs`.
        base = module_dir(source)
        for name in MOD_DECL.findall(text):
            declared.add((base / f"{name}.rs").resolve())
            declared.add((base / name / "mod.rs").resolve())
    return declared


def orphans() -> list[Path]:
    sources = rust_sources()
    declared = declared_files(sources)
    return sorted(
        path
        for path in ROOT.joinpath("src").rglob("*_tests.rs")
        if not SKIP_DIRS.intersection(path.relative_to(ROOT).parts)
        and path.resolve() not in declared
    )


def main() -> int:
    found = orphans()
    total = sum(
        1
        for path in ROOT.joinpath("src").rglob("*_tests.rs")
        if not SKIP_DIRS.intersection(path.relative_to(ROOT).parts)
    )

    if found:
        print(f"Undeclared test files ({len(found)}):", file=sys.stderr)
        for path in found:
            print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        print(
            "\nEach is compiled into nothing and run by nothing. Declare it with\n"
            '`#[cfg(test)] #[path = "<file>.rs"] mod <stem>;` in the parent\n'
            "module, or delete it. A file in no compilation unit is not a test.",
            file=sys.stderr,
        )
        return 1

    print(f"{total} test files under src/, all declared.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
