#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when a ``.rs`` file under ``src/`` is in no compilation unit.

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

A third version still let orphans through: it counted a declaration from
*any* file, including a file that was itself undeclared. MIK-7518's
``invoke/suggestion.rs`` lost its ``mod suggestion;`` in an unrelated docs
commit, and its ``#[path]`` declaration of ``suggestion_authz_tests.rs`` kept
answering for a test file the compiler no longer saw. So the check now walks
declarations from the crate roots (``src/lib.rs``, ``src/main.rs``,
``src/bin/*.rs`` and the ``tests``/``benches``/``examples`` targets) and
reports every source under ``src/`` the walk does not reach -- not only
``*_tests.rs``, because an orphaned production module strands its tests too.
Declarations behind a ``#[cfg]`` still count as reached: the file is in a
compilation unit for some configuration.

So declarations are resolved to the file path they actually name, following
Rust's own rules, and compared against the file on disk. Three further traps
the resolution has to avoid: a ``mod foo { .. }`` block declares an *inline*
module and backs no file; a ``mod`` line inside a comment declares nothing;
and ``#[path]`` is relative to the directory of the declaring file.

Usage:
    check-orphan-test-modules.py    # check, exit 1 when a file is unreachable
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "target", "node_modules"}

# Only `mod foo;` backs a file. `mod foo { .. }` is inline and backs none, so
# the semicolon is load-bearing rather than incidental.
MOD_DECL = re.compile(r"\bmod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*;")
# `mod foo { .. }` -- an inline module. A `mod bar;` inside it names
# `<dir>/foo/bar.rs`, so its name is a candidate directory for the file's
# plain declarations.
INLINE_MOD = re.compile(r"\bmod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*\{")
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


def src_sources() -> list[Path]:
    """Every Rust source under ``src/``, minus build output."""
    return sorted(
        path
        for path in ROOT.joinpath("src").rglob("*.rs")
        if not SKIP_DIRS.intersection(path.relative_to(ROOT).parts)
    )


def crate_roots() -> list[Path]:
    """Every file cargo compiles as the root of a crate in this package."""
    src = ROOT / "src"
    roots = [src / "lib.rs", src / "main.rs", *src.joinpath("bin").glob("*.rs")]
    for target in ("tests", "benches", "examples"):
        roots += ROOT.joinpath(target).glob("*.rs")
        roots += ROOT.joinpath(target).glob("*/main.rs")
    return [root for root in roots if root.is_file()]


def module_dir(source: Path, is_root: bool) -> Path:
    """The directory a plain `mod foo;` in `source` resolves against.

    A crate root, `mod.rs`, `lib.rs` and `main.rs` own their directory; any
    other file owns a subdirectory named after itself.
    """
    if is_root or source.name in {"mod.rs", "lib.rs", "main.rs"}:
        return source.parent
    return source.parent / source.stem


def declarations(source: Path, is_root: bool) -> set[Path]:
    """Resolve every declaration in `source` to the file path it names."""
    declared: set[Path] = set()
    text = strip_comments(source.read_text(encoding="utf-8", errors="replace"))

    # `#[path = "rel"] mod name;` -- relative to the DECLARING FILE'S
    # directory, per the Rust reference, not to the module directory.
    for rel, _name in PATH_MOD.findall(text):
        declared.add((source.parent / rel).resolve())

    # Plain `mod name;` -- `dir/name.rs` or `dir/name/mod.rs`.
    # ponytail: which inline module encloses a `mod name;` is not tracked --
    # that needs brace matching through string literals. Each inline module
    # name in the file is tried as one extra directory level instead; nesting
    # deeper than one inline level would read as a false orphan.
    base = module_dir(source, is_root)
    dirs = [base, *(base / inline for inline in INLINE_MOD.findall(text))]
    for name in MOD_DECL.findall(text):
        for directory in dirs:
            declared.add((directory / f"{name}.rs").resolve())
            declared.add((directory / name / "mod.rs").resolve())
    return declared


def reachable() -> set[Path]:
    """Files reached by following declarations from the crate roots only.

    A declaration inside an unreached file declares nothing: that file is
    not compiled, so neither is anything it names.
    """
    roots = {root.resolve() for root in crate_roots()}
    seen: set[Path] = set()
    stack = list(roots)
    while stack:
        path = stack.pop()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        stack.extend(declarations(path, path in roots))
    return seen


def orphans() -> list[Path]:
    live = reachable()
    return [path for path in src_sources() if path.resolve() not in live]


def main() -> int:
    found = orphans()
    total = len(src_sources())

    if found:
        print(f"Unreachable source files ({len(found)}):", file=sys.stderr)
        for path in found:
            print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        print(
            "\nEach is compiled into nothing and run by nothing. Declare it from a\n"
            "module the crate root reaches (for a test file,\n"
            '`#[cfg(test)] #[path = "<file>.rs"] mod <stem>;`), or delete it.\n'
            "A file in no compilation unit is neither code nor a test.",
            file=sys.stderr,
        )
        return 1

    print(f"{total} source files under src/, all reachable from a crate root.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
