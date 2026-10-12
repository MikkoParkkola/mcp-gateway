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
module and backs no file; a ``mod`` line inside a comment or a string declares
nothing; and ``#[path]`` is relative to the directory of the declaring file.

Usage:
    check-orphan-test-modules.py    # check, exit 1 when a file is unreachable
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "target", "node_modules"}

# One token stream over code with comments and literal contents blanked:
# a `#[path = "` (or raw `r#"`) opener (its value is read back from the literal table), a
# `mod name;` (backs a file) or `mod name {` (inline, backs none), and the
# braces that tell which inline modules enclose a declaration.
TOKEN = re.compile(
    r"""(?P<path>\#\s*\[\s*path\s*=\s*)(?:r\#*)?(?P<quote>")"""
    r"""|(?P<cfg>\#(?P<inner>!)?\s*\[\s*cfg\s*\()"""
    r"""|(?P<attr>\#!?\s*\[)"""
    r"""|\bmod\s+(?:r\#)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<end>[;{])"""
    r"""|(?P<open>\{)|(?P<close>\})|(?P<semi>;)"""
)


def cfg_is_test(expr: str) -> bool:
    """Whether a `#[cfg(<expr>)]` compiles only under test: `test`, or an
    `all(..)` with `test` as a DIRECT operand. A nested `any(test, ..)` or a
    `not(..)` still builds outside tests, and `test_mode` is not `test`
    (MIK-8405.SPLIT.5; the one cfg judgement, shared with
    scripts/release/check_inventory_rows.py)."""
    expr = expr.strip()
    if expr == "test":
        return True
    opener = re.match(r"all\s*\(", expr)
    if not (opener and expr.endswith(")")):
        return False
    operands, depth, start = [], 0, opener.end()
    for i in range(opener.end(), len(expr) - 1):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            operands.append(expr[start:i])
            start = i + 1
    operands.append(expr[start : len(expr) - 1])
    return "test" in (o.strip() for o in operands)


def cfg_expression(code: str, start: int) -> str:
    """The expression of a `#[cfg(` whose `(` ends just before `start`, up to
    its balancing `)`. Literal contents are already blanked."""
    depth, i = 1, start
    while i < len(code) and depth:
        depth += {"(": 1, ")": -1}.get(code[i], 0)
        i += 1
    return code[start : i - 1]
RAW_STRING = re.compile(r'b?r(#*)"')


def blank(text: str) -> tuple[str, dict[int, str]]:
    """Blank comments and literal contents; keep quotes, newlines and offsets.

    A `mod foo;` inside a comment or a string declares nothing. Left in, it
    would let a commented-out declaration keep answering for a file the
    compiler no longer sees -- the exact shape this guard exists to catch.
    Block comments nest in Rust, so they are matched by depth. Returns the
    blanked text and each string literal's value keyed by its opening quote.
    """
    out = list(text)
    literals: dict[int, str] = {}
    n = len(text)

    def wipe(start: int, stop: int) -> None:
        for k in range(start, stop):
            if out[k] != "\n":
                out[k] = " "

    i = 0
    while i < n:
        ident_before = i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            wipe(i, j)
            i = j
        elif text.startswith("/*", i):
            depth, j = 0, i
            while j < n:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                    if depth == 0:
                        break
                else:
                    j += 1
            wipe(i, j)
            i = j
        elif not ident_before and (m := RAW_STRING.match(text, i)):
            quote = m.end() - 1
            j = text.find('"' + m.group(1), m.end())
            j = n if j < 0 else j
            literals[quote] = text[m.end() : j]
            wipe(m.end(), j)
            i = j + 1 + len(m.group(1))
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            literals[i] = text[i + 1 : j]
            wipe(i + 1, j)
            i = j + 1
        elif text[i] == "'":
            # A char literal ('x', '\n', '"') or a lifetime ('a): only the
            # literal forms are skipped, so a lifetime never swallows code.
            # Their contents are blanked: a '{' or '[' is not a brace.
            if text.startswith("\\", i + 1):
                j = text.find("'", i + 3)
                j = n if j < 0 else j
                wipe(i + 1, j)
                i = j + 1
            elif i + 2 < n and text[i + 2] == "'":
                wipe(i + 1, i + 2)
                i += 3
            else:
                i += 1
        else:
            i += 1
    return "".join(out), literals


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
    roots += src.joinpath("bin").glob("*/main.rs")
    for target in ("tests", "benches", "examples"):
        roots += ROOT.joinpath(target).glob("*.rs")
        roots += ROOT.joinpath(target).glob("*/main.rs")
    return [root for root in roots if root.is_file()]


def module_dir(source: Path, owns_dir: bool) -> Path:
    """The directory a plain `mod foo;` in `source` resolves against.

    A crate root, a file loaded through `#[path]` (rustc treats it as a
    mod-rs file), `mod.rs`, `lib.rs` and `main.rs` own their directory; any
    other file owns a subdirectory named after itself.
    """
    if owns_dir or source.name in {"mod.rs", "lib.rs", "main.rs"}:
        return source.parent
    return source.parent / source.stem


def declarations(source: Path, owns_dir: bool) -> set[tuple[Path, bool]]:
    """[`declarations_with_cfg`] without the test flag."""
    return {(path, via_path) for path, via_path, _ in declarations_with_cfg(source, owns_dir)}


def declarations_with_cfg(source: Path, owns_dir: bool) -> set[tuple[Path, bool, bool]]:
    """Resolve every file-backed declaration in `source` to the path it names.

    Per the Rust reference: a plain `mod name;` resolves under the module
    directory plus each enclosing inline module; a `#[path]` resolves against
    the declaring file's directory at top level, and against the module
    directory plus enclosing inline modules inside one. A `#[path]`
    declaration names only its path, never also the default file. Each result
    carries whether it was reached through `#[path]`, which decides where ITS
    child modules resolve, and whether the declaration compiles only under
    test: a test `#[cfg]` on it or on an enclosing inline module
    (MIK-8405.SPLIT.5). A `#[cfg]` is dropped at the end of the item it
    belongs to (`;`, `{` or `}`), so one on a `use` or `fn` never reaches a
    later `mod`. An inner `#![cfg(test)]` makes the file (or the inline
    module it opens) test-only, so everything it declares is too. The body
    of any other attribute is skipped whole, so a brace inside one (say
    `#[doc = concat!{..}]`) never drops a pending `#[cfg]`.
    """
    return _scan(source, owns_dir)[0]


def file_is_test(source: Path) -> bool:
    """Whether `source` opens with an inner `#![cfg(test)]`: the whole file
    then compiles only under test."""
    return _scan(source, True)[1]


def _scan(source: Path, owns_dir: bool) -> tuple[set[tuple[Path, bool, bool]], bool]:
    code, literals = blank(source.read_text(encoding="utf-8", errors="replace"))
    base = module_dir(source, owns_dir)
    declared: set[tuple[Path, bool, bool]] = set()
    # Each open brace: the inline module name it opens (None for any other
    # block) and whether that block compiles only under test.
    inline: list[tuple[str | None, bool]] = []
    pending_path: str | None = None
    pending_test = False
    file_test = False
    pos = 0
    while m := TOKEN.search(code, pos):
        pos = m.end()
        enclosing_test = file_test or any(test for _, test in inline)
        if m.group("quote"):
            pending_path = literals.get(m.start("quote"))
        elif m.group("cfg"):
            test = cfg_is_test(cfg_expression(code, m.end()))
            if not m.group("inner"):
                pending_test = pending_test or test
            elif inline:
                inline[-1] = (inline[-1][0], inline[-1][1] or test)
            else:
                file_test = file_test or test
        elif m.group("attr"):
            pos = attribute_end(code, m.end())
        elif m.group("name"):
            nested = [name for name, _ in inline if name]
            test = pending_test or enclosing_test
            if m.group("end") == "{":
                inline.append((m.group("name"), test))
            elif pending_path is not None:
                start = base.joinpath(*nested) if nested else source.parent
                declared.add(((start / pending_path).resolve(), True, test))
            else:
                directory = base.joinpath(*nested)
                declared.add(((directory / f"{m.group('name')}.rs").resolve(), False, test))
                declared.add(((directory / m.group("name") / "mod.rs").resolve(), False, test))
            pending_path, pending_test = None, False
        elif m.group("open"):
            inline.append((None, pending_test or enclosing_test))
            pending_path, pending_test = None, False
        elif m.group("close"):
            if inline:
                inline.pop()
            pending_path, pending_test = None, False
        elif m.group("semi"):
            pending_path, pending_test = None, False
    return declared, file_test


def attribute_end(code: str, start: int) -> int:
    """The offset just past the `]` closing an attribute whose `[` ends just
    before `start`. Literal contents are already blanked."""
    depth, i = 1, start
    while i < len(code) and depth:
        depth += {"[": 1, "]": -1}.get(code[i], 0)
        i += 1
    return i


def reachable() -> set[Path]:
    """Files reached by following declarations from the crate roots only.

    A declaration inside an unreached file declares nothing: that file is
    not compiled, so neither is anything it names.
    """
    roots = {root.resolve() for root in crate_roots()}
    seen: set[tuple[Path, bool]] = set()
    stack = [(root, True) for root in roots]
    while stack:
        path, owns_dir = stack.pop()
        if (path, owns_dir) in seen or not path.is_file():
            continue
        seen.add((path, owns_dir))
        stack.extend(declarations(path, owns_dir))
    return {path for path, _ in seen}


def library_roots() -> list[Path]:
    """The crate roots that build outside tests: the library and the
    binaries. `tests/`, `benches/` and `examples/` targets build only for
    their own commands, so what they alone reach is test-only."""
    src = ROOT / "src"
    roots = [src / "lib.rs", src / "main.rs", *src.joinpath("bin").glob("*.rs")]
    roots += src.joinpath("bin").glob("*/main.rs")
    return [root for root in roots if root.is_file()]


def compiled_outside_tests() -> set[Path]:
    """Files reached from a library or binary root through declarations none
    of which is test-only."""
    seen: set[tuple[Path, bool]] = set()
    stack = [(root.resolve(), True) for root in library_roots()]
    while stack:
        path, owns_dir = stack.pop()
        if (path, owns_dir) in seen or not path.is_file():
            continue
        declared, file_test = _scan(path, owns_dir)
        if file_test:
            continue
        seen.add((path, owns_dir))
        stack.extend((child, via_path) for child, via_path, test in declared if not test)
    return {path for path, _ in seen}


def test_only_files(live: set[Path] | None = None) -> set[Path]:
    """Files compiled only under test: reachable from a crate root, but not
    through any chain of non-test declarations from the library or a binary
    (MIK-8405.SPLIT.5). check_inventory_rows.py keeps their functions out of
    the critical-function inventory. `live` is `reachable()`, when the
    caller has it already."""
    return (reachable() if live is None else live) - compiled_outside_tests()


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
