#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every function a change adds on the seven COV.3 paths is classified (MIK-7324, MIK-8169).

docs/release/v4.0.0-critical-path-coverage.md: "A function added to one of
these paths that meets the definition is added to the inventory in the same
change." This check makes that mechanical. Each non-test function the change
adds under the seven paths needs a row in the same change, in one of:

  docs/release/inventory.d/<pr>.critical.tsv     it enforces (critical/standard)
  docs/release/inventory.d/<pr>.unenforcing.tsv  reviewed: enforces nothing

A fragment per PR, so row-adding PRs never edit the same file (MIK-8279). The
base ledgers, docs/release/v4.0.0-critical-functions.tsv and
docs/release/v4.0.0-unenforcing-functions.tsv, hold the older rows and are
read together with the fragments by inventory_ledger.py. A key stated twice,
in one ledger or across both, fails.

Usage:
  check_inventory_rows.py <base> [<head>]   fail when a function <head> (default
                                            HEAD) adds since its merge-base with
                                            <base> has no row in <head>
  check_inventory_rows.py --all [<head>]    fail when any function on the paths
                                            in <head> has no row (MIK-8195): a
                                            gap older than the diff check
"""

from __future__ import annotations

import functools
import posixpath
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory_ledger as ledger  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = "docs/release/v4.0.0-critical-functions.tsv"
UNENFORCING = "docs/release/v4.0.0-unenforcing-functions.tsv"
ALL = "--all"
# Diffing against git's empty tree reads every line of <head> as added.
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

# The seven paths, as scripts/release coverage grading names them.
PREFIXES = (
    "src/gateway/server/",
    "src/oauth/",
    "src/transport/http/",
    "src/gateway/router/",
    "src/transport/stdio.rs",
    "src/transport/command_split.rs",
    "src/gateway/input_bridge.rs",
    "src/gateway/task_service/",
    # The module file and its directory, spelled apart: a git pathspec names
    # one path, so the stem alone matched only the directory.
    "src/gateway/meta_mcp/task_confirmation.rs",
    "src/gateway/meta_mcp/task_confirmation/",
    "src/personal_accounts/",
    "src/config/account_bindings.rs",
    "src/identity_propagation/",
    # The outbound read judge and its delivery (MIK-8195 W8 took stdio.rs,
    # MIK-8321 the rest). Inventory and probe surface only:
    # critical_path_coverage.py PATHS does not grade it as a path.
    "src/gateway/outbound/",
)

FN = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+(?:"[^"]*"\s+)?)?fn\s+([A-Za-z_]\w*)')
TEST_FILE = re.compile(r"(^|/)tests?(/|\.rs$)|_tests?\.rs$|_tests/")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def code(line: str) -> str:
    """The line without comments, string and char literals (for brace counts)."""
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])'", "''", line)
    return line.split("//", 1)[0]


def test_only(text: str) -> bool:
    """`#[cfg(test)]`, or a `cfg(all(...))` with `test` as a direct operand.
    A nested `any(test, ...)` or `not(...)` still builds outside tests."""
    if text.startswith("#[cfg(test)]"):
        return True
    if not text.startswith("#[cfg(all("):
        return False
    operands, depth, start = [], 0, len("#[cfg(all(")
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")" and depth == 0:
            operands.append(text[start:i])
            break
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            operands.append(text[start:i])
            start = i + 1
    return "test" in (o.strip() for o in operands)


def bodyless(lines: list[str], line: int) -> bool:
    """The signature at 1-based `line` ends in `;` before any `{`: a trait
    declaration, which has no lines of its own to cover."""
    square = 0  # a `;` inside `[u8; 16]` does not end the signature
    for raw in lines[line - 1 :]:
        for ch in code(raw):
            square += (ch == "[") - (ch == "]")
            if ch == "{" or (ch == ";" and square == 0):
                return ch == ";"
    return False


def test_lines(lines: list[str]) -> set[int]:
    """1-based line numbers inside a `#[cfg(test)]` item (a module, fn or impl)."""
    inside: set[int] = set()
    pending = False
    depth = 0
    start_depth: int | None = None
    for n, raw in enumerate(lines, 1):
        text = code(raw).strip()
        if start_depth is not None:
            inside.add(n)
        elif test_only(text):
            pending = True
        elif pending and text and not text.startswith("#["):
            inside.add(n)
            if text.endswith(";"):
                pending = False  # `#[cfg(test)] mod x;` or a use: one line
            else:
                start_depth = depth
                pending = False
        depth += text.count("{") - text.count("}")
        if start_depth is not None and depth <= start_depth and "}" in text:
            start_depth = None
    return inside


@functools.lru_cache(maxsize=None)
def show(rev: str, path: str) -> str | None:
    """`path` as `rev` has it; None when it does not exist there. Cached:
    callers pass a resolved commit, never a moving name like HEAD."""
    done = subprocess.run(
        ["git", "show", f"{rev}:{path}"], cwd=ROOT, capture_output=True, text=True
    )
    return done.stdout if done.returncode == 0 else None


LEDGER_OF = {INVENTORY: ledger.CRITICAL, UNENFORCING: ledger.UNENFORCING}


@functools.cache
def ledger_rows(root: Path, rev: str, path: str) -> tuple[dict, ...]:
    """The rows of the ledger at `path` as `rev` has it: the base TSV plus its
    fragments (inventory_ledger.py). Raises LedgerError on any bad row."""
    return tuple(ledger.load_rev(root, rev, LEDGER_OF[path], path))


def rows(rev: str, path: str) -> set[tuple[str, str, int]]:
    """(file, fn, occurrence) of every row of one ledger, base and fragments.
    `rev` is resolved first, so the cache never serves a moved name."""
    return {ledger.key(row) for row in ledger_rows(ROOT, git("rev-parse", rev).strip(), path)}


def occurrence(lines: list[str], name: str, line: int) -> int:
    """Which `fn <name>` in the file the definition at 1-based `line` is,
    counted as the grader counts (critical_function_coverage.fn_line): every
    line matching, test code included. A same-named function added beside an
    inventoried one is a new occurrence, so it needs its own row."""
    pattern = re.compile(r"\bfn\s+" + re.escape(name) + r"\b")
    return sum(1 for text in lines[:line] if pattern.search(text))


def under_cfg_test(lines: list[str], n: int) -> bool:
    """Whether the attribute block directly above 1-based line `n` holds
    `#[cfg(test)]`. Only that block: an attribute further up belongs to
    another item."""
    i = n - 2
    if lines and i < len(lines) and lines[n - 1].lstrip().startswith("#[cfg(test)]"):
        return True
    while i >= 0:
        text = lines[i].strip()
        if text.startswith(("#[cfg(test)]", "#[cfg(all(test")):
            return True
        if not (text.startswith("#[") or text.startswith("//")):
            return False
        i -= 1
    return False


@functools.lru_cache(maxsize=None)
def mount_lines(head: str, path: str) -> tuple[tuple[str, int], ...]:
    """Every line at `head` that declares `path` as a module, by
    `#[path = "<file>"]` or `mod <stem>;`, as (declaring file, line). Found with
    `git grep`, so a sibling's `#[path]` counts."""
    name = Path(path).name
    stem = Path(path).stem
    pattern = rf'#\[path = "([^"]*/)?{re.escape(name)}"\]|^[[:space:]]*(pub(\([^)]*\))? )?mod {re.escape(stem)};'
    done = subprocess.run(
        ["git", "grep", "-n", "-E", pattern, head, "--", "src"],
        cwd=ROOT, capture_output=True, text=True,
    )
    hits = [line.split(":", 3) for line in done.stdout.splitlines()]
    found = []
    for _rev, source, number, text in hits:
        lines = (show(head, source) or "").splitlines()
        item = declared_item(lines, int(number))
        if item is not None and mounts(source, lines, item, path):
            found.append((source, item))
    return tuple(found)


ATTRIBUTE_OR_COMMENT = re.compile(r"^\s*(#\[|//)")
PATH_ATTRIBUTE = re.compile(r'#\[path = "([^"]*)"\]')
MOD_DECLARATION = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;")


def declared_item(lines: list[str], n: int) -> int | None:
    """The 1-based line of the `mod x;` that line `n` belongs to: `n` itself,
    or the first line after an attribute block that `n` sits in. `None` when
    no `mod x;` follows (the match was not a declaration)."""
    i = n - 1
    while i < len(lines) and ATTRIBUTE_OR_COMMENT.match(lines[i]) and not MOD_DECLARATION.match(lines[i]):
        i += 1
    if i < len(lines) and MOD_DECLARATION.match(lines[i]):
        return i + 1
    return None


INLINE_MODULE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*\{")


def inline_modules(lines: list[str], item: int) -> list[str]:
    """The inline `mod name { .. }` blocks enclosing 1-based line `item`,
    outermost first. Braces are counted per line with `//` comments dropped;
    string literals in this codebase balance their braces, which is the
    ceiling of a line counter."""
    stack: list[tuple[str, int]] = []
    depth = 0
    for line in lines[: item - 1]:
        code = line.split("//", 1)[0]
        opened = INLINE_MODULE.match(code)
        if opened:
            stack.append((opened.group(1), depth))
        depth += code.count("{") - code.count("}")
        while stack and depth <= stack[-1][1]:
            stack.pop()
    return [name for name, _ in stack]


def mounts(source: str, lines: list[str], item: int, path: str) -> bool:
    """Whether the `mod x;` at 1-based line `item` of `source` mounts `path`,
    by Rust's rules: a `#[path]` in its attribute block is relative to the
    declaring file's directory; otherwise `x.rs` or `x/mod.rs` beside a
    `mod.rs`/`lib.rs`/`main.rs`, or under a directory named for any other
    declaring file, each inside the inline modules that enclose it. Without this, `mod admission;` anywhere in `src` would
    count as a mount of every `admission.rs` (MIK-8405.SPLIT.5)."""
    directory = posixpath.dirname(source)
    stem, _ = posixpath.splitext(posixpath.basename(source))
    own = directory if stem in ("mod", "lib", "main") else posixpath.join(directory, stem)
    inline = inline_modules(lines, item)
    i = item - 2
    while i >= 0 and ATTRIBUTE_OR_COMMENT.match(lines[i]):
        attribute = PATH_ATTRIBUTE.search(lines[i])
        if attribute:
            # Outside an inline block a `#[path]` is relative to the file's
            # directory; inside one, to the file's own module directory plus
            # the inline names (the Rust reference, "the path attribute").
            relative_to = posixpath.join(own, *inline) if inline else directory
            return posixpath.normpath(posixpath.join(relative_to, attribute.group(1))) == path
        i -= 1
    name = MOD_DECLARATION.match(lines[item - 1]).group(1)
    base = posixpath.join(own, *inline)
    return path in (posixpath.join(base, f"{name}.rs"), posixpath.join(base, name, "mod.rs"))


@functools.lru_cache(maxsize=None)
def declared_for_tests(head: str, path: str, depth: int = 0) -> bool:
    """Whether every declaration of `path` at `head` compiles only under test.

    A module file is test-only when the line that declares it sits under
    `#[cfg(test)]` or inside a test item, or in a file that is itself
    test-only by the same rule. A declaring file's name proves nothing
    (MIK-8405.SPLIT.5): a `*_tests.rs` mounted outside tests compiles into
    production, and so does everything it declares.
    """
    hits = mount_lines(head, path)
    if not hits:
        return False
    for source, n in hits:
        if depth < 4 and declared_for_tests(head, source, depth + 1):
            continue  # declared from a file that only tests compile
        lines = (show(head, source) or "").splitlines()
        if not (under_cfg_test(lines, n) or n in test_lines(lines)):
            return False
    return True


def outside_inventory(head: str, path: str) -> bool:
    """Whether `path`'s functions are out of the inventory's scope: it
    compiles only under test, or it is named like a test and mounted nowhere
    (not compiled at all; `test_file_problems` reports that). A test-like name
    mounted outside tests is in scope (MIK-8405.SPLIT.5)."""
    if declared_for_tests(head, path):
        return True
    return bool(TEST_FILE.search(path)) and not mount_lines(head, path)


def test_file_problems(base: str, head: str) -> list[str]:
    """Test-named `.rs` files `head` adds or changes on the COV.3 paths (every
    one with `--all`) that are mounted nowhere, so their tests never compile,
    or mounted outside `#[cfg(test)]`, so their code compiles into production
    under a test's name (MIK-8405.SPLIT.5)."""
    # Resolved first: the mount lookups are cached by revision, and a symbolic
    # name such as HEAD would let one repository's answer stand for another's.
    head = git("rev-parse", head).strip()
    merge_base = EMPTY_TREE if base == ALL else git("merge-base", base, head).strip()
    changed = git(
        "diff", "--name-only", "--no-renames", "--diff-filter=AM", merge_base, head, "--", *PREFIXES
    ).split()
    problems = []
    for path in changed:
        if not path.endswith(".rs") or not TEST_FILE.search(path):
            continue
        if not mount_lines(head, path):
            problems.append(f"{path}: named like a test file but mounted nowhere, so its tests never compile")
        elif not declared_for_tests(head, path):
            problems.append(f"{path}: named like a test file but compiled outside tests")
    return problems


def added_functions(base: str, head: str) -> list[tuple[str, str, int, int]]:
    merge_base = EMPTY_TREE if base == ALL else git("merge-base", base, head).strip()
    diff = git("diff", "-U0", "--no-renames", merge_base, head, "--", *PREFIXES)
    found: list[tuple[str, str, int, int]] = []
    path = None
    lines: list[str] = []
    tests: set[int] = set()
    new_line = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
            if path and (not path.endswith(".rs") or outside_inventory(head, path)):
                path = None
            if path:
                lines = (show(head, path) or "").splitlines()
                tests = test_lines(lines)
        elif line.startswith("@@"):
            new_line = int(re.match(r"@@ -\S+ \+(\d+)", line).group(1))
        elif line.startswith("+") and path:
            match = FN.match(line[1:])
            if match and new_line not in tests and not bodyless(lines, new_line):
                name = match.group(1)
                found.append((path, name, new_line, occurrence(lines, name, new_line)))
            new_line += 1
    return found


def missing_rows(base: str, head: str) -> list[tuple[str, str, int, int]]:
    """Functions `head` adds since its merge-base with `base` that have no row
    in `head`: (file, fn, line, occurrence)."""
    head = git("rev-parse", head).strip()
    known = rows(head, INVENTORY) | rows(head, UNENFORCING)
    return [f for f in added_functions(base, head) if (f[0], f[1], f[3]) not in known]


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    head = argv[2] if len(argv) == 3 else "HEAD"
    try:
        resolved = git("rev-parse", head).strip()
        broken = ledger.overlap(list(ledger_rows(ROOT, resolved, INVENTORY)), list(ledger_rows(ROOT, resolved, UNENFORCING)))
        missing = missing_rows(argv[1], head)
        misnamed = test_file_problems(argv[1], resolved)
    except ledger.LedgerError as error:
        broken = error.problems
        missing = []
        misnamed = []
    for problem in broken:
        print(f"inventory: {problem}")
    if broken:
        print(f"{len(broken)} inventory problem(s); see inventory_ledger.py for the row rules.")
        return 1
    for problem in misnamed:
        print(f"test file: {problem}")
    if misnamed:
        print(
            f"{len(misnamed)} test-named file(s) are not mounted only for tests. Mount each "
            "under #[cfg(test)], or rename a file that is production code (MIK-8405.SPLIT.5)."
        )
        return 1
    for path, name, line, nth in missing:
        print(f"no inventory row: {path}:{line} fn {name} (occurrence {nth})")
    if missing:
        print(
            f"{len(missing)} function(s) on the COV.3 paths have no row. Add each to "
            "docs/release/inventory.d/<pr>.critical.tsv (it enforces) or "
            "docs/release/inventory.d/<pr>.unenforcing.tsv (it does not, with a reason)."
        )
        return 1
    scope = "on the COV.3 paths" if argv[1] == ALL else "added on the COV.3 paths"
    print(f"every function {scope} has a row")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
