#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every function a change adds on the seven COV.3 paths is classified (MIK-7324, MIK-8169).

docs/release/v4.0.0-critical-path-coverage.md: "A function added to one of
these paths that meets the definition is added to the inventory in the same
change." This check makes that mechanical. Each non-test function the change
adds under the seven paths needs a row in the same change, in one of:

  docs/release/v4.0.0-critical-functions.tsv     it enforces (critical/standard)
  docs/release/v4.0.0-unenforcing-functions.tsv  reviewed: enforces nothing

Usage:
  check_inventory_rows.py <base> [<head>]   fail when a function <head> (default
                                            HEAD) adds since its merge-base with
                                            <base> has no row in <head>
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = "docs/release/v4.0.0-critical-functions.tsv"
UNENFORCING = "docs/release/v4.0.0-unenforcing-functions.tsv"

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
    "src/gateway/meta_mcp/task_confirmation",
    "src/personal_accounts/",
    "src/config/account_bindings.rs",
    "src/identity_propagation/",
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
    """`#[cfg(test)]`, or a `cfg(all(...))` with `test` as an operand outside a `not(...)`."""
    if text.startswith("#[cfg(test)]"):
        return True
    if not text.startswith("#[cfg(all("):
        return False
    return re.search(r"\btest\b", re.sub(r"not\([^()]*\)", "", text)) is not None


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


def show(rev: str, path: str) -> str | None:
    """`path` as `rev` has it; None when it does not exist there."""
    done = subprocess.run(
        ["git", "show", f"{rev}:{path}"], cwd=ROOT, capture_output=True, text=True
    )
    return done.stdout if done.returncode == 0 else None


def rows(rev: str, path: str) -> set[tuple[str, str, int]]:
    """(file, fn, occurrence) of every row; both files carry the occurrence
    in their third column, as the grader reads it."""
    out = set()
    for line in (show(rev, path) or "").splitlines():
        cells = line.split("\t")
        # An unenforcing row counts only with its reason: that is what was reviewed.
        reasoned = path != UNENFORCING or (len(cells) > 3 and cells[3].strip())
        if len(cells) >= 3 and not line.startswith("#") and cells[2].isdigit() and reasoned:
            out.add((cells[0], cells[1], int(cells[2])))
    return out


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


def declared_for_tests(head: str, path: str, depth: int = 0) -> bool:
    """Whether every declaration of `path` at `head` compiles only under test.

    A module file is test-only when the line that declares it, by
    `#[path = "<file>"]` or `mod <stem>;`, sits under `#[cfg(test)]` or inside
    a test item, or in a file that is itself test-only. Found with `git grep`,
    so a sibling's `#[path]` counts.
    """
    name = Path(path).name
    stem = Path(path).stem
    pattern = rf'#\[path = "([^"]*/)?{re.escape(name)}"\]|^\s*(pub(\([^)]*\))? )?mod {re.escape(stem)};'
    done = subprocess.run(
        ["git", "grep", "-n", "-E", pattern, head, "--", "src"],
        cwd=ROOT, capture_output=True, text=True,
    )
    hits = [line.split(":", 3) for line in done.stdout.splitlines()]
    if not hits:
        return False
    for _rev, source, number, _text in hits:
        if TEST_FILE.search(source) or (depth < 4 and declared_for_tests(head, source, depth + 1)):
            continue  # declared from a file that only tests compile
        lines = (show(head, source) or "").splitlines()
        n = int(number)
        if not (under_cfg_test(lines, n) or n in test_lines(lines)):
            return False
    return True


def added_functions(base: str, head: str) -> list[tuple[str, str, int, int]]:
    merge_base = git("merge-base", base, head).strip()
    diff = git("diff", "-U0", "--no-renames", merge_base, head, "--", *PREFIXES)
    found: list[tuple[str, str, int, int]] = []
    path = None
    lines: list[str] = []
    tests: set[int] = set()
    new_line = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
            if path and (
                not path.endswith(".rs")
                or TEST_FILE.search(path)
                or declared_for_tests(head, path)
            ):
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
    known = rows(head, INVENTORY) | rows(head, UNENFORCING)
    return [f for f in added_functions(base, head) if (f[0], f[1], f[3]) not in known]


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    head = argv[2] if len(argv) == 3 else "HEAD"
    missing = missing_rows(argv[1], head)
    for path, name, line, nth in missing:
        print(f"no inventory row: {path}:{line} fn {name} (occurrence {nth})")
    if missing:
        print(
            f"{len(missing)} added function(s) on the COV.3 paths have no row. Add each to "
            f"{INVENTORY} (it enforces) or {UNENFORCING} (it does not, with a reason)."
        )
        return 1
    print("every added function on the COV.3 paths has a row")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
