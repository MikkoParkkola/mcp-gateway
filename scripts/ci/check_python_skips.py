#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every Python test skip is listed, with the reason it is by design.

A test that skips because a tool or a right is missing reads as a pass on a machine that lacks it: the
feature it checks can be broken while the log is green. So a skip in a tracked Python file must be
listed in scripts/ci/python-skips.tsv (`path<TAB>reason text<TAB>why`), and a row that no longer matches
a skip is refused too, so the list cannot go stale. The why says either "by design" (a platform or a
row that does not apply) or how a missing tool fails where TESTS_REQUIRE_ALL is set.

Usage: check_python_skips.py [--self-test]
"""
from __future__ import annotations

import ast
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIST = Path("scripts/ci/python-skips.tsv")
CALLS = {"skipTest": 0, "skip": 0, "skipIf": 1, "skipUnless": 1}  # name -> index of the reason argument
DYNAMIC = "<dynamic>"


def skips_in(source: str) -> list[str]:
    """The reason of every skip construct in one file's source (DYNAMIC when it is not a literal)."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in CALLS:
                index = CALLS[name]
                arg = node.args[index] if len(node.args) > index else None
                found.append(arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else DYNAMIC)
            elif name == "SkipTest":
                arg = node.args[0] if node.args else None
                found.append(arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else DYNAMIC)
    return found


def tracked_python(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "*.py"], cwd=root, capture_output=True, text=True, check=True)
    return sorted(out.stdout.split())


def listed(root: Path) -> set[tuple[str, str]]:
    rows = set()
    for line in (root / LIST).read_text().splitlines():
        if line and not line.startswith("#"):
            path, reason, _why = line.split("\t")
            rows.add((path, reason))
    return rows


def findings(root: Path) -> list[str]:
    allowed = listed(root)
    seen: set[tuple[str, str]] = set()
    out = []
    for rel in tracked_python(root):
        for reason in skips_in((root / rel).read_text()):
            seen.add((rel, reason))
            if (rel, reason) not in allowed:
                out.append(f"{rel}: a skip that is not listed: {reason!r}. A skip for a missing tool must fail where "
                           f"TESTS_REQUIRE_ALL is set; a by-design one is a row in {LIST} with its why")
    out += [f"{LIST}: no skip {reason!r} in {path} any more: remove the row" for path, reason in sorted(allowed - seen)]
    return out


def self_test() -> int:
    def tree(files: dict[str, str], rows: str) -> Path:
        d = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        for rel, text in files.items():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text(text)
        (d / LIST).parent.mkdir(parents=True, exist_ok=True)
        (d / LIST).write_text(rows)
        subprocess.run(["git", "add", "-A"], cwd=d, check=True)
        return d

    one = "import unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n        self.skipTest('no uv here')\n"
    cases = [
        ("an unlisted skip is refused", tree({"a.py": one}, ""), 1, "not listed"),
        ("a listed skip passes", tree({"a.py": one}, "a.py\tno uv here\tby design\n"), 0, ""),
        ("a stale row is refused", tree({"a.py": "x = 1\n"}, "a.py\tno uv here\tby design\n"), 1, "remove the row"),
        ("a decorator reason is read", tree({"a.py": "import unittest\n@unittest.skipUnless(1, 'needs jq')\nclass T: pass\n"}, ""), 1, "needs jq"),
        ("a non-literal reason is refused", tree({"a.py": "import unittest\nunittest.skipIf(0, f'x{1}')\n"}, ""), 1, DYNAMIC),
        ("a raised SkipTest is found", tree({"a.py": "import unittest\nraise unittest.SkipTest('gone')\n"}, ""), 1, "gone"),
    ]
    wrong = 0
    for label, root, want, text in cases:
        got = findings(root)
        ok = (len(got) > 0) == bool(want) and all(text in g for g in got[:1])
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}" + ("" if ok else f": {got}"))
    print(f"check_python_skips self-test: {wrong} wrong")
    return 1 if wrong else 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if argv:
        print(__doc__)
        return 2
    got = findings(ROOT)
    for line in got:
        print(line)
    print(f"{len(got)} unlisted or stale python skip(s)" if got else "every python skip is listed")
    return 1 if got else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
