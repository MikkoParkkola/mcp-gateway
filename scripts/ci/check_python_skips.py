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


def calls_required_mode(source: str) -> bool:
    """True when the file calls required_mode.required(...) or required_mode.skip_or_fail(...) (not only names it)."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("required", "skip_or_fail"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "required_mode":
                return True
    return False


def tracked_python(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "*.py"], cwd=root, capture_output=True, text=True, check=True)
    return sorted(out.stdout.split())


EXEMPT = {"scripts/ci/required_mode.py"}  # the sanctioned helper: its own skipTest is the thing every other test calls
KINDS = ("design", "tool")


def listed(root: Path) -> tuple[dict[tuple[str, str], str], list[str]]:
    """The allow-list as {(path, reason): kind}, and a finding for every malformed row."""
    rows: dict[tuple[str, str], str] = {}
    bad = []
    for line in (root / LIST).read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) != 4 or cols[2] not in KINDS:
            bad.append(f"{LIST}: a row needs `path<TAB>reason<TAB>kind<TAB>why` with kind design or tool (kind {cols[2:3]!r}): {line[:80]!r}")
            continue
        if cols[1] == DYNAMIC or (cols[0], cols[1]) in rows:
            bad.append(f"{LIST}: a listed reason must be a literal and unique per file: {line[:80]!r}")
            continue
        rows[(cols[0], cols[1])] = cols[2]
    return rows, bad


def findings(root: Path) -> list[str]:
    allowed, out = listed(root)
    seen: set[tuple[str, str]] = set()
    for rel in tracked_python(root):
        if rel in EXEMPT:
            continue
        text = (root / rel).read_text()
        for reason in skips_in(text):
            seen.add((rel, reason))
            kind = allowed.get((rel, reason))
            if kind is None:
                out.append(f"{rel}: a skip that is not listed: {reason!r}. A skip for a missing tool calls "
                           f"required_mode.skip_or_fail; a by-design one is a row in {LIST} with its why")
            elif kind == "tool" and not calls_required_mode(text):
                out.append(f"{rel}: the tool row {reason!r} needs the file to call required_mode.required or required_mode.skip_or_fail (it must fail where required)")
    out += [f"{LIST}: no skip {reason!r} in {path} any more: remove the row" for path, reason in sorted(set(allowed) - seen)]
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
    guarded = "import required_mode\nrequired_mode.required()\n" + one
    named_only = "import required_mode\n# required_mode is named here only\n" + one
    cases = [
        ("D1 an unlisted skip is refused", tree({"a.py": one}, ""), 1, "not listed"),
        ("D2 a listed design skip passes", tree({"a.py": one}, "a.py\tno uv here\tdesign\tby design\n"), 0, ""),
        ("D3 a stale row is refused", tree({"a.py": "x = 1\n"}, "a.py\tno uv here\tdesign\tby design\n"), 1, "remove the row"),
        ("D4 a decorator reason is read", tree({"a.py": "import unittest\n@unittest.skipUnless(1, 'needs jq')\nclass T: pass\n"}, ""), 1, "needs jq"),
        ("D4 a non-literal reason is refused", tree({"a.py": "import unittest\nunittest.skipIf(0, f'x{1}')\n"}, ""), 1, DYNAMIC),
        ("D4 a raised SkipTest is found", tree({"a.py": "import unittest\nraise unittest.SkipTest('gone')\n"}, ""), 1, "gone"),
        ("D6 a row with no kind is refused", tree({"a.py": one}, "a.py\tno uv here\tby design\n"), 1, "kind"),
        ("D6 a row with an unlisted kind is refused", tree({"a.py": one}, "a.py\tno uv here\tmaybe\twhy\n"), 1, "kind"),
        ("D7 a tool row whose file does not use required_mode is refused", tree({"a.py": one}, "a.py\tno uv here\ttool\tmissing uv\n"), 1, "required_mode"),
        ("D7 a file that only names required_mode (import, comment) does not satisfy a tool row", tree({"a.py": named_only}, "a.py\tno uv here\ttool\tmissing uv\n"), 1, "required_mode"),
        ("a duplicate row is refused", tree({"a.py": one}, "a.py\tno uv here\tdesign\tby design\na.py\tno uv here\tdesign\tagain\n"), 1, "unique"),
        ("D7 a tool row whose file uses required_mode passes", tree({"a.py": guarded}, "a.py\tno uv here\ttool\tmissing uv\n"), 0, ""),
        ("the sanctioned helper module is not itself flagged", tree({"scripts/ci/required_mode.py": "import unittest\nunittest.TestCase().skipTest(f'x{1}')\n"}, ""), 0, ""),
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
