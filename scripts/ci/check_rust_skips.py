#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every Rust test skip goes through `crate::test_wait::skip_or_fail` (or `skip_unshipped`, for a file the package
leaves out on purpose) and returns right after it.

A test that prints "skipped" and returns reads as a pass on a host that lacks what it needs. Two rules over every tracked
`src/**/*.rs` and `tests/**/*.rs` file (comments are not code):
  1. no hand-written skip: a `println!`/`eprintln!` whose text contains "skip", followed by `return` or `None`;
  2. every `skip_or_fail(` and `skip_unshipped(` statement is followed, at the same indent, by `return` or `None` (the
     caller must return).
A bare early `return` with no message and no helper call cannot be told from an ordinary early return and is not found:
the accepted residual (the census of these is by hand and in review). Exempt files, each with its reason, are in EXEMPT.

Usage: check_rust_skips.py [--self-test]
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# The skip helpers rule 2 covers: a missing host requirement, and a file the package leaves out on purpose.
HELPERS = ("skip_or_fail", "skip_unshipped")
EXEMPT = {
    "src/test_wait.rs": "defines the helper and prints its skip line",
    "src/preview_sandbox/linux/fetch_uv_real_fixture.rs": (
        "its real-uv rows need uv 0.13.1 on PATH, which no test shard installs yet; through the helper they would "
        "fail every required shard, so they keep their printed skip until a shard installs that uv"
    ),
    "tests/preview_sandbox_linux.rs": "keeps its own required switch (PREVIEW_SANDBOX_REQUIRED)",
    "tests/common/preview_sandbox.rs": "the preview-sandbox suite's own required switch (PREVIEW_SANDBOX_REQUIRED)",
    "tests/preview_sandbox_linux_fetch.rs": "the preview-sandbox suite's own required switch (PREVIEW_SANDBOX_REQUIRED)",
    "src/preview_sandbox/linux/fetch_rows.rs": "the preview-sandbox suite's own required switch (PREVIEW_SANDBOX_REQUIRED)",
    "tests/heygen_connector_tests.rs": "#[ignore] plus a secret: a manual check by design",
}


def code_lines(text: str) -> list[tuple[int, str]]:
    """(line number, stripped text) of every non-blank line that is not a whole-line comment."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped and not stripped.startswith("//"):
            out.append((n, line))
    return out


def indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def statement_end(lines: list[tuple[int, str]], i: int) -> int:
    """Index of the line that ends the statement starting at lines[i] (the first line ending in ';')."""
    j = i
    while j < len(lines) - 1 and not lines[j][1].rstrip().endswith(";"):
        j += 1
    return j


def returns_after(lines: list[tuple[int, str]], i: int) -> bool:
    j = statement_end(lines, i)
    if j + 1 >= len(lines):
        return False
    nxt = lines[j + 1][1]
    word = nxt.strip().rstrip(";").strip()
    return indent(nxt) == indent(lines[i][1]) and (word == "return" or word.startswith("return ") or word == "None")


def findings_in(rel: str, text: str) -> list[str]:
    out = []
    lines = code_lines(text)
    for i, (n, line) in enumerate(lines):
        stripped = line.strip()
        is_print = stripped.startswith(("eprintln!(", "println!("))
        if is_print and "skip" in stripped.lower() and rel != "src/test_wait.rs" and returns_after(lines, i):
            out.append(f"{rel}:{n}: a hand-written skip (a print naming skip, then return): use crate::test_wait::skip_or_fail")
        helper = next((h for h in HELPERS if h + "(" in stripped), None)
        if helper and not stripped.startswith("pub") and f"fn {helper}" not in stripped:
            if not returns_after(lines, i):
                out.append(f"{rel}:{n}: {helper} must be followed, at the same indent, by return or None")
    return out


def tracked(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "src/*.rs", "tests/*.rs"], cwd=root, capture_output=True, text=True, check=True)
    return sorted(out.stdout.split())


def findings(root: Path) -> list[str]:
    out = []
    for rel in tracked(root):
        if rel in EXEMPT:
            continue
        out += findings_in(rel, (root / rel).read_text())
    return out


def self_test() -> int:
    hand = 'fn t() {\n    if x {\n        eprintln!("skipped: no uv");\n        return;\n    }\n}\n'
    helper = 'fn t() {\n    if x {\n        crate::test_wait::skip_or_fail("uv");\n        return;\n    }\n}\n'
    cases = [
        ("B1 a hand-written skip is found", hand, 1, "hand-written"),
        ("B1 the helper followed by return passes", helper, 0, ""),
        ("B1 a print naming skip not followed by return is not a skip", 'fn t() {\n    eprintln!("skipped {}", 1);\n    work();\n}\n', 0, ""),
        ("B1 the helper without a return is found", helper.replace("        return;\n", "        work();\n"), 1, "followed"),
        ("B1b a decoy return in a comment does not count", helper.replace("        return;\n", "        // return;\n        work();\n"), 1, "followed"),
        ("B1b a return in a nested if does not count", helper.replace("        return;\n", "        if y {\n            return;\n        }\n"), 1, "followed"),
        ("B1b a return at a deeper indent does not count", helper.replace("        return;\n", "            return;\n"), 1, "followed"),
        ("B1 an Option-returning helper site ends in None", helper.replace("        return;\n", "        None\n"), 0, ""),
        ("B1 a multi-line helper call is read to its semicolon", 'fn t() {\n    skip_or_fail(\n        &format!("{}", 1),\n    );\n    return;\n}\n', 0, ""),
        ("B2 the unshipped-file helper followed by return passes",
         helper.replace('skip_or_fail("uv")', 'skip_unshipped(true, "uv")'), 0, ""),
        ("B2 the unshipped-file helper without a return is found",
         helper.replace('skip_or_fail("uv")', 'skip_unshipped(true, "uv")').replace("        return;\n", "        work();\n"),
         1, "skip_unshipped must be followed"),
        ("an inline test module in an ordinary src file is scanned", "mod tests {\n" + hand + "}\n", 1, "hand-written"),
    ]
    # Every helper fixture also runs against skip_unshipped: the return-after rule is the same for both helpers
    # (multi-line calls, decoy returns in comments, nested or deeper returns, an Option site ending in None).
    cases += [
        (label + " (skip_unshipped)",
         text.replace('skip_or_fail("uv")', 'skip_unshipped(true, "uv")').replace("skip_or_fail(\n", "skip_unshipped(\n        true,\n"),
         want, needle)
        for label, text, want, needle in list(cases) if "skip_or_fail(" in text
    ]
    wrong = 0
    for label, text, want, needle in cases:
        got = findings_in("src/a.rs", text)
        ok = (len(got) > 0) == bool(want) and all(needle in g for g in got[:1])
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}" + ("" if ok else f": {got}"))
    d = Path(tempfile.mkdtemp())
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    (d / "src").mkdir()
    (d / "src/a.rs").write_text(hand)
    (d / "src/deep/er").mkdir(parents=True)
    (d / "src/deep/er/b.rs").write_text(hand)
    (d / "src/test_wait.rs").write_text('fn skip_or_fail(r: &str) {\n    eprintln!("skipped: {r}");\n}\n')
    subprocess.run(["git", "add", "-A"], cwd=d, check=True)
    ok = len(findings(d)) == 2 and any("src/deep/er/b.rs" in f for f in findings(d))
    wrong += not ok
    print(f"{'ok   ' if ok else 'WRONG'} a nested tracked file is scanned; the helper file itself and exempt files are not flagged: {findings(d)}")
    print(f"check_rust_skips self-test: {wrong} wrong")
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
    print(f"{len(got)} rust skip(s) outside the helper" if got else "every rust skip goes through the helper")
    return 1 if got else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
