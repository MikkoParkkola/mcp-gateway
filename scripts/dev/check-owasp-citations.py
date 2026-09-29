#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Keep the OWASP self-assessment tied to the tree it describes (MIK-7570.OWASP.1).

The self-assessment cites source paths as evidence and lists the tests that pin
each control. A path that no longer exists, or a test name that matches no test,
is a claim nobody can check any more; this fails on either.

Validation commands must have the shape `cargo test [--lib] <name>`; any other
`cargo test` line is reported rather than skipped.

    python3 scripts/dev/check-owasp-citations.py [path/to/doc.md]
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "OWASP_AGENTIC_AI_COMPLIANCE.md"

# A backticked repository path: `src/...`, `tests/...`, `docs/...`, `scripts/...`
# or `.github/...`, optionally ending in `/` (a directory).
CITED_PATH = re.compile(r"`((?:src|tests|docs|scripts|\.github)/[^`\s]*)`")
# `cargo test [flags] <name>`: the only command form the document may use, so a
# form this check cannot read fails rather than going unchecked.
CARGO_LINE = re.compile(r"^\s*cargo\s+test\b.*$", re.M)
# `--lib` is the only flag it reads; any other shape is reported, not skipped.
CARGO_TEST = re.compile(r"^\s*cargo\s+test(\s+--lib)?\s+([A-Za-z_][A-Za-z0-9_]*)\s*$")
# A test function: `#[test]` or `#[tokio::test(...)]`, then attributes, then `fn`.
TEST_FN = re.compile(r"#\[(?:tokio::)?test\b[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")


def _rust_lexer():
    """The orphan-module gate, for its comment- and string-aware `blank`."""
    spec = importlib.util.spec_from_file_location(
        "orphan_gate", Path(__file__).resolve().parent / "check-orphan-test-modules.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_names_defined(root: Path, subs: tuple[str, ...] = ("src", "tests")) -> set[str]:
    """Every test function under `subs`: a filter must match one of them.

    `--lib` runs the library target only, which is what src/ minus src/bin and
    src/main.rs compiles; callers pass ("src",) for it and skip the bin files.
    """
    names: set[str] = set()
    for sub in subs:
        for path in (root / sub).rglob("*.rs"):
            rel = path.relative_to(root).parts
            if subs == ("src",) and (rel[:2] == ("src", "bin") or rel == ("src", "main.rs")):
                continue
            # A commented-out test is not a test. The orphan gate's lexer
            # blanks nested block comments and string contents correctly.
            text, _ = _rust_lexer().blank(path.read_text(encoding="utf-8", errors="replace"))
            names.update(TEST_FN.findall(text))
    return names


def problems(doc: Path, root: Path) -> list[str]:
    text = doc.read_text(encoding="utf-8")
    found = []
    for cited in sorted(set(CITED_PATH.findall(text))):
        if not (root / cited.rstrip("/")).exists():
            found.append(f"cited path does not exist: {cited}")
    defined = test_names_defined(root)
    defined_lib = test_names_defined(root, ("src",))
    for line in CARGO_LINE.findall(text):
        match = CARGO_TEST.match(line)
        if match is None:
            found.append(f"validation command form not checkable: {line.strip()}")
            continue
        # `cargo test NAME` is a substring filter; it must match at least one test.
        # `--lib` narrows the target: a test that lives only under tests/ does
        # not satisfy it, and `cargo test --lib` would run 0 tests and pass.
        name = match.group(2)
        pool = defined_lib if match.group(1) else defined
        if not any(name in d for d in pool):
            found.append(f"validation command matches no test: cargo test {name}")
    return found


def main(argv: list[str]) -> int:
    doc = Path(argv[1]) if len(argv) > 1 else DOC
    found = problems(doc, ROOT)
    for line in found:
        print(f"{doc.relative_to(ROOT) if doc.is_relative_to(ROOT) else doc}: {line}")
    if found:
        return 1
    print(f"{doc.name}: every cited path and validation test exists.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
