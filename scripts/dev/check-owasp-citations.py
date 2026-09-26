#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Keep the OWASP self-assessment tied to the tree it describes (MIK-7570.OWASP.1).

The self-assessment cites source paths as evidence and lists the tests that pin
each control. A path that no longer exists, or a test name that matches no test,
is a claim nobody can check any more; this fails on either.

    python3 scripts/dev/check-owasp-citations.py [path/to/doc.md]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "OWASP_AGENTIC_AI_COMPLIANCE.md"

# A backticked repository path: `src/...`, `tests/...`, `docs/...`, `scripts/...`
# or `.github/...`, optionally ending in `/` (a directory).
CITED_PATH = re.compile(r"`((?:src|tests|docs|scripts|\.github)/[^`\s]*)`")
# `cargo test [flags] <name>` inside the validation-command block.
CARGO_TEST = re.compile(r"^\s*cargo test(?:\s+--?[\w-]+)*\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", re.M)


def test_names_defined(root: Path) -> set[str]:
    """Every `fn name` under src/ and tests/: a filter must match one of them."""
    names: set[str] = set()
    fn = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
    for sub in ("src", "tests"):
        for path in (root / sub).rglob("*.rs"):
            names.update(fn.findall(path.read_text(encoding="utf-8", errors="replace")))
    return names


def problems(doc: Path, root: Path) -> list[str]:
    text = doc.read_text(encoding="utf-8")
    found = []
    for cited in sorted(set(CITED_PATH.findall(text))):
        if not (root / cited.rstrip("/")).exists():
            found.append(f"cited path does not exist: {cited}")
    defined = test_names_defined(root)
    for name in sorted(set(CARGO_TEST.findall(text))):
        # `cargo test NAME` is a substring filter; it must match at least one fn.
        if not any(name in d for d in defined):
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
