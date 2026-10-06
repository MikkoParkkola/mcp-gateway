#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Keep the OWASP self-assessment tied to the tree it describes (MIK-7570.OWASP.1).

The self-assessment cites source paths as evidence and lists the tests that pin
each control. A path that no longer exists, or a test name that matches no test,
is a claim nobody can check any more; this fails on either. It also fails when
the headline or the summary table counts disagree with the matrix rows.

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
# A matrix row: `| ASI01 | <risk> | <STATUS> | ...`.
MATRIX_ROW = re.compile(r"^\|\s*(ASI\d{2})\s*\|[^|]*\|\s*(COVERED|PARTIAL|GAP)\s*\|", re.M)
# The headline: a bold run naming a status, e.g. `**3/10 COVERED, 7/10 PARTIAL**`.
HEADLINE = re.compile(r"\*\*([^*]*\b(?:COVERED|PARTIAL|GAP)\b[^*]*)\*\*")
# One status in the headline. `HEADLINE_STATUS` finds every status named, so a
# status whose count does not parse is reported rather than skipped.
HEADLINE_PART = re.compile(r"(\d+)\s*/\s*(\d+)\s+(COVERED|PARTIAL|GAP)\b")
HEADLINE_STATUS = re.compile(r"\b(COVERED|PARTIAL|GAP)\b")
# A summary row: `| COVERED | 3/10 | ASI01, ASI02, ASI08 |`.
SUMMARY_ROW = re.compile(r"^\|\s*(COVERED|PARTIAL|GAP)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|", re.M)
COUNT = re.compile(r"^(\d+)\s*/\s*(\d+)$")
RISK = re.compile(r"ASI\d{2}")


def count_problems(text: str) -> list[str]:
    """The headline and the summary table must say what the matrix rows say.

    The rows are the assessment; every count is derived from them, so a count
    edited on its own is reported against the rows rather than trusted. Counts
    are read whatever their spacing, and one that cannot be read is reported.
    """
    rows = MATRIX_ROW.findall(text)
    headlines = HEADLINE.findall(text)
    summaries = SUMMARY_ROW.findall(text)
    if not rows:
        return ["counts are claimed but no matrix rows were found"] if headlines or summaries else []
    if not headlines:
        return ["no header count found for the matrix rows"]
    by_status: dict[str, list[str]] = {}
    for risk, status in rows:
        by_status.setdefault(status, []).append(risk)

    def actual(status: str) -> str:
        return f"{len(by_status.get(status, []))}/{len(rows)}"

    found = []
    for headline in headlines:
        parts = HEADLINE_PART.findall(headline)
        if len(parts) != len(HEADLINE_STATUS.findall(headline)):
            found.append(f"header count not readable: {headline}")
            continue
        for num, den, status in parts:
            if f"{num}/{den}" != actual(status):
                found.append(f"header says {num}/{den} {status}; the matrix rows give {actual(status)}")
    for status, count, risks in summaries:
        match = COUNT.match(count)
        if match is None:
            found.append(f"summary {status} count not readable: {count}")
            continue
        claimed = f"{match.group(1)}/{match.group(2)}"
        want = by_status.get(status, [])
        if claimed != actual(status) or sorted(RISK.findall(risks)) != sorted(want):
            found.append(
                f"summary {status} says {claimed} {risks}; "
                f"the matrix rows give {actual(status)} {', '.join(want) or '-'}"
            )
    return found


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
            found.append(f"validation command matches no test: cargo test {'--lib ' if match.group(1) else ''}{name}")
    found.extend(count_problems(text))
    return found


def main(argv: list[str]) -> int:
    doc = Path(argv[1]) if len(argv) > 1 else DOC
    found = problems(doc, ROOT)
    for line in found:
        print(f"{doc.relative_to(ROOT) if doc.is_relative_to(ROOT) else doc}: {line}")
    if found:
        return 1
    print(f"{doc.name}: every cited path and validation test exists, and the counts match the rows.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
