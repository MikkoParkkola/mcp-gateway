#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""C4, W1 and W2: coverage part wiring, checked against the live checkout."""
from __future__ import annotations

import ast
from collections import Counter
import contextlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import coverage_shards  # noqa: E402
import lib_union  # noqa: E402


# Exact (file, line text) pairs, with multiplicity: the two plan 3 definitions
# occur once each. Identical definitions in another plan must still fail W1.
# Escaped hyphens keep this allowlist's source from matching its own search.
# Scope is the coverage pipeline only (its workflow and every file with "coverage" in its name under scripts/ci,
# scripts/release and docs/release): the plain test shards keep their own lib-a/lib-b names, which are not coverage
# parts, and a whole-word match keeps names such as linux-lib-build out.
STALE_NAME_ALLOWLIST = Counter([
    ("scripts/ci/coverage_shards.py", '        "lib\x2da": _LIB_A,'),
    ("scripts/ci/coverage_shards.py", '        "lib\x2db": _LIB_B,'),
])
OLD_PART = re.compile(r"(?<![\w-])lib\x2d[ab](?![\w-])")


def condition_matches(condition: str, part: str) -> bool:
    """Evaluate only the small matrix condition language used by add-swap."""
    expression = condition.strip()
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression[3:-2].strip()
    if "||" in expression:
        return any(condition_matches(term, part) for term in expression.split("||"))
    if "&&" in expression:
        return all(condition_matches(term, part) for term in expression.split("&&"))
    match = re.fullmatch(r"startsWith\(\s*matrix\.part\s*,\s*(['\"])(.*?)\1\s*\)", expression)
    if match:
        return part.lower().startswith(match[2].lower())
    match = re.fullmatch(r"matrix\.part\s*(==|!=)\s*(['\"])(.*?)\2", expression)
    if match:
        equal = part.lower() == match[3].lower()
        return equal if match[1] == "==" else not equal
    raise AssertionError(f"unsupported add-swap condition: {condition!r}")


class CoveragePartsWiring(unittest.TestCase):
    def test_C4_live_census_and_restored_allowance(self) -> None:
        script = ROOT / "scripts/ci/check_swap_jobs.py"
        source = script.read_text(encoding="utf-8")
        assignments = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "WHOLE_BUILD_ALLOWED"
                               for target in node.targets)]
        self.assertEqual(len(assignments), 1, "expected one census allowance table")
        assignment = assignments[0]
        allowed = ast.literal_eval(assignment.value)
        coverage = ("coverage-probe.yml", "linux-part")

        live = subprocess.run([sys.executable, str(script)], cwd=ROOT, capture_output=True, text=True)
        with self.subTest(case="live tree, coverage allowance deleted"):
            self.assertEqual(live.returncode, 0, live.stdout + live.stderr)
            self.assertNotIn(coverage, allowed, "live census still allows the whole coverage lib build")

        # Replace only this table in a temporary script, preserving the rest of
        # the checker and reading workflows from the real checkout in both runs.
        allowed[coverage] = "restored coverage whole-build allowance for C4"
        lines = source.splitlines(keepends=True)
        restored = ("".join(lines[:assignment.lineno - 1]) + f"WHOLE_BUILD_ALLOWED = {allowed!r}\n"
                    + "".join(lines[assignment.end_lineno:]))
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "check_swap_jobs.py"
            copy.write_text(restored, encoding="utf-8")
            result = subprocess.run([sys.executable, str(copy)], cwd=ROOT, capture_output=True, text=True)
        with self.subTest(case="coverage allowance restored"):
            message = "coverage-probe.yml:linux-part is allowed a whole build but no longer has one; delete its row"
            self.assertTrue(result.returncode != 0 and message in result.stdout,
                            f"restored allowance: exit {result.returncode}; expected {message!r}; "
                            f"output: {result.stdout}{result.stderr}")

    def test_W1_only_explicit_stale_name_allowlist(self) -> None:
        paths = [ROOT / ".github/workflows/coverage-probe.yml"]
        for directory in ("scripts/ci", "scripts/release", "docs/release"):
            paths.extend(path for path in (ROOT / directory).rglob("*")
                         if path.is_file() and "__pycache__" not in path.parts and "coverage" in path.name
                         and path.resolve() != Path(__file__).resolve())
        occurrences = Counter()
        locations = {}
        for path in sorted(paths):
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue  # Compiled fixtures have no source lines to allowlist.
            for number, line in enumerate(lines, 1):
                if OLD_PART.search(line):
                    pair = (path.relative_to(ROOT).as_posix(), line)
                    occurrences[pair] += 1
                    locations.setdefault(pair, []).append(number)
        unexpected = occurrences - STALE_NAME_ALLOWLIST
        details = [f"{file}:{','.join(map(str, locations[(file, line)]))}: {line} "
                   f"({count} occurrence(s) beyond allowlist)"
                   for (file, line), count in sorted(unexpected.items())]
        self.assertEqual(sum(unexpected.values()), 0, "unallowlisted old part names:\n" + "\n".join(details))

    def test_W2_swap_matches_numbered_lib_parts_only(self) -> None:
        doc = yaml.safe_load((ROOT / ".github/workflows/coverage-probe.yml").read_text(encoding="utf-8"))
        job = doc["jobs"]["linux-part"]
        steps = [step for step in job["steps"] if step.get("uses") == "./.github/actions/add-swap"]
        self.assertEqual(len(steps), 1, "linux-part must have exactly one add-swap step")
        condition = str(steps[0].get("if", ""))
        with contextlib.chdir(ROOT):
            parts = set(coverage_shards.plan(4))
        matches = {part for part in parts if condition_matches(condition, part)}
        count = lib_union.part_count(ROOT / "scripts/dev/test-parts-build.rs")
        expected_lib = {f"lib-{k}" for k in range(1, count + 1)}
        self.assertEqual(parts, expected_lib | {"int-a", "int-b"},
                         "plan 4 must expose every numbered lib part before swap coverage can be proved")
        self.assertEqual(matches, expected_lib, f"add-swap {condition!r} matches {sorted(matches)}")


if __name__ == "__main__":
    unittest.main()
