#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""C4 and W1-W4: coverage part wiring, checked against the live checkout."""
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
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import coverage_shards  # noqa: E402
import lib_union  # noqa: E402


# Exact (file, line text) pairs, with multiplicity: the two plan 3 definitions
# occur once each. Identical definitions in another plan must still fail W1.
# Escaped hyphens keep this allowlist's source from matching its own search.
# Scope is the coverage pipeline: its workflow, its shell entry points and every file with "coverage" in its name
# under scripts/ci, scripts/release and docs/release. The plain test shards keep their own lib-a/lib-b names, which
# are not coverage parts, and a whole-word match keeps names such as linux-lib-build out.
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
        paths = [ROOT / relative for relative in (".github/workflows/coverage-probe.yml",
                                                  "scripts/ci/lib-parts.sh", "scripts/ci/compile-cgroup.sh")]
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

    def test_W1_checks_coverage_entry_points_without_coverage_in_name(self) -> None:
        # Inject a stale name into reads, leaving the live scripts (and concurrent edits) untouched.
        read_text = Path.read_text
        for relative in ("scripts/ci/lib-parts.sh", "scripts/ci/compile-cgroup.sh"):
            with self.subTest(path=relative):
                def with_stale_name(path, *args, **kwargs):
                    source = read_text(path, *args, **kwargs)
                    return source + "\n# lib\x2da\n" if path == ROOT / relative else source

                with patch.object(Path, "read_text", with_stale_name):
                    with self.assertRaisesRegex(AssertionError, re.escape(relative)):
                        self.test_W1_only_explicit_stale_name_allowlist()

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

    def test_W3_scripts_run_by_path_are_executable(self) -> None:
        # The coverage part step runs these by path, not through `bash`: the workflow runs the first three, and
        # lib-parts.sh runs the gate. A tracked mode of 100644 fails on the runner with "Permission denied" (found by
        # the hosted-runner probe; the unit rows run the gate through bash, so they cannot see it).
        listed = subprocess.run(["git", "ls-files", "-s", "--", *RUN_BY_PATH], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout.splitlines()
        modes = {line.split("\t", 1)[1]: line.split()[0] for line in listed}
        self.assertEqual(sorted(modes), sorted(RUN_BY_PATH), "a script run by path is not tracked")
        self.assertEqual({path: mode for path, mode in modes.items() if mode != "100755"}, {},
                         "scripts run by path must be tracked executable (100755)")

    def test_W4_one_coverage_part_per_job(self) -> None:
        # lib-parts.sh's cov cleanup removes every deps/p<digits> folder on each run. Running a second part in
        # the same job and target directory would delete the first part's executable before the coverage merge.
        doc = yaml.safe_load((ROOT / ".github/workflows/coverage-probe.yml").read_text(encoding="utf-8"))
        invocation = re.compile(r"scripts/ci/lib-parts\.sh\s+cov\b")
        steps = [(name, step) for name, job in doc["jobs"].items() for step in job.get("steps", [])
                 if invocation.search(step.get("run", ""))]
        self.assertEqual([name for name, _ in steps], ["linux-part"],
                         "exactly one step across all jobs may run lib-parts.sh cov, in linux-part")
        step = steps[0][1]
        matrix = doc["jobs"]["linux-part"].get("strategy", {}).get("matrix", {})
        self.assertIsInstance(matrix, dict, "linux-part must declare a part matrix")
        self.assertIn("part", matrix, "linux-part must declare a part matrix")
        self.assertEqual(step.get("env", {}).get("PART"), "${{ matrix.part }}",
                         "the coverage step must take PART directly from matrix.part")
        self.assertEqual(set(re.findall(r"\bmatrix\.([\w-]+)", yaml.safe_dump(step))), {"part"},
                         "part must be the only matrix key used by the coverage step")
        run = step["run"].replace("\\\n", " ")
        self.assertEqual(len(invocation.findall(run)), 1, "the step must invoke cov exactly once")
        self.assertNotRegex(run, r"\b(?:for|while|until)\b", "coverage parts must not run in a loop")
        command = re.search(r'scripts/ci/lib-parts\.sh\s+cov[^\n]*', run).group()
        self.assertNotIn(",", command, "cov must receive one part, never a comma-separated list")
        self.assertRegex(command, r'^scripts/ci/lib-parts\.sh\s+cov\s+\S+\s+"\$PART"\s*(?:[<>]|$)',
                         'cov must receive "$PART" as its single part argument')

    def test_W4_rejects_workflow_mutations(self) -> None:
        workflow = ROOT / ".github/workflows/coverage-probe.yml"
        read_text = Path.read_text
        source = workflow.read_text(encoding="utf-8")
        for case in ("second step", "another job", "fixed PART"):
            with self.subTest(case=case):
                doc = yaml.safe_load(source)
                steps = doc["jobs"]["linux-part"]["steps"]
                step = next(step for step in steps if "scripts/ci/lib-parts.sh cov" in step.get("run", ""))
                if case == "second step":
                    steps.append(dict(step))
                elif case == "another job":
                    doc["jobs"]["extra-part"] = {"runs-on": "ubuntu-24.04", "steps": [dict(step)]}
                else:
                    step["env"]["PART"] = "lib-1"
                mutated = yaml.safe_dump(doc)

                def with_mutation(path, *args, **kwargs):
                    return mutated if path == workflow else read_text(path, *args, **kwargs)

                with patch.object(Path, "read_text", with_mutation):
                    with self.assertRaises(AssertionError):
                        self.test_W4_one_coverage_part_per_job()


RUN_BY_PATH = ("scripts/ci/with-memory-log.sh", "scripts/ci/lib-parts.sh", "scripts/ci/memory-tripwire.sh",
               "scripts/ci/compile-cgroup.sh")


if __name__ == "__main__":
    unittest.main()
