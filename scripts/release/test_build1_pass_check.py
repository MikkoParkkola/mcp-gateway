#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for build1_pass_check.jq (MIK-8602).

Runs every fixture in fixtures/build1_pass_check/ through
`jq -s -e -f` and asserts the exit status matches the table.
Standard library only.
"""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILTER = HERE / "build1_pass_check.jq"
FIXTURES = HERE / "fixtures" / "build1_pass_check"

CASES = [
    ("good-string-content.jsonl", True),
    ("good-array-content.jsonl", True),
    ("good-no-is-error.jsonl", True),
    ("is-error-true.jsonl", False),
    ("no-tool-use.jsonl", False),
    ("unmatched-result.jsonl", False),
    ("empty-content.jsonl", False),
    ("empty-array-content.jsonl", False),
    ("missing-result-line.jsonl", False),
    ("result-is-error.jsonl", False),
    ("result-no-is-error.jsonl", False),
    ("empty.jsonl", False),
]


class Build1PassCheckTests(unittest.TestCase):
    def test_cases_table_is_not_empty(self) -> None:
        self.assertGreater(len(CASES), 0)

    def test_every_fixture_is_in_the_table(self) -> None:
        on_disk = sorted(p.name for p in FIXTURES.glob("*.jsonl"))
        in_table = sorted(name for name, _ in CASES)
        self.assertEqual(on_disk, in_table)

    def test_fixtures_exit_status(self) -> None:
        jq = shutil.which("jq")
        if jq is None:
            self.fail("jq is not on PATH; install jq to run this test")
        for name, expected_pass in CASES:
            with self.subTest(fixture=name):
                done = subprocess.run(
                    [jq, "-s", "-e", "-f", str(FILTER), str(FIXTURES / name)],
                    capture_output=True,
                    text=True,
                )
                if expected_pass:
                    self.assertEqual(done.returncode, 0, msg=done.stderr)
                else:
                    self.assertNotEqual(done.returncode, 0, msg=done.stdout)


if __name__ == "__main__":
    unittest.main()
