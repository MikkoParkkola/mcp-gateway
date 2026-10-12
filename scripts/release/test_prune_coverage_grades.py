#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for prune_coverage_grades.py (MIK-8217)."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("prune", HERE / "prune_coverage_grades.py")
prune = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prune)


class PruneCoverageGrades(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_dir(self, name: str, age: int) -> Path:
        d = self.root / name
        (d / "art").mkdir(parents=True)
        (d / "art" / "linux.lcov").write_text("x")
        os.utime(d, (1_000_000 - age, 1_000_000 - age))
        return d

    def left(self) -> set[str]:
        return {d.name for d in self.root.iterdir()}

    def test_runs_beyond_keep_are_removed_and_the_pinned_baseline_kept(self) -> None:
        for age, name in enumerate(["50", "40", "30", "20", "10"]):
            self.run_dir(name, age)
        self.assertEqual(prune.main([str(self.root), "3", "10"]), 0)
        # The three newest stay, the oldest beyond them is removed, and the
        # pinned baseline survives though it is the oldest of all.
        self.assertEqual(self.left(), {"50", "40", "30", "10"})

    def test_only_run_directories_are_touched(self) -> None:
        for age, name in enumerate(["3", "2", "1"]):
            self.run_dir(name, age)
        (self.root / "notes").mkdir()
        (self.root / "README").write_text("keep")
        prune.main([str(self.root), "1"])
        self.assertEqual(self.left(), {"3", "notes", "README"})

    def test_a_missing_directory_is_not_an_error_and_a_bad_keep_is(self) -> None:
        self.assertEqual(prune.main([str(self.root / "absent"), "3"]), 0)
        self.assertEqual(prune.main([str(self.root), "three"]), 2)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
