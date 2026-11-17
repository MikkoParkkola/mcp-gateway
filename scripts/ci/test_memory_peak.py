#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/memory-peak.sh, the per-job memory tripwire: a whole lib test build peaks near 15 GB and a
part near 11 GB on the hosted runner, so a job's cgroup peak above the limit means a whole build came back."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().with_name("memory-peak.sh")
MIB = 1024 * 1024


def run(peak_bytes: int | None, limit_mib: int = 13312):
    with TemporaryDirectory() as tmp:
        t = Path(tmp)
        if peak_bytes is not None:
            (t / "memory.peak").write_text(f"{peak_bytes}\n")
        out = t / "trend.txt"
        done = subprocess.run(["bash", str(SCRIPT), str(limit_mib), str(out)], capture_output=True, text=True,
                              env={**os.environ, "MEM_PEAK_CGROUP": str(t)})
        return done, out.read_text() if out.exists() else ""


class Tripwire(unittest.TestCase):
    def test_a_part_sized_peak_passes_and_is_recorded(self):
        done, trend = run(int(12.9 * 1024) * MIB)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("13209", trend)

    def test_a_whole_build_sized_peak_fails(self):
        done, _ = run(int(13.1 * 1024) * MIB)
        self.assertNotEqual(done.returncode, 0)

    def test_the_limit_itself_passes(self):
        self.assertEqual(run(13312 * MIB)[0].returncode, 0)

    def test_a_missing_peak_file_fails_closed(self):
        done, _ = run(None)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("memory.peak", done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
