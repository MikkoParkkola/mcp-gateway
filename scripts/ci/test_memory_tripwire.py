#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/memory-tripwire.sh, the per-job memory tripwire. On the hosted Linux runner every lib test part
writes nothing to swap and a whole lib test build about 7 GiB (E1, 2026-11-17), so a job's swap-out above the limit
means a whole build came back. The cgroup's memory.peak is printed for the trend and gates nothing."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().with_name("memory-tripwire.sh")
MIB = 1024 * 1024
PAGE = os.sysconf("SC_PAGESIZE")
LIMIT = 2048


def pages_for(mib: int) -> int:
    return mib * MIB // PAGE


def run(pswpout: int | None, peak_bytes: int | None = 13_000 * MIB, vmstat_line: str | None = None):
    with TemporaryDirectory() as tmp:
        t = Path(tmp)
        if vmstat_line is not None:
            (t / "vmstat").write_text(vmstat_line)
        elif pswpout is not None:
            (t / "vmstat").write_text(f"nr_free_pages 12345\npswpin 7\npswpout {pswpout}\npgfault 99\n")
        if peak_bytes is not None:
            (t / "memory.peak").write_text(f"{peak_bytes}\n")
        out = t / "trend.txt"
        done = subprocess.run(["bash", str(SCRIPT), str(LIMIT), str(out)], capture_output=True, text=True,
                              env={**os.environ, "MEM_VMSTAT": str(t / "vmstat"), "MEM_PEAK_CGROUP": str(t)})
        return done, out.read_text() if out.exists() else ""


class Tripwire(unittest.TestCase):
    def test_a_part_that_swaps_nothing_passes_whatever_its_peak(self):
        # A part's cgroup peak reached 13.5 GB with page cache, over the old 13 GB line; it gates nothing now.
        done, trend = run(0, peak_bytes=13_507 * MIB)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("swap_out_mib=0", trend)
        self.assertIn("memory_peak_mib=13507", trend)

    def test_the_limit_itself_passes_and_one_mib_over_fails(self):
        self.assertEqual(run(pages_for(LIMIT))[0].returncode, 0)
        done, _ = run(pages_for(LIMIT + 1))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("above", done.stdout + done.stderr)

    def test_a_whole_build_sized_swap_out_fails(self):
        done, trend = run(pages_for(7_048))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("swap_out_mib=7048", trend)

    def test_an_unreadable_swap_count_fails_closed(self):
        for label, kwargs in (("no vmstat file", {"pswpout": None}),
                              ("no pswpout line", {"pswpout": None, "vmstat_line": "pswpin 7\n"}),
                              ("a count that is not a number", {"pswpout": None, "vmstat_line": "pswpout x\n"})):
            with self.subTest(label):
                done, _ = run(**kwargs)
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("pswpout", done.stdout + done.stderr)

    def test_a_missing_memory_peak_is_reported_and_gates_nothing(self):
        done, trend = run(0, peak_bytes=None)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("memory_peak_mib=unknown", trend)


if __name__ == "__main__":
    unittest.main()
