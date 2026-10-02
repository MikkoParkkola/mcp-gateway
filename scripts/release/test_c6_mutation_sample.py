# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The published NFR.BUILD.1 C6 sample must still be what its nonce draws from
the inventory. An inventory edit that changes a Critical row fails here, so the
sample is re-published deliberately rather than redrawn silently."""

import pathlib
import re
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
RANKING = ROOT / "docs/release/v4.0.0-c6-mutation-ranking.tsv"


class C6Sample(unittest.TestCase):
    def test_published_ranking_reproduces(self):
        text = RANKING.read_text()
        nonce = re.search(r"c6_mutation_sample\.py ([0-9a-f]{32})", text).group(1)
        published = [l for l in text.splitlines() if l and not l.startswith(("#", "rank\t"))]
        drawn = subprocess.run(
            [sys.executable, str(ROOT / "scripts/release/c6_mutation_sample.py"), nonce],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        self.assertEqual(published, drawn)

    def test_sample_quotas(self):
        rows = [l.split("\t") for l in RANKING.read_text().splitlines()
                if l and not l.startswith(("#", "rank\t"))]
        sample = [r for r in rows if r[1] == "SAMPLE"]
        self.assertEqual(len(sample), 68)


if __name__ == "__main__":
    unittest.main()
