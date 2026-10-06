# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The published NFR.BUILD.1 C6 sample must still be what its nonce draws from
the frozen sampling frame. The frame is not the live inventory: an inventory
edit (a new Critical row, a promoted stage) cannot move the sample, and an edit
to the frame itself fails here, so the sample is re-published deliberately
rather than redrawn silently."""

import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
RANKING = ROOT / "docs/release/v4.0.0-c6-mutation-ranking.tsv"
FRAME = ROOT / "docs/release/v4.0.0-c6-sampling-frame.tsv"
# The frame as frozen. A change to it is an edit to a published gate obligation.
NONCE = "8edb1c00edf8571ffabc3e492341e347"  # the first and only draw
FRAME_SHA256 = "76d59ee30271da57a8f8324e8519b23c63e90301249b82b2dd8b58a89df661ae"


class C6Sample(unittest.TestCase):
    def test_published_ranking_reproduces(self):
        text = RANKING.read_text(encoding="utf-8")
        nonce = re.search(r"c6_mutation_sample\.py ([0-9a-f]{32})", text).group(1)
        published = [l for l in text.splitlines() if l and not l.startswith(("#", "rank\t"))]
        drawn = subprocess.run(
            [sys.executable, str(ROOT / "scripts/release/c6_mutation_sample.py"), nonce],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        self.assertEqual(published, drawn)

    def test_the_frame_is_frozen(self):
        self.assertEqual(hashlib.sha256(FRAME.read_bytes()).hexdigest(), FRAME_SHA256)
        # The nonce is pinned beside the frame: regenerating the ranking under a
        # new nonce cannot replace the first draw while the frame pin still holds.
        header = RANKING.read_text(encoding="utf-8")
        self.assertEqual(re.search(r"c6_mutation_sample\.py ([0-9a-f]{32})", header).group(1), NONCE)

    def test_the_draw_ignores_the_live_inventory(self):
        nonce = re.search(r"c6_mutation_sample\.py ([0-9a-f]{32})",
                          RANKING.read_text(encoding="utf-8")).group(1)
        inventory = ROOT / "docs/release/v4.0.0-critical-functions.tsv"
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scratch = pathlib.Path(tmp.name) / "inventory.tsv"
        # An inventory with one more Critical row than the frame has.
        extra = "src/gateway/router/handlers.rs\tzz_added_later\t1\tcritical\td\tzz_added_later\tadded after the draw\n"
        scratch.write_text(inventory.read_text(encoding="utf-8") + extra, encoding="utf-8")
        run = lambda *args: subprocess.run(
            [sys.executable, str(ROOT / "scripts/release/c6_mutation_sample.py"), nonce, *args],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        self.assertEqual(run(), run(str(FRAME)))
        self.assertNotEqual(run(str(scratch)), run(str(FRAME)))

    def test_a_moved_stdio_function_stays_in_stdio_dispatch(self):
        live = subprocess.run(
            [sys.executable, str(ROOT / "scripts/release/c6_mutation_sample.py"), NONCE,
             str(ROOT / "docs/release/v4.0.0-critical-functions.tsv")],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
        groups = {l.split("\t")[2] for l in live
                  if l.split("\t")[3] == "src/transport/stdio_env.rs"}
        self.assertEqual(groups, {"stdio dispatch"})

    def test_sample_quotas(self):
        rows = [l.split("\t") for l in RANKING.read_text(encoding="utf-8").splitlines()
                if l and not l.startswith(("#", "rank\t"))]
        counts = {}
        for r in rows:
            if r[1] == "SAMPLE":
                counts[r[2]] = counts.get(r[2], 0) + 1
        self.assertEqual(counts, {"account paths": 16, "HTTP dispatch": 16, "startup": 8,
                                  "OAuth": 8, "stdio dispatch": 8, "tasks": 8, "bridge": 4})

    def test_a_path_without_a_quota_refuses_to_draw(self):
        # MIK-7852: every named path has an explicit quota; a missing one must
        # not fall through to a default that a redrawn frame could exceed.
        source = (ROOT / "scripts/release/c6_mutation_sample.py").read_text(encoding="utf-8")
        self.assertIn('"bridge": 4,', source)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        script = pathlib.Path(tmp.name) / "c6_mutation_sample.py"
        script.write_text(source.replace('"bridge": 4,', ""), encoding="utf-8")
        run = subprocess.run([sys.executable, str(script), NONCE, str(FRAME)],
                             cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("bridge", run.stderr)


if __name__ == "__main__":
    unittest.main()
