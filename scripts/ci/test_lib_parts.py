#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/lib-parts.sh export (H1, H3): a fake `cargo` first on PATH records each call's part variable
and answers with a fake lib test executable, so no real build runs."""

from __future__ import annotations

import os
import stat
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "ci" / "lib-parts.sh"

FAKE_CARGO = """#!/bin/sh
# Records the part variable, writes a fake lib test executable and reports it as cargo's JSON artifact does.
echo "part=${MCP_GATEWAY_TEST_PART:-unset} args=$*" >> "$FAKE_LOG"
exe="$FAKE_DIR/lib-test-exe-${MCP_GATEWAY_TEST_PART:-unset}"
printf '#!/bin/sh\\n[ "$FAKE_EMPTY" = 1 ] || echo "p%s::t: test"\\necho\\n' "${MCP_GATEWAY_TEST_PART:-unset}" > "$exe"
chmod +x "$exe"
printf '{"reason":"compiler-artifact","target":{"kind":["lib"]},"profile":{"test":true},"executable":"%s"}\\n' "$exe"
"""


class Export(unittest.TestCase):
    def run_export(self, parts: str, empty: bool = False):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        t = Path(tmp.name)
        (t / "bin").mkdir()
        cargo = t / "bin" / "cargo"
        cargo.write_text(FAKE_CARGO)
        cargo.chmod(cargo.stat().st_mode | stat.S_IEXEC)
        env = {**os.environ, "PATH": f"{t / 'bin'}:{os.environ['PATH']}", "FAKE_LOG": str(t / "log"),
               "FAKE_DIR": str(t), "FAKE_EMPTY": "1" if empty else "0"}
        env.pop("MCP_GATEWAY_TEST_PART", None)
        done = subprocess.run(["bash", str(HELPER), "export", parts, str(t / "out")], cwd=ROOT, env=env,
                              capture_output=True, text=True)
        log = (t / "log").read_text() if (t / "log").exists() else ""
        return done, t / "out", log

    def test_one_part_builds_with_its_variable_and_lands_in_its_folder(self):
        done, out, log = self.run_export("2")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("part=2 ", log)
        self.assertNotIn("part=unset", log)
        self.assertTrue((out / "p2" / "lib-tests-p2").is_file())
        self.assertEqual((out / "p2" / "list.txt").read_text().splitlines()[0], "p2::t: test")

    def test_a_grouped_leg_keeps_each_part_apart(self):
        done, out, log = self.run_export("1,3")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("part=1 ", log)
        self.assertIn("part=3 ", log)
        self.assertIn("p1::t: test", (out / "p1" / "list.txt").read_text())
        self.assertIn("p3::t: test", (out / "p3" / "list.txt").read_text())

    def test_a_part_outside_one_to_n_is_refused(self):
        for parts in ("0", "6", "x", "1,9"):
            with self.subTest(parts=parts):
                done, _out, log = self.run_export(parts)
                self.assertNotEqual(done.returncode, 0)
                self.assertEqual(log, "", "nothing may build before the parts are checked")

    def test_a_part_that_lists_no_test_fails(self):
        done, _out, _log = self.run_export("4", empty=True)
        self.assertNotEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main()
