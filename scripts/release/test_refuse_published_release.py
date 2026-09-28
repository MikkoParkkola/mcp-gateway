# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""refuse-published-release.sh continues only on a confirmed draft or absence.

`gh` is replaced by a stub on PATH that prints a canned release list, or
fails the way an API error would. A published release and a failed lookup
must both stop the release job; only "no release yet" and "draft only" pass.
"""

import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("refuse-published-release.sh")
TAG = "v4.0.0"

GH = """#!/usr/bin/env python3
import os, sys
if os.environ.get("STUB_GH_FAIL"):
    print("HTTP 502: Bad Gateway", file=sys.stderr)
    sys.exit(1)
sys.stdout.write(os.environ["STUB_GH_RELEASES"])
"""


@unittest.skipUnless(shutil.which("jq"), "jq is required")
class RefusePublishedRelease(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.bin = pathlib.Path(temp.name)
        gh = self.bin / "gh"
        gh.write_text(GH)
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)

    def run_script(self, releases=None, fail=False):
        env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "STUB_GH_RELEASES": json.dumps(releases or []),
        }
        if fail:
            env["STUB_GH_FAIL"] = "1"
        return subprocess.run(
            ["bash", str(SCRIPT), "owner/repo", TAG], env=env, capture_output=True, text=True
        )

    def test_no_release_yet_continues(self):
        done = self.run_script([{"tag_name": "v3.5.1", "draft": False}])
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_draft_continues(self):
        done = self.run_script([{"tag_name": TAG, "draft": True}])
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_published_release_stops_the_job(self):
        done = self.run_script([{"tag_name": TAG, "draft": False}])
        self.assertEqual(done.returncode, 1)
        self.assertIn("already published", done.stderr)

    def test_a_failed_lookup_stops_the_job(self):
        done = self.run_script(fail=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("HTTP 502", done.stderr)

    def test_a_tag_with_filter_syntax_is_data_not_code(self):
        done = subprocess.run(
            ["bash", str(SCRIPT), "owner/repo", '") or true or ("'],
            env={**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                 "STUB_GH_RELEASES": json.dumps([{"tag_name": TAG, "draft": False}])},
            capture_output=True, text=True,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("no release", done.stdout)


if __name__ == "__main__":
    unittest.main()
