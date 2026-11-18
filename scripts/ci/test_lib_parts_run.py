#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/lib-parts.sh run (J2 R1-R7c): a fake `cargo` first on PATH records each call's exact argv, its
working directory and MCP_GATEWAY_TEST_PART, and fails the phases named in FAKE_FAIL, so no real build runs."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "ci" / "lib-parts.sh"

# The phase is read from the selector: a part call has --lib, the doc call --doc, the rest call --bins.
FAKE_CARGO = """#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
part = os.environ.get("MCP_GATEWAY_TEST_PART", "unset")
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "part": part}) + "\\n")
phase = "part:" + part if "--lib" in argv else "doc" if "--doc" in argv else "rest" if "--bins" in argv else "other"
sys.exit(1 if phase in os.environ.get("FAKE_FAIL", "").split(",") else 0)
"""


def crate(root: Path, n: int | None) -> Path:
    """A crate directory whose build script declares `n` parts (none when n is None)."""
    (root / "scripts" / "dev").mkdir(parents=True)
    body = "fn main() {}\n" if n is None else f"const N: u32 = {n};\nfn main() {{}}\n"
    (root / "scripts" / "dev" / "test-parts-build.rs").write_text(body)
    return root


def expected(n: int, flags: list[str], args: list[str]) -> list[dict]:
    """The exact call sequence of a run: parts 1..n, then the other targets, then the doctests."""
    parts = [{"argv": ["test", *flags, "--no-fail-fast", "--lib", "--", *args], "part": str(k)} for k in range(1, n + 1)]
    rest = {"argv": ["test", *flags, "--no-fail-fast", "--bins", "--test", "*", "--examples", "--", *args],
            "part": "unset"}
    doc = {"argv": ["test", *flags, "--no-fail-fast", "--doc", "--", *args], "part": "unset"}
    return [*parts, rest, doc]


class Run(unittest.TestCase):
    def run_helper(self, n: int | None, cli: list[str], fail: str = "", inherited: str | None = None):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        t = Path(tmp.name)
        (t / "bin").mkdir()
        cargo = t / "bin" / "cargo"
        cargo.write_text(FAKE_CARGO)
        cargo.chmod(cargo.stat().st_mode | stat.S_IEXEC)
        work = crate(t / "crate", n)
        env = {**os.environ, "PATH": f"{t / 'bin'}:{os.environ['PATH']}", "FAKE_LOG": str(t / "log"), "FAKE_FAIL": fail}
        env.pop("MCP_GATEWAY_TEST_PART", None)
        if inherited is not None:
            env["MCP_GATEWAY_TEST_PART"] = inherited
        done = subprocess.run(["bash", str(HELPER), "run", *cli], cwd=work, env=env, capture_output=True, text=True)
        calls = [json.loads(line) for line in (t / "log").read_text().splitlines()] if (t / "log").exists() else []
        return done, calls, work

    def assert_sequence(self, calls: list[dict], want: list[dict], work: Path):
        self.assertEqual([{"argv": c["argv"], "part": c["part"]} for c in calls], want)
        self.assertEqual({c["cwd"] for c in calls}, {str(work.resolve())}, "every call runs in the crate it tests")

    def test_r1_all_phases_pass_in_order_with_exact_argv(self):
        done, calls, work = self.run_helper(3, ["--all-features", "--", "--skip", "x"])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assert_sequence(calls, expected(3, ["--all-features"], ["--skip", "x"]), work)

    def test_r2_flags_and_test_args_reach_every_call_unchanged(self):
        args = ["--skip", "a b", "--exact"]
        done, calls, work = self.run_helper(2, ["--all-features", "--locked", "--", *args])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assert_sequence(calls, expected(2, ["--all-features", "--locked"], args), work)

    def test_r2b_a_bare_run_adds_nothing(self):
        done, calls, work = self.run_helper(2, ["--"])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assert_sequence(calls, expected(2, [], []), work)

    def test_r3_a_failed_part_runs_every_later_phase_and_fails_the_run(self):
        done, calls, work = self.run_helper(4, ["--"], fail="part:2")
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assert_sequence(calls, expected(4, [], []), work)

    def test_r4_a_failed_rest_phase_still_runs_the_doctests_and_fails_the_run(self):
        done, calls, work = self.run_helper(2, ["--"], fail="rest")
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assert_sequence(calls, expected(2, [], []), work)

    def test_r4b_a_failed_doc_phase_fails_the_run(self):
        done, calls, work = self.run_helper(2, ["--"], fail="doc")
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assert_sequence(calls, expected(2, [], []), work)

    def test_r5_an_inherited_part_variable_reaches_no_rest_or_doc_call(self):
        done, calls, work = self.run_helper(3, ["--"], inherited="9")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assert_sequence(calls, expected(3, [], []), work)

    def test_r6_n_and_the_working_directory_come_from_the_crate_not_the_helper(self):
        # The helper's own tree declares its real N; the crate under test declares 3.
        own = (ROOT / "scripts" / "dev" / "test-parts-build.rs").read_text()
        self.assertNotIn("const N: u32 = 3;", own, "the fixture must differ from the helper's own tree")
        done, calls, work = self.run_helper(3, ["--"])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assert_sequence(calls, expected(3, [], []), work)

    def test_r7a_a_run_without_the_separator_is_a_usage_error(self):
        done, calls, _ = self.run_helper(3, ["--all-features"])
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertEqual(calls, [])

    def test_r7b_a_crate_whose_build_script_declares_no_n_is_refused(self):
        done, calls, _ = self.run_helper(None, ["--"])
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("declares no const N", done.stderr)
        self.assertEqual(calls, [])

    def test_r7c_zero_parts_is_refused(self):
        done, calls, _ = self.run_helper(0, ["--"])
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
