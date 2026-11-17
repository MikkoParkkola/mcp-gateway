#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Coverage helper rows H1-H8, with a fake Python runner and compile gate."""

from __future__ import annotations

import os
import stat
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "ci" / "lib-parts.sh"
DEPS = Path("target/llvm-cov-target/debug/deps")

FAKE_PYTHON = """#!/bin/sh
echo "part=${MCP_GATEWAY_TEST_PART:-unset} argv=$*" >> "$FAKE_LOG"
exit "${FAKE_RC:-0}"
"""

FAKE_GATE = """#!/bin/sh
echo "gate argv=$*" >> "$FAKE_LOG"
if [ "${FAKE_GATE_RC:-0}" -ne 0 ]; then
  exit "$FAKE_GATE_RC"
fi
exec "$@"
"""

# These must never count as the lib test executable or be renamed. Even the
# dependency file and shared library are executable, so the name matters too.
DECOYS = {
    "mcp_gateway-deadbeef.d": ("dependency metadata\n", True),
    "mcp_gateway-deadbeef.so": ("shared library\n", True),
    "mcp_gateway-cafebabe": ("not executable\n", False),
    "integration-feedface": ("#!/bin/sh\nexit 0\n", True),
}


class Coverage(unittest.TestCase):
    longMessage = False

    def run_cov(self, part="lib-3", *, n=5, inherited=None,
                candidates=("mcp_gateway-abc123",), runner_rc=0, gate_rc=0):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        ci = root / "scripts" / "ci"
        ci.mkdir(parents=True)
        (root / "scripts" / "dev").mkdir()
        helper = ci / "lib-parts.sh"
        helper.write_bytes(HELPER.read_bytes())
        (root / "scripts" / "dev" / "test-parts-build.rs").write_text(f"const N: u32 = {n};\n")
        (root / "bin").mkdir()
        for path, content in ((root / "bin" / "python3", FAKE_PYTHON),
                              (ci / "compile-cgroup.sh", FAKE_GATE)):
            path.write_text(content)
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
        deps = root / DEPS
        deps.mkdir(parents=True)
        files = {**DECOYS, **{name: (f"#!/bin/sh\n# {name}\nexit 0\n", True)
                             for name in candidates}}
        for name, (content, executable) in files.items():
            path = deps / name
            path.write_text(content)
            path.chmod(0o755 if executable else 0o644)
        before = self.snapshot(deps)
        env = {**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
               "FAKE_LOG": str(root / "log"), "FAKE_RC": str(runner_rc),
               "FAKE_GATE_RC": str(gate_rc)}
        env.pop("MCP_GATEWAY_TEST_PART", None)
        if inherited is not None:
            env["MCP_GATEWAY_TEST_PART"] = inherited
        done = subprocess.run(["bash", str(helper), "cov", "4", part], cwd=root, env=env,
                              capture_output=True, text=True)
        log = (root / "log").read_text().splitlines() if (root / "log").exists() else []
        return done, root, log, before

    @staticmethod
    def snapshot(deps):
        return {path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                for path in deps.iterdir() if path.is_file()}

    def assert_runner(self, root, log, part, value):
        self.assertEqual([line for line in log if line.startswith("part=")],
                         [f"part={value} argv={root / 'scripts/ci/coverage_shards.py'} run 4 {part}"],
                         "runner must receive the exact argv and part environment")

    def test_h1_lib_runner_argv_and_environment(self):
        done, root, log, _before = self.run_cov()
        self.assert_runner(root, log, "lib-3", "3")
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_h2_lib_overrides_inherited_part(self):
        done, root, log, _before = self.run_cov(inherited="1")
        self.assert_runner(root, log, "lib-3", "3")
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_h3_int_clears_inherited_part(self):
        done, root, log, before = self.run_cov("int-a", inherited="3")
        self.assert_runner(root, log, "int-a", "unset")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.snapshot(root / DEPS), before, "int parts must not rename lib executables")

    def test_h4_bounds_are_read_from_build_script_before_any_call(self):
        for n, part, accepted in ((5, "lib-1", True), (5, "lib-5", True),
                                  (5, "lib-0", False), (5, "lib-6", False),
                                  (5, "lib-x", False), (3, "lib-4", False)):
            with self.subTest(n=n, part=part):
                done, root, log, before = self.run_cov(part, n=n)
                if accepted:
                    self.assertEqual(done.returncode, 0, done.stderr)
                    self.assert_runner(root, log, part, part.removeprefix("lib-"))
                else:
                    self.assertNotEqual(done.returncode, 0, "out-of-range lib part must be refused")
                    self.assertEqual(log, [], "neither gate nor runner may run before bounds validation")
                    self.assertEqual(self.snapshot(root / DEPS), before)

    def test_h5_exactly_one_lib_executable_is_renamed(self):
        for candidates in (("mcp_gateway-abc123",), (),
                           ("mcp_gateway-abc123", "mcp_gateway-def456")):
            with self.subTest(candidates=candidates):
                done, root, log, before = self.run_cov(candidates=candidates)
                if len(candidates) == 1:
                    self.assertEqual(done.returncode, 0, done.stderr)
                    expected = dict(before)
                    expected["mcp_gateway-abc123-p3"] = expected.pop("mcp_gateway-abc123")
                    self.assertEqual(self.snapshot(root / DEPS), expected,
                                     "the sole lib executable must be renamed to -p3, preserving contents and mode")
                else:
                    self.assertNotEqual(done.returncode, 0, "zero or two lib executables must fail")
                    self.assertEqual(self.snapshot(root / DEPS), before, "ambiguous candidates must not be renamed")
                self.assert_runner(root, log, "lib-3", "3")

    def test_h6_failures_keep_exact_status_and_rename_nothing(self):
        for runner_rc, gate_rc, expected in ((9, 0, 9), (0, 1, 1)):
            with self.subTest(runner_rc=runner_rc, gate_rc=gate_rc):
                done, root, log, before = self.run_cov(runner_rc=runner_rc, gate_rc=gate_rc)
                self.assertEqual(done.returncode, expected,
                                 f"failure status must be preserved: expected {expected}, got {done.returncode}")
                self.assertEqual(self.snapshot(root / DEPS), before, "failed runs must rename nothing")
                if gate_rc:
                    self.assertEqual([line for line in log if line.startswith("part=")], [],
                                     "a refused gate must not run Python")
                else:
                    self.assert_runner(root, log, "lib-3", "3")

    def test_h7_int_without_lib_executable_skips_gate_and_rename(self):
        done, root, log, before = self.run_cov("int-a", candidates=())
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assert_runner(root, log, "int-a", "unset")
        self.assertEqual([line for line in log if line.startswith("gate ")], [],
                         "int parts must not call the gate")
        self.assertEqual(self.snapshot(root / DEPS), before, "int parts must rename nothing")

    def test_h8_lib_calls_gate_once_with_exact_runner_command(self):
        done, root, log, _before = self.run_cov()
        self.assertEqual([line for line in log if line.startswith("gate ")],
                         [f"gate argv=python3 {root / 'scripts/ci/coverage_shards.py'} run 4 lib-3"],
                         "lib parts must call the gate exactly once with the runner command")
        self.assert_runner(root, log, "lib-3", "3")
        self.assertTrue(log[0].startswith("gate "), "the gate must run before Python")
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_h9_an_already_renamed_binary_is_never_a_candidate(self):
        # A target dir that still holds part 2's renamed binary (no `cargo llvm-cov clean` before the run): only
        # the fresh binary may be renamed, and part 2's stays as it was.
        done, root, _log, before = self.run_cov(candidates=("mcp_gateway-def456", "mcp_gateway-abc123-p2"))
        self.assertEqual(done.returncode, 0, done.stderr)
        expected = dict(before)
        expected["mcp_gateway-def456-p3"] = expected.pop("mcp_gateway-def456")
        self.assertEqual(self.snapshot(root / DEPS), expected,
                         "only the fresh binary is renamed; an already-renamed -pK binary is left alone")


if __name__ == "__main__":
    unittest.main()
