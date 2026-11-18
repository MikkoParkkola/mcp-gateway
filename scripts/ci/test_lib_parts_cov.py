#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Coverage helper rows H1-H13, with a fake Python runner and compile gate."""

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
# Model a build refreshing its executables after the coverage command starts.
while IFS= read -r executable; do
  # Cleanup may have removed a previous part's directory before the runner starts.
  if [ -f "$executable" ]; then
    touch "$executable"
  fi
done < "$FAKE_FRESH"
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
                candidates=("mcp_gateway-abc123",), stale=(), runner_rc=0, gate_rc=0):
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
                             for name in (*candidates, *stale)}}
        for name, (content, executable) in files.items():
            path = deps / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(0o755 if executable else 0o644)
            os.utime(path, (1, 1))
        fresh = root / "fresh"
        # Fresh decoys still exercise the name and executable-bit rules, not just the age rule.
        fresh.write_text("".join(f"{deps / name}\n" for name in (*DECOYS, *candidates)))
        before = self.snapshot(deps)
        env = {**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
               "FAKE_LOG": str(root / "log"), "FAKE_RC": str(runner_rc),
               "FAKE_GATE_RC": str(gate_rc), "FAKE_FRESH": str(fresh)}
        env.pop("MCP_GATEWAY_TEST_PART", None)
        if inherited is not None:
            env["MCP_GATEWAY_TEST_PART"] = inherited
        done = subprocess.run(["bash", str(helper), "cov", "4", part], cwd=root, env=env,
                              capture_output=True, text=True)
        log = (root / "log").read_text().splitlines() if (root / "log").exists() else []
        return done, root, log, before

    @staticmethod
    def snapshot(deps):
        return {str(path.relative_to(deps)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                for path in deps.rglob("*") if path.is_file()}

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

    def test_h5_exactly_one_lib_executable_is_moved(self):
        for candidates in (("mcp_gateway-abc123",), (),
                           ("mcp_gateway-abc123", "mcp_gateway-def456")):
            with self.subTest(candidates=candidates):
                done, root, log, before = self.run_cov(candidates=candidates)
                if len(candidates) == 1:
                    self.assertEqual(done.returncode, 0, done.stderr)
                    expected = dict(before)
                    expected["p3/mcp_gateway-abc123"] = expected.pop("mcp_gateway-abc123")
                    self.assertEqual(self.snapshot(root / DEPS), expected,
                                     "the sole lib executable must move into p3/, preserving its name, contents and mode")
                else:
                    self.assertNotEqual(done.returncode, 0, "zero or two lib executables must fail")
                    self.assertEqual(self.snapshot(root / DEPS), before, "ambiguous candidates must not be moved")
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

    def test_h9_lib_removes_previous_part_directories(self):
        # Both previous bundles are in the fresh list: age filtering cannot remove them.
        # Cleanup must discard even this part's old bundle before moving the new executable.
        old_bundles = ("p2/mcp_gateway-abc123", "p3/mcp_gateway-0ld0ld")
        done, root, _log, before = self.run_cov(candidates=(*old_bundles, "mcp_gateway-def456"))
        self.assertEqual(done.returncode, 0, done.stderr)
        expected = {name: before[name] for name in DECOYS}
        expected["p3/mcp_gateway-def456"] = before["mcp_gateway-def456"]
        self.assertEqual(self.snapshot(root / DEPS), expected,
                         "previous part bundles must be removed; p3/ must hold only this run's fresh executable")
        self.assertFalse((root / DEPS / "p2").exists(), "the previous p2 directory must be removed")

    def test_h10_an_older_unrenamed_binary_is_never_a_candidate(self):
        done, root, _log, before = self.run_cov(stale=("mcp_gateway-deadbeef",))
        self.assertEqual(done.returncode, 0, done.stderr)
        expected = dict(before)
        expected["p3/mcp_gateway-abc123"] = expected.pop("mcp_gateway-abc123")
        self.assertEqual(self.snapshot(root / DEPS), expected,
                         "only this run's fresh executable may move into p3/")
        self.assertEqual((root / DEPS / "mcp_gateway-deadbeef").stat().st_mtime, 1,
                         "the older unrenamed executable must stay untouched")

    def test_h11_int_removes_previous_part_directories(self):
        # Integration runs also clear old lib bundles, while preserving all other files.
        old_bundles = ("p2/mcp_gateway-abc123", "p3/mcp_gateway-0ld0ld")
        done, root, _log, before = self.run_cov("int-a", candidates=(*old_bundles, "mcp_gateway-def456"))
        self.assertEqual(done.returncode, 0, done.stderr)
        part_dirs = [path.name for path in (root / DEPS).iterdir()
                     if path.is_dir() and path.name.startswith("p") and path.name[1:].isdigit()]
        self.assertEqual(part_dirs, [], "int runs must remove every deps/p<digits> directory")
        expected = {name: value for name, value in before.items() if name not in old_bundles}
        self.assertEqual(self.snapshot(root / DEPS), expected,
                         "int cleanup must leave every other file unchanged")

    def test_h12_refused_part_preserves_previous_part_directories(self):
        # Bounds validation must happen before cleanup, so refusal leaves prior bundles intact.
        old_bundles = ("p2/mcp_gateway-abc123", "p3/mcp_gateway-0ld0ld")
        done, root, log, before = self.run_cov("lib-9", n=5,
                                               candidates=(*old_bundles, "mcp_gateway-def456"))
        self.assertNotEqual(done.returncode, 0, "out-of-range lib part must be refused")
        self.assertEqual(self.snapshot(root / DEPS), before,
                         "a refused part must leave previous bundles and every other file unchanged")
        self.assertEqual(log, [], "a refused part must not run the gate or runner")

    def test_h13_cleanup_preserves_p256_crate_artifacts(self):
        # A crate name starting with p<digits> is not a whole-name part directory.
        decoys = ("p256-0123abcd.d", "p256-0123abcd/x")
        done, root, _log, before = self.run_cov(
            "lib-3", stale=(*decoys, "p2/mcp_gateway-abc123"))
        self.assertEqual(done.returncode, 0, done.stderr)
        after = self.snapshot(root / DEPS)
        for name in decoys:
            self.assertEqual(after.get(name), before[name],
                             f"p256 decoy {name} must survive part cleanup unchanged")
            self.assertEqual((root / DEPS / name).stat().st_mtime, 1,
                             f"p256 decoy {name} must keep its modification time")
        self.assertFalse((root / DEPS / "p2").exists(),
                         "the stale p2 directory must be removed")


if __name__ == "__main__":
    unittest.main()
