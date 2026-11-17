#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""U1-U3 and M1: execute the grade's union step and the real bundle/merge path."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEPS = Path("target/llvm-cov-target/debug/deps")
PARTS = [f"lib-{k}" for k in range(1, 6)]
FAKE_RUSTC = '''#!/bin/sh
case "$*" in
  -Vv) printf 'rustc 1.99.1\nrelease: 1.99.1\ncommit-hash: fixture-compiler\n' ;;
  '--print cfg --target x86_64-unknown-linux-gnu')
    printf 'unix\ntarget_os="linux"\ntarget_arch="x86_64"\n' ;;
  *) echo "unexpected rustc arguments: $*" >&2; exit 2 ;;
esac
'''


def write(root, name, content, executable=False):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        path.chmod(0o755)
    return path


def copy_scripts(root, names):
    for name in names:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)


def fixture_env(root):
    write(root, "bin/rustc", FAKE_RUSTC, executable=True)
    (root / "runner-temp").mkdir(exist_ok=True)
    env = {**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
           "RUNNER_TEMP": str(root / "runner-temp"), "COVERAGE_PARTS": "4",
           "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("MCP_GATEWAY_TEST_PART", None)
    return env


def run(argv, root, env):
    return subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True)


class UnionRows(unittest.TestCase):
    def union_run_text(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/coverage-probe.yml").read_text())
        steps = workflow.get("jobs", {}).get("linux-grade", {}).get("steps", [])
        matches = [s for s in steps if s.get("name") == "Lib test parts union"]
        self.assertTrue(matches, 'linux-grade is missing step "Lib test parts union"')
        self.assertEqual(len(matches), 1, "the union step must occur exactly once")
        command = matches[0].get("run")
        self.assertIsInstance(command, str, "the union step needs run: text")
        self.assertTrue(command.strip(), "the union step's run: text must not be empty")
        return command

    def fixture(self, root):
        copy_scripts(root, ["scripts/ci/coverage_shards.py", "scripts/ci/shard_tests.py",
                            "scripts/ci/lib_union.py", "scripts/dev/test_parts.py",
                            "scripts/dev/test_parts_expect.py",
                            "scripts/dev/check-orphan-test-modules.py"])
        write(root, "scripts/dev/test-parts-build.rs", "const N: u32 = 5;\n")
        write(root, "scripts/dev/test-parts-shared.txt", "")
        write(root, "scripts/dev/test-parts-ci.tsv",
              "config\tx86_64-unknown-linux-gnu\t--all-features\n")
        write(root, "scripts/dev/test-parts.tsv",
              "".join(f"src/part{k}\t{k}\n" for k in range(1, 6)))
        write(root, "Cargo.toml", '[package]\nname = "fixture"\n'
              'build = "scripts/dev/test-parts-build.rs"\n'
              'include = ["src/**", "scripts/dev/test-parts-build.rs"]\n'
              '[features]\ndefault = []\n')
        write(root, "src/lib.rs",
              "#![cfg_attr(tp_partial, allow(unused, unfulfilled_lint_expectations))]\n" +
              "".join(f"mod part{k};\n" for k in range(1, 6)))
        for k in range(1, 6):
            write(root, f"src/part{k}/mod.rs",
                  f"#[cfg(tp{k})]\n#[cfg(test)]\nmod tests {{\n"
                  "    #[test]\n    fn listed() {}\n}\n")
            write(root, f"shards/cov-shard-lib-{k}/tests.tsv",
                  f"unittests src/lib.rs\tpart{k}::tests::listed\tok\n"
                  "tests/x.rs\tintegration_only\tok\n")
        for part in ("int-a", "int-b", "sdk"):
            write(root, f"shards/cov-shard-{part}/tests.tsv",
                  "tests/x.rs\tintegration_only\tok\n"
                  "unittests src/lib.rs\tforeign_shard_test\tok\n")
        # Accommodate the pinned interpreter path used by the existing Linux lib gate.
        python = root / "scripts/gate-env/.venv/bin/python"
        python.parent.mkdir(parents=True)
        python.symlink_to(sys.executable)
        return fixture_env(root)

    def exercise(self, mutation=None):
        command = self.union_run_text()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self.fixture(root)
            if mutation == "duplicate":
                path = root / "shards/cov-shard-lib-4/tests.tsv"
                with path.open("a") as stream:
                    stream.write("unittests src/lib.rs\tpart2::tests::listed\tok\n")
            elif mutation == "missing":
                shutil.rmtree(root / "shards/cov-shard-lib-5")
            return run(["bash", "-e", "-o", "pipefail", "-c", command], root, env)

    def test_u1_consistent_union_passes(self):
        done = self.exercise()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_u2_duplicate_names_test_and_both_parts(self):
        done = self.exercise("duplicate")
        output = done.stdout + done.stderr
        self.assertNotEqual(done.returncode, 0, "duplicate test in parts 2 and 4 was accepted")
        self.assertRegex(output, r"part2::tests::listed[^\n]*two parts: 2 and 4")

    def test_u3_missing_part_is_reported(self):
        done = self.exercise("missing")
        self.assertNotEqual(done.returncode, 0, "missing part 5 was accepted")
        self.assertIn("part 5 was not built", done.stdout + done.stderr)


class MergeRow(unittest.TestCase):
    def merge_fixture(self, root, rename):
        copy_scripts(root, ["scripts/ci/coverage_shard_merge.sh",
                            "scripts/ci/coverage_shards.py", "scripts/ci/shard_tests.py",
                            "scripts/ci/lib_union.py"])
        env = fixture_env(root)
        contents = {}
        for k, part in enumerate(PARTS, 1):
            leg = root / part
            copy_scripts(leg, ["scripts/ci/lib-parts.sh", "scripts/ci/coverage_shard_bundle.sh",
                               "scripts/ci/coverage_shards.py", "scripts/ci/shard_tests.py",
                               "scripts/ci/lib_union.py"])
            write(leg, "scripts/dev/test-parts-build.rs", "const N: u32 = 5;\n")
            write(leg, "scripts/ci/compile-cgroup.sh", '#!/bin/sh\nexec "$@"\n', True)
            write(leg, "fake-runner/python3", "#!/bin/sh\nexit 0\n", True)
            content = f"#!/bin/sh\n# distinct coverage executable for part {k}\nexit 0\n"
            write(leg, DEPS / "mcp_gateway-abc123", content, True)
            contents[f"mcp_gateway-abc123-p{k}"] = content
            write(leg, "target/llvm-cov-target/fixture.profraw", f"profile {k}\n")
            write(leg, "run.log", f"part {k} passed\n")
            write(leg, "tests.tsv", f"unittests src/lib.rs\tpart{k}::tests::listed\tok\n")
            if rename:
                helper_env = {**env, "PATH": f"{leg / 'fake-runner'}:{env['PATH']}"}
                done = run(["bash", "scripts/ci/lib-parts.sh", "cov", "4", part], leg, helper_env)
                self.assertEqual(done.returncode, 0, f"{part} helper: {done.stdout}{done.stderr}")
            # Real Python computes and verifies manifests; only the coverage runner is fake.
            done = run(["bash", "scripts/ci/coverage_shard_bundle.sh", part], leg, env)
            self.assertEqual(done.returncode, 0, f"{part} bundle: {done.stdout}{done.stderr}")
            shutil.copytree(leg / "bundle", root / "shards" / f"cov-shard-{part}")
        done = run(["bash", "scripts/ci/coverage_shard_merge.sh", *PARTS], root, env)
        return done, contents

    def test_m1_rename_bundle_merge_and_collision_control(self):
        for rename in (True, False):
            with self.subTest(rename=rename), TemporaryDirectory() as tmp:
                root = Path(tmp)
                done, contents = self.merge_fixture(root, rename)
                output = done.stdout + done.stderr
                if rename:
                    self.assertEqual(done.returncode, 0,
                                     "renamed lib parts must merge successfully:\n" + output)
                    actual = {p.name: p.read_text() for p in (root / DEPS).iterdir()}
                    self.assertEqual(actual, contents, "merge must preserve all five -pK executables")
                    self.assertEqual(len(list((root / "target/llvm-cov-target").glob("*.profraw"))), 5)
                else:
                    self.assertNotEqual(done.returncode, 0, "unrenamed colliding executables were accepted")
                    self.assertIn("mcp_gateway-abc123: coverage sections differ between shards", output)


if __name__ == "__main__":
    unittest.main()
