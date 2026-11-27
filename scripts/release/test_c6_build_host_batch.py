#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Offline rows for c6_build_host_batch.sh, the gate-day C6 runner on the build host.

Real git against a throwaway bare repository whose base commit carries a stand-in harness:
it records its environment, writes a result table and one log per row, then cleans the
checkout the way the real harness does after every row. Only rustup, rustc, cargo and nproc
are stand-ins, so no toolchain or network is touched.

    python3 scripts/release/test_c6_build_host_batch.py
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

# C6_SCRIPT_UNDER_TEST points the rows at another copy, for red runs only.
SCRIPT = Path(os.environ.get("C6_SCRIPT_UNDER_TEST", Path(__file__).resolve().parent / "c6_build_host_batch.sh"))
STAMP = "990001"

# Stand-in harness, committed at scripts/ci/mutants/run_mutants.py in the base commit.
HARNESS = r'''
import os, subprocess, sys
out = sys.argv[sys.argv.index("--out") + 1]
os.makedirs(os.path.join(out, "logs"), exist_ok=True)
with open(os.path.join(out, "env.txt"), "w") as f:
    for k in ("RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_TERM_COLOR", "GITHUB_REF", "RUNNER_NAME"):
        f.write(f"{k}={os.environ.get(k, '')}\n")
with open(os.path.join(out, "logs", "R1.log"), "w") as f:
    f.write("panicked at src/x.rs:1:1\n")
# The real harness cleans its checkout after every row; evidence kept inside it would go.
subprocess.run(["git", "clean", "-fdxq", "-e", "target", "-e", "mutants-out"], check=True)
os.makedirs(out, exist_ok=True)  # the table is written last, so it survives a clean; the row logs do not
with open(os.path.join(out, "mutants-linux.tsv"), "w") as f:
    f.write("id\tverdict\nR1\tRED\n")
print("R1 RED")
sys.exit(int(os.environ.get("FAKE_EXIT_" + os.environ["GITHUB_REF"].rsplit("-", 1)[1], "0")))
'''

# As mutants.yml has it: the same pin on each job (hosted, trusted, windows) is one pin.
PINS_AS_CI = "jobs:\n" + "".join(f"  {j}:\n    with:\n      toolchain: 1.99.1\n" for j in ("hosted", "trusted", "windows"))

STUBS = {
    "rustup": '#!/bin/sh\necho "$*" >> "$HOME/rustup-calls.txt"\nexit "${FAKE_RUSTUP_EXIT:-0}"\n',
    "rustc": '#!/bin/sh\necho "rustc ${FAKE_RUSTC:-1.99.1} (stub 2026-01-01)"\n',
    "cargo": '#!/bin/sh\necho "cargo ${FAKE_RUSTC:-1.99.1} (stub 2026-01-01)"\n',
    "nproc": "#!/bin/sh\necho 4\n",
}


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class Host(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / "home"
        self.home.mkdir()
        stubs = self.tmp / "bin"
        stubs.mkdir()
        for name, body in STUBS.items():
            (stubs / name).write_text(body)
            (stubs / name).chmod(0o755)
        self.path = f"{stubs}{os.pathsep}{os.environ['PATH']}"
        self.make_repo(PINS_AS_CI)

    def make_repo(self, mutants_yml: str) -> None:
        """The bare repository: a base commit with the harness and mutants.yml, and one c6-gate branch per batch."""
        work = self.tmp / f"work-{len(list(self.tmp.iterdir()))}"
        work.mkdir()
        git(work, "init", "-q", "-b", "base")
        git(work, "config", "user.email", "t@example.invalid")
        git(work, "config", "user.name", "t")
        (work / "scripts/ci/mutants").mkdir(parents=True)
        (work / "scripts/ci/mutants/run_mutants.py").write_text(HARNESS)
        (work / ".github/workflows").mkdir(parents=True)
        (work / ".github/workflows/mutants.yml").write_text(mutants_yml)
        git(work, "add", ".")
        git(work, "commit", "-q", "-m", "base")
        self.freeze = git(work, "rev-parse", "HEAD")
        self.batch_sha = {}
        for b in ("1", "2"):
            git(work, "switch", "-q", "-c", f"throwaway/c6-gate-{STAMP}{b}", "base")
            (work / ".mutants").mkdir(exist_ok=True)
            (work / ".mutants/manifest.tsv").write_text(f"head_sha\t{self.freeze}\nR1\tlinux\tp.patch\t--lib x\n")
            git(work, "add", ".")
            git(work, "commit", "-q", "-m", f"batch {b}")
            self.batch_sha[b] = git(work, "rev-parse", "HEAD")
        self.bare = self.tmp / f"repo-{len(list(self.tmp.iterdir()))}.git"
        git(self.tmp, "clone", "-q", "--bare", str(work), str(self.bare))

    def run_host(self, slot: str, **env: str) -> subprocess.CompletedProcess:
        full = {"PATH": self.path, "HOME": str(self.home), "C6_REPO": str(self.bare),
                "FREEZE_SHA": self.freeze, "STAMP": STAMP, "SLOT": slot, **env}
        # Run as the procedure runs it, by path: a script committed without its executable bit fails here.
        return subprocess.run([str(SCRIPT)], env=full, capture_output=True, text=True, timeout=60)

    def batch_dir(self, b: str) -> Path:
        return self.home / f"c6-gate-{STAMP}{b}"

    def test_a_batch_keeps_its_evidence_outside_the_cleaned_checkout(self) -> None:
        r = self.run_host("1")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = self.batch_dir("1")
        self.assertTrue((d / "out/logs/R1.log").is_file(), "a row log was cleaned away with the checkout")
        self.assertTrue((d / "out/mutants-linux.tsv").is_file())
        log = (d / "run.log").read_text()
        self.assertIn(f"batch_sha {self.batch_sha['1']}", log.splitlines()[0])
        self.assertIn("arch ", log)
        self.assertIn("rustc 1.99.1", log)
        self.assertIn("cargo 1.99.1", log)
        self.assertIn("batch 1 end", log)

    def test_the_harness_gets_what_ci_sets(self) -> None:
        self.assertEqual(self.run_host("1").returncode, 0)
        env = dict(line.split("=", 1) for line in (self.batch_dir("1") / "out/env.txt").read_text().splitlines())
        self.assertEqual(env["RUSTUP_TOOLCHAIN"], "1.99.1")
        self.assertEqual(env["RUSTFLAGS"], "--cap-lints=warn")
        self.assertEqual(env["CARGO_TERM_COLOR"], "never")
        self.assertEqual(env["GITHUB_REF"], f"refs/heads/throwaway/mutants-{STAMP}1")

    def test_a_rustc_other_than_the_pin_stops_before_the_harness(self) -> None:
        r = self.run_host("1", FAKE_RUSTC="1.100.0")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not 1.99.1", r.stderr)
        self.assertFalse((self.batch_dir("1") / "out").exists())

    def test_a_failed_toolchain_install_stops_before_the_harness(self) -> None:
        r = self.run_host("1", FAKE_RUSTUP_EXIT="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot install Rust 1.99.1", r.stderr)
        self.assertFalse((self.batch_dir("1") / "out").exists())

    def test_the_install_never_updates_rustup_on_the_shared_host(self) -> None:
        self.assertEqual(self.run_host("1").returncode, 0)
        calls = (self.home / "rustup-calls.txt").read_text()
        self.assertIn("toolchain install 1.99.1", calls)
        self.assertIn("--no-self-update", calls)

    def test_the_script_is_executable_as_the_procedure_calls_it(self) -> None:
        self.assertTrue(os.access(SCRIPT, os.X_OK), f"{SCRIPT} has no executable bit; the procedure calls it by path")

    def test_the_toolchain_follows_the_workflow_pin(self) -> None:
        self.make_repo(PINS_AS_CI.replace("1.99.1", "1.98.0"))
        r = self.run_host("1", FAKE_RUSTC="1.98.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        env = dict(line.split("=", 1) for line in (self.batch_dir("1") / "out/env.txt").read_text().splitlines())
        self.assertEqual(env["RUSTUP_TOOLCHAIN"], "1.98.0")
        self.assertIn("rustc 1.98.0", (self.batch_dir("1") / "run.log").read_text())

    def test_no_toolchain_pin_stops(self) -> None:
        self.make_repo("jobs: {}\n")
        r = self.run_host("1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("exactly one toolchain; found: none", r.stderr)
        self.assertFalse((self.batch_dir("1") / "out").exists())

    def test_two_different_toolchain_pins_stop(self) -> None:
        self.make_repo("a:\n  toolchain: 1.99.1\nb:\n  toolchain: 1.100.0 # other\n")
        r = self.run_host("1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("exactly one toolchain; found: 1.100.0 1.99.1", r.stderr)
        self.assertFalse((self.batch_dir("1") / "out").exists())

    def test_an_existing_directory_stops(self) -> None:
        self.batch_dir("1").mkdir()
        r = self.run_host("1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("fresh directory", r.stderr)

    def test_a_batch_not_on_the_frozen_commit_stops(self) -> None:
        r = self.run_host("1", FREEZE_SHA="0" * 40)
        self.assertEqual(r.returncode, 1)
        self.assertIn("FREEZE_SHA", r.stderr)

    def test_a_failing_batch_does_not_stop_the_next_and_sets_the_exit(self) -> None:
        r = self.run_host("1 2", **{f"FAKE_EXIT_{STAMP}1": "1"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("batch 1 end", (self.batch_dir("1") / "run.log").read_text())
        self.assertIn("batch 2 end", (self.batch_dir("2") / "run.log").read_text())
        self.assertIn("exit 1", (self.batch_dir("1") / "run.log").read_text())

    def test_a_missing_input_stops(self) -> None:
        r = subprocess.run(["bash", str(SCRIPT)], env={"PATH": self.path, "HOME": str(self.home)},
                           capture_output=True, text=True, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FREEZE_SHA", r.stderr)


if __name__ == "__main__":
    unittest.main()
