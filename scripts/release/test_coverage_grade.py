#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Offline contract tests for the coverage grade's lcov-only inputs."""

import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCRIPT = HERE / "coverage_grade.sh"
BASELINE = ROOT / "docs/release/baselines/coverage-39396107020"
# The script is the one source of the pinned revision; this reads it rather than repeating it.
SELF_REV = next(line.split("=", 1)[1].strip() for line in
                (Path(__file__).resolve().parent / "coverage_grade.sh").read_text().splitlines()
                if line.startswith("SELF_REV="))
UNION = "scripts/ci/coverage_union.py"
PROBE = ".github/workflows/coverage-probe.yml"
REPO = "MikkoParkkola/mcp-gateway"
RUN = "600000006"
JOBS_QUERY = (
    '[.jobs[] | select(.name == "llvm-cov Linux, grade" or '
    '.name == "llvm-cov Windows, grade") | .conclusion]\n'
    '   | if length == 2 and all(. == "success") then "success" else "failure" end'
)

# Intercept the git subcommand, not an executable called git-push. All other
# operations use real git, including creation and verification of probe commits.
GIT_WRAPPER = r'''
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with open(os.environ["GRADE_GIT_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")
if args and args[0] == "push":
    if os.environ["GRADE_ALLOW_FIXTURE_PUSH"] != "1":
        print("fixture blocked git push", file=sys.stderr)
        sys.exit(73)
    probe, ref = args[-1].split(":", 1)
    Path(os.environ["GRADE_PROBE_STATE"]).write_text(json.dumps([probe, ref]))
    sys.exit(0)
os.execv(os.environ["GRADE_REAL_GIT"], [os.environ["GRADE_REAL_GIT"], *args])
'''

# Serve only the calls the shell script actually makes. Unknown arguments fail
# closed; run metadata refers to the real, locally created probe commit.
GH_STUB = r'''
import json
import os
from pathlib import Path
import shutil
import sys

args = sys.argv[1:]
with open(os.environ["GRADE_GH_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")
answers = json.loads(Path(os.environ["GRADE_GH_ANSWERS"]).read_text())
state = Path(os.environ["GRADE_PROBE_STATE"])
probe, ref = json.loads(state.read_text()) if state.exists() else ["", ""]
for call, answer in answers:
    call = [arg.replace("@PROBE@", probe).replace("@BRANCH@", ref.removeprefix("refs/heads/"))
            for arg in call]
    if args == call:
        if answer == "@DOWNLOAD@":
            shutil.copytree(os.environ["GRADE_ARTIFACTS"], args[-1])
        else:
            print(answer.replace("@PROBE@", probe))
        sys.exit(0)
print("unexpected gh call: " + repr(args), file=sys.stderr)
sys.exit(91)
'''


class CoverageGrade(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="coverage-grade-test-")
        self.addCleanup(self.temp.cleanup)
        # Git canonicalizes its common directory (notably /var on macOS).
        self.directory = Path(self.temp.name).resolve()
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git, "git is required for offline probe fixtures")
        self.git = str(Path(real_git).resolve())
        # Do not inherit a caller's index, worktree or object destination. The
        # disposable clone owns every new object and the grade/pruning directory.
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Coverage fixture",
            "GIT_AUTHOR_EMAIL": "coverage@example.invalid",
            "GIT_COMMITTER_NAME": "Coverage fixture",
            "GIT_COMMITTER_EMAIL": "coverage@example.invalid",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "file",
            "PYTHONDONTWRITEBYTECODE": "1",
        })

    def command(self, args, cwd=ROOT):
        return subprocess.run(args, cwd=cwd, env=self.env, text=True,
                              capture_output=True, timeout=90)

    def assert_status(self, result, expected):
        self.assertEqual(expected, result.returncode, result.stdout + result.stderr)

    def require_self_rev(self):
        in_ci = os.environ.get("CI") == "true"
        present = not self.command([self.git, "cat-file", "-e", f"{SELF_REV}^{{commit}}"]).returncode
        fetched = None
        if in_ci:
            # CI checks out shallow, and a clone of a shallow repository ignores --shared and copies only what a ref
            # reaches, so isolated_probe's clone sees the pinned commit only through a ref. Point a branch at it:
            # locally when the object is already here (even unreferenced), else by fetching the one commit (read
            # from the script, so the two cannot drift) from the real origin. The fetch runs outside the fixture
            # environment, which allows only file:// transports, but without the GIT_* variables setUp strips, so
            # nothing in the caller's environment can point it at another repository.
            ref = "refs/heads/coverage-grade-self-rev"
            if present:
                self.command([self.git, "update-ref", ref, SELF_REV])
            else:
                env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
                env["GIT_TERMINAL_PROMPT"] = "0"
                fetched = subprocess.run([self.git, "fetch", "--no-tags", "--depth=1", "origin",
                                          f"+{SELF_REV}:{ref}"],
                                         cwd=ROOT, env=env, text=True, capture_output=True, timeout=90)
                present = not self.command([self.git, "cat-file", "-e", f"{SELF_REV}^{{commit}}"]).returncode
        if not present:
            # A silent skip in CI would leave the self-check and the refusal untested, so CI fails instead.
            if in_ci:
                detail = fetched.stderr.strip() if fetched else ""
                self.fail(f"pinned SELF_REV {SELF_REV} is absent in CI and could not be fetched: {detail}")
            self.skipTest("pinned SELF_REV is absent from local history; no fetch attempted")

    def isolated_probe(self):
        self.checkout = self.directory / "checkout"
        result = self.command([self.git, "clone", "--quiet", "--shared", "--no-checkout",
                               str(ROOT), str(self.checkout)])
        self.assert_status(result, 0)
        self.head = self.command([self.git, "rev-parse", "HEAD"]).stdout.strip()
        self.assertEqual(self.head, self.command(
            [self.git, "rev-parse", "HEAD"], self.checkout).stdout.strip())
        # Execute the working copy of the shell script, just as a developer
        # would; the revision it archives and grades remains the real HEAD.
        shutil.copytree(HERE, self.checkout / "scripts/release",
                        ignore=shutil.ignore_patterns("__pycache__"))
        (self.checkout / PROBE).parent.mkdir(parents=True)
        shutil.copyfile(ROOT / PROBE, self.checkout / PROBE)
        self.git_log = self.directory / "git.jsonl"
        self.gh_log = self.directory / "gh.jsonl"
        self.state = self.directory / "probe.json"
        self.answers = self.directory / "answers.json"
        self.answers.write_text("[]")
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        for name, source in (("git", GIT_WRAPPER), ("gh", GH_STUB)):
            executable = self.bin / name
            executable.write_text(f"#!{sys.executable}\n" + source)
            executable.chmod(0o755)
        self.env.update({
            "PATH": str(self.bin) + os.pathsep + self.env.get("PATH", ""),
            "GRADE_REAL_GIT": self.git,
            "GRADE_GIT_LOG": str(self.git_log),
            "GRADE_GH_LOG": str(self.gh_log),
            "GRADE_PROBE_STATE": str(self.state),
            "GRADE_GH_ANSWERS": str(self.answers),
            "GRADE_ALLOW_FIXTURE_PUSH": "0",
        })

    @staticmethod
    def calls(path):
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def grade(self, revision, tag):
        return self.command(["bash", str(self.checkout / "scripts/release/coverage_grade.sh"),
                             revision, tag], self.checkout)

    def test_s1_pinned_baseline_and_self_check_use_lcov(self):
        # These checks stay independent: a retained JSON file must not hide a
        # stale checksum manifest, an old paths table, or a broken self-check.
        with self.subTest(contract="no JSON baseline"):
            self.assertFalse((BASELINE / "cov.json.xz").exists(),
                             "S1: pinned baseline still contains cov.json.xz")
        with self.subTest(contract="no JSON checksum"):
            self.assertNotIn("cov.json.xz", (BASELINE / "SHA256SUMS").read_text())
        with self.subTest(contract="paths reproduced from pinned Linux lcov"):
            report = self.directory / "linux.lcov"
            report.write_bytes(lzma.decompress((BASELINE / "linux.lcov.xz").read_bytes()))
            result = self.command([sys.executable, str(HERE / "critical_path_coverage.py"), str(report)])
            self.assert_status(result, 0)
            self.assertEqual((BASELINE / "paths.txt").read_text(), result.stdout)
        with self.subTest(contract="offline self-check"):
            self.require_self_rev()
            self.assert_status(self.command(["bash", str(SCRIPT), "--self-check"]), 0)

    def test_s2_old_revision_is_refused_before_push_and_head_reaches_push(self):
        # The pinned commit must be in the checkout before the probe clones it (see require_self_rev). Outside CI
        # a missing commit still skips only the SELF_REV subtest, not the head's push below.
        try:
            self.require_self_rev()
            missing = None
        except unittest.SkipTest as skip:
            missing = skip
        self.isolated_probe()
        with self.subTest(revision=SELF_REV):
            if missing:
                raise missing
            absent = self.command([self.git, "cat-file", "-e", f"{SELF_REV}:{UNION}"])
            self.assertNotEqual(0, absent.returncode, "old-revision fixture unexpectedly has the union script")
            result = self.grade(SELF_REV, "old-revision")
            self.assertNotEqual(0, result.returncode)
            # Assert both the diagnostic and the absence of a push, even when
            # one fails. A push failure is not a preflight refusal.
            with self.subTest(contract="missing script named"):
                self.assertIn(UNION, result.stdout + result.stderr)
            with self.subTest(contract="no push"):
                self.assertFalse([call for call in self.calls(self.git_log) if call[0] == "push"],
                                 "S2: old revision reached git push")
            self.assertEqual([], self.calls(self.gh_log))

        self.git_log.write_text("")
        self.gh_log.write_text("")
        result = self.grade("HEAD", "head-control")
        # HEAD is deliberately not patched with a pretend union script: this
        # control stays red until the implementation is in the tested revision.
        with self.subTest(revision="HEAD", contract="union script present"):
            present = self.command([self.git, "cat-file", "-e", f"HEAD:{UNION}"], self.checkout)
            self.assert_status(present, 0)
        with self.subTest(revision="HEAD", contract="push reached"):
            self.assert_status(result, 73)
            pushes = [call for call in self.calls(self.git_log) if call[0] == "push"]
            self.assertEqual(1, len(pushes), self.calls(self.git_log))
            self.assertIn("fixture blocked git push", result.stderr)
            self.assertEqual([], self.calls(self.gh_log))

    def fixture_calls(self, out):
        return [
            (["run", "list", "-R", REPO, "--branch", "@BRANCH@", "--workflow",
              "coverage-probe.yml", "-L", "20", "--json", "databaseId,headSha", "-q",
              '[.[] | select(.headSha == "@PROBE@") | .databaseId][0] // empty'], RUN),
            (["api", f"repos/{REPO}/actions/runs/{RUN}", "-q", ".path"], PROBE),
            (["run", "view", RUN, "-R", REPO, "--json", "headSha", "-q", ".headSha"], "@PROBE@"),
            (["run", "view", RUN, "-R", REPO, "--json", "status", "-q", ".status"], "completed"),
            (["run", "view", RUN, "-R", REPO, "--json", "jobs", "-q", JOBS_QUERY], "success"),
            # Only the two graded reports: the run's raw-profile shards are ~14 GB unpacked.
            (["run", "download", RUN, "-R", REPO, "-n", "coverage-linux", "-n", "coverage-windows",
              "-D", str(out / "art")], "@DOWNLOAD@"),
        ]

    def assert_fixture_calls(self, expected):
        self.assertTrue(self.state.is_file(), "fixture push was never reached")
        probe, ref = json.loads(self.state.read_text())
        calls = [[arg.replace("@PROBE@", probe).replace("@BRANCH@", ref.removeprefix("refs/heads/"))
                  for arg in call] for call, _ in expected]
        self.assertEqual(calls, self.calls(self.gh_log))
        git_calls = self.calls(self.git_log)
        self.assertEqual(1, sum(call[0] == "push" for call in git_calls))
        self.assertFalse(any(call[0] == "fetch" for call in git_calls), "probe should already exist locally")

    def test_s3_normal_grade_uses_linux_lcov_and_refuses_json_fallback(self):
        self.isolated_probe()
        artifacts = self.directory / "artifacts"
        linux = artifacts / "coverage-linux"
        windows = artifacts / "coverage-windows"
        uploaded_grade = artifacts / "coverage-grade"
        for directory in (linux, windows, uploaded_grade):
            directory.mkdir(parents=True)
        # Real pinned reports exercise both graders. The function verdict may
        # differ at HEAD; this row requires a grade and exact lcov path output.
        for platform, directory in (("linux", linux), ("windows", windows)):
            (directory / f"{platform}.lcov").write_bytes(lzma.decompress(
                (BASELINE / f"{platform}.lcov.xz").read_bytes()))
        for name in ("functions.txt", "paths.txt"):
            (uploaded_grade / name).write_text("uploaded grade must be recomputed\n")
        self.env.update({"GRADE_ARTIFACTS": str(artifacts), "GRADE_ALLOW_FIXTURE_PUSH": "1"})
        out = self.checkout / ".git/coverage-grade" / RUN
        expected_calls = self.fixture_calls(out)
        self.answers.write_text(json.dumps(expected_calls))

        with self.subTest(artifact="linux.lcov without cov.json"):
            self.assertFalse((linux / "cov.json").exists())
            result = self.grade("HEAD", "lcov-fixture")
            self.assert_fixture_calls(expected_calls)
            self.assertIn(result.returncode, (0, 1), "S3: lcov-only run was not graded\n" + result.stdout + result.stderr)
            self.assertRegex(result.stdout, rf"(?m)^GRADE rev={self.head} run={RUN} conclusion=success: (PASS|FAIL)$")
            self.assertNotIn("NOT GRADED", result.stdout)
            expected = self.command([sys.executable, str(HERE / "critical_path_coverage.py"),
                                     str(linux / "linux.lcov")])
            self.assert_status(expected, 0)
            self.assertEqual(expected.stdout, (out / "paths.txt").read_text())

        # A genuinely passing old-format report makes a fallback observable.
        # Keep Windows and the uploaded grade; remove only the required Linux
        # report. The shell must refuse before producing any path grade.
        with self.subTest(artifact="passing cov.json without linux.lcov"):
            filenames = ["src/gateway/server/a.rs", "src/oauth/a.rs", "src/transport/http/a.rs",
                         "src/transport/stdio.rs", "src/gateway/input_bridge.rs",
                         "src/gateway/task_service/a.rs", "src/personal_accounts/a.rs"]
            document = {"data": [{"files": [
                {"filename": filename, "summary": {"lines": {"covered": 100, "count": 100}}}
                for filename in filenames
            ]}]}
            (linux / "cov.json").write_text(json.dumps(document))
            (linux / "linux.lcov").unlink()
            self.git_log.write_text("")
            self.gh_log.write_text("")
            self.state.unlink()
            result = self.grade("HEAD", "json-fixture")
            self.assert_fixture_calls(expected_calls)
            self.assert_status(result, 5)
            self.assertIn(f"input missing: {out}/art/coverage-linux/linux.lcov", result.stdout)
            self.assertRegex(result.stdout, rf"(?m)^GRADE rev={self.head} run={RUN} conclusion=success: NOT GRADED \(an input is missing; see above\)$")
            self.assertNotRegex(result.stdout, r"(?m)^GRADE .*: (PASS|FAIL)$")
            self.assertNotIn("paths failing:", result.stdout)
            self.assertFalse((out / "paths.txt").exists(), "JSON fallback produced a path grade")


if __name__ == "__main__":
    unittest.main()
