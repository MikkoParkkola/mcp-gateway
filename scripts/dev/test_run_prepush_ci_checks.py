# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for the pre-push CI-check runner (MIK-8410 LIST.1a, TIME.1a, RUST.1).

Every row asserts a positive observation the empty skeleton cannot produce: a
marker a command wrote, a reported failure, a recorded argument, a dead child.
Fixture repositories are made with `git init` in a temp dir; fixture commands
are `python3 -c` one-liners that write markers outside the clone.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_prepush_ci_checks as runner  # noqa: E402

PY = sys.executable


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class Fixture:
    """A repo with commits: merge-base -> base tip, and merge-base -> head.

    `scripts` maps commit name ("base", "tip", "head") to {path: source}."""

    def __init__(self, base=None, tip=None, head=None):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)
        self.repo = self.dir / "repo"
        self.out = self.dir / "out"
        self.out.mkdir()
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.email", "t@example.invalid")
        git(self.repo, "config", "user.name", "t")
        (self.repo / ".gitignore").write_text("*.ignored\n")
        self._commit(base or {}, "base")
        self.merge_base = git(self.repo, "rev-parse", "HEAD")
        if tip:
            git(self.repo, "checkout", "-q", "-b", "line")
            self._commit(tip, "tip")
            self.base_tip = git(self.repo, "rev-parse", "HEAD")
            git(self.repo, "checkout", "-q", "main")
        else:
            self.base_tip = self.merge_base
        self._commit(head or {}, "head")
        self.head = git(self.repo, "rev-parse", "HEAD")

    def _commit(self, files, message):
        for path, text in files.items():
            f = self.repo / path
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", message)

    def marker(self, name):
        return self.out / name

    def run(self, lines, **kw):
        kw.setdefault("line_timeout_s", 30)
        kw.setdefault("deadline_s", 60)
        return runner.run(
            lines, repo=self.repo, head=self.head, merge_base=self.merge_base, base_tip=self.base_tip, **kw
        )

    def close(self):
        self._tmp.cleanup()


def py(code):
    """A list-file command running `code` with the fixture's interpreter."""
    return f"{PY} -c {code!r}"


def line(command, seconds=1, direction="closed", **extra):
    tail = "".join(f"\t{k}={v}" for k, v in extra.items())
    return f"{command}\t{seconds}\t{direction}{tail}"


def touch(path):
    return py(f"open({str(path)!r}, 'w').write('x')")


class Runner(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def tearDown(self):
        self.f.close()

    # X1
    def test_x1_every_line_runs_and_failures_and_timeouts_are_reported(self):
        a, b = self.f.marker("a"), self.f.marker("b")
        report = self.f.run(
            [line(touch(a)), line(py("raise SystemExit(3)")), line(touch(b)), line(py("import time; time.sleep(60)"))],
            line_timeout_s=2,
        )
        self.assertTrue(a.exists() and b.exists(), "both passing lines ran")
        statuses = sorted(r.status for r in report.failures)
        self.assertEqual(statuses, ["failed", "timeout"])
        self.assertNotEqual(report.rc, 0)

    # X2
    def test_x2_at_most_three_lines_run_at_once(self):
        self.assertEqual(runner.PREPUSH_CI_WORKERS, 3)
        source = (HERE / "run_prepush_ci_checks.py").read_text()
        self.assertIn("Lead ruling 2026-10-22", source.split("PREPUSH_CI_WORKERS = 3")[0][-200:])
        lock, state = threading.Lock(), {"now": 0, "max": 0, "calls": 0}

        def executor(command, workdir, timeout_s):
            with lock:
                state["now"] += 1
                state["calls"] += 1
                state["max"] = max(state["max"], state["now"])
            time.sleep(0.2)
            with lock:
                state["now"] -= 1
            return 0, ""

        self.f.run([line(f"true {i}") for i in range(9)], executor=executor)
        self.assertEqual(state["calls"], 9)
        self.assertEqual(state["max"], 3)

    # X3
    def test_x3_slowest_first(self):
        order = []

        def executor(command, workdir, timeout_s):
            order.append(command)
            return 0, ""

        self.f.run([line("five", 5), line("thirty", 30), line("one", 1)], executor=executor, workers=1)
        self.assertEqual(order, ["thirty", "five", "one"])

    # X4
    def test_x4_missing_yaml_names_the_install(self):
        code = f"import sys; sys.path.insert(0, {str(HERE)!r}); import run_prepush_ci_checks as r; print(r.yaml_status())"
        out = subprocess.run([PY, "-I", "-S", "-c", code], capture_output=True, text=True).stdout
        self.assertIn("pip install --user pyyaml", out)

    # X5
    def test_x5_a_check_failing_on_the_merge_base_too_is_pre_existing(self):
        f = Fixture(base={"chk.py": "raise SystemExit(1)\n"}, head={"x": "1"})
        try:
            report = f.run([line(f"{PY} chk.py")])
            self.assertIn(f"PRE-EXISTING ON MERGE-BASE {f.merge_base}", report.text)
            self.assertNotEqual(report.rc, 0)
        finally:
            f.close()

    # X5b
    def test_x5b_a_check_absent_on_the_merge_base_is_not_comparable(self):
        f = Fixture(base={"x": "0"}, head={"chk.py": "raise SystemExit(1)\n"})
        try:
            report = f.run([line(f"{PY} chk.py")])
            self.assertIn(f"NOT COMPARABLE ON MERGE-BASE {f.merge_base}", report.text)
            self.assertNotIn("PRE-EXISTING", report.text)
            self.assertNotEqual(report.rc, 0)
        finally:
            f.close()

    # X6
    def test_x6_an_open_line_printing_its_skip_marker_fails(self):
        report = self.f.run([line(py("print('SKIPPED: base unreadable')"), direction="open", marker="SKIPPED: base unreadable")])
        self.assertNotEqual(report.rc, 0)
        self.assertEqual(len(report.failures), 1)

    # X7
    def test_x7_the_deadline_stops_the_pool_and_queued_work(self):
        queued = self.f.marker("queued")
        pid = self.f.marker("pid")
        spawn = py(
            "import subprocess,sys,time; "
            f"c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); open({str(pid)!r},'w').write(str(c.pid)); time.sleep(60)"
        )
        start = time.monotonic()
        report = self.f.run(
            [line(spawn, 60), line(py("import time; time.sleep(60)"), 59), line(py("import time; time.sleep(60)"), 58), line(touch(queued), 1)],
            deadline_s=3,
        )
        self.assertLess(time.monotonic() - start, 3 + 5)
        self.assertFalse(queued.exists(), "the queued line was never dispatched")
        self.assertTrue(any(r.status == "deadline" for r in report.failures))
        child = int(pid.read_text())
        self.assertFalse(alive(child), "the deadline killed the whole process group")

    # X7b
    def test_x7b_base_reruns_share_the_deadline(self):
        f = Fixture(base={"chk.py": "import time; time.sleep(60)\n"}, head={"chk.py": "raise SystemExit(1)\n"})
        try:
            start = time.monotonic()
            report = f.run([line(f"{PY} chk.py")], deadline_s=3)
            self.assertLess(time.monotonic() - start, 3 + 5)
            self.assertIn("NOT COMPARABLE ON MERGE-BASE", report.text)
            self.assertNotEqual(report.rc, 0)
        finally:
            f.close()

    # X8
    def test_x8_the_lanes_tree_is_untouched(self):
        ran = self.f.marker("ran")
        before = git(self.f.repo, "status", "--porcelain", "--ignored")
        self.f.run([line(py(f"open('inside.txt','w').write('x'); open({str(ran)!r},'w').write('x')"))])
        self.assertTrue(ran.exists(), "the writer ran")
        self.assertEqual(git(self.f.repo, "status", "--porcelain", "--ignored"), before)

    # X9
    def test_x9_a_failing_drift_test_stops_the_pool(self):
        ran = self.f.marker("ran")
        report = self.f.run([line(touch(ran))], drift=lambda: ["stale: scripts/y.py"])
        self.assertIn("stale: scripts/y.py", report.text)
        self.assertFalse(ran.exists())
        self.assertNotEqual(report.rc, 0)

    # X10
    def test_x10_a_failure_prints_its_last_20_lines_and_keeps_the_log(self):
        report = self.f.run([line(py("[print(f'line {i}') for i in range(1, 51)]; raise SystemExit(1)"))])
        shown = [l for l in report.text.splitlines() if l.strip().startswith("line ")]
        self.assertEqual(shown, [f"line {i}" for i in range(31, 51)])
        log = report.failures[0].log
        self.assertTrue(log is not None and log.exists() and str(log) in report.text)

    # X11
    def test_x11_the_bounds_are_pinned(self):
        self.assertEqual(runner.LINE_TIMEOUT_S, 300)
        self.assertEqual(runner.DEADLINE_S, 300)

    # X12
    def test_x12_a_timeout_kills_the_lines_children(self):
        pid = self.f.marker("pid")
        spawn = py(
            "import subprocess,sys,time; "
            f"c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(600)']); open({str(pid)!r},'w').write(str(c.pid)); time.sleep(600)"
        )
        report = self.f.run([line(spawn)], line_timeout_s=2)
        self.assertEqual([r.status for r in report.failures], ["timeout"])
        self.assertFalse(alive(int(pid.read_text())))

    # X13
    def test_x13_concurrent_lines_do_not_see_each_others_files(self):
        gate, saw = self.f.marker("gate"), self.f.marker("saw")
        writer = py(
            "import os,time; os.makedirs('src/tmpx', exist_ok=True); open('src/tmpx/f.rs','w').write('x'); "
            f"open({str(gate)!r},'w').write('w'); "
            f"[time.sleep(0.1) for _ in range(300) if open({str(gate)!r}).read()!='done']"
        )
        reader = py(
            "import os,time; "
            f"[time.sleep(0.1) for _ in range(300) if not os.path.exists({str(gate)!r})]; "
            f"open({str(saw)!r},'w').write('present' if os.path.exists('src/tmpx') else 'absent'); "
            f"open({str(gate)!r},'w').write('done')"
        )
        self.f.run([line(writer, 2), line(reader, 1)], workers=3)
        self.assertEqual(saw.read_text(), "absent")

    # X13b
    def test_x13b_a_worker_is_reset_between_commands(self):
        self.f._commit({"tracked.txt": "orig\n"}, "tracked")
        self.f.head = git(self.f.repo, "rev-parse", "HEAD")
        saw = self.f.marker("saw")
        dirty = py("open('tracked.txt','w').write('edited'); open('new.txt','w').write('x'); open('a.ignored','w').write('x')")
        check = py(
            "import os; clean = open('tracked.txt').read()=='orig\\n' and not os.path.exists('new.txt') and not os.path.exists('a.ignored'); "
            f"open({str(saw)!r},'w').write('clean' if clean else 'dirty')"
        )
        self.f.run([line(dirty, 2), line(check, 1)], workers=1)
        self.assertEqual(saw.read_text(), "clean")

    # X14
    def test_x14_a_pipeline_runs_whole_under_pipefail(self):
        f = Fixture(head={
            "corpus.json": "AB\n",
            "gen_bad.py": "print('XX')\n",
            "gen_exit.py": "print('AB'); raise SystemExit(1)\n",
        })
        try:
            bad = f.run([line(f"{PY} gen_bad.py | cmp - corpus.json")])
            self.assertEqual(len(bad.failures), 1, "a mismatching corpus fails")
            exit1 = f.run([line(f"{PY} gen_exit.py | cmp - corpus.json")])
            self.assertEqual(len(exit1.failures), 1, "pipefail: the producer's exit 1 fails though cmp matched")
            missing = f.run([line(f"{PY} gen_bad.py", requires="0123456789abcdef0123456789abcdef01234567")])
            self.assertIn("git fetch origin 0123456789abcdef0123456789abcdef01234567", missing.text)
            self.assertNotEqual(missing.rc, 0)
        finally:
            f.close()

    # X15
    def test_x15_the_base_tip_is_fetched_before_it_is_pinned(self):
        bare = self.f.dir / "remote.git"
        git(self.f.dir, "init", "-q", "--bare", str(bare))
        git(self.f.repo, "remote", "add", "origin", str(bare))
        git(self.f.repo, "push", "-q", "origin", "HEAD:refs/heads/line")
        git(self.f.repo, "fetch", "-q", "origin")
        stale = git(self.f.repo, "rev-parse", "origin/line")
        self.f._commit({"new.txt": "1"}, "ahead")
        ahead = git(self.f.repo, "rev-parse", "HEAD")
        git(self.f.repo, "push", "-q", "origin", "HEAD:refs/heads/line")
        git(self.f.repo, "update-ref", "refs/remotes/origin/line", stale)
        self.assertEqual(runner.resolve_base_tip(self.f.repo, branch="line"), ahead)
        git(self.f.repo, "remote", "set-url", "origin", str(self.f.dir / "nowhere.git"))
        with self.assertRaises(Exception) as caught:
            runner.resolve_base_tip(self.f.repo, branch="line", timeout_s=10)
        self.assertIn("git fetch", str(caught.exception))

    # X16
    def test_x16_passing_on_the_merge_base_with_a_moved_tip_says_rebase(self):
        f = Fixture(base={"chk.py": "pass\n"}, tip={"t.txt": "1"}, head={"chk.py": "raise SystemExit(1)\n"})
        try:
            report = f.run([line(f"{PY} chk.py")])
            self.assertIn(f"PASSES ON MERGE-BASE {f.merge_base}", report.text)
            self.assertIn(f.base_tip, report.text)
            self.assertIn("rebase", report.text)
            self.assertNotEqual(report.rc, 0)
        finally:
            f.close()
        twin = Fixture(base={"chk.py": "pass\n"}, head={"chk.py": "raise SystemExit(1)\n"})
        try:
            report = twin.run([line(f"{PY} chk.py")])
            self.assertNotEqual(report.rc, 0)
            self.assertEqual(len(report.failures), 1)
            self.assertNotIn("rebase", report.text)
        finally:
            twin.close()

    # X17
    def test_x17_placeholders_are_substituted_and_head_rebound_on_the_base(self):
        rec = "import sys; open(sys.argv[1],'a').write(' '.join(sys.argv[2:])+'\\n'); raise SystemExit(1)\n"
        f = Fixture(base={"rec.py": rec}, tip={"t.txt": "1"}, head={"x.txt": "1"})
        try:
            log = f.marker("argv")
            f.run([line(f"{PY} rec.py {log} <HEAD> <BASE_TIP> <TMP>/x")])
            first, second = log.read_text().splitlines()[:2]
            head, tip, tmp = first.split()
            self.assertEqual((head, tip), (f.head, f.base_tip))
            self.assertTrue(tmp.endswith("/x") and not tmp.startswith("<"))
            self.assertEqual(second.split()[0], f.merge_base, "HEAD is rebound to the merge-base clone")
        finally:
            f.close()


class Step(unittest.TestCase):
    # P1: the step script fails when the runner fails, naming the step. Its
    # unconditional call from pre-push.sh is a text check (the weaker half).
    def test_p1_the_step_fails_when_the_runner_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            step = d / "prepush_ci_step.sh"
            step.write_text((HERE / "prepush_ci_step.sh").read_text())
            (d / "run_prepush_ci_checks.py").write_text("raise SystemExit(1)\n")
            done = subprocess.run(["bash", str(step), "deadbeef"], cwd=d, capture_output=True, text=True)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn("CI script checks", done.stdout + done.stderr)
        pre_push = (HERE / "pre-push.sh").read_text()
        calls = [l for l in pre_push.splitlines() if "prepush_ci_step.sh" in l and not l.lstrip().startswith("#")]
        self.assertEqual(len(calls), 1, calls)
        self.assertNotIn("||", calls[0])

    # P2
    def test_p2_the_rust_step_runs_the_derived_targets_with_all_features(self):
        f = Fixture()
        try:
            rec = f.marker("cargo")
            cargo = f.dir / "cargo"
            cargo.write_text(f"#!/bin/sh\necho \"$@\" >> {rec}\nexit 1\n")
            cargo.chmod(0o755)
            report = runner.run_rust(["a", "b"], cargo=str(cargo), repo=f.repo, merge_base=f.merge_base, base_tip=f.base_tip)
            calls = rec.read_text().splitlines()
            self.assertEqual(calls[0], "test --all-features --test a --test b")
            self.assertNotEqual(report.rc, 0)
            self.assertIn("MERGE-BASE", report.text)
        finally:
            f.close()


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


if __name__ == "__main__":
    unittest.main()
