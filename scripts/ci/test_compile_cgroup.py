#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Section C, G1-G15 (G10 is split into a-d): RED rows for compile-cgroup.sh.

Plain temporary files model cgroupfs. PATH wrappers supply files at mkdir,
observe external reads, and remove the pseudo-files at rmdir as cgroupfs would.
They also redirect the two report-only /proc paths, without adding gate knobs.
The child really execs, receives signals, and records its pid and arguments.
No real cgroup or sudo is used. Kernel movement/killing remains runner-level.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().with_name("compile-cgroup.sh")
MIB = 1024 * 1024
KEYS = (
    "cgroup", "page_size", "swap_out_mib", "swap_in_mib", "peak_mib",
    "leftovers", "cmd_status", "verdict", "swap_free_mib", "psi_some_avg10",
    "psi_full_avg10", "memstat_pswpin", "memstat_pswpout",
)

# This is a filesystem emulator, not a gate: it never calculates a verdict,
# converts counters, returns CMD's status, or prints a compile-cgroup record.
WRAPPER = r'''
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

base = Path(os.environ["CG_FIXTURE"])
cfg = json.loads((base / "config.json").read_text())
name = Path(sys.argv[0]).name
args = sys.argv[1:]
root = base / "cgroups"

def event(value):
    with (base / "events").open("a") as stream:
        stream.write(value + "\n")

def put(path, value):
    if value is not None:
        path.write_text(str(value) + "\n")

if name == "sudo":
    event("unexpected:sudo")
    sys.exit(93)  # Never fall through to a real sudo, even for a broken gate.
if name == "getconf" and args == ["PAGESIZE"]:
    if cfg["getconf"] is None:
        sys.exit(1)
    print(cfg["getconf"])
    sys.exit(0)

if name == "mkdir":
    targets = [Path(a) for a in args if not a.startswith("-")]
    groups = [p for p in targets if p.parent == root and p.name.startswith("covpart-")]
    if groups and not (root.stat().st_mode & stat.S_IWUSR):
        print("fixture: cgroup root is not writable", file=sys.stderr)
        sys.exit(1)
    result = subprocess.run([cfg["real"][name], *args])
    if result.returncode == 0:
        for group in groups:
            event("create:" + group.name)
            (base / "group").write_text(str(group))
            (group / "cgroup.controllers").write_text(cfg["controllers"])
            (group / "cgroup.procs").write_text("")
            if cfg["move_fails"]:
                (group / "cgroup.procs").chmod(0o400)
            if cfg["kill_exists"]:
                (group / "cgroup.kill").write_text("")
            put(group / "memory.stat", cfg["memstat"])
            put(group / "memory.pressure", cfg["pressure"])
            if cfg["remove_fails"]:
                (group / "child").mkdir()
    sys.exit(result.returncode)

group_file = base / "group"
group = Path(group_file.read_text()) if group_file.exists() else None
state_file = base / "state.json"
state = json.loads(state_file.read_text()) if state_file.exists() else {"killed": False, "polls": 0}
if group is not None:
    kill = group / "cgroup.kill"
    if kill.exists() and kill.read_text().strip() == "1" and not state["killed"]:
        state["killed"] = True
        event("kill:1")

mapped = {"/proc/meminfo": str(base / "meminfo"),
          "/proc/pressure/memory": str(base / "pressure")}
args = [mapped.get(a, a) for a in args]
reads = {str(base / "vmstat"): "vmstat", str(base / "meminfo"): "meminfo",
         str(base / "pressure"): "pressure", str(root / "cgroup.controllers"): "root-controllers"}
if group is not None:
    reads.update({str(group / "cgroup.procs"): "procs",
                  str(group / "memory.peak"): "peak",
                  str(group / "cgroup.controllers"): "controllers",
                  str(group / "memory.stat"): "memstat",
                  str(group / "memory.pressure"): "pressure"})
paths = set(args)
# Also observe commands such as `wc -l < cgroup.procs`.
if name in ("cat", "awk", "sed", "grep", "wc", "head", "tail", "cut"):
    incoming = os.fstat(0)
    for path in reads:
        try:
            info = os.stat(path)
        except FileNotFoundError:
            continue
        if (info.st_dev, info.st_ino) == (incoming.st_dev, incoming.st_ino):
            paths.add(path)
    for path, label in reads.items():
        if path not in paths:
            continue
        if label == "procs" and state["killed"]:
            state["polls"] += 1
            event("poll:" + str(state["polls"]))
            if cfg["empty_after"] is not None and state["polls"] >= cfg["empty_after"]:
                (group / "cgroup.procs").write_text("")
                if not state.get("settled"):
                    state["settled"] = True
                    # Premature peak reads find NO file; premature final vmstat
                    # reads find invalid counters. Only post-kill draining
                    # publishes the measured values, synchronously with a poll.
                    put(group / "memory.peak", cfg["peak"])
                    (base / "vmstat").write_text(cfg["after"])
                    event("empty")
        else:
            phase = "after-kill" if state["killed"] else "before-kill"
            event("read:" + label + ":" + phase)
state_file.write_text(json.dumps(state))

if name == "rmdir" and group is not None and str(group) in args:
    event("rmdir")
    if (group / "cgroup.procs").read_text().strip():
        print("fixture: cgroup still populated", file=sys.stderr)
        sys.exit(1)
    # Only the kernel's pseudo-files disappear automatically. A real child
    # directory remains and makes real rmdir fail (G10c).
    for path in group.iterdir():
        if path.is_file():
            path.unlink()
os.execv(cfg["real"][name], [cfg["real"][name], *args])
'''

CHILD = r'''
import json
import os
import signal
import sys
import time
from pathlib import Path

base = Path(os.environ["CG_FIXTURE"])
cfg = json.loads((base / "config.json").read_text())
group_file = base / "group"
group = Path(group_file.read_text()) if group_file.exists() else None
moved = (group / "cgroup.procs").read_text() if group is not None else ""
(base / "command.json").write_text(json.dumps({"pid": os.getpid(), "moved": moved,
                                              "argv": sys.argv[1:]}))

def finish():
    if group is not None:
        (group / "cgroup.procs").write_text("".join(
            str(900000001 + index) + "\n" for index in range(cfg["leftovers"])))
    (base / "vmstat").write_text("pswpin unsettled\npswpout unsettled\n")
    with (base / "events").open("a") as stream:
        stream.write("cmd:return\n")

if cfg["mode"] == "signal":
    def receive(number, frame):
        (base / "signal").write_text(signal.Signals(number).name)
        finish()
        sys.exit(128 + number)
    signal.signal(signal.SIGTERM, receive)
    signal.signal(signal.SIGINT, receive)
    (base / "ready").write_text("ready\n")
    while True:
        time.sleep(0.01)
finish()
if cfg["mode"] == "kill":
    os.kill(os.getpid(), signal.SIGKILL)
sys.exit(cfg["status"])
'''


def vmstat(pswpin=101, pswpout=211):
    return "nr_free_pages 123\n" + "".join(
        f"{key} {value}\n" for key, value in (("pswpin", pswpin), ("pswpout", pswpout))
        if value is not None
    )


class Fixture:
    def __init__(self, directory, **overrides):
        self.base = Path(directory)
        self.root = self.base / "cgroups"
        self.root.mkdir()
        self.cfg = dict(before=vmstat(), after=vmstat(), peak=7000 * MIB,
                        page_size="4096", getconf="4096", controllers="cpu memory io\n",
                        kill_exists=True, move_fails=False, create_fails=False,
                        remove_fails=False, leftovers=2, empty_after=1, status=0,
                        mode="normal", memstat="anon 4096\nfile 8192\npswpin 17\npswpout 23\n",
                        meminfo="SwapTotal: 8388608 kB\nSwapFree: 4194304 kB\n",
                        pressure="some avg10=0.25 avg60=0.00 avg300=0.00 total=1\n"
                                 "full avg10=0.10 avg60=0.00 avg300=0.00 total=1\n")
        self.cfg.update(overrides)
        names = ("mkdir", "rmdir", "cat", "awk", "sed", "grep", "wc", "head", "tail", "cut", "getconf")
        self.cfg["real"] = {name: shutil.which(name) for name in names}
        (self.base / "config.json").write_text(json.dumps(self.cfg))
        (self.base / "vmstat").write_text(self.cfg["before"])
        (self.base / "events").write_text("")
        for name in ("meminfo", "pressure"):
            if self.cfg[name] is not None:
                (self.base / name).write_text(self.cfg[name])
        (self.root / "cgroup.controllers").write_text("cpu memory io\n")
        (self.root / "memory.peak").write_text(str(7000 * MIB))
        if self.cfg["create_fails"]:
            self.root.chmod(0o500)
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        for name in (*names, "sudo"):
            path = bin_dir / name
            path.write_text(f"#!{sys.executable}\n" + WRAPPER)
            path.chmod(0o755)
        (self.base / "child.py").write_text(CHILD)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("MEM_")}
        self.env.update(PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], CG_FIXTURE=str(self.base),
                        MEM_VMSTAT=str(self.base / "vmstat"), MEM_CGROUP_ROOT=str(self.root),
                        MEM_SUDO="", MEM_KILL_WAIT_S="1", MEM_POLL_S="0.02")
        if self.cfg["page_size"] is not None:
            self.env["MEM_PAGESIZE"] = str(self.cfg["page_size"])
        self.proc = None
        self.timed_out = False

    def start(self, script=SCRIPT, args=(), no_command=False):
        command = [] if no_command else [sys.executable, str(self.base / "child.py"), *args]
        self.started = time.monotonic()
        self.proc = subprocess.Popen(["bash", str(script), *command], env=self.env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, start_new_session=True)

    def finish(self, timeout=6):
        try:
            stdout, stderr = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.timed_out = True
            self.stop()
            stdout, stderr = self.proc.communicate()
        self.elapsed = time.monotonic() - self.started
        return subprocess.CompletedProcess(self.proc.args, self.proc.returncode, stdout, stderr)

    def run(self, **kwargs):
        self.start(**kwargs)
        return self.finish()

    def stop(self):
        if self.proc is not None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.communicate()
        self.root.chmod(0o700)

    def events(self):
        return (self.base / "events").read_text().splitlines()


class CompileCgroup(unittest.TestCase):
    def fixture(self, **kwargs):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture = Fixture(temporary.name, **kwargs)
        self.addCleanup(fixture.stop)
        return fixture

    def record(self, fixture, done):
        self.assertFalse(fixture.timed_out, "gate exceeded the fixture timeout")
        lines = [line for line in (done.stdout + done.stderr).splitlines()
                 if line.startswith("compile-cgroup:")]
        self.assertEqual(len(lines), 1, "expected exactly one compile-cgroup: record")
        fields = lines[0].split()[1:]
        self.assertTrue(all(re.fullmatch(r"[a-z0-9_]+=[^\s=]+", field) for field in fields),
                        "record fields must be key=value")
        self.assertEqual(tuple(field.split("=", 1)[0] for field in fields), KEYS,
                         "record keys must match D2 exactly, in order")
        return dict(field.split("=", 1) for field in fields)

    def outcome(self, fixture, done, status=0, rule=None):
        self.assertEqual(done.returncode, status, f"expected gate exit {status}: {done.stdout}{done.stderr}")
        record = self.record(fixture, done)
        self.assertEqual(record["cgroup"], "own")
        self.assertEqual(record["cmd_status"], str(fixture.cfg["status"]))
        if rule is None:
            self.assertEqual(record["verdict"], "pass")
        else:
            self.assertNotEqual(record["verdict"], "pass")
            self.assertIn(rule, record["verdict"], f"verdict must identify {rule}")
        return record

    def assert_cleanup_order(self, fixture):
        events = fixture.events()
        self.assertIn("cmd:return", events, "CMD did not run to completion")
        events = events[events.index("cmd:return") + 1:]
        for expected in ("read:procs:before-kill", "kill:1", "empty",
                         "read:vmstat:after-kill", "read:peak:after-kill", "rmdir"):
            self.assertIn(expected, events, f"cleanup did not record {expected}")
        count, kill, empty, counters, peak, remove = (
            events.index(event) for event in ("read:procs:before-kill", "kill:1", "empty",
                                             "read:vmstat:after-kill", "read:peak:after-kill", "rmdir")
        )
        self.assertLess(count, kill)
        self.assertLess(kill, empty)
        self.assertLess(empty, min(counters, peak))
        self.assertLess(max(counters, peak), remove)
        self.assertNotIn("read:vmstat:before-kill", events, "final counters were read before killing leftovers")
        self.assertNotIn("read:peak:before-kill", events, "peak was read before killing leftovers")
        self.assertFalse(list(fixture.root.glob("covpart-*")), "cgroup was not removed")

    def test_G1_swap_out_one_page_boundary(self):
        for growth, status in ((65535, 0), (65536, 1)):
            with self.subTest(pages=growth):
                fixture = self.fixture(after=vmstat(pswpout=211 + growth))
                record = self.outcome(fixture, fixture.run(), status, "swap_out" if status else None)
                self.assertEqual(record["swap_out_mib"], str(growth * 4096 // MIB))
                self.assertEqual(record["swap_in_mib"], "0")

    def test_G2_swap_in_one_page_boundary(self):
        for growth, status in ((65535, 0), (65536, 1)):
            with self.subTest(pages=growth):
                fixture = self.fixture(after=vmstat(pswpin=101 + growth))
                record = self.outcome(fixture, fixture.run(), status, "swap_in" if status else None)
                self.assertEqual(record["swap_in_mib"], str(growth * 4096 // MIB))
                self.assertEqual(record["swap_out_mib"], "0")

    def test_G3_eight_kib_pages(self):
        for counter in ("pswpout", "pswpin"):
            for growth, status in ((32767, 0), (32768, 1)):
                with self.subTest(counter=counter, pages=growth):
                    values = dict(pswpout=211, pswpin=101)
                    values[counter] += growth
                    fixture = self.fixture(page_size="8192", after=vmstat(**values))
                    rule = "swap_out" if counter == "pswpout" else "swap_in"
                    record = self.outcome(fixture, fixture.run(), status, rule if status else None)
                    self.assertEqual(record["page_size"], "8192")
                    self.assertEqual(record[rule + "_mib"], str(growth * 8192 // MIB))

    def test_G4_peak_one_byte_boundary(self):
        for peak, status in ((14000 * MIB, 0), (14000 * MIB + 1, 1)):
            with self.subTest(bytes=peak):
                fixture = self.fixture(peak=peak)
                record = self.outcome(fixture, fixture.run(), status, "peak" if status else None)
                self.assertEqual(record["peak_mib"], "14000")

    def test_G5_zero_counters_and_growth_pass(self):
        fixture = self.fixture(before=vmstat(0, 0), after=vmstat(0, 0))
        record = self.outcome(fixture, fixture.run())
        self.assertEqual((record["swap_out_mib"], record["swap_in_mib"]), ("0", "0"))

    def test_G6_invalid_deciding_readings_fail_closed(self):
        cases = []
        for counter, field in (("pswpout", "swap_out_mib"), ("pswpin", "swap_in_mib")):
            for phase in ("before", "after"):
                for label, value in (("absent", None), ("non-numeric", "invalid")):
                    cases.append((f"{counter} {phase} {label}", {phase: vmstat(**{counter: value})},
                                  field, counter))
        cases.extend((
            ("page size absent", dict(page_size=None, getconf=None), "page_size", "page_size"),
            ("page size non-numeric", dict(page_size="invalid"), "page_size", "page_size"),
            ("page size zero", dict(page_size="0"), "page_size", "page_size"),
            ("peak absent", dict(peak=None), "peak_mib", "peak"),
            ("peak non-numeric", dict(peak="invalid"), "peak_mib", "peak"),
            ("peak zero", dict(peak=0), "peak_mib", "peak"),
        ))
        for label, changes, field, rule in cases:
            with self.subTest(reading=label):
                fixture = self.fixture(**changes)
                done = fixture.run()
                self.assertNotEqual(done.returncode, 0, f"{label} must fail closed")
                record = self.record(fixture, done)
                self.assertEqual(record[field], "na")
                self.assertIn(rule, record["verdict"], f"verdict must name {rule}")

    def test_G7_unusable_cgroup_never_runs_command(self):
        for label, changes in (
            ("creation", dict(create_fails=True)),
            ("memory controller", dict(controllers="cpu io\n")),
            ("kill file", dict(kill_exists=False)),
            ("child move", dict(move_fails=True)),
        ):
            with self.subTest(failure=label):
                fixture = self.fixture(**changes)
                done = fixture.run()
                self.assertFalse((fixture.base / "command.json").exists(), "unmeasured CMD ran")
                self.assertNotEqual(done.returncode, 0, f"{label} failure must reject the cgroup")
                record = self.record(fixture, done)
                self.assertEqual(record["cgroup"], "inconclusive")
                self.assertNotEqual(record["verdict"], "pass")

    def test_G8_child_moves_itself_then_execs(self):
        fixture = self.fixture()
        done = fixture.run()
        marker = fixture.base / "command.json"
        self.assertTrue(marker.exists(), "CMD did not report its pid")
        command = json.loads(marker.read_text())
        self.assertEqual(command["moved"].split(), [str(command["pid"])])
        self.assertNotEqual(command["pid"], fixture.proc.pid)
        self.assertNotIn(str(fixture.proc.pid), command["moved"].split())
        self.assertIn(f"create:covpart-{fixture.proc.pid}", fixture.events())
        self.outcome(fixture, done)

    def test_G9_command_status_is_preserved(self):
        fixture = self.fixture(status=7)
        done = fixture.run()
        self.assertEqual(done.returncode, 7, "CMD exit 7 must be returned unchanged")
        record = self.record(fixture, done)
        self.assertEqual(record["cmd_status"], "7")
        self.assertNotEqual(record["verdict"], "pass")
        self.assert_cleanup_order(fixture)

    def test_G10a_kill_drain_read_remove_order(self):
        fixture = self.fixture(after=vmstat(pswpin=357, pswpout=723), peak=8123 * MIB)
        done = fixture.run()
        self.assert_cleanup_order(fixture)
        record = self.outcome(fixture, done)
        self.assertEqual((record["swap_in_mib"], record["swap_out_mib"], record["peak_mib"]),
                         ("1", "2", "8123"))
        self.assertEqual(record["leftovers"], "2")

    def test_G10b_never_empty_has_bounded_wait(self):
        fixture = self.fixture(empty_after=None)
        fixture.start()
        done = fixture.finish(timeout=3)
        self.assertFalse(fixture.timed_out, "gate did not give up within MEM_KILL_WAIT_S + 2 seconds")
        self.assertLessEqual(fixture.elapsed, 3, "gate exceeded the kill-wait bound plus slack")
        self.assertNotEqual(done.returncode, 0, "a cgroup that never empties must fail")
        self.assertIn("could not be emptied", done.stdout + done.stderr)
        record = self.record(fixture, done)
        self.assertNotEqual(record["verdict"], "pass")
        self.assertEqual(record["leftovers"], "2")
        self.assertIn("kill:1", fixture.events())

    def test_G10c_removal_failure_is_reported(self):
        fixture = self.fixture(remove_fails=True)
        done = fixture.run()
        self.assertNotEqual(done.returncode, 0, "cgroup removal failure must fail the gate")
        self.assertRegex(done.stdout + done.stderr, r"(?i)(remov[^\n]*(fail|cannot|could not)|"
                         r"(fail|cannot|could not)[^\n]*remov)")
        record = self.record(fixture, done)
        self.assertNotEqual(record["verdict"], "pass")
        self.assertIn("rmdir", fixture.events())
        self.assertTrue(list(fixture.root.glob("covpart-*/child")))

    def test_G10d_waits_for_third_poll(self):
        fixture = self.fixture(empty_after=3, leftovers=3)
        done = fixture.run()
        self.assertIn("poll:3", fixture.events(), "gate did not wait for the third process-list poll")
        self.assert_cleanup_order(fixture)
        record = self.outcome(fixture, done)
        self.assertEqual(record["leftovers"], "3")

    def test_G11_exact_record_and_unreadable_fields(self):
        cases = [("all readable", {}, None)]
        for field, changes in (
            ("swap_free_mib", dict(meminfo=None)),
            ("psi_some_avg10", dict(pressure="full avg10=0.10 avg60=0 avg300=0 total=1\n")),
            ("psi_full_avg10", dict(pressure="some avg10=0.25 avg60=0 avg300=0 total=1\n")),
            ("memstat_pswpin", dict(memstat="pswpout 23\n")),
            ("memstat_pswpout", dict(memstat="pswpin 17\n")),
        ):
            cases.append((field, changes, field))
        cases.append(("deciding peak", dict(peak=None), "peak_mib"))
        expected = dict(zip(KEYS[-5:], ("4096", "0.25", "0.10", "17", "23")))
        for label, changes, missing in cases:
            with self.subTest(reading=label):
                fixture = self.fixture(**changes)
                deciding = missing == "peak_mib"
                record = self.outcome(fixture, fixture.run(), 1 if deciding else 0,
                                      "peak" if deciding else None)
                self.assertEqual(record["leftovers"], "2")
                for field, value in expected.items():
                    if field == missing:
                        self.assertEqual(record[field], "na")
                    elif field.startswith("psi_"):
                        self.assertRegex(record[field], r"^[0-9]+(?:\.[0-9]+)?$")
                        self.assertEqual(float(record[field]), float(value))
                    else:
                        self.assertEqual(record[field], value)
                if missing:
                    self.assertEqual(record[missing], "na")

    def test_G12_term_and_int_reach_child_and_report(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig.name):
                fixture = self.fixture(mode="signal")
                fixture.start()
                deadline = time.monotonic() + 2
                while (not (fixture.base / "ready").exists() and fixture.proc.poll() is None
                       and time.monotonic() < deadline):
                    time.sleep(0.01)
                self.assertTrue((fixture.base / "ready").exists(), "CMD never became ready to receive a signal")
                os.kill(fixture.proc.pid, sig)  # Only the gate; never broadcast to the child.
                done = fixture.finish()
                marker = fixture.base / "signal"
                self.assertTrue(marker.exists(), f"child did not receive {sig.name}")
                self.assertEqual(marker.read_text(), sig.name)
                self.assertEqual(done.returncode, 128 + sig)
                record = self.record(fixture, done)
                self.assertEqual(record["cmd_status"], str(128 + sig))
                self.assert_cleanup_order(fixture)

    def test_G13_sigkill_still_reports_and_cleans(self):
        fixture = self.fixture(mode="kill")
        done = fixture.run()
        self.assertNotEqual(done.returncode, 0, "SIGKILL of CMD must not pass")
        self.assertEqual(done.returncode, 128 + signal.SIGKILL)
        record = self.record(fixture, done)
        self.assertEqual(record["cmd_status"], str(128 + signal.SIGKILL))
        self.assert_cleanup_order(fixture)

    def test_G14_threshold_constants_control_decisions(self):
        for name, original, replacement, changes, rule in (
            ("SWAP_LIMIT_MIB", 256, 128, dict(after=vmstat(pswpout=211 + 200 * MIB // 4096)), "swap_out"),
            ("PEAK_LIMIT_MIB", 14000, 13000, dict(peak=13500 * MIB), "peak"),
        ):
            with self.subTest(constant=name):
                fixture = self.fixture(**changes)
                source = SCRIPT.read_text()
                pattern = rf"(?m)^(\s*(?:(?:readonly|declare -r)\s+)?{name}=)[\"']?{original}[\"']?(?=\s|$)"
                patched, count = re.subn(pattern, rf"\g<1>{replacement}", source)
                self.assertEqual(count, 1, f"expected one {name}={original} shell constant assignment")
                copy = fixture.base / "patched-gate.sh"
                copy.write_text(patched)
                self.outcome(fixture, fixture.run(script=copy), 1, rule)

    def test_G15_arguments_and_usage(self):
        with self.subTest(case="no CMD"):
            fixture = self.fixture()
            done = fixture.run(no_command=True)
            self.assertEqual(done.returncode, 2, "no CMD must exit 2")
            self.assertRegex(done.stdout + done.stderr, r"(?i)usage:")
        with self.subTest(case="literal argv"):
            fixture = self.fixture()
            done = fixture.run(args=("argument with spaces", ""))
            marker = fixture.base / "command.json"
            self.assertTrue(marker.exists(), "CMD did not receive its arguments")
            self.assertEqual(json.loads(marker.read_text())["argv"], ["argument with spaces", ""])
            self.outcome(fixture, done)


if __name__ == "__main__":
    unittest.main()
