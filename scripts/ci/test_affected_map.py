#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for the per-test file map (scripts/ci/affected_map.py) and its workflow (.github/workflows/affected-map.yml).

Pure rows run anywhere. RealTrace runs the builder's exact strace command on a small walker fixture and needs strace
(Linux; CI installs it): elsewhere it skips, and in required mode it fails. The coverage row on a real gateway child (M1's function half), the
trace's cost (M5c) and the replay of the historical misses (M7) run on Spark against a built map.

    python3 scripts/ci/test_affected_map.py
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
_SPEC = importlib.util.spec_from_file_location("affected_map", HERE / "affected_map.py")
am = importlib.util.module_from_spec(_SPEC)
sys.modules["affected_map"] = am
_SPEC.loader.exec_module(am)

REPO = "/w/repo"
NOW = datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc)


def run(**kw) -> "am.Run":
    base = dict(seconds=1.0, passed=2, ignored=0, listed=2, trace_rc=0, trace_text="", covered=set())
    base.update(kw)
    return am.Run(**base)


class Coverage(unittest.TestCase):
    """M1: a killed gateway child still credits its code: counter relocation plus continuous mode (%c)."""

    def test_the_flags_keep_a_killed_childs_counters(self) -> None:
        self.assertIn("-C instrument-coverage", am.COVERAGE_RUSTFLAGS)
        self.assertIn("-runtime-counter-relocation", am.COVERAGE_RUSTFLAGS)
        self.assertIn("%c", am.PROFILE_NAME)
        env = am.unit_env("/tmp/u1")
        self.assertEqual(env["LLVM_PROFILE_FILE"], os.path.join("/tmp/u1", am.PROFILE_NAME))


class Weight(unittest.TestCase):
    """M2: a group over 10% of the run's lib time splits one level deeper, again and again, down to single tests."""

    def units(self, times: dict[str, float], prefix: str, total: float, share: float | None = None):
        def measure(_key, names):
            return sum(times[n] for n in names)
        names = [n for n in times if n == prefix or n.startswith(prefix + "::")]
        return am.split_heavy(prefix, names, len(prefix.split("::")), total, measure, share)

    def test_a_group_at_twelve_percent_splits_and_one_at_nine_does_not(self) -> None:
        times = {"a::b::x::t1": 6.0, "a::b::y::t2": 6.0}
        self.assertEqual(set(self.units(times, "a::b", 100.0)), {"a::b::x", "a::b::y"})
        times = {"a::b::x::t1": 4.5, "a::b::y::t2": 4.5}
        self.assertEqual(set(self.units(times, "a::b", 100.0)), {"a::b"})

    def test_the_share_is_the_constant(self) -> None:
        times = {"a::b::x::t1": 6.0, "a::b::y::t2": 6.0}
        self.assertEqual(set(self.units(times, "a::b", 100.0, share=0.13)), {"a::b"})

    def test_a_heavy_child_splits_again_down_to_single_tests(self) -> None:
        # a::b weighs 17%; its child a::b::x still weighs 12%, so it splits too (6% per test); a::b::y, 5%, stays.
        times = {"a::b::x::t1": 6.0, "a::b::x::t2": 6.0, "a::b::y::t3": 5.0}
        got = self.units(times, "a::b", 100.0)
        self.assertEqual(set(got), {"a::b::x::t1", "a::b::x::t2", "a::b::y"})

    def test_a_single_test_over_the_share_stays_one_unit(self) -> None:
        times = {"a::b::t1": 30.0, "a::b::t2": 1.0}
        self.assertEqual(self.units(times, "a::b", 100.0), {"a::b::t1": ["a::b::t1"], "a::b::t2": ["a::b::t2"]})

    def test_a_heavy_group_of_one_test_is_not_run_again(self) -> None:
        # a::b::x holds one test at 30%: it stays the unit a::b::x, measured once, not split to its test and re-run.
        times = {"a::b::x::t1": 30.0, "a::b::y::t2": 1.0}
        measured = []

        def measure(key, names):
            measured.append(key)
            return sum(times[n] for n in names)
        got = am.split_heavy("a::b", list(times), 2, 100.0, measure)
        self.assertEqual(set(got), {"a::b::x", "a::b::y"})
        self.assertEqual(sorted(measured), ["a::b", "a::b::x", "a::b::y"])


class Units(unittest.TestCase):
    """M3, M4, M8: the unit record and the map document."""

    def test_a_unit_has_exactly_the_seven_keys(self) -> None:
        rec = am.unit_record(run(), ["t1", "t2"], "tests/x.rs", set(), REPO)
        self.assertEqual(tuple(sorted(rec)), tuple(sorted(am.UNIT_KEYS)))
        self.assertEqual(set(am.UNIT_KEYS), {"files", "dirs", "probes", "tests", "seconds", "binary", "unmapped"})
        self.assertIs(rec["unmapped"], False)

    def test_the_map_has_exactly_its_three_keys(self) -> None:
        doc = am.map_document("abc", "2026-01-01T00:00:00Z", {})
        self.assertEqual(set(doc), {"map_sha", "built_at", "units"})

    def test_a_pass_count_that_differs_from_the_listing_is_unmapped(self) -> None:
        self.assertTrue(am.unit_record(run(passed=1, listed=2), ["t1", "t2"], "b", set(), REPO)["unmapped"])
        self.assertFalse(am.unit_record(run(passed=1, ignored=1, listed=2), ["t1", "t2"], "b", set(), REPO)["unmapped"])

    def test_a_failed_or_missing_trace_is_unmapped(self) -> None:
        self.assertTrue(am.unit_record(run(trace_rc=1), ["t"], "b", set(), REPO)["unmapped"])
        self.assertTrue(am.unit_record(run(trace_text=None), ["t"], "b", set(), REPO)["unmapped"])

    def test_a_trace_naming_no_repository_file_stays_mapped_on_its_coverage(self) -> None:
        trace = '7 openat(AT_FDCWD</etc>, "/etc/hosts", O_RDONLY) = 3</etc/hosts>\n'
        rec = am.unit_record(run(trace_text=trace, covered={"src/a.rs"}), ["t1", "t2"], "b", set(), REPO)
        self.assertFalse(rec["unmapped"])
        self.assertEqual(rec["files"], ["src/a.rs"])

    def test_libtest_counts_come_from_the_last_summary(self) -> None:
        # A child run of the same binary can print its own summary first; the run's own comes last.
        out = "test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured\ntest result: ok. 2 passed; 0 failed; 0 ignored"
        self.assertEqual(am.results(out), (2, 0))
        self.assertEqual(am.results("no summary"), (0, 0))

    def test_missing_or_failed_coverage_is_unmapped(self) -> None:
        self.assertTrue(am.unit_record(run(coverage_ok=False), ["t1", "t2"], "b", set(), REPO)["unmapped"])

    def test_a_failed_listing_is_unmapped(self) -> None:
        self.assertTrue(am.unit_record(run(listed=-1), [], "b", set(), REPO)["unmapped"])


class Trace(unittest.TestCase):
    """M5 and M9 on recorded trace text: opens, folder reads and probes, by repository-relative key."""

    LONG = "src/a_directory_name_well_past_thirty_two_bytes/a_file_name_also_long.txt"

    def parse(self, text: str):
        return am.parse_trace(text, REPO, REPO)

    def test_a_file_read_through_a_walker_is_credited_by_its_repo_key(self) -> None:
        text = (
            f'9 openat(AT_FDCWD</w/repo>, "src/a_directory_name_well_past_thirty_two_bytes", '
            "O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 4</w/repo/src/a_directory_name_well_past_thirty_two_bytes>\n"
            "9 getdents64(4</w/repo/src/a_directory_name_well_past_thirty_two_bytes>, 0x5 /* 3 entries */, 32768) = 96\n"
            '9 openat(4</w/repo/src/a_directory_name_well_past_thirty_two_bytes>, "a_file_name_also_long.txt", '
            f"O_RDONLY|O_CLOEXEC) = 5</w/repo/{self.LONG}>\n"
        )
        got = self.parse(text)
        self.assertIn(self.LONG, got.files)
        self.assertNotIn("src/a_directory_name_well_past_thirty_two_bytes/sibling.txt", got.files)
        self.assertIn("src/a_directory_name_well_past_thirty_two_bytes", got.dirs)

    def test_the_trace_keeps_whole_paths(self) -> None:
        cmd = am.strace_command("/tmp/t")
        self.assertIn("-s", cmd, "strace cuts every string at 32 bytes without -s")
        self.assertEqual(cmd[cmd.index("-s") + 1], "4096")
        self.assertIn("-f", cmd)
        self.assertIn("-y", cmd)

    def test_a_listed_folder_is_credited_and_a_named_open_credits_no_folder(self) -> None:
        listed = '3 getdents64(5</w/repo/fixtures>, 0x1 /* 4 entries */, 32768) = 120\n'
        named = '3 openat(AT_FDCWD</w/repo>, "docs/guide.md", O_RDONLY) = 6</w/repo/docs/guide.md>\n'
        got = self.parse(listed + named)
        self.assertEqual(got.dirs, {"fixtures"})
        self.assertEqual(got.files, {"docs/guide.md"})

    def test_probes_count_present_absent_and_failed_opens(self) -> None:
        text = (
            '4 newfstatat(AT_FDCWD</w/repo>, "Cargo.toml", {st_mode=S_IFREG|0644}, 0) = 0\n'
            '4 statx(AT_FDCWD</w/repo>, "not/yet/here", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x1) = -1 ENOENT (No such file)\n'
            '4 access("docs/maybe.md", F_OK) = -1 ENOENT (No such file or directory)\n'
            '4 openat(AT_FDCWD</w/repo>, "fixtures/new.json", O_RDONLY) = -1 ENOENT (No such file or directory)\n'
            '4 readlinkat(AT_FDCWD</w/repo>, "link", "target", 4095) = 6\n'
        )
        got = self.parse(text)
        self.assertEqual(got.probes, {"Cargo.toml", "not/yet/here", "docs/maybe.md", "fixtures/new.json", "link"})
        self.assertEqual(got.files, set())

    def test_split_halves_and_working_directory_changes_resolve(self) -> None:
        text = (
            '8 chdir("/w/repo/tests") = 0\n'
            '8 openat(AT_FDCWD, "data/x.txt", O_RDONLY <unfinished ...>\n'
            '9 openat(AT_FDCWD</w/repo>, "README.md", O_RDONLY) = 3</w/repo/README.md>\n'
            "8 <... openat resumed>) = 4</w/repo/tests/data/x.txt>\n"
        )
        got = self.parse(text)
        self.assertEqual(got.files, {"tests/data/x.txt", "README.md"})

    def test_a_file_opened_through_a_link_also_credits_its_real_name(self) -> None:
        text = '2 openat(AT_FDCWD</w/repo>, "linked/a.txt", O_RDONLY) = 3</w/repo/real/a.txt>\n'
        self.assertEqual(self.parse(text).files, {"linked/a.txt", "real/a.txt"})

    def test_a_child_process_inherits_the_working_directory_and_a_thread_shares_it(self) -> None:
        text = (
            '10 chdir("/w/repo/tests") = 0\n'
            "10 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x7f) = 11\n"
            '11 access("fixtures/a.json", R_OK) = 0\n'
            "10 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_THREAD, exit_signal=0}, 88) = 12\n"
            '12 chdir("/w/repo/docs") = 0\n'
            '10 access("guide.md", F_OK) = 0\n'
            '11 access("later.json", F_OK) = 0\n'
        )
        got = self.parse(text)
        self.assertEqual(got.probes, {"tests/fixtures/a.json", "docs/guide.md", "tests/later.json"})

    def test_a_child_acting_before_its_creation_returns_still_inherits(self) -> None:
        # strace -f may print the child's first call between the creator's unfinished clone and its resumption.
        text = (
            '20 chdir("/w/repo/tests") = 0\n'
            "20 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD <unfinished ...>\n"
            '21 access("fixtures/a.json", R_OK) = 0\n'
            "20 <... clone resumed>, child_tidptr=0x7f) = 21\n"
            "20 clone3({flags=CLONE_VM|CLONE_FS|CLONE_THREAD, exit_signal=0} <unfinished ...>\n"
            '22 chdir("/w/repo/docs") = 0\n'
            "20 <... clone3 resumed>, 88) = 22\n"
            '20 access("guide.md", F_OK) = 0\n'
        )
        got = self.parse(text)
        self.assertEqual(got.probes, {"tests/fixtures/a.json", "docs/guide.md"})

    def test_ordinary_orders_resolve_and_stay_unambiguous(self) -> None:
        # A grandchild acts before its parent's creation returns; a vfork child; a copying child's own chdir.
        text = (
            '40 chdir("/w/repo/tests") = 0\n'
            "40 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>\n"
            "41 vfork( <unfinished ...>\n"
            '42 access("deep.txt", F_OK) = 0\n'
            "41 <... vfork resumed>) = 42\n"
            "40 <... clone resumed>) = 41\n"
            '41 chdir("/w/repo/docs") = 0\n'
            '41 access("own.md", F_OK) = 0\n'
            '40 access("parent.txt", F_OK) = 0\n'
        )
        got = self.parse(text)
        self.assertEqual(got.probes, {"tests/deep.txt", "docs/own.md", "tests/parent.txt"})
        self.assertFalse(got.ambiguous)

    def test_a_childs_own_chdir_survives_its_creators_later_return(self) -> None:
        text = ('45 chdir("/w/repo/tests") = 0\n'
                "45 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>\n"
                '46 chdir("/w/repo/docs") = 0\n'
                "45 <... clone resumed>) = 46\n"
                '46 access("own.md", F_OK) = 0\n')
        got = self.parse(text)
        self.assertEqual(got.probes, {"docs/own.md"})
        self.assertFalse(got.ambiguous)

    def test_a_creation_that_never_returned_is_ambiguous(self) -> None:
        text = ('50 chdir("/w/repo/tests") = 0\n'
                "50 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>\n"
                '51 access("a.txt", F_OK) = 0\n')
        self.assertTrue(self.parse(text).ambiguous)

    def test_a_reused_pid_is_ambiguous(self) -> None:
        before = '60 access("x", F_OK) = 0\n61 clone(child_stack=NULL, flags=SIGCHLD) = 60\n'
        twice = ("61 clone(child_stack=NULL, flags=SIGCHLD) = 62\n"
                 "61 clone(child_stack=NULL, flags=SIGCHLD) = 62\n")
        self.assertTrue(self.parse(before).ambiguous)
        self.assertTrue(self.parse(twice).ambiguous)

    def test_a_directory_change_in_a_shared_directory_is_ambiguous(self) -> None:
        text = ("70 clone3({flags=CLONE_VM|CLONE_FS|CLONE_THREAD, exit_signal=0}, 88) = 71\n"
                '71 chdir("/w/repo/docs") = 0\n')
        self.assertTrue(self.parse(text).ambiguous)
        alone = '72 chdir("/w/repo/docs") = 0\n'
        self.assertFalse(self.parse(alone).ambiguous)

    def test_an_ambiguous_trace_is_unmapped(self) -> None:
        text = "80 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>\n"
        self.assertTrue(am.unit_record(run(trace_text=text), ["t1", "t2"], "b", set(), REPO)["unmapped"])

    def test_escaped_descriptor_paths_are_decoded(self) -> None:
        text = (
            "6 getdents64(5</w/repo/p\\303\\244iv\\303\\244>, 0x1 /* 2 entries */, 32768) = 48\n"
            '6 openat(5</w/repo/p\\303\\244iv\\303\\244>, "f.txt", O_RDONLY) = 7</w/repo/p\\303\\244iv\\303\\244/f.txt>\n'
        )
        got = self.parse(text)
        self.assertEqual(got.dirs, {"päivä"})
        self.assertEqual(got.files, {"päivä/f.txt"})

    def test_a_link_from_outside_credits_the_file_it_reaches(self) -> None:
        text = '2 openat(AT_FDCWD</tmp>, "/tmp/link/a.txt", O_RDONLY) = 3</w/repo/real/a.txt>\n'
        self.assertEqual(self.parse(text).files, {"real/a.txt"})

    def test_a_folder_opened_through_a_link_credits_both_names(self) -> None:
        text = ('2 openat(AT_FDCWD</w/repo>, "linkdir", O_RDONLY|O_DIRECTORY) = 4</w/repo/realdir>\n')
        self.assertEqual(self.parse(text).dirs, {"linkdir", "realdir"})

    def test_escaped_bytes_in_a_path_are_read_back_as_its_name(self) -> None:
        text = '5 openat(AT_FDCWD</w/repo>, "docs/p\\303\\244iv\\303\\244 \\"q\\".md", O_RDONLY) = 3\n'
        self.assertEqual(self.parse(text).files, {'docs/päivä "q".md'})

    def test_paths_outside_the_repository_are_dropped(self) -> None:
        text = '1 openat(AT_FDCWD</tmp>, "/usr/lib/libc.so", O_RDONLY) = 3</usr/lib/libc.so>\n'
        got = self.parse(text)
        self.assertEqual((got.files, got.dirs, got.probes), (set(), set(), set()))


class Inputs(unittest.TestCase):
    """M6: a non-.rs compile input reaches every unit of its binary; .rs inputs do not."""

    def test_only_non_rust_compile_inputs_are_taken(self) -> None:
        depinfo = (f"/w/repo/target/debug/deps/x-1: {REPO}/src/lib.rs {REPO}/src/a.rs {REPO}/fixtures/data.json "
                   f"{REPO}/docs/guide.md /home/u/.cargo/registry/dep.rs\n")
        self.assertEqual(am.depinfo_inputs(depinfo, REPO), {"fixtures/data.json", "docs/guide.md"})

    def test_an_artifacts_depinfo_is_found_beside_it(self) -> None:
        exe = {"executable": "/w/repo/target/debug/deps/serve-1a2b", "filenames": ["/w/repo/target/debug/deps/serve-1a2b"]}
        lib = {"executable": None, "filenames": ["/w/repo/target/debug/deps/libmcp_gateway-9f8e.rlib",
                                                 "/w/repo/target/debug/deps/libmcp_gateway-9f8e.rmeta"]}
        self.assertEqual(am.artifact_depinfo_path(exe), "/w/repo/target/debug/deps/serve-1a2b.d")
        self.assertEqual(am.artifact_depinfo_path(lib), "/w/repo/target/debug/deps/mcp_gateway-9f8e.d")
        self.assertIsNone(am.artifact_depinfo_path({"executable": None, "filenames": ["/x/libfoo.so"]}))

    def test_lcov_files_are_those_with_an_executed_function(self) -> None:
        lcov = (f"SF:{REPO}/src/a.rs\nFN:1,f\nFNDA:3,f\nend_of_record\n"
                f"SF:{REPO}/src/b.rs\nFN:1,g\nFNDA:0,g\nend_of_record\n")
        self.assertEqual(am.lcov_files(lcov, REPO), {"src/a.rs"})


class Age(unittest.TestCase):
    """M10: the map is rebuilt when none is published or the newest is at least 20 hours old, by its own time."""

    def test_the_age_guard(self) -> None:
        stamp = lambda hours: (NOW - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")  # noqa: E731
        self.assertTrue(am.should_build(None, NOW))
        self.assertTrue(am.should_build("not a time", NOW))
        self.assertTrue(am.should_build(stamp(21), NOW))
        self.assertTrue(am.should_build(stamp(20), NOW))
        self.assertFalse(am.should_build(stamp(19), NOW))
        self.assertFalse(am.should_build(stamp(0.5), NOW))
        self.assertEqual(am.MAP_AGE, timedelta(hours=20))

    def test_the_guard_command_reads_the_maps_own_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "m.json")
            path.write_text('{"built_at": "2026-01-02T00:00:00Z"}', encoding="utf-8")
            out = subprocess.run([sys.executable, str(HERE / "affected_map.py"), "guard", str(path),
                                  "2026-01-02T10:00:00Z"], capture_output=True, text=True)
            self.assertEqual(out.stdout.strip(), "build=false")
            out = subprocess.run([sys.executable, str(HERE / "affected_map.py"), "guard", str(Path(tmp, "none")),
                                  "2026-01-02T10:00:00Z"], capture_output=True, text=True)
            self.assertEqual(out.stdout.strip(), "build=true")


class Merge(unittest.TestCase):
    """The merge: the run's lib total over every part, a heavy group re-run deeper, nothing lost or counted twice."""

    def test_a_heavy_group_is_replaced_by_its_leaves_and_the_rest_kept(self) -> None:
        unit = lambda tests, seconds, binary=am.LIB_BINARY: {  # noqa: E731
            "files": ["src/a.rs"], "dirs": [], "probes": [], "tests": tests, "seconds": seconds,
            "binary": binary, "unmapped": False}
        part = {"part": "lib-1", "binary": "bin/p1/lib-tests-p1", "extra_files": ["fixtures/x.json"], "units": {
            "lib:a::b": unit(["a::b::x::t1", "a::b::x::t2", "a::b::y::t3"], 30.0),
            "lib:c::d": unit(["c::d::t4"], 5.0),
            "test:e2e": unit(["t5"], 50.0, binary="tests/e2e.rs")}}
        other = {"part": "lib-2", "binary": "bin/p2/lib-tests-p2", "extra_files": [], "units": {
            "lib:f::g": unit(["f::g::t6"], 65.0)}}
        seconds = {"a::b::x::t1": 4.0, "a::b::x::t2": 4.0, "a::b::y::t3": 3.0}
        calls = []

        def fake_run(binary, args, listed, unit_dir, objects):
            names = [a for a in args if a != "--exact"]
            calls.append(sorted(names))
            return am.Run(sum(seconds[n] for n in names), len(names), 0, listed, 0, "", {"src/deep.rs"})

        with tempfile.TemporaryDirectory() as tmp:
            for name, doc in (("p1", part), ("p2", other)):
                Path(tmp, name).mkdir()
                Path(tmp, name, "part.json").write_text(__import__("json").dumps(doc))
            saved = am.run_unit
            am.run_unit = fake_run
            try:
                am.merge("abc", [str(Path(tmp, "p1")), str(Path(tmp, "p2"))], str(Path(tmp, "out")), NOW)
            finally:
                am.run_unit = saved
            doc = __import__("json").loads(Path(tmp, "out", "affected-map.json").read_text())
        # lib total = 30 + 5 + 65 = 100 s: a::b (30%) splits into x (8%) and y (3%); f::g (65%) is one test, kept.
        self.assertEqual(set(doc["units"]), {"lib:a::b::x", "lib:a::b::y", "lib:c::d", "lib:f::g", "test:e2e"})
        self.assertEqual(sorted(t for u in doc["units"].values() for t in u["tests"]),
                         sorted(["a::b::x::t1", "a::b::x::t2", "a::b::y::t3", "c::d::t4", "f::g::t6", "t5"]))
        self.assertIn("fixtures/x.json", doc["units"]["lib:a::b::x"]["files"])
        self.assertIn("fixtures/x.json", doc["units"]["lib:c::d"]["files"])
        self.assertEqual(doc["map_sha"], "abc")
        self.assertNotIn(["f::g::t6"], calls, "a single heavy test is not re-run")


class Workflow(unittest.TestCase):
    """MAP.1 and MAP.4: release-line pushes, one running and one pending, no schedule, publish only on that push."""

    @classmethod
    def setUpClass(cls) -> None:
        import yaml
        cls.doc = yaml.safe_load((ROOT / ".github/workflows/affected-map.yml").read_text(encoding="utf-8"))
        cls.on = cls.doc.get("on", cls.doc.get(True))

    def steps(self, job: str) -> list[dict]:
        return self.doc["jobs"][job]["steps"]

    def test_triggers_are_the_release_line_push_and_a_dispatch(self) -> None:
        self.assertEqual(set(self.on), {"push", "workflow_dispatch"})
        self.assertEqual(self.on["push"]["branches"], ["docs/ranking-1-release-line"])

    def test_release_line_pushes_queue_and_are_never_cancelled(self) -> None:
        conc = self.doc["concurrency"]
        self.assertIs(conc["cancel-in-progress"], False)
        self.assertIn("'release-line'", conc["group"])
        self.assertIn("github.run_id", conc["group"])

    def test_the_first_job_asks_the_age_guard_and_a_dispatch_always_builds(self) -> None:
        age = next(s for s in self.steps("guard") if s.get("id") == "age")
        self.assertIn("affected_map.py guard", age["run"])
        self.assertIn('[ "$EVENT" != push ]', age["run"])
        for job in ("part", "merge"):
            self.assertEqual(self.doc["jobs"][job]["if"], "needs.guard.outputs.build == 'true'")

    def test_only_a_release_line_push_publishes(self) -> None:
        saves = [s for job in self.doc["jobs"] for s in self.steps(job)
                 if str(s.get("uses", "")).startswith("actions/cache/save@")]
        self.assertEqual(len(saves), 1)
        self.assertTrue(saves[0]["with"]["key"].startswith("affected-map-"))
        self.assertEqual(saves[0]["if"],
                         "github.ref == 'refs/heads/docs/ranking-1-release-line' && github.event_name == 'push'")
        restore = next(s for s in self.steps("guard") if str(s.get("uses", "")).startswith("actions/cache/restore@"))
        self.assertEqual(restore["with"]["restore-keys"], "affected-map-")
        self.assertEqual(restore["with"]["path"], saves[0]["with"]["path"])


def _mutants() -> list[tuple[str, str, dict]]:
    """(name, the row class that must fail, the module attributes the mutant replaces). Each patch keeps the
    original's signature, so only the behaviour the row guards changes."""
    real_tree = am.creation_tree
    real = {name: getattr(am, name) for name in (
        "split_heavy", "unit_record", "parse_trace", "depinfo_inputs", "group", "repo_key", "_completed_calls",
        "should_build", "lcov_files", "results", "map_document", "unit_env", "artifact_depinfo_path")}

    def split_by_name(prefix, members, depth, total, measure, share=None):
        share = am.SPLIT_SHARE if share is None else share
        units, pending = {}, [(prefix, members, depth)]
        while pending:
            key, names, d = pending.pop()
            if measure(key, names) > share * total and not (len(names) == 1 and names[0] == key):
                pending.extend((k, v, d + 1) for k, v in am.group(names, d + 1).items())
            else:
                units[key] = sorted(names)
        return units

    def summed(output):
        found = am._RESULT.findall(output)
        return sum(int(p) for p, _f, _i in found), sum(int(i) for _p, _f, i in found)

    def no_inheritance(text, repo, cwd):
        keep = [x for x in text.splitlines() if not re.search(r"^\d+ (clone3?|v?fork)\(", x)]
        return real["parse_trace"]("\n".join(keep) + "\n", repo, cwd)

    def no_descriptor_names(text, repo, cwd):
        return real["parse_trace"](re.sub(r"(= \d+)<[^>]*>", r"\1", text), repo, cwd)

    def one_level(prefix, members, depth, total, measure, share=None):
        share = am.SPLIT_SHARE if share is None else share
        if measure(prefix, members) > share * total and not (len(members) == 1 and members[0] == prefix):
            return {k: sorted(v) for k, v in am.group(members, depth + 1).items()}
        return {prefix: sorted(members)}

    def no_pass_count(r, *a):
        return {**real["unit_record"](r, *a), "unmapped": r.trace_rc != 0 or r.trace_text is None}

    def trace_ignored(r, *a):
        return {**real["unit_record"](r, *a), "unmapped": r.passed + r.ignored != r.listed}

    def ok_calls_only(text, repo, cwd):
        return real["parse_trace"]("\n".join(x for x in text.splitlines() if "= -1 " not in x) + "\n", repo, cwd)

    def files_only(text, repo, cwd):
        got = real["parse_trace"](text, repo, cwd)
        return am.Access(files=got.files)

    def every_input(text, repo):
        return {k for line in text.splitlines() if ":" in line
                for k in (am.repo_key(d, repo) for d in line.split(":", 1)[1].split()) if k}

    def no_split_halves(lines):
        return [(m.group(1), m.group(2), i) for i, m in enumerate(am._LINE.match(x) for x in lines) if m], []

    def ambiguity_ignored(r, *a):
        rec = real["unit_record"](r, *a)
        if r.trace_text is not None and real["parse_trace"](r.trace_text, a[-1], a[-1]).ambiguous:
            rec["unmapped"] = r.trace_rc != 0 or not r.coverage_ok or r.passed + r.ignored != r.listed
        return rec

    return [
        ("M1 no counter relocation", "Coverage", {"COVERAGE_RUSTFLAGS": "-C instrument-coverage"}),
        ("M1 no continuous mode (%c)", "Coverage", {"PROFILE_NAME": "%m-%p.profraw"}),
        ("M1 the profile outside the unit folder", "Coverage", {"unit_env": lambda d: {"LLVM_PROFILE_FILE": "x"}}),
        ("M2 the share constant at 13%", "Weight", {"SPLIT_SHARE": 0.13}),
        ("M2 a split that stops after one level", "Weight", {"split_heavy": one_level}),
        ("M2 groups by the whole name", "Weight", {"group": lambda names, depth: {n: [n] for n in names}}),
        ("M3 the pass count ignored", "Units", {"unit_record": no_pass_count}),
        ("M4 an eighth unit key", "Units", {"unit_record": lambda *a: {**real["unit_record"](*a), "x": 1}}),
        ("M4 a fourth map key", "Units", {"map_document": lambda *a: {**real["map_document"](*a), "x": 1}}),
        ("M4 only the first libtest line counted", "Units",
         {"results": lambda out: real["results"](out.split("\n")[0])}),
        ("M5/M8 a failed or missing trace kept mapped", "Units", {"unit_record": trace_ignored}),
        ("M5 the trace without -s 4096", "Trace", {"strace_command": lambda p: ["strace", "-f", "-y", "-o", p, "--"]}),
        ("M5 split strace halves not joined", "Trace", {"_completed_calls": no_split_halves}),
        ("M5 escaped path bytes kept escaped", "Trace", {"_unescape": lambda s: s}),
        ("M5 absolute paths, no repository key", "Trace",
         {"repo_key": lambda p, r: os.path.normpath(p) if os.path.normpath(p).startswith(r) else None}),
        ("M6 every compile input credited", "Inputs", {"depinfo_inputs": every_input}),
        ("M6 a function that never ran counts", "Inputs",
         {"lcov_files": lambda t, r: real["lcov_files"](t.replace("FNDA:0,", "FNDA:1,"), r)}),
        ("M9 failed probes dropped", "Trace", {"parse_trace": ok_calls_only}),
        ("M9 folders and probes dropped", "Trace", {"parse_trace": files_only}),
        ("M10 the age compared the wrong way", "Age",
         {"should_build": lambda b, now: not real["should_build"](b, now) if b else True}),
        ("M10 a 24-hour age", "Age", {"MAP_AGE": timedelta(hours=24)}),
        ("M2 a one-test group split again by its name", "Weight", {"split_heavy": split_by_name}),
        ("M3 missing or failed coverage kept mapped", "Units",
         {"unit_record": lambda r, *a: {**real["unit_record"](am.Run(**{**r.__dict__, "coverage_ok": True}), *a)}}),
        ("M4 the libtest summaries summed", "Units", {"results": summed}),
        ("M5 a new process does not inherit the working directory", "Trace", {"parse_trace": no_inheritance}),
        ("M5 the descriptor's real path ignored", "Trace", {"parse_trace": no_descriptor_names}),
        ("M6 a library's dep-info not found", "Inputs",
         {"artifact_depinfo_path": lambda a: a["executable"] + ".d" if a.get("executable") else None}),
        ("M2 the merge never splits deeper", "Merge", {"SPLIT_SHARE": 1.0}),
        ("M5 the creation tree not read", "Trace", {"creation_tree": lambda calls: ({}, False)}),
        ("M5 an ambiguous trace kept mapped", "Trace", {"unit_record": ambiguity_ignored}),
        ("M5 pid reuse not seen", "Trace",
         {"creation_tree": lambda calls: (real_tree(calls)[0], False)}),
    ]


class Mutants(unittest.TestCase):
    """Each named mutant, applied in this process, turns its row red: the proof that the rows above can fail."""

    def test_each_mutant_turns_its_row_red(self) -> None:
        import io
        for name, target, patch in _mutants():
            with self.subTest(mutant=name):
                saved = {k: getattr(am, k) for k in patch}
                for k, v in patch.items():
                    setattr(am, k, v)
                try:
                    suite = unittest.defaultTestLoader.loadTestsFromTestCase(globals()[target])
                    outcome = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
                finally:
                    for k, v in saved.items():
                        setattr(am, k, v)
                # An assertion must fail: a mutant that only crashes the row proves nothing about what it checks.
                self.assertTrue(outcome.failures, f"{name}: {target} had no failing assertion "
                                f"({len(outcome.errors)} errors)")


class RealTrace(unittest.TestCase):
    """M5 and M9 on a real trace: the builder's exact command over a walker fixture, children included. CI installs
    strace for it; where it is missing the row skips, and fails instead in required mode (CI)."""

    def test_the_real_trace_credits_walked_files_listed_folders_and_probes(self) -> None:
        if not (shutil.which("strace") and sys.platform.startswith("linux")):
            sys.path.insert(0, str(HERE))
            import required_mode  # noqa: E402
            required_mode.skip_or_fail(self, "strace on Linux")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp, "repo")
            deep = repo / "src" / "a_directory_name_well_past_thirty_two_bytes"
            deep.mkdir(parents=True)
            (deep / "a_file_name_also_long.txt").write_text("x")
            (deep / "sibling.txt").write_text("y")
            (repo / "named.txt").write_text("z")
            walker = (
                "import os, sys\n"
                "root = sys.argv[1]\n"
                "d = os.path.join(root, 'src', 'a_directory_name_well_past_thirty_two_bytes')\n"
                "open(os.path.join(d, 'a_file_name_also_long.txt')).read() if 'a_file_name_also_long.txt' in "
                "os.listdir(d) else None\n"
                "os.path.exists(os.path.join(root, 'not', 'yet', 'here'))\n"
                "open(os.path.join(root, 'named.txt')).read()\n"
            )
            script = Path(tmp, "walker.py")
            script.write_text(walker)
            trace = Path(tmp, "trace.txt")
            proc = subprocess.run([*am.strace_command(str(trace)), sys.executable, "-I", str(script), str(repo)],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            got = am.parse_trace(trace.read_text(), str(repo), tmp)
            self.assertIn("src/a_directory_name_well_past_thirty_two_bytes/a_file_name_also_long.txt", got.files)
            self.assertNotIn("src/a_directory_name_well_past_thirty_two_bytes/sibling.txt", got.files)
            self.assertIn("src/a_directory_name_well_past_thirty_two_bytes", got.dirs)
            self.assertIn("named.txt", got.files)
            self.assertNotIn("", got.dirs, "a named open credits no folder")
            self.assertIn("not/yet/here", got.probes)


if __name__ == "__main__":
    unittest.main()
