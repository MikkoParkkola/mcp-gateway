#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/affected_select.py and its wiring in ci.yml. Each row names the case it
covers. The Mutants class applies each named break in this process and requires its row to fail an assertion,
so the rows are shown able to fail. Run: python3 scripts/ci/test_affected_select.py
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
_SPEC = importlib.util.spec_from_file_location("affected_select", HERE / "affected_select.py")
sel = importlib.util.module_from_spec(_SPEC)
sys.modules["affected_select"] = sel
_SPEC.loader.exec_module(sel)

REPO_NAME = "owner/repo"
LIB = "lib-a"


def unit(files=(), dirs=(), probes=(), tests=(), unmapped=False) -> dict:
    return {"files": list(files), "dirs": list(dirs), "probes": list(probes), "tests": list(tests), "seconds": 1.0,
            "binary": "b", "unmapped": unmapped}


def change(status: str, path: str, old: str = "100644", new: str = "100644") -> "sel.Change":
    return sel.Change(status, path, "000000" if status == "A" else old, "000000" if status == "D" else new)


def pick(units: dict, changes: list, at_map=("",), at_merge=("",), build=None):
    """The chosen labels, or "full: <reason>", so a row compares values and a break shows as a failed assertion."""
    try:
        return set(sel.select_units(units, sel.History("base", changes, set(at_map), set(at_merge)), build))
    except sel.Full as full:
        return f"full: {full.reason}"


def lane_event(head_sha: str = "h" * 40, base: str = "docs/ranking-1-release-line", repo: str = REPO_NAME,
               ref: str = "fix/x") -> dict:
    return {"pull_request": {"base": {"ref": base},
                             "head": {"ref": ref, "sha": head_sha, "repo": {"full_name": repo}}}}


def inputs(**kw) -> "sel.Inputs":
    base = dict(leg="int-a", event_name="pull_request", event=lane_event(), repository=REPO_NAME, ref="", merge="m",
                origin="o", map_path="/nonexistent/map.json", lib_bin=None, attempt=1, restored=True)
    base.update(kw)
    return sel.Inputs(**base)


class Events(unittest.TestCase):
    """S1': a run that is not a lane PR is full, says why, and reads neither the map nor git."""

    def setUp(self) -> None:
        self.touched: list[str] = []
        self.saved = sel.read_map, sel.history
        sel.read_map = lambda *a: self.touched.append("map") or {}
        sel.history = lambda *a: self.touched.append("git")

    def tearDown(self) -> None:
        sel.read_map, sel.history = self.saved

    def check(self, reason: str, **kw) -> None:
        rec = sel.decide(inputs(**kw))
        self.assertEqual((rec["mode"], rec["reason"]), ("full", reason))
        self.assertEqual(self.touched, [])

    def test_each_class_that_is_not_a_lane_pr(self) -> None:
        self.check("event: train PR", event=lane_event(ref="train/70z1"))
        self.check("event: push", event_name="push", event={}, ref="refs/heads/docs/ranking-1-release-line")
        self.check("event: tag", event_name="push", event={}, ref="refs/tags/v4.0.0")
        self.check("event: dispatch", event_name="workflow_dispatch", event={})
        self.check("event: fork PR", event=lane_event(repo="someone/fork"))
        self.check("event: PR into another base", event=lane_event(base="main"))
        self.check("event: PR into another base", event=lane_event(base="docs/ranking-1-release-line-next"))
        self.check("event: PR into another base", event=lane_event(base="release/3.5.x"))

    def test_a_lane_pr_goes_on_to_the_map(self) -> None:
        sel.read_map = self.saved[0]
        rec = sel.decide(inputs())
        self.assertEqual((rec["mode"], rec["reason"]), ("full", "map missing"))


class MapShape(unittest.TestCase):
    """S2 (map half): a missing, unreadable or wrongly shaped map is full."""

    def reason(self, text: str | None) -> str:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "m.json")
            if text is not None:
                Path(path).write_text(text, encoding="utf-8")
            try:
                sel.read_map(path)
                return "read"
            except sel.Full as full:
                return full.reason

    def test_missing_unreadable_and_misshapen_maps(self) -> None:
        good_unit = unit()
        self.assertEqual(self.reason(None), "map missing")
        self.assertEqual(self.reason("{not json"), "map unreadable")
        self.assertEqual(self.reason(json.dumps({"map_sha": "a", "units": {}})), "map not the map schema")
        extra = {"map_sha": "a", "built_at": "t", "units": {"u": {**good_unit, "x": 1}}}
        self.assertEqual(self.reason(json.dumps(extra)), "map not the map schema")
        self.assertEqual(self.reason(json.dumps({"map_sha": "a", "built_at": "t", "units": {"u": good_unit}})), "read")


# The force-full set, held here as two parts so the code's own literal is compared, never copied.
FOLDERS = {".cargo/", ".github/actions/", ".github/workflows/", "scripts/ci/", "tests/common/"}
FILES = {"Cargo.lock", "Cargo.toml", "rust-toolchain", "rust-toolchain.toml", "scripts/dev/test-parts.tsv",
         "scripts/dev/test_parts.py"}


class Rule(unittest.TestCase):
    """S3', S4, S5, S14, S16, S22, LINK and S13: the selection over one map, as exact label sets."""

    UNITS = {
        "lib:x": unit(files=["src/x.rs", "fixtures/a/data.json"], tests=["x::t"]),
        "lib:y": unit(files=["src/y.rs"], tests=["y::t"]),
        "lib:walker": unit(files=["src/w.rs"], dirs=["fixtures"], tests=["w::t"]),
        "lib:sublister": unit(files=["src/u.rs"], dirs=["fixtures/sub"], tests=["u::t"]),
        "lib:root": unit(files=["src/r.rs"], dirs=[""], tests=["r::t"]),
        "lib:prober": unit(files=["src/p.rs"], probes=["fixtures/new.json", "fixtures/sub"], tests=["p::t"]),
        "lib:sizer": unit(files=["src/s.rs"], probes=["docs/size.md"], tests=["s::t"]),
        "lib:sib": unit(files=["src/b.rs"], dirs=["other"], probes=["other/thing"], tests=["b::t"]),
        "lib:near": unit(files=["src/n.rs"], probes=["deep"], tests=["n::t"]),
        "lib:gone": unit(unmapped=True, tests=["g::t"]),
    }
    AT_MAP = ("", "src", "fixtures", "fixtures/a", "fixtures/sub", "docs", "other", "deep")

    def chosen(self, changes, at_merge=None):
        return pick(self.UNITS, changes, self.AT_MAP, self.AT_MAP if at_merge is None else at_merge)

    def test_the_force_full_set_and_the_build_script(self) -> None:
        self.assertEqual(set(sel.FORCE_FULL), FOLDERS | FILES)
        for entry in sorted(FOLDERS | FILES):
            path = entry + "x.yml" if entry.endswith("/") else entry
            self.assertEqual(self.chosen([change("M", path), change("M", "docs/size.md")]), "full: force-full path",
                             path)
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Cargo.toml").write_text('[package]\nname = "x"\nbuild = "tools/gen.rs"\n', encoding="utf-8")
            build = sel.build_script(os.path.join(d, "Cargo.toml"))
        self.assertEqual(build, "tools/gen.rs")
        self.assertEqual(pick(self.UNITS, [change("M", "tools/gen.rs")], self.AT_MAP, self.AT_MAP, build),
                         "full: force-full path")
        self.assertEqual(sel.build_script(str(ROOT / "Cargo.toml")), "scripts/dev/test-parts-build.rs")

    def test_a_changed_rs_no_unit_executed_is_full(self) -> None:
        for path in ("src/new.rs", "benches/b.rs", "examples/e.rs", "crates/c/src/lib.rs", "scripts/s.rs"):
            self.assertEqual(self.chosen([change("M", path)]), "full: unmapped .rs", path)
            self.assertEqual(self.chosen([change("M", "src/x.rs"), change("M", path)]), "full: unmapped .rs", path)

    def test_a_changed_file_selects_exactly_its_units(self) -> None:
        self.assertEqual(self.chosen([change("M", "src/x.rs")]), {"lib:x", "lib:gone"})
        self.assertEqual(self.chosen([change("M", "src/y.rs")]), {"lib:y", "lib:gone"})

    def test_added_deleted_and_renamed_paths_select_their_folders_listers(self) -> None:
        # A file added to a folder present on both sides: that folder's readers and probers, nothing above it.
        self.assertEqual(self.chosen([change("A", "fixtures/sub/new data.txt")]),
                         {"lib:sublister", "lib:prober", "lib:gone"})
        # The folder sub vanishes with its last file, so the lister of fixtures sees a different listing too.
        gone_sub = tuple(d for d in self.AT_MAP if d != "fixtures/sub")
        self.assertEqual(self.chosen([change("D", "fixtures/sub/only.txt")], at_merge=gone_sub),
                         {"lib:sublister", "lib:prober", "lib:walker", "lib:gone"})
        # A rename is a delete and an add: the opener of the old name is selected.
        renamed = [change("D", "fixtures/a/data.json"), change("A", "fixtures/a/data2.json")]
        self.assertIn("lib:x", self.chosen(renamed))
        self.assertNotIn("lib:sib", self.chosen(renamed))
        self.assertNotIn("lib:root", self.chosen(renamed))
        self.assertEqual(self.chosen([change("D", "fixtures/a/data.json")]) & {"lib:x"}, {"lib:x"})

    def test_probes_select_on_add_delete_and_modify(self) -> None:
        self.assertIn("lib:prober", self.chosen([change("A", "fixtures/new.json")]))
        self.assertIn("lib:prober", self.chosen([change("D", "fixtures/new.json")]))
        self.assertIn("lib:sizer", self.chosen([change("M", "docs/size.md")]))
        self.assertIn("lib:prober", self.chosen([change("A", "fixtures/sub/y.txt")]))
        # A new folder under deep: its prober is selected through the nearest folder the map knew.
        self.assertIn("lib:near", self.chosen([change("A", "deep/newdir/z.txt")]))
        self.assertNotIn("lib:sib", self.chosen([change("A", "fixtures/new.json")]))

    def test_dirs_never_count_as_executed(self) -> None:
        units = {"lib:w": unit(files=["src/w.rs"], dirs=["src/extra"], tests=["w::t"])}
        self.assertEqual(pick(units, [change("M", "src/extra/mod.rs")], ("", "src", "src/extra"),
                              ("", "src", "src/extra")), "full: unmapped .rs")

    def test_a_path_with_a_space_survives_the_diff_parse(self) -> None:
        raw = ":100644 100644 aaa bbb M\0fixtures/new data.txt\0:000000 100644 000 ccc A\0docs/a b/c.md\0"
        self.assertEqual([(c.status, c.path) for c in sel.parse_raw(raw)],
                         [("M", "fixtures/new data.txt"), ("A", "docs/a b/c.md")])

    def test_a_link_or_a_type_change_is_full(self) -> None:
        for c in (sel.Change("A", "docs/l", "000000", "120000"), sel.Change("M", "docs/l", "120000", "120000"),
                  sel.Change("D", "docs/l", "120000", "000000"), sel.Change("T", "docs/l", "100644", "120000"),
                  sel.Change("T", "docs/l", "120000", "100644")):
            self.assertEqual(self.chosen([c]), "full: link or type change", c)

    def test_two_maps_each_answer_for_their_own_leg(self) -> None:
        other = {"lib:z": unit(files=["src/x.rs"], tests=["z::t"])}
        self.assertEqual(pick(other, [change("M", "src/x.rs")]), {"lib:z"})
        self.assertEqual(self.chosen([change("M", "src/x.rs")]), {"lib:x", "lib:gone"})


class Legs(unittest.TestCase):
    """S7, S17, S20, S21, UPG, LIST: a leg's mode and names from the chosen units."""

    UNITS = {
        "lib:a": unit(tests=["a::one", "a::two"]),
        "lib:g": unit(tests=["g::old"]),
        "lib:up": unit(tests=["commands::upgrade::upgrade_notice_tests::shown"]),
        "test:alpha": unit(tests=["new::t"]),
        "test:zeta": unit(tests=["z"]),
        "bin:mcp-gateway": unit(tests=["cli"]),
    }

    def test_a_listed_name_no_lib_unit_holds_is_selected(self) -> None:
        mode, names = sel.leg_record(LIB, self.UNITS, set(), {"a::one", "new::t"})
        self.assertEqual((mode, names), ("reduced", ["new::t"]))

    def test_a_new_test_inside_an_existing_group_is_selected(self) -> None:
        self.assertEqual(sel.leg_record(LIB, self.UNITS, set(), {"g::old", "g::added"}), ("reduced", ["g::added"]))

    def test_a_lib_leg_says_none_only_when_nothing_is_left(self) -> None:
        self.assertEqual(sel.leg_record(LIB, self.UNITS, set(), {"a::one", "a::two"}), ("none", []))
        self.assertEqual(sel.leg_record(LIB, self.UNITS, {"lib:a"}, {"a::one", "g::old"}), ("reduced", ["a::one"]))

    def test_an_integration_leg_is_never_none(self) -> None:
        mode, names = sel.leg_record("int-a", self.UNITS, set(), None)
        self.assertEqual(mode, "reduced")
        self.assertEqual(names, ["bin:mcp-gateway", "bins", "test:integration_tests"])
        self.assertEqual(sel.leg_record("int-a", self.UNITS, {"test:alpha", "test:zeta"}, None)[1],
                         ["bin:mcp-gateway", "bins", "test:alpha", "test:integration_tests"])
        self.assertEqual(sel.leg_record("int-b", self.UNITS, {"test:alpha", "test:zeta"}, None),
                         ("reduced", ["doc", "examples", "test:upgrading_summary_rows", "test:zeta"]))

    def test_tests_run_beside_the_shard_step_are_always_recorded(self) -> None:
        listing = {"commands::upgrade::upgrade_notice_tests::shown", "a::one"}
        self.assertEqual(sel.leg_record("lib-b", self.UNITS, set(), listing),
                         ("reduced", ["commands::upgrade::upgrade_notice_tests::shown"]))

    def test_an_unreadable_listing_is_full(self) -> None:
        saved = sel.shard_tests.part_binaries, sel.shard_tests.listed
        try:
            for binaries, listed in ((({}, ["part 2 missing"]), None), (({1: "b"}, []), RuntimeError("x")),
                                     (({1: "b"}, []), set())):
                sel.shard_tests.part_binaries = lambda d, r=binaries: r
                sel.shard_tests.listed = (lambda b, a, o, e=listed: (_ for _ in ()).throw(e)) \
                    if isinstance(listed, Exception) else (lambda b, a, o, s=listed: s or set())
                with self.assertRaises(sel.Full) as got:
                    sel.lib_listing(LIB, "/bin-dir")
                self.assertEqual(got.exception.reason, "listing unread")
        finally:
            sel.shard_tests.part_binaries, sel.shard_tests.listed = saved


class Record(unittest.TestCase):
    """REC and S9: the record's keys and reasons; an unexpected error is a full record, never a crash."""

    def test_a_record_has_exactly_its_keys(self) -> None:
        rec = sel.decide(inputs(event_name="push", event={}))
        self.assertEqual(sorted(rec), sorted(sel.RECORD_KEYS))
        self.assertIn(rec["reason"], sel.REASONS)

    def test_an_exception_is_a_full_record(self) -> None:
        saved = sel.read_map
        sel.read_map = lambda p: (_ for _ in ()).throw(KeyError("boom"))
        try:
            rec = sel.decide(inputs())
        finally:
            sel.read_map = saved
        self.assertEqual((rec["mode"], rec["reason"]), ("full", "error"))

    def test_the_record_is_written_whole(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r", "lib-a.json")
            sel.write_record(path, sel.record("lib-a", "none", "lane PR", "abc", [], 2))
            self.assertEqual(json.loads(Path(path).read_text())["run_attempt"], 2)
            self.assertEqual(os.listdir(os.path.dirname(path)), ["lib-a.json"])


def sh(*args: str, cwd: str | None = None) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class GitHistory(unittest.TestCase):
    """S2 (DAG), S6, S23, CLEAN: real repositories. The origin holds a PR merge commit M; the leg's checkout is a
    depth-1 clone of M, as actions/checkout leaves it, and the selector fetches what it lacks."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.server = cls.tmp
        cls.origin = os.path.join(cls.tmp, REPO_NAME + ".git")
        work = os.path.join(cls.tmp, "work")
        os.makedirs(work)
        g = lambda *a: sh("git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a, cwd=work)
        g("init", "-q", "-b", "main")
        for path, text in (("src/x.rs", "x"), ("src/y.rs", "y"), ("docs/a.md", "a")):
            Path(work, path).parent.mkdir(parents=True, exist_ok=True)
            Path(work, path).write_text(text)
        g("add", "-A")
        g("commit", "-q", "-m", "c0")
        Path(work, "docs/a.md").write_text("a2")
        g("commit", "-q", "-am", "map commit")
        cls.map_sha = g("rev-parse", "HEAD")
        Path(work, "src/y.rs").write_text("y2")
        g("commit", "-q", "-am", "base after the map")
        cls.base = g("rev-parse", "HEAD")
        g("checkout", "-q", "-b", "pr")
        Path(work, "src/x.rs").write_text("x2")
        g("commit", "-q", "-am", "the PR")
        cls.head = g("rev-parse", "HEAD")
        g("checkout", "-q", "-b", "merge", "main")
        g("merge", "-q", "--no-ff", "-m", "merge", "pr")
        cls.merge = g("rev-parse", "HEAD")
        sh("git", "init", "-q", "--bare", cls.origin)
        sh("git", "-C", cls.origin, "config", "uploadpack.allowFilter", "true")
        sh("git", "-C", cls.origin, "config", "uploadpack.allowAnySHA1InWant", "true")
        g("push", "-q", cls.origin, "main", "pr", "merge:refs/pull/1/merge")
        cls.url = "file://" + cls.origin
        cls.checkout = os.path.join(cls.tmp, "checkout")
        sh("git", "init", "-q", cls.checkout)
        sh("git", "-C", cls.checkout, "fetch", "-q", "--depth=1", cls.url, cls.merge)
        sh("git", "-C", cls.checkout, "checkout", "-q", "FETCH_HEAD")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def outcome(self, head: str | None = None, map_sha: str | None = None):
        """The history's changed paths, or "full: <reason>", or "error: <type>" for anything else."""
        with tempfile.TemporaryDirectory() as scratch:
            try:
                h = sel.history(self.url, self.merge, head or self.head, map_sha or self.map_sha, scratch)
                return sorted(c.path for c in h.changes)
            except sel.Full as full:
                return f"full: {full.reason}"
            except Exception as e:  # noqa: BLE001
                return f"error: {type(e).__name__}"

    def test_the_checkout_is_shallow_and_lacks_the_parents(self) -> None:
        self.assertTrue(os.path.isfile(os.path.join(self.checkout, ".git", "shallow")))
        missing = subprocess.run(["git", "-C", self.checkout, "cat-file", "-e", self.merge + "^1"],
                                 capture_output=True)
        self.assertNotEqual(missing.returncode, 0)

    def test_a_map_on_the_base_reads_the_whole_diff_to_the_merge(self) -> None:
        # src/y.rs changed on the base after the map, src/x.rs in the PR: both are in the diff.
        self.assertEqual(self.outcome(), ["src/x.rs", "src/y.rs"])

    def test_a_map_built_on_the_pr_head_is_not_an_ancestor_of_the_base(self) -> None:
        self.assertEqual(self.outcome(map_sha=self.head), "full: map not an ancestor of the base")

    def test_the_merge_must_have_the_events_head_as_second_parent(self) -> None:
        self.assertEqual(self.outcome(head=self.base), "full: not the PR merge")

    def test_a_map_commit_the_origin_lacks_is_an_unread_diff(self) -> None:
        self.assertEqual(self.outcome(map_sha="f" * 40), "full: diff unread")

    def run_main(self, checkout: str, tracked: bool, restored: bool) -> dict:
        map_path = os.path.join(checkout, "map", "affected-map.json")
        os.makedirs(os.path.dirname(map_path), exist_ok=True)
        units = {"test:alpha": unit(files=["src/x.rs"], tests=["t"]), "test:beta": unit(files=["src/y.rs"])}
        Path(map_path).write_text(json.dumps({"map_sha": self.map_sha, "built_at": "t", "units": units}))
        self.map_bytes = Path(map_path).read_bytes()
        if tracked:
            sh("git", "-C", checkout, "add", "map/affected-map.json")
        with tempfile.TemporaryDirectory() as d:
            Path(d, "event.json").write_text(json.dumps(lane_event(head_sha=self.head)))
            env = {"GITHUB_EVENT_PATH": os.path.join(d, "event.json"), "GITHUB_EVENT_NAME": "pull_request",
                   "GITHUB_REPOSITORY": REPO_NAME, "GITHUB_SHA": self.merge, "GITHUB_SERVER_URL": "file://" + self.server,
                   "GITHUB_WORKSPACE": checkout, "RUNNER_TEMP": d, "GITHUB_RUN_ATTEMPT": "1",
                   "RESTORED": "affected-map-" + self.map_sha if restored else ""}
            saved = dict(os.environ)
            os.environ.update(env)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    sel.main(["affected_select.py", "int-a", os.path.join(d, "rec.json")])
                return json.loads(Path(d, "rec.json").read_text())
            finally:
                os.environ.clear()
                os.environ.update(saved)

    def test_the_checkout_is_left_as_it_was(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            checkout = os.path.join(d, "co")
            shutil.copytree(self.checkout, checkout, symlinks=True)
            before = {n: Path(checkout, ".git", n).read_bytes() for n in ("config", "shallow")}
            rec = self.run_main(checkout, tracked=False, restored=True)
            after = {n: Path(checkout, ".git", n).read_bytes() for n in ("config", "shallow")}
            self.assertEqual((rec["mode"], rec["reason"]), ("reduced", "lane PR"))
            self.assertEqual(after, before)
            # The restore made map/ as well as the file: both are gone.
            self.assertFalse(os.path.exists(os.path.join(checkout, "map")))

    def test_a_map_file_the_pr_put_there_is_kept_and_the_record_is_full(self) -> None:
        for tracked in (True, False):
            with tempfile.TemporaryDirectory() as d:
                checkout = os.path.join(d, "co")
                shutil.copytree(self.checkout, checkout, symlinks=True)
                rec = self.run_main(checkout, tracked=tracked, restored=False)
                self.assertEqual((rec["mode"], rec["reason"]), ("full", "map path taken"), tracked)
                kept = Path(checkout, "map", "affected-map.json")
                self.assertEqual(kept.read_bytes() if kept.exists() else b"", self.map_bytes, tracked)


class Timeout(unittest.TestCase):
    """TIME: a git call that hangs ends as an unread diff, quickly."""

    def test_a_hanging_git_is_an_unread_diff(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d, "git")
            fake.write_text("#!/bin/sh\nsleep 3\n")
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            saved_path, saved_timeout = os.environ["PATH"], sel.GIT_TIMEOUT
            os.environ["PATH"] = d + os.pathsep + saved_path
            sel.GIT_TIMEOUT = 1
            started = time.monotonic()
            try:
                try:
                    sel.git(d, "status")
                    got = "answered"
                except sel.Full as full:
                    got = full.reason
            finally:
                os.environ["PATH"], sel.GIT_TIMEOUT = saved_path, saved_timeout
            self.assertEqual(got, "diff unread")
            self.assertLess(time.monotonic() - started, 2.5)


JOBS = {"test-shards": "Shard suite", "test-shards-lib": "Shard suite from the part binaries"}
NEW_STEPS = ("Affected tests map", "Affected tests (shadow)", "Affected tests record", "Upload the affected tests record")
LANE_PR = ("github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line' && "
           "github.event.pull_request.head.repo.full_name == github.repository && "
           "!startsWith(github.head_ref, 'train/')")
# sha256 over the four legs' other steps (name, if, uses, run), as at the base: this part changes none of them.
# Child E, which gates those steps, updates this value; the failure message prints the current one.
# Since then the shared writer's root rows add three steps to int-b and three to lib-b.
EXISTING_DIGEST = "2295c6d0df862718523c3bc0d649ea33f4e67b28840012d8a0b2be3018be6017"


def _yaml(name: str) -> dict:
    import yaml
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))


def ci_doc() -> dict:
    return _yaml("ci.yml")


def existing_digest(doc: dict) -> str:
    rows = [[job, s.get("name"), s.get("if"), s.get("uses"), s.get("run")]
            for job in JOBS for s in doc["jobs"][job]["steps"] if s.get("name") not in NEW_STEPS]
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def finalize_text(doc: dict) -> str:
    return next(s["run"] for s in doc["jobs"]["test-shards"]["steps"] if s.get("name") == "Affected tests record")


class Wiring(unittest.TestCase):
    """S10', S11, S12, S19 (wiring), TIME (wiring), CLEAN (restore condition): parsing ci.yml."""

    def setUp(self) -> None:
        self.doc = ci_doc()

    def steps(self, job: str) -> list[dict]:
        return self.doc["jobs"][job]["steps"]

    def test_each_leg_has_the_four_steps_right_before_its_shard_step(self) -> None:
        for job, shard in JOBS.items():
            names = [s.get("name") for s in self.steps(job)]
            at = names.index(shard)
            self.assertEqual(tuple(names[at - 4:at]), NEW_STEPS, job)
            new = {s["name"]: s for s in self.steps(job) if s.get("name") in NEW_STEPS}
            for name, s in new.items():
                self.assertIs(s.get("continue-on-error"), True, (job, name))
                self.assertLessEqual(int(s.get("timeout-minutes", 99)), 3, (job, name))
            self.assertEqual(new["Affected tests map"]["if"], "${{ " + LANE_PR + " && hashFiles('map/**') == '' }}")
            self.assertEqual(new["Affected tests (shadow)"].get("id"), "select")
            self.assertEqual(new["Affected tests map"].get("id"), "affected-map")
            for name in ("Affected tests (shadow)", "Affected tests record"):
                self.assertEqual(new[name]["env"]["RESTORED"], "${{ steps.affected-map.outputs.cache-matched-key }}")
            for name in ("Affected tests record", "Upload the affected tests record"):
                self.assertEqual(new[name]["if"], "${{ !cancelled() }}", (job, name))
        lib = [s.get("name") for s in self.steps("test-shards-lib")]
        self.assertLess(lib.index("Fetch the lib test part binaries"), lib.index("Affected tests (shadow)"))

    def test_the_restore_reads_what_the_map_workflow_saves(self) -> None:
        save = next(s for s in _yaml("affected-map.yml")["jobs"]["merge"]["steps"] if s.get("name") == "Publish the map")
        for job in JOBS:
            restore = next(s for s in self.steps(job) if s.get("name") == "Affected tests map")
            self.assertEqual(restore["with"]["path"], save["with"]["path"])
            self.assertTrue(save["with"]["key"].startswith(restore["with"]["restore-keys"]))
            self.assertEqual(restore["uses"].split("@")[1], save["uses"].split("@")[1])

    def test_no_other_step_of_the_legs_changed(self) -> None:
        self.assertEqual(existing_digest(self.doc), EXISTING_DIGEST, "the four legs' other steps changed")
        for job in JOBS:
            for s in self.steps(job):
                if s.get("name") not in NEW_STEPS:
                    self.assertNotIn("steps.select", json.dumps(s), (job, s.get("name")))

    def test_no_test_leg_reads_the_scope_job(self) -> None:
        for job in JOBS:
            needs = self.doc["jobs"][job].get("needs", [])
            self.assertNotIn("scope", [needs] if isinstance(needs, str) else needs, job)

    def test_no_producer_or_windows_job_selects(self) -> None:
        jobs = [j for j in self.doc["jobs"] if j.startswith("windows")]
        for job in ["linux-lib-build", "linux-lib-union", "linux-gateway-bin", *jobs]:
            for s in self.doc["jobs"][job].get("steps", []):
                self.assertNotIn("affected_select", json.dumps(s), (job, s.get("name")))
                self.assertNotIn(s.get("name"), NEW_STEPS, job)

    def run_finalize(self, existing: str | None, restored: str = "") -> dict:
        """The record step's own script, in a folder that is not a repository; also notes whether map/ is left."""
        with tempfile.TemporaryDirectory() as d:
            record = Path(d, "affected-select", "lib-a.json")
            if existing is not None:
                record.parent.mkdir()
                record.write_text(existing)
            Path(d, "map").mkdir()
            Path(d, "map", "affected-map.json").write_text("{}")
            env = {"PATH": os.environ["PATH"], "RUNNER_TEMP": d, "LEG": "lib-a", "OUTCOME": "failure", "ATTEMPT": "3",
                   "RESTORED": restored}
            # bash as GitHub runs a step (-e, pipefail).
            subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", finalize_text(self.doc)],
                           cwd=d, env=env, check=False, capture_output=True)
            self.map_left = Path(d, "map").exists()
            return json.loads(record.read_text()) if record.exists() else {}

    def test_the_record_step_removes_only_a_restored_map(self) -> None:
        self.run_finalize(None, restored="affected-map-abc")
        self.assertFalse(self.map_left)
        self.run_finalize(None, restored="")
        self.assertTrue(self.map_left)

    def test_the_record_step_writes_a_record_without_the_repository(self) -> None:
        made = self.run_finalize(None)
        self.assertEqual(sorted(made), sorted(sel.RECORD_KEYS))
        self.assertEqual((made["mode"], made["reason"], made["run_attempt"]), ("full", "select failure", 3))
        self.assertIn(made["reason"], sel.REASONS)
        self.assertEqual(self.run_finalize('{"leg": "lib-a", "mo')["reason"], "select failure")
        valid = sel.record("lib-a", "none", "lane PR", "abc", [], 3)
        self.assertEqual(self.run_finalize(json.dumps(valid)), valid)


def _edit(doc: dict, job: str, name: str, **fields) -> dict:
    doc = copy.deepcopy(doc)
    step = next(s for s in doc["jobs"][job]["steps"] if s.get("name") == name)
    for k, v in fields.items():
        if v is None:
            step.pop(k, None)
        else:
            step[k] = v
    return doc


def _mutants() -> list:
    """(name, row class, [(object, attribute, replacement), ...]). Each replacement wraps the real code."""
    me = sys.modules[__name__]
    real = {k: getattr(sel, k) for k in ("event_class", "select_units", "leg_record", "lib_listing", "history",
                                         "git", "is_ancestor", "record", "write_record", "drop_restored_map")}
    real_doc, real_final, real_decide = ci_doc, finalize_text, sel.decide

    def head_of(e: dict) -> dict:
        return ((e.get("pull_request") or {}).get("head") or {})

    def with_event(e: dict, base=None, ref=None) -> dict:
        e = copy.deepcopy(e)
        pr = e.get("pull_request")
        if pr is not None and base is not None:
            pr["base"]["ref"] = base(pr["base"]["ref"])
        if pr is not None and ref is not None:
            pr["head"]["ref"] = ref(pr["head"]["ref"])
        return e

    def units_map(fn):
        return lambda u, h, b: real["select_units"]({k: fn(dict(v)) for k, v in u.items()}, h, b)

    def history_map(fn):
        return lambda u, h, b: real["select_units"](u, fn(h), b)

    def changes_map(fn):
        return history_map(lambda h: sel.History(h.base, [fn(c) for c in h.changes], h.dirs_at_map, h.dirs_at_merge))

    def folder_only(v: dict) -> dict:
        v["dirs"] = sorted({os.path.dirname(p) for p in v["files"]})
        v["files"] = []
        return v

    def groups_known(leg, units, chosen, listing):
        groups = {k[len("lib:"):] for k in units if k.startswith("lib:")}
        keep = None if listing is None else {n for n in listing if not any(n.startswith(g + "::") for g in groups)
                                             or any(n in u["tests"] for u in units.values())}
        return real["leg_record"](leg, units, chosen, keep)

    def empty_means_none(leg, units, chosen, listing):
        mode, names = real["leg_record"](leg, units, chosen, listing)
        if leg not in sel.LIB_LEGS and not any(n.startswith("test:") and n not in sel.ALWAYS.get(leg, ())
                                               for n in names):
            return "none", []
        return mode, names

    def quiet_listing(leg, d):
        try:
            return real["lib_listing"](leg, d)
        except sel.Full:
            return set()

    def second_parent_ignored(origin, merge, head, map_sha, scratch):
        actual = sh("git", "-C", origin.removeprefix("file://"), "rev-parse", merge + "^2")
        return real["history"](origin, merge, actual, map_sha, scratch)

    def no_fetch(repo, *a):
        return "" if a and a[0] == "fetch" else real["git"](repo, *a)

    def diff_from_base(repo, *a):
        if a and a[0] == "diff":
            a = (*a[:-2], real["git"](repo, "rev-parse", a[-1] + "^1").strip(), a[-1])
        return real["git"](repo, *a)

    def failures_as_empty(repo, *a):
        try:
            return real["git"](repo, *a)
        except sel.Full:
            return ""

    def fetch_into_checkout(origin, merge, head, map_sha, scratch):
        sh("git", "-C", os.environ["GITHUB_WORKSPACE"], "fetch", "-q", "--depth=2", origin, merge)
        return real["history"](origin, merge, head, map_sha, scratch)

    def no_timeout(repo, *a):
        return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True).stdout

    def doc_with(job, name, **fields):
        return lambda: _edit(real_doc(), job, name, **fields)

    def needs_scope():
        doc = copy.deepcopy(real_doc())
        doc["jobs"]["test-shards"]["needs"] = ["scope"]
        return doc

    def producer_selects():
        doc = copy.deepcopy(real_doc())
        doc["jobs"]["linux-lib-build"]["steps"].append(
            {"name": "Affected tests (shadow)", "run": "python3 scripts/ci/affected_select.py lib-a x"})
        return doc

    def mode_read():
        shard = next(s for s in real_doc()["jobs"]["test-shards"]["steps"] if s.get("name") == "Shard suite")
        return _edit(real_doc(), "test-shards", "Shard suite", run=shard["run"] + " ${{ steps.select.outputs.mode }}")

    return [
        ("S1' the same-repository clause dropped", "Events", [(sel, "event_class", lambda n, e, r, ref="":
            real["event_class"](n, e, (head_of(e).get("repo") or {}).get("full_name", r), ref))]),
        ("S1' the train/ test dropped", "Events", [(sel, "event_class", lambda n, e, r, ref="":
            real["event_class"](n, with_event(e, ref=lambda x: x.removeprefix("train/")), r, ref))]),
        ("S1' the base matched by prefix", "Events", [(sel, "event_class", lambda n, e, r, ref="":
            real["event_class"](n, with_event(e, base=lambda b: sel.LINE if b.startswith(sel.LINE) else b), r, ref))]),
        ("S2 an extra unit key accepted", "MapShape", [(sel, "UNIT_KEYS", sel.UNIT_KEYS | {"x"})]),
        ("S3' the build script hard-coded", "Rule", [(sel, "build_script", lambda p: "scripts/dev/test-parts-build.rs")]),
        ("S3' folder entries matched exactly", "Rule", [(sel, "force_full", lambda p, b: p in sel.FORCE_FULL or p == b)]),
        ("S4 R3 only under src/", "Rule", [(sel, "select_units", history_map(lambda h: sel.History(
            h.base, [c for c in h.changes if not c.path.endswith(".rs") or c.path.startswith("src/")],
            h.dirs_at_map, h.dirs_at_merge)))]),
        ("S5 selected by folder only", "Rule", [(sel, "select_units", units_map(folder_only))]),
        ("S14 the path's own name only", "Rule", [(sel, "ancestors", lambda p: [])]),
        ("S14 the walk goes to the root", "Rule", [(sel, "select_units", history_map(
            lambda h: sel.History(h.base, h.changes, h.dirs_at_map, set())))]),
        ("S14 the walk stops at the first folder the map knew", "Rule", [(sel, "select_units", history_map(
            lambda h: sel.History(h.base, h.changes, h.dirs_at_map, h.dirs_at_map | h.dirs_at_merge)))]),
        ("S14 the files rule dropped", "Rule", [(sel, "select_units", units_map(lambda v: {**v, "files": []}))]),
        ("S16 probes dropped", "Rule", [(sel, "select_units", units_map(lambda v: {**v, "probes": []}))]),
        ("S16 only the direct parent", "Rule", [(sel, "ancestors", lambda p: [os.path.dirname(p)])]),
        ("S22 a file under a listed folder counted as executed", "Rule", [(sel, "select_units", lambda u, h, b:
            real["select_units"]({k: {**v, "files": [*v["files"], *(c.path for c in h.changes
                                                                    if os.path.dirname(c.path) in v["dirs"])]}
                                  for k, v in u.items()}, h, b))]),
        ("LINK only the new side's mode", "Rule", [(sel, "select_units", changes_map(
            lambda c: sel.Change(c.status, c.path, "100644", c.new_mode)))]),
        ("LINK the type change ignored", "Rule", [(sel, "select_units", changes_map(
            lambda c: sel.Change("M" if c.status == "T" else c.status, c.path, c.old_mode,
                                 "100644" if c.status == "T" else c.new_mode)))]),
        ("S17 decided before the listing", "Legs", [(sel, "leg_record", lambda leg, u, c, l: real["leg_record"](
            leg, u, c, None if l is None else {t for t in l if any(t in v["tests"] for v in u.values())}))]),
        ("S17 compared with every unit's names", "Legs", [(sel, "leg_record", lambda leg, u, c, l: real["leg_record"](
            leg, {(k if k.startswith("lib:") else "lib:" + k): v for k, v in u.items()}, c, l))]),
        ("S20 group paths compared, not names", "Legs", [(sel, "leg_record", groups_known)]),
        ("S21 an empty target list means none", "Legs", [(sel, "leg_record", empty_means_none)]),
        ("UPG the always table dropped", "Legs", [(sel, "ALWAYS", {})]),
        ("LIST an unreadable listing taken as empty", "Legs", [(sel, "lib_listing", quiet_listing)]),
        ("REC an extra key", "Record", [(sel, "record", lambda *a: {**real["record"](*a), "x": 1})]),
        ("S9 an error recorded as a lane PR", "Record", [(sel, "record", lambda leg, mode, reason, *a:
            real["record"](leg, mode, "lane PR" if reason == "error" else reason, *a))]),
        ("REC a temporary file left beside the record", "Record", [(sel, "write_record", lambda path, rec: (
            real["write_record"](path, rec), Path(path).with_name(".record-left").write_text("")))]),
        ("S2 ancestry not checked", "GitHistory", [(sel, "is_ancestor", lambda repo, a, b: True)]),
        ("S2 the second parent not checked", "GitHistory", [(sel, "history", second_parent_ignored)]),
        ("S2 the fetches skipped", "GitHistory", [(sel, "git", no_fetch)]),
        ("S6 the diff taken from the base", "GitHistory", [(sel, "git", diff_from_base)]),
        ("S23 a failed git read as empty", "GitHistory", [(sel, "git", failures_as_empty)]),
        ("CLEAN fetched into the checkout", "GitHistory", [(sel, "history", fetch_into_checkout)]),
        ("CLEAN the restored map left", "GitHistory", [(sel, "drop_restored_map", lambda p, t: None)]),
        ("CLEAN the PR's own map file deleted", "GitHistory", [(sel, "drop_restored_map",
                                                               lambda p, r: real["drop_restored_map"](p, True))]),
        ("CLEAN a map read without a restore", "GitHistory", [(sel, "decide", lambda inp: real_decide(
            sel.Inputs(**{**inp.__dict__, "restored": True})))]),
        ("CLEAN the record step removes a map it did not restore", "Wiring", [(me, "finalize_text", lambda doc:
            real_final(doc).replace('[ -n "$RESTORED" ]', "true", 1))]),
        ("S21 the examples build left out", "Legs", [(sel.shard_tests, "EXAMPLES", {})]),
        ("TIME no timeout on git", "Timeout", [(sel, "git", no_timeout)]),
        ("S10' an if added to the shard step", "Wiring", [(me, "ci_doc", doc_with("test-shards", "Shard suite",
                                                                              **{"if": "false"}))]),
        ("S10' the shard step reads the mode", "Wiring", [(me, "ci_doc", mode_read)]),
        ("S10' the select step not continue-on-error", "Wiring", [(me, "ci_doc", doc_with(
            "test-shards-lib", "Affected tests (shadow)", **{"continue-on-error": None}))]),
        ("CLEAN the hashFiles clause dropped", "Wiring", [(me, "ci_doc", doc_with(
            "test-shards", "Affected tests map", **{"if": "${{ " + LANE_PR + " }}"}))]),
        ("TIME the select step without a timeout", "Wiring", [(me, "ci_doc", doc_with(
            "test-shards", "Affected tests (shadow)", **{"timeout-minutes": None}))]),
        ("S19 the upload behind the shard step's success", "Wiring", [(me, "ci_doc", doc_with(
            "test-shards", "Upload the affected tests record", **{"if": "${{ success() }}"}))]),
        ("S11 a leg needs scope", "Wiring", [(me, "ci_doc", needs_scope)]),
        ("S12 a build leg selects", "Wiring", [(me, "ci_doc", producer_selects)]),
        ("S19 an existing record overwritten", "Wiring", [(me, "finalize_text", lambda doc: real_final(doc).replace(
            "if ! python3", "if true || python3", 1))]),
        ("S19 a repository script called", "Wiring", [(me, "finalize_text", lambda doc:
            "python3 scripts/ci/affected_select.py fallback\n" + real_final(doc))]),
    ]


def failed_assertions(case_class: type) -> tuple[int, int]:
    """Run one row class quietly; return (assertion failures, errors)."""
    result = unittest.TestResult()
    unittest.TestLoader().loadTestsFromTestCase(case_class).run(result)
    return len(result.failures), len(result.errors)


class Mutants(unittest.TestCase):
    """Every break listed in _mutants() must trip an assertion in its row class. A break that only raises an error
    shows nothing about what the row checks, so errors alone do not count."""

    def test_every_break_is_caught(self) -> None:
        module = sys.modules[__name__]
        for name, target, patches in _mutants():
            with self.subTest(name):
                originals = [(obj, attr, getattr(obj, attr)) for obj, attr, _ in patches]
                try:
                    for obj, attr, value in patches:
                        setattr(obj, attr, value)
                    failures, errors = failed_assertions(getattr(module, target))
                finally:
                    for obj, attr, value in originals:
                        setattr(obj, attr, value)
                self.assertGreater(failures, 0, f"{name}: {target} stayed green under this break ({errors} errors)")


if __name__ == "__main__":
    unittest.main()
