#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for the map's split plan: the SPLIT_MAX largest lib groups of the previous map split one level,
the merge only folds, and the workflow carries the list. P1-P8 and P10 here; P9 lives beside the selector.

    python3 scripts/ci/test_affected_map_plan.py
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import affected_map as am  # noqa: E402

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/affected-map.yml"
NOW = datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc)


def unit(tests, seconds, binary=None, **kw) -> dict:
    rec = dict(files=[], dirs=[], probes=[], tests=list(tests), seconds=seconds, binary=binary or am.LIB_BINARY,
               unmapped=False)
    rec.update(kw)
    return rec


def lib_map(groups: dict[str, tuple[int, float]]) -> dict:
    """A previous map: label -> (how many tests, seconds); its test names are the label plus t0, t1, ..."""
    return {"map_sha": "s", "built_at": "2026-01-01T00:00:00Z", "units": {
        "lib:" + k: unit([f"{k}::t{i}" for i in range(n)], s) for k, (n, s) in groups.items()}}


def filler(n: int, each: float) -> dict[str, tuple[int, float]]:
    return {f"f{i:02d}::g": (2, each) for i in range(n)}


class Plan(unittest.TestCase):
    """P1-P2: the SPLIT_MAX largest lib groups of the previous map, by seconds; no threshold."""

    # z, y, x: seconds order z > y > x; test counts x > y > z; label order x < y < z. y holds 8% of the total.
    GROUPS = {"z::a": (2, 50.0), "y::b": (3, 8.0), "x::c": (4, 6.0), **filler(9, 4.0)}

    def test_p1_no_map_or_an_unreadable_one_splits_nothing(self) -> None:
        self.assertEqual(am.plan(None), [])
        self.assertEqual(am.plan({"units": "not a dict"}), [])
        self.assertEqual(am.unit_key("a::b::c::t", []), "a::b")

    def test_p2a_the_largest_by_seconds_and_the_cap_moves_the_cut(self) -> None:
        doc = lib_map(self.GROUPS)
        self.assertEqual(am.plan(doc, 2), ["z::a", "y::b"])
        self.assertEqual(am.plan(doc, 1), ["z::a"])
        self.assertEqual(am.plan(doc, 3), ["z::a", "y::b", "x::c"])
        self.assertEqual(am.plan(doc), ["z::a", "y::b"], "SPLIT_MAX is 2")

    def test_p2a2_a_group_over_ten_percent_that_missed_the_cut_keeps_depth_two(self) -> None:
        doc = lib_map({"a::a": (2, 40.0), "b::b": (2, 30.0), "c::c": (2, 20.0), **filler(5, 2.0)})
        listed = am.plan(doc, 1)
        self.assertEqual(listed, ["a::a"])
        self.assertEqual(am.unit_key("c::c::m::t", listed), "c::c")
        self.assertEqual(am.unit_key("a::a::m::t", listed), "a::a::m")

    def test_p2b2_an_already_split_group_ranks_on_its_childrens_sum(self) -> None:
        doc = lib_map({"big::one": (2, 30.0), "k::m::p": (2, 20.0), "k::m::q": (2, 20.0), **filler(3, 5.0)})
        self.assertEqual(am.plan(doc, 1), ["k::m"])

    def test_p2c_equal_seconds_break_by_label(self) -> None:
        doc = lib_map({"b::b": (2, 10.0), "a::a": (2, 10.0), "c::c": (2, 10.0)})
        self.assertEqual(am.plan(doc, 2), ["a::a", "b::b"])

    def test_p2d_integration_units_never_rank(self) -> None:
        doc = lib_map(self.GROUPS)
        doc["units"]["test:e2e"] = unit(["e2e"], 500.0, binary="tests/e2e.rs")
        self.assertEqual(am.plan(doc, 2), ["z::a", "y::b"])


def write_parts(tmp: str, docs: list[dict]) -> list[str]:
    dirs = []
    for i, doc in enumerate(docs):
        d = Path(tmp, f"p{i}")
        d.mkdir()
        (d / "part.json").write_text(json.dumps(doc))
        dirs.append(str(d))
    return dirs


def merged(docs: list[dict]) -> tuple[dict, dict]:
    with tempfile.TemporaryDirectory() as tmp:
        am.merge("s", write_parts(tmp, docs), str(Path(tmp, "out")), NOW)
        return (json.loads(Path(tmp, "out", "affected-map.json").read_text()),
                json.loads(Path(tmp, "out", "unmapped-reasons.json").read_text()))


def part_doc(units: dict, reasons: dict | None = None, extra=()) -> dict:
    return {"part": "lib-x", "binary": None, "extra_files": list(extra), "units": units,
            "unmapped_reasons": reasons or {k: [] for k in units}}


class Plans(unittest.TestCase):
    """P3: recomputed every run, one level only, and the merge's map plans the same list."""

    @staticmethod
    def build(test_seconds: dict[str, float], split: list[str]) -> dict:
        units: dict[str, dict] = {}
        for name, s in test_seconds.items():
            u = units.setdefault("lib:" + am.unit_key(name, split), unit([], 0.0))
            u["tests"].append(name)
            u["seconds"] += s
        return {"map_sha": "s", "built_at": "2026-01-01T00:00:00Z", "units": units}

    def test_p3a_a_group_that_falls_out_returns_to_depth_two(self) -> None:
        doc = lib_map({"k::m::p": (2, 3.0), "k::m::q": (2, 3.0), "a::a": (2, 40.0), "b::b": (2, 30.0)})
        listed = am.plan(doc, 2)
        self.assertEqual(listed, ["a::a", "b::b"])
        self.assertEqual(am.unit_key("k::m::p::t0", listed), "k::m")

    def test_p3b_no_accumulation_and_never_a_second_level(self) -> None:
        # h::d's children are heavy and their names run four segments past the prefix.
        tests = {f"h::d::c{i}::x::t{j}": 6.0 for i in range(3) for j in range(4)}
        tests.update({f"g::e::t{j}": 2.0 for j in range(10)})
        tests.update({f"n::w::t{j}": 1.0 for j in range(10)})
        split: list[str] = []
        for step in range(3):
            if step == 2:  # n::w overtakes g::e
                tests.update({f"n::w::t{j}": 9.0 for j in range(10)})
            split = am.plan(self.build(tests, split))
            self.assertLessEqual(len(split), am.SPLIT_MAX)
            keys = set(self.build(tests, split)["units"])
            self.assertTrue(all(len(k[4:].split("::")) <= 3 for k in keys), keys)
        self.assertEqual(split, ["n::w", "h::d"])
        self.assertEqual(am.unit_key("h::d::c0::x::t0", split), "h::d::c0")

    def test_p3c_the_merged_map_plans_the_same_list_by_seconds(self) -> None:
        doc, _ = merged([part_doc({"lib:a::a": unit(["a::a::t"], 1.0), "lib:m::m": unit(["m::m::t", "m::m::u"], 30.0),
                                   "lib:z::z": unit(["z::z::t", "z::z::u"], 20.0), "lib:b::b": unit(["b::b::t"], 2.0)})])
        self.assertEqual(am.plan(doc, 2), ["m::m", "z::z"])

    def test_p2b1_a_label_ranks_in_only_on_its_sum_over_two_parts(self) -> None:
        light = {"lib:q::q": unit(["q::q::t1"], 6.0), "lib:r::r": unit(["r::r::t"], 9.0)}
        doc, _ = merged([part_doc(light), part_doc({"lib:q::q": unit(["q::q::t2"], 6.0)})])
        self.assertEqual(am.plan(doc, 1), ["q::q"])


class Keys(unittest.TestCase):
    """P4: a test's unit key; a split prefix adds one segment, matched on whole segments."""

    def test_p4a_a_test_under_a_split_prefix_gets_the_three_segment_key(self) -> None:
        self.assertEqual(am.unit_key("k::m::sub::t", ["k::m"]), "k::m::sub")
        self.assertEqual(am.unit_key("k::m::brand_new::t", ["k::m"]), "k::m::brand_new")
        self.assertEqual(am.unit_key("k::m::sub::t", []), "k::m")

    def test_p4b_doctor_on_the_list_does_not_split_doctor_extra(self) -> None:
        split = ["commands::doctor"]
        self.assertEqual(am.unit_key("commands::doctor::npm_pin::t", split), "commands::doctor::npm_pin")
        self.assertEqual(am.unit_key("commands::doctor_extra::npm_pin::t", split), "commands::doctor_extra")

    def test_p4c_literal_keys_for_short_and_shared_names(self) -> None:
        split = ["k::m"]
        self.assertEqual(am.unit_key("solo", split), "solo")
        self.assertEqual(am.unit_key("k::m", split), "k::m")
        self.assertEqual(am.unit_key("k::m::a::t1", split), am.unit_key("k::m::a::t2", split))
        self.assertEqual(am.unit_key("k::m::a::t1", split), "k::m::a")
        self.assertNotEqual(am.unit_key("k::m::a::t1", split), am.unit_key("k::m::b::t1", split))


class Fold(unittest.TestCase):
    """P6: one label in several parts becomes one unit; every field is kept from every part."""

    @staticmethod
    def side(i: int, unmapped: bool, reasons: list[str]) -> dict:
        u = unit([f"k::m::t{i}"], float(i + 1), files=[f"src/f{i}.rs"], dirs=[f"d{i}"], probes=[f"p{i}"],
                 unmapped=unmapped)
        return part_doc({"lib:k::m": u}, {"lib:k::m": reasons})

    def test_p6a_two_parts_that_disagree_on_every_field(self) -> None:
        for flags in ((False, True), (True, False)):
            doc, counts = merged([self.side(0, flags[0], ["coverage"] if flags[0] else []),
                                  self.side(1, flags[1], ["coverage", "trace"] if flags[1] else [])])
            u = doc["units"]["lib:k::m"]
            self.assertEqual(sorted(u["tests"]), ["k::m::t0", "k::m::t1"])
            self.assertEqual(sorted(u["files"]), ["src/f0.rs", "src/f1.rs"])
            self.assertEqual(sorted(u["dirs"]), ["d0", "d1"])
            self.assertEqual(sorted(u["probes"]), ["p0", "p1"])
            self.assertEqual(u["seconds"], 3.0)
            self.assertIs(u["unmapped"], True)
        doc, counts = merged([self.side(0, True, ["coverage", "trace"]), self.side(1, True, ["coverage"])])
        self.assertEqual(counts, {"coverage": 1, "trace": 1}, "a reason counts once per unit")
        doc, counts = merged([self.side(0, False, []), self.side(1, False, [])])
        self.assertIs(doc["units"]["lib:k::m"]["unmapped"], False)
        self.assertEqual(counts, {})

    def test_p6b_four_parts(self) -> None:
        doc, _ = merged([self.side(i, i == 2, ["listing"] if i == 2 else []) for i in range(4)])
        u = doc["units"]["lib:k::m"]
        self.assertEqual(sorted(u["tests"]), [f"k::m::t{i}" for i in range(4)])
        self.assertEqual(u["seconds"], 10.0)
        self.assertIs(u["unmapped"], True)
        self.assertEqual(sorted(u["files"]), [f"src/f{i}.rs" for i in range(4)])


class Merge(unittest.TestCase):
    """P7: the merge reads part.json files and starts nothing."""

    def test_p7_merge_starts_no_process(self) -> None:
        def refuse(*_a, **_k):
            raise AssertionError("the merge started a process")
        saved = am.run_unit, am.subprocess.run
        am.run_unit, am.subprocess.run = refuse, refuse
        try:
            doc, _ = merged([part_doc({"lib:k::m": unit(["k::m::a::t", "k::m::b::t"], 9000.0)})])
        finally:
            am.run_unit, am.subprocess.run = saved
        self.assertEqual(set(doc["units"]), {"lib:k::m"})


class Part(unittest.TestCase):
    """P8c and P10: a lib part keys its tests by the list and traces each test exactly once."""

    NAMES = ["commands::doctor::npm_pin::t1", "commands::doctor::npm_pin::t2", "commands::doctor::hidden::t3",
             "commands::doctor_extra::x::t4", "gateway::ui::t5"]

    def units(self, split: list[str]) -> tuple[dict, list[list[str]]]:
        calls: list[list[str]] = []

        def run(key: str, members: list[str]):
            calls.append(list(members))
            return unit(members, 1.0), []
        got, _ = am.lib_units(self.NAMES, split, run)
        return got, calls

    def test_p8c_a_list_holding_doctor_gives_depth_three_doctor_keys(self) -> None:
        got, _ = self.units(["commands::doctor"])
        self.assertEqual(set(got), {"lib:commands::doctor::npm_pin", "lib:commands::doctor::hidden",
                                    "lib:commands::doctor_extra", "lib:gateway::ui"})

    def test_p10_each_test_is_traced_once_one_process_per_unit(self) -> None:
        got, calls = self.units(["commands::doctor"])
        self.assertEqual(len(calls), len(got))
        self.assertEqual(sorted(t for c in calls for t in c), sorted(self.NAMES))


class Workflow(unittest.TestCase):
    """P8a and P8b: the guard plans the list on every event, each lib part gets it, the merge only parses JSON."""

    @classmethod
    def setUpClass(cls) -> None:
        import yaml
        cls.jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]

    def runs(self, job: str) -> str:
        return "\n".join(str(s.get("run", "")) + str(s.get("uses", "")) for s in self.jobs[job]["steps"])

    def test_p8a_parts_upload_only_part_json_and_the_merge_is_lean(self) -> None:
        upload = next(s for s in self.jobs["part"]["steps"] if str(s.get("uses", "")).startswith("actions/upload"))
        self.assertEqual(upload["with"]["path"].split(), ["${{ runner.temp }}/part/part.json"])
        merge = self.runs("merge")
        for gone in ("strace", "rust-toolchain", "add-swap", "chmod"):
            self.assertNotIn(gone, merge)
        self.assertEqual(self.jobs["merge"]["timeout-minutes"], 5)

    def test_p8b_the_guard_plans_on_every_event_and_each_part_gets_the_list(self) -> None:
        step = next(s for s in self.jobs["guard"]["steps"] if "affected_map.py plan" in str(s.get("run", "")))
        self.assertNotIn("if", step, "a dispatch plans the same way as a push")
        self.assertIn("steps.split.outputs.split", self.jobs["guard"]["outputs"]["split"])
        self.assertEqual(step.get("id"), "split")
        part = next(s for s in self.jobs["part"]["steps"] if "affected_map.py part" in str(s.get("run", "")))
        self.assertIn("needs.guard.outputs.split", str(part.get("env", {})))
        self.assertIn('"$SPLIT"', part["run"])

    def test_p8b_the_plan_command_prints_the_list(self) -> None:
        import subprocess
        doc = lib_map({"a::a": (2, 40.0), "b::b": (2, 30.0), "c::c": (2, 20.0)})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "m.json")
            path.write_text(json.dumps(doc))
            out = subprocess.run([sys.executable, str(Path(am.__file__)), "plan", str(path)], capture_output=True,
                                 text=True, check=True).stdout
            none = subprocess.run([sys.executable, str(Path(am.__file__)), "plan", str(Path(tmp, "absent"))],
                                  capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.strip(), 'split=["a::a", "b::b"]')
        self.assertEqual(none.strip(), "split=[]")


if __name__ == "__main__":
    unittest.main()
