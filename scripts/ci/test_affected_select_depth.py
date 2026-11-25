#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Regression guards for the selector on depth-3 units (the map split's row family P9). The selector picks units by the
files they recorded and names from each unit's own test list, so it needs no change for the map's split; these rows
keep it that way.

    python3 scripts/ci/test_affected_select_depth.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import affected_select as sel  # noqa: E402

LEG = "lib-a"  # a lib leg with no ALWAYS prefixes


def unit(tests: list[str], files: list[str]) -> dict:
    return dict(files=files, dirs=[], probes=[], tests=tests, seconds=1.0, binary="unittests src/lib.rs",
                unmapped=False)


def chosen_names(units: dict, changed: list[str], listing: set[str]) -> list[str]:
    h = sel.History("base", [sel.Change("M", p, "100644", "100644") for p in changed], set(), set())
    picked = sel.select_units(units, h, None)
    return sel.leg_record(LEG, units, picked, listing)[1]


class Depth(unittest.TestCase):
    UNITS = {
        "lib:k::m::a": unit(["k::m::a::t1"], ["src/a.rs"]),
        "lib:k::m::b": unit(["k::m::b::t2"], ["src/b.rs"]),
        "lib:commands::doctor::x": unit(["commands::doctor::x::t3"], ["src/doctor.rs"]),
        "lib:commands::doctor_extra": unit(["commands::doctor_extra::y::t4"], ["src/extra.rs"]),
        "lib:solo": unit(["solo"], ["src/solo.rs"]),
    }
    LISTING = {t for u in UNITS.values() for t in u["tests"]}

    def test_p9a_a_file_on_one_depth_three_unit_selects_only_its_tests(self) -> None:
        self.assertEqual(chosen_names(self.UNITS, ["src/a.rs"], self.LISTING), ["k::m::a::t1"])

    def test_p9b_short_names_and_the_doctor_boundary_select_their_own_unit(self) -> None:
        self.assertEqual(chosen_names(self.UNITS, ["src/extra.rs"], self.LISTING), ["commands::doctor_extra::y::t4"])
        self.assertEqual(chosen_names(self.UNITS, ["src/doctor.rs"], self.LISTING), ["commands::doctor::x::t3"])
        self.assertEqual(chosen_names(self.UNITS, ["src/solo.rs"], self.LISTING), ["solo"])

    def test_p9c_a_test_no_unit_knows_always_runs(self) -> None:
        # The unknown-test fail-safe (leg_record: listed names no lib unit knows), not depth-3 selection.
        listing = self.LISTING | {"k::m::a::brand_new"}
        self.assertEqual(chosen_names(self.UNITS, ["src/b.rs"], listing), ["k::m::a::brand_new", "k::m::b::t2"])


def _mutants() -> list[tuple[str, str, dict]]:
    """Breaks that would make the selector depend on a unit label's shape (test plan sidecar 1)."""
    real = sel.select_units

    def by_depth_two_prefix(units, h, build):
        picked = real(units, h, build)
        heads = {"::".join(label.split("::")[:2]) for label in picked}
        return picked | {label for label in units if "::".join(label.split("::")[:2]) in heads}

    def by_string_prefix(units, h, build):
        # The depth-2 head compared as raw text, with no segment boundary: commands::doctor takes doctor_extra too.
        picked = real(units, h, build)
        heads = {"::".join(label.split("::")[:2]) for label in picked}
        return picked | {label for label in units if any(label.startswith(p) for p in heads)}

    def unknown_tests_dropped(leg, units, chosen, listing):
        mode, names = real_record(leg, units, chosen, listing)
        known = {t for u in units.values() for t in u["tests"]}
        kept = [n for n in names if n in known]
        return ("reduced" if kept else "none"), kept
    real_record = sel.leg_record
    return [
        ("labels matched by their depth-2 prefix", "Depth", {"select_units": by_depth_two_prefix}),
        ("labels matched by string prefix", "Depth", {"select_units": by_string_prefix}),
        ("the unknown-test fail-safe dropped", "Depth", {"leg_record": unknown_tests_dropped}),
    ]


class Mutants(unittest.TestCase):
    def test_each_mutant_turns_a_guard_red(self) -> None:
        from mutant_rows import check_mutants
        check_mutants(self, sel, _mutants(), globals())


if __name__ == "__main__":
    unittest.main()
