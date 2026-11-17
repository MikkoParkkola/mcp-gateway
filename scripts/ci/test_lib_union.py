#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/lib_union.py: the per-run union check over the lib test part binaries' lists (U1)."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().with_name("lib_union.py")
_spec = importlib.util.spec_from_file_location("lib_union", SCRIPT)
U = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(U)

BUILD = "fn main() {\n    const N: u32 = 3;\n}\n"
EXPECT = {1: ["a::t1", "a::t2"], 2: ["b::t3"], 3: ["c::t4"]}


def problems(lists: dict[int, list[str]], expected=EXPECT, build=BUILD) -> list[str]:
    """Run the check on `lists` (part -> names, as each part leg's list.txt holds them, `name: test` lines)."""
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "build.rs").write_text(build)
        for part, names in lists.items():
            d = root / "lists" / f"linux-lib-tests-p{part}" / f"p{part}"
            d.mkdir(parents=True)
            (d / "list.txt").write_text("".join(f"{n}: test\n" for n in names) + "\n3 tests, 0 benchmarks\n")
        for part, names in expected.items():
            (root / "expected").mkdir(exist_ok=True)
            (root / "expected" / f"p{part}.txt").write_text("".join(f"{n}\n" for n in names))
        return U.problems(root / "lists", root / "expected", root / "build.rs")


class Union(unittest.TestCase):
    def test_exact_lists_pass(self):
        self.assertEqual(problems(EXPECT), [])

    def test_a_missing_part(self):
        self.assertTrue(any("part 3" in p for p in problems({1: EXPECT[1], 2: EXPECT[2]})))

    def test_a_part_beyond_n(self):
        self.assertTrue(problems({**EXPECT, 4: ["d::t5"]}))

    def test_n_disagreeing_with_the_build_script(self):
        self.assertTrue(problems(EXPECT, build="fn main() {\n    const N: u32 = 4;\n}\n"))

    def test_a_name_missing_from_a_part(self):
        found = problems({**EXPECT, 1: ["a::t1"]})
        self.assertTrue(any("a::t2" in p for p in found), found)

    def test_an_extra_name_in_a_part(self):
        found = problems({**EXPECT, 2: ["b::t3", "b::stray"]})
        self.assertTrue(any("b::stray" in p for p in found), found)

    def test_two_parts_sharing_a_name(self):
        both = {1: ["a::t1", "a::t2"], 2: ["b::t3", "a::t1"], 3: ["c::t4"]}
        expected = {1: ["a::t1", "a::t2"], 2: ["b::t3", "a::t1"], 3: ["c::t4"]}
        self.assertTrue(any("a::t1" in p and "two parts" in p for p in problems(both, expected)))

    def test_an_empty_part(self):
        self.assertTrue(problems({**EXPECT, 3: []}, {**EXPECT, 3: []}))


if __name__ == "__main__":
    unittest.main()
