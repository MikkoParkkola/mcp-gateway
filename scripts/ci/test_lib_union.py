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


def fixture(root: Path, lists: dict[int, list[str]], expected=EXPECT, build=BUILD) -> list[str]:
    """Write `lists` (part -> names, as each part leg's list.txt holds them, `name: test` lines) under `root`, and
    return the check's arguments: the lists folder, the expected folder and the build script."""
    (root / "build.rs").write_text(build)
    for part, names in lists.items():
        d = root / "lists" / f"linux-lib-tests-p{part}" / f"p{part}"
        d.mkdir(parents=True)
        (d / "list.txt").write_text("".join(f"{n}: test\n" for n in names) + "\n3 tests, 0 benchmarks\n")
    for part, names in expected.items():
        (root / "expected").mkdir(exist_ok=True)
        (root / "expected" / f"p{part}.txt").write_text("".join(f"{n}\n" for n in names))
    return [str(root / "lists"), str(root / "expected"), str(root / "build.rs")]


def problems(lists: dict[int, list[str]], expected=EXPECT, build=BUILD) -> list[str]:
    with TemporaryDirectory() as tmp:
        return U.problems(*map(Path, fixture(Path(tmp), lists, expected, build)))


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

    def test_the_exit_status_is_what_ci_reads(self):
        """CI reads the script's exit status, not the problem list: 1 on any problem, 0 on exact lists."""
        for lists, want in ((EXPECT, 0), ({1: EXPECT[1], 2: EXPECT[2]}, 1)):
            with TemporaryDirectory() as tmp:
                self.assertEqual(U.main(["lib_union.py", *fixture(Path(tmp), lists)]), want, lists)


if __name__ == "__main__":
    unittest.main()
